"""Sealing-key files and case-body signing helpers (Phase 3 U2).

A sealing key is an Ed25519 key pair whose seed lives in a private JSON
key file (mode 0600, never committed) and whose public half may be
shared.  Case bodies are signed with a DSSE envelope over the canonical
JSON bytes of the case body, so a sealed case file can be verified
against the signer's public key without trusting the file itself.

Stdlib only.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import os
import tempfile
from collections.abc import Mapping
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .dsse import sign_envelope, verify_envelope
from .ed25519 import fingerprint, keygen, public_key_from_seed

SEALING_KEY_SCHEMA = "textforensics.sealing-key/v1"
SEALING_KEY_ALGORITHM = "ed25519"

# Case signing contract versions (W3: C02).  The DSSE envelope's
# ``payloadType`` IS the contract version marker — it is authenticated
# (inside the DSSE PAE), so a contract cannot be silently downgraded.
#
# * v1 (legacy, ``textforensics.case-file/v3``): the signed body
#   excludes the ENTIRE ``seal.signature`` mapping, so the displayed
#   signer identity/role/fingerprint are NOT authenticated.  Genuine
#   v1-signed cases still verify, with an explicit warning that the
#   signer record is unauthenticated; fingerprint and algorithm
#   mutations still fail (checked against the supplied key).
# * v2 (current, ``textforensics.case-signing/v2``): the signed body
#   excludes ONLY ``seal.signature.dsse`` — the signer record
#   (``algorithm``, ``key_fingerprint``, ``signer.identity``,
#   ``signer.role``) is inside the signed body.  New signatures are
#   always v2; production never signs v1.
# See hidden_files/audit-w3-signed-body-contract.md.
CASE_SIGNING_CONTRACT_V1 = "textforensics.case-file/v3"
CASE_SIGNING_CONTRACT_V2 = "textforensics.case-signing/v2"

_CASE_BODY_EXCLUDED_KEYS = frozenset({"case_sha256", "created_at_utc"})

# ---------------------------------------------------------------------------
# Portable-case privacy policy (W1: C03 — shared helper, single owner).
#
# The recursive forbidden-key policy is the ONE implementation of the
# raw-text portability check.  It is consumed by the sealer, the case
# writer (via the sealer), the primary and combined verifiers, and the
# packer (via primary verification).  The standalone verifier
# (``_standalone_verify.py``) cannot import this package — it must stay
# a stdlib-only file that ships inside bundles — so it carries a
# verbatim mirror of the key set, pinned equal by
# ``tests/test_w1_worker_d.py::TestC03WholeCasePrivacy::
# test_standalone_forbidden_key_set_matches_canonical``.
#
# Policy (key-based, never content-guessing):
# * A key whose stripped, lower-cased name is in
#   ``FORBIDDEN_RAW_TEXT_KEYS`` may carry literal source text, so it is
#   rejected anywhere in a completed portable case unless the caller
#   explicitly opts in (see ``check_case_portability``).
# * Every other key is permitted, including the free-text process
#   metadata fields listed in ``ALLOWED_PROCESS_METADATA_KEYS``
#   (reviewer ``reasoning``, checklist ``note``, disposition ``reason``,
#   ...).  Their *values* are never scanned or guessed at: legitimate
#   free-text reasoning that happens to quote source material is not
#   prohibited by guessing its content.
# * ``raw_text_included`` is never emitted contradictorily: the default
#   (``allow_raw_text=False``) seals ``raw_text_included=False`` only
#   after the whole-case check passes; the explicit opt-in seals
#   ``raw_text_included=True``.  An opted-in case is accurately
#   labelled but is NOT portable evidence — portable verification
#   refuses it (``raw_text_policy_violation``) rather than passing it
#   off as clean.
# ---------------------------------------------------------------------------

FORBIDDEN_RAW_TEXT_KEYS = frozenset(
    {
        "text",
        "raw_text",
        "source_text",
        "document_text",
        "content",
        "snippet",
        "quote",
        "excerpt",
    }
)

# Process-metadata fields whose free-text values are legitimate reviewer
# reasoning / process records.  They are documented here so the boundary
# is explicit; the checker never scans their values.
ALLOWED_PROCESS_METADATA_KEYS = frozenset(
    {
        # Checklist items (D1-D10).
        "status",
        "evidence",
        "actor",
        "at_utc",
        "note",
        # Reviewer (D4) / appeal (D5) / subject response (D7).
        "identity",
        "role",
        "reasoning",
        "agreed_with_tool",
        "decider",
        "appeal_decider",
        "route",
        "deadline",
        "opportunity_given",
        "response_attached",
        # Retention (D9).
        "period",
        "legal_basis",
        "access",
        "disposal",
        "expungement",
        # Evidence dispositions (D1) / alternative explanations (D3).
        "disposition",
        "reason",
        "tested",
        "outcome",
        # Contrary evidence (D2).
        "detector_id",
    }
)


def find_forbidden_raw_text_keys(value: Any, path: str = "$") -> list[str]:
    """Find forbidden raw-text keys in *value*.

    Returns the JSON-style paths (``$.process.reviewer.raw_text``,
    ``$.limitations.counterfactuals[0].excerpt``) of every mapping key
    whose stripped, lower-cased name is in
    :data:`FORBIDDEN_RAW_TEXT_KEYS`.  Mapping values, list items and
    nested mappings are all scanned.  Only key *names* are inspected —
    values are never read for content.

    Iterative (explicit stack, no recursion): a deeply nested case file
    must not raise ``RecursionError`` here. The traversal order is the
    same depth-first pre-order as the recursive version — children are
    pushed in reverse so they are visited in order, and a forbidden
    key's path is recorded when its child is visited.
    """
    found: list[str] = []
    # (value, path, key_is_forbidden). The root has no key, so it is
    # never itself reported.
    stack: list[tuple[Any, str, bool]] = [(value, path, False)]
    while stack:
        current, current_path, is_forbidden = stack.pop()
        if is_forbidden:
            found.append(current_path)
        if isinstance(current, Mapping):
            children = [
                (
                    child,
                    f"{current_path}.{key}",
                    str(key).strip().lower() in FORBIDDEN_RAW_TEXT_KEYS,
                )
                for key, child in current.items()
            ]
            stack.extend(reversed(children))
        elif isinstance(current, list):
            stack.extend(
                reversed(
                    [
                        (child, f"{current_path}[{index}]", False)
                        for index, child in enumerate(current)
                    ]
                )
            )
    return found


def check_case_portability(case: Any, *, allow_raw_text: bool = False) -> list[str]:
    """Check a completed case for smuggled literal source text.

    Returns the list of forbidden-key paths (empty when the case is
    portable).  With ``allow_raw_text=True`` the caller has explicitly
    opted in to retaining raw material, so no paths are reported — the
    caller must then record ``raw_text_included=True`` accurately (see
    :func:`textforensics.casefile.seal_case_file`).  Never raises for
    bad input: a non-mapping case reports its own path.
    """
    if allow_raw_text:
        return []
    if not isinstance(case, Mapping):
        return ["$"]
    return find_forbidden_raw_text_keys(case)


def assert_case_portable(case: Any, *, allow_raw_text: bool = False) -> None:
    """Raise ``ValueError`` unless :func:`check_case_portability` passes."""
    forbidden = check_case_portability(case, allow_raw_text=allow_raw_text)
    if forbidden:
        raise ValueError(
            "Portable case files reject fields that may contain raw source text: "
            + ", ".join(forbidden[:5])
        )


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode_strict(value: Any) -> bytes | None:
    """Decode strict base64; None when the value is not canonical base64."""
    if not isinstance(value, str):
        return None
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        return None
    if _b64encode(decoded) != value:
        return None
    return decoded


def generate_sealing_key(identity: str, role: str) -> dict[str, Any]:
    """Generate a fresh sealing key; the seed is held in memory only.

    ``identity`` names the key holder and ``role`` the key's purpose
    (for example ``"auditor"``); both are recorded in the public half.
    """
    if not isinstance(identity, str) or not identity:
        raise ValueError("identity must be a non-empty string")
    if not isinstance(role, str) or not role:
        raise ValueError("role must be a non-empty string")
    seed, public_key = keygen()
    return {
        "schema": SEALING_KEY_SCHEMA,
        "algorithm": SEALING_KEY_ALGORITHM,
        "seed_b64": _b64encode(seed),
        "public_key_b64": _b64encode(public_key),
        "keyid": fingerprint(public_key),
        "created_at_utc": datetime.now(UTC).isoformat(),
        "identity": identity,
        "role": role,
    }


def save_sealing_key(path: str | Path, key_dict: Mapping[str, Any]) -> Path:
    """Atomically write a sealing-key file with mode 0600.

    Refuses to overwrite an existing file (fail closed: a sealing key
    must never be silently replaced).  Raises ``FileExistsError`` when
    the destination already exists and ``ValueError`` when the key dict
    is not a well-formed sealing key.

    Publication is genuinely atomic (W3: C11): the key is written to
    a temporary file in the destination directory, made owner-private
    before any key bytes are written, fsynced, and then published
    with a hard link, which fails with ``FileExistsError`` when the
    destination already exists — including a racing writer that won
    between the existence check above and publication.  The temporary
    file descriptor is closed on EVERY failure path (a failed
    ``fchmod`` used to leak it), and the temporary file is removed.
    """
    destination = Path(path)
    if destination.exists():
        raise FileExistsError(f"sealing key file already exists: {destination}")
    _validate_key_dict(key_dict)
    encoded = json.dumps(dict(key_dict), indent=2, sort_keys=True).encode("utf-8")
    fd, temp_name = tempfile.mkstemp(
        dir=str(destination.parent), prefix=destination.name + ".", suffix=".tmp"
    )
    temp_path = Path(temp_name)
    fd_owned = True  # This function owns the descriptor until os.fdopen takes it.
    try:
        _set_private(fd, temp_path)
        with os.fdopen(fd, "wb") as handle:
            fd_owned = False
            handle.write(encoded)
            handle.write(b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        _publish_no_clobber(temp_path, destination)
    finally:
        if fd_owned:
            with contextlib.suppress(OSError):
                os.close(fd)
        with contextlib.suppress(OSError):
            temp_path.unlink(missing_ok=True)
    return destination


def _set_private(fd: int, temp_path: Path) -> None:
    """Make a fresh key file owner-private before any key bytes are written.

    POSIX: ``fchmod`` the descriptor to 0600.  Windows (no ``fchmod``):
    restrict the path's DACL to the current user.  Raises ``OSError``
    on failure — the caller closes the descriptor and removes the
    temporary file, so a key is never saved with unknown access.
    """
    fchmod = getattr(os, "fchmod", None)
    if fchmod is not None:
        fchmod(fd, 0o600)
        return
    _restrict_to_owner_windows(temp_path)


def _publish_no_clobber(temp_path: Path, destination: Path) -> None:
    """Atomically publish *temp_path* as *destination* without clobbering.

    A hard link is atomic: it fails with ``FileExistsError`` when the
    destination already exists (including a racing writer that won
    between the caller's existence check and this call), and it never
    overwrites.  The caller removes the temporary name afterwards; the
    destination keeps the inode (and its owner-private mode/ACL).
    A filesystem that cannot hard-link fails closed here rather than
    silently replacing the destination.
    """
    try:
        os.link(temp_path, destination)
    except FileExistsError:
        raise FileExistsError(f"sealing key file already exists: {destination}") from None
    except OSError as exc:
        raise OSError(f"could not publish sealing key file {destination}: {exc}") from exc


def _restrict_to_owner_windows(path: Path) -> None:
    """Restrict *path* to the current user on Windows (owner-only DACL).

    Builds a DACL with a single ACE granting the current user
    ``GENERIC_ALL`` and applies it with inheritance blocked, via
    ctypes + advapi32 only (no third-party dependency).  Raises
    ``OSError`` when the ACL cannot be established — fail closed, so
    a sealing key is never saved with unknown access.  Only called
    where ``os.fchmod`` is unavailable.
    """
    import ctypes
    from ctypes import wintypes

    try:
        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32
    except AttributeError as exc:
        raise OSError("Windows owner-only ACL restriction requires Windows APIs") from exc

    TOKEN_QUERY = 0x0008
    TokenUser = 1
    SE_FILE_OBJECT = 1
    DACL_SECURITY_INFORMATION = 0x00000004
    PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
    GENERIC_ALL = 0x10000000
    SET_ACCESS = 2
    NO_INHERITANCE = 0
    TRUSTEE_IS_SID = 0
    TRUSTEE_IS_USER = 1

    class SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Sid", wintypes.LPVOID), ("Attributes", wintypes.DWORD)]

    class TOKEN_USER(ctypes.Structure):
        _fields_ = [("User", SID_AND_ATTRIBUTES)]

    class TRUSTEE(ctypes.Structure):
        _fields_ = [
            ("pMultipleTrustee", wintypes.LPVOID),
            ("MultipleTrusteeOperation", wintypes.DWORD),
            ("TrusteeForm", wintypes.DWORD),
            ("TrusteeType", wintypes.DWORD),
            ("ptstrName", wintypes.LPVOID),
        ]

    class EXPLICIT_ACCESS(ctypes.Structure):
        _fields_ = [
            ("grfAccessPermissions", wintypes.DWORD),
            ("grfAccessMode", wintypes.DWORD),
            ("grfInheritance", wintypes.DWORD),
            ("Trustee", TRUSTEE),
        ]

    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.SetEntriesInAclW.argtypes = [
        wintypes.ULONG,
        ctypes.POINTER(EXPLICIT_ACCESS),
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPVOID),
    ]
    advapi32.SetEntriesInAclW.restype = wintypes.DWORD
    advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
    ]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.LPVOID]
    kernel32.LocalFree.restype = wintypes.LPVOID

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)
    ):
        raise OSError(f"OpenProcessToken failed: {ctypes.FormatError(ctypes.get_last_error())}")
    try:
        size = wintypes.DWORD(0)
        # First call returns the required buffer size.
        advapi32.GetTokenInformation(token, TokenUser, None, 0, ctypes.byref(size))
        token_info = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(token, TokenUser, token_info, size, ctypes.byref(size)):
            raise OSError(
                f"GetTokenInformation failed: {ctypes.FormatError(ctypes.get_last_error())}"
            )
        user_sid = ctypes.cast(token_info, ctypes.POINTER(TOKEN_USER)).contents.User.Sid
        entry = EXPLICIT_ACCESS()
        entry.grfAccessPermissions = GENERIC_ALL
        entry.grfAccessMode = SET_ACCESS
        entry.grfInheritance = NO_INHERITANCE
        entry.Trustee.TrusteeForm = TRUSTEE_IS_SID
        entry.Trustee.TrusteeType = TRUSTEE_IS_USER
        entry.Trustee.ptstrName = user_sid
        new_acl = wintypes.LPVOID()
        error = advapi32.SetEntriesInAclW(1, ctypes.byref(entry), None, ctypes.byref(new_acl))
        if error != 0:
            raise OSError(f"SetEntriesInAclW failed: {ctypes.FormatError(error)}")
        try:
            error = advapi32.SetNamedSecurityInfoW(
                str(path),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                new_acl,
                None,
            )
            if error != 0:
                raise OSError(f"SetNamedSecurityInfoW failed: {ctypes.FormatError(error)}")
        finally:
            kernel32.LocalFree(new_acl)
    finally:
        kernel32.CloseHandle(token)


def load_sealing_key(path: str | Path) -> dict[str, Any]:
    """Load and validate a sealing-key file.

    Validates the schema and algorithm, the base64 fields, that the
    public key matches the seed (recomputed and compared), and that the
    keyid matches the public-key fingerprint.  Raises ``ValueError`` on
    any mismatch.  On POSIX, refuses a key file readable by anyone other
    than its owner (mode & 0o077 != 0): a private key file readable by
    others is a misconfiguration, so loading fails closed.
    """
    key_path = Path(path)
    if os.name == "posix":
        mode = os.stat(key_path).st_mode
        if mode & 0o077 != 0:
            raise ValueError(
                f"sealing key file {key_path} is readable by others "
                f"(mode {mode & 0o777:03o}); refusing to load"
            )
    try:
        raw = key_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"sealing key file {key_path} is not valid UTF-8") from exc
    try:
        key_dict = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"sealing key file {key_path} is not valid JSON") from exc
    _validate_key_dict(key_dict)
    return dict(key_dict)


def _validate_key_dict(key_dict: Any) -> dict[str, Any]:
    """Validate a sealing-key dict in memory; returns it on success."""
    if not isinstance(key_dict, Mapping):
        raise ValueError("sealing key must be a mapping")
    required = {
        "schema",
        "algorithm",
        "seed_b64",
        "public_key_b64",
        "keyid",
        "created_at_utc",
        "identity",
        "role",
    }
    if set(key_dict.keys()) != required:
        raise ValueError(
            "sealing key must have exactly the fields "
            "schema, algorithm, seed_b64, public_key_b64, keyid, "
            "created_at_utc, identity and role"
        )
    if key_dict["schema"] != SEALING_KEY_SCHEMA:
        raise ValueError(f"unsupported sealing key schema: {key_dict['schema']!r}")
    if key_dict["algorithm"] != SEALING_KEY_ALGORITHM:
        raise ValueError(f"unsupported sealing key algorithm: {key_dict['algorithm']!r}")
    for field in ("created_at_utc", "identity", "role", "keyid"):
        if not isinstance(key_dict[field], str) or not key_dict[field]:
            raise ValueError(f"sealing key field {field} must be a non-empty string")
    seed = _b64decode_strict(key_dict["seed_b64"])
    if seed is None or len(seed) != 32:
        raise ValueError("sealing key seed_b64 is not canonical base64 of 32 bytes")
    public_key = _b64decode_strict(key_dict["public_key_b64"])
    if public_key is None or len(public_key) != 32:
        raise ValueError("sealing key public_key_b64 is not canonical base64 of 32 bytes")
    if public_key_from_seed(seed) != public_key:
        raise ValueError("sealing key public key does not match its seed")
    if fingerprint(public_key) != key_dict["keyid"]:
        raise ValueError("sealing key keyid does not match its public key")
    return dict(key_dict)


def public_key_info(key_dict: Mapping[str, Any]) -> dict[str, Any]:
    """Return the public half of a sealing key (safe to publish/share)."""
    _validate_key_dict(key_dict)
    return {
        "algorithm": SEALING_KEY_ALGORITHM,
        "public_key_b64": key_dict["public_key_b64"],
        "keyid": key_dict["keyid"],
        "identity": key_dict["identity"],
        "role": key_dict["role"],
    }


def _canonical_json_bytes(payload: Mapping[str, Any]) -> bytes:
    # Intentional duplication of textforensics.casefile.canonical_json_bytes:
    # casefile imports this module for signature verification, so importing
    # casefile here would create a cycle.  The two implementations must
    # agree byte-for-byte; tests/test_sealing.py cross-checks them.
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def build_signature_record(public_key: bytes, identity: str, role: str) -> dict[str, Any]:
    """Build the signer record that goes inside the signed body (C02, v2).

    The record is placed in ``case["seal"]["signature"]`` BEFORE signing
    (with ``dsse`` still ``None``); only the envelope is added
    afterwards.  The fingerprint is derived from the supplied public
    key, never copied from an untrusted record.
    """
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        raise ValueError("public key must be exactly 32 bytes")
    if not isinstance(identity, str) or not identity:
        raise ValueError("signer identity must be a non-empty string")
    if not isinstance(role, str) or not role:
        raise ValueError("signer role must be a non-empty string")
    return {
        "algorithm": SEALING_KEY_ALGORITHM,
        "key_fingerprint": fingerprint(bytes(public_key)),
        "signer": {"identity": identity, "role": role},
        "dsse": None,
    }


def _require_signature_record(case: Mapping[str, Any], seed: bytes) -> None:
    """Require a well-formed pre-placed signer record for v2 signing.

    Signing a body and attaching a signer record afterwards would leave
    the record unauthenticated — exactly the C02 defect — so v2 signing
    refuses a case with no record, a malformed record, or a record
    whose fingerprint is not the signing key's fingerprint.
    """
    seal = case.get("seal")
    if not isinstance(seal, Mapping):
        raise ValueError("case has no seal mapping; cannot place a signer record")
    signature = seal.get("signature")
    if not isinstance(signature, Mapping):
        raise ValueError(
            "case seal has no pre-placed signer record; place one with "
            "build_signature_record before signing (v2 contract)"
        )
    if signature.get("algorithm") != SEALING_KEY_ALGORITHM:
        raise ValueError("signer record algorithm must be ed25519")
    expected = fingerprint(public_key_from_seed(seed))
    if signature.get("key_fingerprint") != expected:
        raise ValueError("signer record key_fingerprint does not match the signing key")
    signer = signature.get("signer")
    if (
        not isinstance(signer, Mapping)
        or not isinstance(signer.get("identity"), str)
        or not signer["identity"]
        or not isinstance(signer.get("role"), str)
        or not signer["role"]
    ):
        raise ValueError("signer record needs a non-empty identity and role")


def case_signing_payload(
    case: Mapping[str, Any], *, contract: str = CASE_SIGNING_CONTRACT_V2
) -> bytes:
    """Canonical JSON bytes of a case body, for signing.

    The top-level ``case_sha256`` and ``created_at_utc`` fields are
    removed first, so that sealing the same case body twice produces
    the same signed bytes regardless of when the seal was created or
    what signature it already carries.

    ``contract`` selects the signing contract (W3: C02): under the
    legacy v1 contract the ENTIRE ``seal.signature`` mapping is
    removed (signer identity/role/fingerprint unauthenticated); under
    the current v2 contract only the recursive DSSE envelope
    (``seal.signature.dsse``) is removed, so the signer record is
    inside the signed body.
    """
    if not isinstance(case, Mapping):
        raise ValueError("case must be a mapping")
    if contract not in (CASE_SIGNING_CONTRACT_V1, CASE_SIGNING_CONTRACT_V2):
        raise ValueError(f"unknown case signing contract: {contract!r}")
    body = deepcopy(dict(case))
    for key in _CASE_BODY_EXCLUDED_KEYS:
        body.pop(key, None)
    seal = body.get("seal")
    if isinstance(seal, Mapping):
        seal = dict(seal)
        if contract == CASE_SIGNING_CONTRACT_V1:
            seal.pop("signature", None)
        else:
            signature = seal.get("signature")
            if isinstance(signature, Mapping):
                signature = dict(signature)
                signature.pop("dsse", None)
                seal["signature"] = signature
        body["seal"] = seal
    return _canonical_json_bytes(body)


def sign_case_body(
    case: Mapping[str, Any], seed: bytes, *, contract: str = CASE_SIGNING_CONTRACT_V2
) -> dict[str, Any]:
    """DSSE envelope signing the canonical bytes of a case body.

    Signs under the v2 contract by default: the signer record must
    already be placed in ``case["seal"]["signature"]`` (see
    :func:`build_signature_record`).  The legacy v1 contract is
    available for building legacy fixtures only; production never
    signs v1.
    """
    if contract == CASE_SIGNING_CONTRACT_V2:
        _require_signature_record(case, seed)
    return sign_envelope(contract, case_signing_payload(case, contract=contract), seed)


def verify_case_signature(case: Mapping[str, Any], public_key: bytes) -> dict[str, Any]:
    """Verify the DSSE signature carried in ``case["seal"]["signature"]["dsse"]``.

    Never raises for bad input: every problem is reported in ``errors``
    and ``valid`` is False.  Returns ``{"valid", "errors", "keyid",
    "signing_contract", "warnings"}``.

    The signing contract is dispatched on the envelope's
    ``payloadType`` (W3: C02).  For BOTH contracts the recorded
    algorithm must be ``ed25519`` and the recorded ``key_fingerprint``
    must equal the fingerprint of the trusted supplied public key —
    so a zeroed fingerprint fails even for a legacy v1 case.  Under
    v2 the signer identity/role are authenticated by the signature;
    under v1 they are not, and the result says so in ``warnings``
    (``signer_identity_role_not_authenticated_legacy_contract``).
    A signed self-asserted identity still does not replace an
    external key-to-identity trust policy (human-only).
    """
    errors: list[str] = []
    warnings: list[str] = []
    contract: str | None = None

    def _fail(message: str) -> dict[str, Any]:
        errors.append(message)
        return {
            "valid": False,
            "errors": errors,
            "keyid": None,
            "signing_contract": contract,
            "warnings": warnings,
        }

    if not isinstance(case, Mapping):
        return _fail("case must be a mapping")
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        return _fail("public key must be exactly 32 bytes")
    seal = case.get("seal")
    if not isinstance(seal, Mapping):
        return _fail("case has no seal mapping")
    signature = seal.get("signature")
    if not isinstance(signature, Mapping):
        return _fail("case seal has no signature mapping")
    envelope = signature.get("dsse")
    if envelope is None:
        return _fail("case seal signature has no dsse envelope")
    payload_type = envelope.get("payloadType") if isinstance(envelope, Mapping) else None
    if payload_type == CASE_SIGNING_CONTRACT_V2:
        contract = "v2"
    elif payload_type == CASE_SIGNING_CONTRACT_V1:
        contract = "v1"
    else:
        return _fail(f"unknown case signing contract (payloadType {payload_type!r})")
    if signature.get("algorithm") != SEALING_KEY_ALGORITHM:
        return _fail("case seal signature algorithm is not ed25519")
    if signature.get("key_fingerprint") != fingerprint(bytes(public_key)):
        return _fail("case seal key_fingerprint does not match the supplied public key")
    signer = signature.get("signer")
    if (
        not isinstance(signer, Mapping)
        or not isinstance(signer.get("identity"), str)
        or not signer["identity"]
        or not isinstance(signer.get("role"), str)
        or not signer["role"]
    ):
        return _fail("case seal signer must carry a non-empty identity and role")
    expected_contract = CASE_SIGNING_CONTRACT_V2 if contract == "v2" else CASE_SIGNING_CONTRACT_V1
    try:
        expected_payload = case_signing_payload(case, contract=expected_contract)
    except (ValueError, TypeError) as exc:
        return _fail(f"case body cannot be canonicalised: {exc}")
    result = verify_envelope(envelope, bytes(public_key), expected_payload_type=expected_contract)
    if not result["valid"]:
        return {
            "valid": False,
            "errors": [*result["errors"]],
            "keyid": result["keyid"],
            "signing_contract": contract,
            "warnings": warnings,
        }
    if result["payload"] != expected_payload:
        return _fail("signed payload does not match the case body")
    if contract == "v1":
        warnings.append(
            "signer_identity_role_not_authenticated_legacy_contract: "
            "this case was signed under the legacy v1 contract, whose "
            "signed body excludes the signer record; identity and role "
            "are self-asserted, not authenticated by the signature."
        )
    return {
        "valid": True,
        "errors": [],
        "keyid": result["keyid"],
        "signing_contract": contract,
        "warnings": warnings,
    }
