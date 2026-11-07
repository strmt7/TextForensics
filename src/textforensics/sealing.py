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

from .dsse import PAYLOAD_TYPE_CASE_FILE, sign_envelope, verify_envelope
from .ed25519 import fingerprint, keygen, public_key_from_seed

SEALING_KEY_SCHEMA = "textforensics.sealing-key/v1"
SEALING_KEY_ALGORITHM = "ed25519"

_CASE_BODY_EXCLUDED_KEYS = frozenset({"case_sha256", "created_at_utc"})


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
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.write(b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, destination)
    except BaseException:
        with contextlib.suppress(OSError):
            temp_path.unlink(missing_ok=True)
        raise
    return destination


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


def case_signing_payload(case: Mapping[str, Any]) -> bytes:
    """Canonical JSON bytes of a case body, for signing.

    The top-level ``case_sha256`` and ``created_at_utc`` fields and the
    ``seal.signature`` field are removed first, so that sealing the same
    case body twice produces the same signed bytes regardless of when
    the seal was created or what signature it already carries.
    """
    if not isinstance(case, Mapping):
        raise ValueError("case must be a mapping")
    body = deepcopy(dict(case))
    for key in _CASE_BODY_EXCLUDED_KEYS:
        body.pop(key, None)
    seal = body.get("seal")
    if isinstance(seal, Mapping):
        seal = dict(seal)
        seal.pop("signature", None)
        body["seal"] = seal
    return _canonical_json_bytes(body)


def sign_case_body(case: Mapping[str, Any], seed: bytes) -> dict[str, Any]:
    """DSSE envelope signing the canonical bytes of a case body."""
    return sign_envelope(PAYLOAD_TYPE_CASE_FILE, case_signing_payload(case), seed)


def verify_case_signature(case: Mapping[str, Any], public_key: bytes) -> dict[str, Any]:
    """Verify the DSSE signature carried in ``case["seal"]["signature"]["dsse"]``.

    Never raises for bad input: every problem is reported in ``errors``
    and ``valid`` is False.  Returns ``{"valid", "errors", "keyid"}``.
    """
    errors: list[str] = []

    def _fail(message: str) -> dict[str, Any]:
        errors.append(message)
        return {"valid": False, "errors": errors, "keyid": None}

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
    try:
        expected_payload = case_signing_payload(case)
    except (ValueError, TypeError) as exc:
        return _fail(f"case body cannot be canonicalised: {exc}")
    result = verify_envelope(
        envelope, bytes(public_key), expected_payload_type=PAYLOAD_TYPE_CASE_FILE
    )
    if not result["valid"]:
        return {
            "valid": False,
            "errors": [*result["errors"]],
            "keyid": result["keyid"],
        }
    if result["payload"] != expected_payload:
        return _fail("signed payload does not match the case body")
    return {"valid": True, "errors": [], "keyid": result["keyid"]}
