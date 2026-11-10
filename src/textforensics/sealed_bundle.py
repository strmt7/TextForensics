"""Sealed bundle packing and verification (Phase 3 U2).

A sealed bundle is a deterministic ZIP carrying a sealed case file
(``case.json``), the standalone verifier (``verify.py``), an optional
RFC 3161 token (``timestamp-token.der``) and an MPL manifest
(``manifest.json``).  The packing follows the model-protocol-lab
pattern adopted verbatim (see the module docstring of
``_standalone_verify.py`` and docs): canonical JSON
(``sort_keys=True``, ``separators=(",",":")``, ``ensure_ascii=True``),
sorted ZIP_STORED entries, normalised ZipInfo (``date_time=(1980,1,1)``,
``create_system=0``, ``external_attr=0o644<<16``, no extra fields, no
per-entry comments), and the archive comment exactly
``mpl-bundle-sha256:<64 lowercase hex>`` — the SHA-256 of the exact
stored bytes of ``manifest.json``.

The existing ``bundle.py`` packer is a different, older format
(``textforensics.bundle-manifest/v1``; ZIP_DEFLATED, 2020 timestamp)
and is deliberately left alone: changing it would break its own
consumers.  The sealed bundle is the MPL-conformant path.

Digests recorded in the companion seal record:

- ``manifest_sha256``: SHA-256 of the exact stored ``manifest.json`` bytes
  (identical to the archive comment value).
- ``bundle_sha256``: SHA-256 over the concatenated bytes of the files
  listed in the manifest, in listed order (the logical bundle content;
  the manifest itself is not listed and is excluded).
- ``archive_sha256``: SHA-256 of the complete ZIP bytes as stored.

The T2 signature is a DSSE envelope over the canonical manifest bytes
with the signature field itself null (a signature cannot sign bytes
that contain it).  The signer record is part of the signed bytes (it
is known before signing).  The verifier reconstructs exactly those
bytes and compares the envelope payload against them.

The T3 timestamp token covers the SHA-256 of the ``case.json`` bytes
(the case as sealed); that digest is stable across re-packs, so the
token stays valid when the manifest gains the token reference.  The
packer verifies the token before packing and refuses a token whose
message imprint does not match the case bytes.
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from collections.abc import Iterable
from importlib.resources import files as _resource_files
from pathlib import Path
from typing import Any

from ._build_info import get_version
from .casefile import (
    CASE_SCHEMA_V3,
    CASE_SCHEMA_V4,
    replay_case_file,
    verify_case_file,
)
from .dsse import sign_envelope
from .sealing import fingerprint as _key_fingerprint
from .sealing import public_key_from_seed
from .timestamp import verify_timestamp_token

MANIFEST_SCHEMA = "textforensics.sealed-bundle-manifest/v1"
SEAL_RECORD_SCHEMA = "textforensics.sealed-bundle-seal-record/v1"
BUNDLE_SCHEMA = "textforensics.sealed-bundle/v1"
PAYLOAD_TYPE = "textforensics.sealed-bundle-manifest/v1"
COMMENT_PREFIX = "mpl-bundle-sha256:"

# MPL caps (mirrored in _standalone_verify.py; enforced in order,
# before content is read there, and at pack time here).
MAX_BUNDLE_BYTES = 288 * 1024 * 1024
MAX_ENTRIES = 1024
MAX_ENTRY_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_SEALED_RESULTS_BYTES = 32 * 1024 * 1024

_ROLE_BY_PATH = {
    "case.json": "case-file",
    "manifest.json": "manifest",
    "verify.py": "verifier",
    "timestamp-token.der": "timestamp-token",
}


class SealedBundleError(ValueError):
    """Raised when a sealed bundle cannot be packed or verified."""


def canonical_json_bytes(payload: Any) -> bytes:
    """MPL canonical JSON bytes (sorted keys, tight separators, ASCII)."""
    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _standalone_verifier_bytes() -> bytes:
    return _resource_files("textforensics").joinpath("_standalone_verify.py").read_bytes()


def _checklist_digest(case: dict[str, Any]) -> str | None:
    process = case.get("process")
    if not isinstance(process, dict):
        return None
    return _sha256(canonical_json_bytes(process))


def build_manifest(
    case: dict[str, Any],
    files: dict[str, bytes],
    *,
    signature: dict[str, Any] | None = None,
    signer: dict[str, Any] | None = None,
    timestamp_token_sha256: str | None = None,
    timestamp_imprint: str | None = None,
) -> dict[str, Any]:
    """Build the sealed-bundle manifest for *files* (name -> bytes).

    ``files`` must not contain ``manifest.json`` (a manifest cannot
    list itself).  ``registry_sha256`` is a recorded claim: it is the
    registry id cited by the case's validation refs, reported as
    recorded, not recomputed (MPL ``catalog_sha256`` semantics).  The
    DSSE envelope in ``signature`` stays exactly the three DSSE fields;
    the signer identity/role/fingerprint live beside it in ``signer``.
    """
    if "manifest.json" in files:
        raise SealedBundleError("The manifest cannot list itself.")
    registry_sha256 = None
    for ref in case.get("validation_refs") or []:
        if isinstance(ref, dict) and ref.get("registry_id"):
            registry_sha256 = ref["registry_id"]
            break
    input_sha256 = None
    input_section = case.get("input")
    if isinstance(input_section, dict):
        input_sha256 = input_section.get("content_sha256")
    return {
        "schema": MANIFEST_SCHEMA,
        "context": {
            "tool_version": get_version(),
            "case_id": case.get("case_sha256"),
            "input_sha256": input_sha256,
            "registry_sha256": registry_sha256,
            "signature": signature,
            "signer": signer,
            "timestamp_token_sha256": timestamp_token_sha256,
            "timestamp_imprint": timestamp_imprint,
            "appeal_checklist_digest": _checklist_digest(case),
        },
        "files": [
            {
                "path": name,
                "role": _ROLE_BY_PATH.get(name, "other"),
                "sha256": _sha256(data),
                "size": len(data),
            }
            for name, data in sorted(files.items())
        ],
    }


def _pack_zip(files: dict[str, bytes], comment: str) -> bytes:
    """Pack *files* into a deterministic MPL-normalised ZIP."""
    if len(files) > MAX_ENTRIES:
        raise SealedBundleError("Too many entries for a sealed bundle.")
    total = sum(len(data) for data in files.values())
    if total > MAX_TOTAL_BYTES:
        raise SealedBundleError("Sealed bundle exceeds the 256 MiB total cap.")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        for name in sorted(files):
            data = files[name]
            if len(data) > MAX_ENTRY_BYTES:
                raise SealedBundleError(f"Entry {name} exceeds the 64 MiB cap.")
            info = zipfile.ZipInfo(filename=name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 0
            info.external_attr = 0o644 << 16
            zf.writestr(info, data)
        zf.comment = comment.encode("ascii")
    archive = buf.getvalue()
    if len(archive) > MAX_BUNDLE_BYTES:
        raise SealedBundleError("Sealed bundle exceeds the 288 MiB outer cap.")
    return archive


def _bundle_digest(files: dict[str, bytes], manifest: dict[str, Any]) -> str:
    """SHA-256 over the concatenated bytes of the manifest-listed files."""
    blob = bytearray()
    for item in manifest["files"]:
        blob += files[item["path"]]
    return _sha256(bytes(blob))


def pack_sealed_bundle(
    case: dict[str, Any],
    *,
    signing_seed: bytes | None = None,
    signer: dict[str, Any] | None = None,
    timestamp_token: bytes | None = None,
    tsa_url: str | None = None,
    digest_publication: dict[str, Any] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Pack a sealed v3/v4 case file into a sealed bundle.

    Returns ``(bundle_bytes, seal_record)``.  The seal record is the
    companion file the sealer keeps or publishes alongside the bundle;
    it holds the manifest, the three digests, the signature and the
    timestamp record.

    The case must verify before packing (fail closed); a timestamp
    token must verify against the case bytes before packing.  Only
    case-file/v3 and case-file/v4 cases can be packed: v1/v2 carry no
    checklist or custody sections for the manifest context to
    reference.
    """
    if not isinstance(case, dict):
        raise SealedBundleError("A case file must be a JSON object.")
    if case.get("schema") not in {CASE_SCHEMA_V3, CASE_SCHEMA_V4}:
        raise SealedBundleError("Only case-file/v3 and case-file/v4 cases can be packed.")
    verification = verify_case_file(case)
    if not verification["valid"]:
        raise SealedBundleError(
            "Refusing to pack a case file that does not verify: "
            + "; ".join(verification["errors"])
        )
    if (signing_seed is None) != (signer is None):
        raise SealedBundleError("signing_seed and signer must be given together.")
    if signing_seed is not None and (
        not isinstance(signer, dict) or not signer.get("identity") or not signer.get("role")
    ):
        raise SealedBundleError("signer needs identity and role.")

    case_bytes = canonical_json_bytes(case)
    if len(case_bytes) > MAX_SEALED_RESULTS_BYTES:
        raise SealedBundleError("case.json exceeds the 32 MiB sealed-results cap.")
    case_digest = _sha256(case_bytes)
    case_digest_bytes = hashlib.sha256(case_bytes).digest()

    timestamp_record: dict[str, Any] | None = None
    token_sha256: str | None = None
    if timestamp_token is not None:
        token_sha256 = _sha256(timestamp_token)
        token_report = verify_timestamp_token(timestamp_token, expected_digest=case_digest_bytes)
        if not token_report["valid"]:
            raise SealedBundleError(
                "Refusing to pack a timestamp token that does not verify: "
                + "; ".join(token_report["errors"])
            )
        timestamp_record = {
            "token_sha256": token_sha256,
            "imprint": case_digest,
            "imprint_algorithm": "sha256",
            "gen_time": token_report["gen_time"],
            "gen_time_utc": token_report["gen_time_utc"],
            "policy": token_report["policy"],
            "serial_number": token_report["serial_number"],
            "nonce": token_report["nonce"],
            "tsa_url": tsa_url,
            "signer_cert_fingerprint": token_report["signer_cert_fingerprint"],
            "signature_algorithm": token_report["signature_algorithm"],
            "qualified": token_report["qualified"],
            "qualification_method": token_report["qualification_method"],
            "qualification_label": token_report["qualification_label"],
        }

    files: dict[str, bytes] = {
        "case.json": case_bytes,
        "verify.py": _standalone_verifier_bytes(),
    }
    if timestamp_token is not None:
        files["timestamp-token.der"] = timestamp_token

    # The signer record is part of the signed manifest (it is known
    # before signing); only the envelope itself is added afterwards.
    signer_record: dict[str, Any] | None = None
    if signing_seed is not None:
        if not isinstance(signing_seed, (bytes, bytearray)) or len(signing_seed) != 32:
            raise SealedBundleError("signing_seed must be 32 bytes.")
        signer_record = {
            "identity": signer["identity"],
            "role": signer["role"],
            "key_fingerprint": _key_fingerprint(public_key_from_seed(bytes(signing_seed))),
        }
    unsigned_manifest = build_manifest(
        case,
        files,
        signer=signer_record,
        timestamp_token_sha256=token_sha256,
        timestamp_imprint=case_digest if timestamp_token is not None else None,
    )
    unsigned_bytes = canonical_json_bytes(unsigned_manifest)
    signature: dict[str, Any] | None = None
    if signing_seed is not None:
        signature = sign_envelope(PAYLOAD_TYPE, unsigned_bytes, bytes(signing_seed))
    manifest = build_manifest(
        case,
        files,
        signature=signature,
        signer=signer_record,
        timestamp_token_sha256=token_sha256,
        timestamp_imprint=case_digest if timestamp_token is not None else None,
    )
    manifest_bytes = canonical_json_bytes(manifest)
    files["manifest.json"] = manifest_bytes
    comment = COMMENT_PREFIX + _sha256(manifest_bytes)
    archive = _pack_zip(files, comment)

    publication = digest_publication
    if publication is None:
        seal = case.get("seal")
        if isinstance(seal, dict):
            publication = seal.get("digest_publication")
    seal_record = {
        "schema": SEAL_RECORD_SCHEMA,
        "manifest": manifest,
        "manifest_sha256": _sha256(manifest_bytes),
        "bundle_sha256": _bundle_digest(files, manifest),
        "archive_sha256": _sha256(archive),
        "signature": signature,
        "timestamp": timestamp_record,
        "digest_publication": publication,
    }
    return archive, seal_record


def _read_capped(zf: zipfile.ZipFile, name: str) -> bytes:
    """Read one member through a capped stream (W1: C06).

    Never ``ZipFile.read``: the stream read is bounded at
    ``MAX_ENTRY_BYTES + 1`` so a member whose declared size lied
    about its contents is rejected instead of decompressed without
    bound.  Raises :class:`SealedBundleError` over the cap and lets
    ``KeyError`` / ``BadZipFile`` propagate to the caller's handler.
    """
    with zf.open(name) as stream:
        data = stream.read(MAX_ENTRY_BYTES + 1)
    if len(data) > MAX_ENTRY_BYTES:
        raise SealedBundleError(f"Entry {name} exceeds the 64 MiB cap on read.")
    return data


def verify_sealed_bundle(
    data: bytes,
    *,
    expected_digest: str | None = None,
    public_key: bytes | None = None,
    seal_record: dict[str, Any] | None = None,
    text: str | None = None,
    detectors: Iterable[Any] | None = None,
    validation_registry: Any | None = None,
) -> dict[str, Any]:
    """Verify a sealed bundle, with optional seal-record cross-check and replay.

    The standalone checks run first; replay runs only if the seal
    passes (``seal_failed`` gating — a failed seal reports replay as
    ``unavailable`` with detail ``seal_failed``).  Returns a report
    dict with the standalone report embedded under ``standalone``,
    the seal-record cross-check under ``seal_record`` (when supplied),
    and replay under ``replay`` (when requested).

    Exit-code mapping for a requested replay (``report["exit_code"]``,
    when the seal itself passed):

    - ``0`` — the replay reproduced (``replay_outcome`` is
      ``"reproduced"``) and no warning was raised;
    - ``1`` — the replay failed (``replay_outcome`` is ``"failed"``,
      i.e. ``replay["valid"]`` is ``False``);
    - ``2`` — the replay is valid but inconclusive
      (``replay_outcome`` is ``"inconclusive"``: a detector declared
      ``non_deterministic`` at seal time could not be reproduced, so
      the replay carries a ``"not_reproducible:<detector_id>"``
      warning).  An inconclusive replay is valid-but-inconclusive,
      never silently passed as a clean verification and never
      reported as a seal failure.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_standalone_verify",
        str(_resource_files("textforensics").joinpath("_standalone_verify.py")),
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    standalone = module.verify_bundle_bytes(
        data, expected_digest=expected_digest, public_key=public_key
    )
    report: dict[str, Any] = {
        "schema": "textforensics.sealed-bundle-verification-report/v1",
        "standalone": standalone,
        "seal_record": None,
        "replay": {
            "status": "not_requested",
            "reason": "no replay text was supplied",
        },
        "exit_code": standalone["exit_code"],
    }
    seal_failed = standalone["exit_code"] != 0

    if seal_record is not None:
        record_checks: list[dict[str, Any]] = []
        record_errors: list[str] = []
        seal_record_unavailable = False
        if not isinstance(seal_record, dict):
            # The shared tail below turns record_errors into the report;
            # nulling seal_record skips the manifest comparisons.
            record_errors.append("seal_record must be a JSON object")
            seal_record = None
        elif seal_failed:
            # W1: C06 — after the standalone verifier rejected the
            # container, the optional cross-check is UNAVAILABLE: it
            # must never open the rejected archive again, and
            # certainly never call uncapped ZipFile.read on its
            # members.  A rejected archive never reaches a
            # less-restricted second reader.
            report["seal_record"] = {
                "status": "unavailable",
                "reason": "seal_failed",
                "checks": [],
                "errors": [
                    "seal-record cross-check unavailable: standalone "
                    "verification rejected the container"
                ],
            }
            seal_record = None
            seal_record_unavailable = True
        manifest_bytes = b""
        manifest: dict[str, Any] | None = None
        files: dict[str, bytes] = {}
        if seal_record is not None:
            # Rereading is unavoidable here (the standalone verifier
            # does not hand back its contents), so the same guards
            # apply before and during reads: entry count, STORED-only
            # compression, per-entry and aggregate caps, capped
            # stream reads — never an uncapped ZipFile.read.
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    infos = zf.infolist()
                    if len(infos) > MAX_ENTRIES:
                        raise SealedBundleError("Too many entries for a sealed bundle.")
                    total = 0
                    for info in infos:
                        if info.compress_type != zipfile.ZIP_STORED:
                            raise SealedBundleError(f"Entry {info.filename} is not STORED.")
                        if info.file_size > MAX_ENTRY_BYTES:
                            raise SealedBundleError(
                                f"Entry {info.filename} exceeds the 64 MiB cap."
                            )
                        total += info.file_size
                        if total > MAX_TOTAL_BYTES:
                            raise SealedBundleError("Sealed bundle exceeds the 256 MiB total cap.")
                    manifest_bytes = _read_capped(zf, "manifest.json")
                    for info in infos:
                        if info.filename != "manifest.json":
                            files[info.filename] = _read_capped(zf, info.filename)
                manifest = json.loads(manifest_bytes.decode("utf-8"))
            except (zipfile.BadZipFile, KeyError, OSError, ValueError) as exc:
                record_errors.append(f"bundle unreadable for seal-record check: {exc}")
            except SealedBundleError as exc:
                record_errors.append(f"bundle exceeds seal-record check caps: {exc}")
        if manifest is not None and seal_record is not None:
            if not isinstance(manifest, dict):
                record_errors.append("bundle manifest is not a JSON object")
            else:
                try:
                    if seal_record.get("manifest") != manifest:
                        record_errors.append(
                            "seal_record.manifest does not match the bundle manifest"
                        )
                    if seal_record.get("manifest_sha256") != _sha256(manifest_bytes):
                        record_errors.append("seal_record.manifest_sha256 mismatch")
                    if seal_record.get("archive_sha256") != _sha256(data):
                        record_errors.append("seal_record.archive_sha256 mismatch")
                    if seal_record.get("bundle_sha256") != _bundle_digest(files, manifest):
                        record_errors.append("seal_record.bundle_sha256 mismatch")
                    context = manifest.get("context")
                    if not isinstance(context, dict):
                        record_errors.append("bundle manifest context is not a mapping")
                    elif seal_record.get("signature") != context.get("signature"):
                        record_errors.append(
                            "seal_record.signature does not match the manifest signature"
                        )
                    token_record = seal_record.get("timestamp")
                    if token_record is not None:
                        token_bytes = files.get("timestamp-token.der")
                        if token_bytes is None:
                            record_errors.append(
                                "seal_record lists a timestamp but the bundle has no token"
                            )
                        elif _sha256(token_bytes) != token_record.get("token_sha256"):
                            record_errors.append("seal_record timestamp token digest mismatch")
                except (KeyError, TypeError, AttributeError) as exc:
                    record_errors.append(f"seal-record cross-check failed: {exc}")
        if not seal_record_unavailable:
            for error in record_errors:
                record_checks.append(
                    {"id": "seal_record_cross_check", "status": "fail", "detail": error}
                )
            if not record_errors:
                record_checks.append(
                    {
                        "id": "seal_record_cross_check",
                        "status": "pass",
                        "detail": "seal record matches the bundle",
                    }
                )
            report["seal_record"] = {"checks": record_checks, "errors": record_errors}
            if record_errors:
                report["exit_code"] = 1

    if text is not None or detectors is not None:
        if seal_failed:
            report["replay"] = {
                "status": "unavailable",
                "reason": "seal_failed",
            }
            if report["exit_code"] == 0:
                report["exit_code"] = 2
        else:
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    case = json.loads(_read_capped(zf, "case.json").decode("utf-8"))
            except (zipfile.BadZipFile, KeyError, OSError, ValueError) as exc:
                report["replay"] = {"status": "unavailable", "reason": str(exc)}
                report["exit_code"] = 1
                return report
            except SealedBundleError as exc:
                report["replay"] = {"status": "unavailable", "reason": str(exc)}
                report["exit_code"] = 1
                return report
            replay = replay_case_file(
                case,
                text=text,
                detectors=detectors,
                validation_registry=validation_registry,
            )
            report["replay"] = replay
            if not replay["valid"]:
                report["exit_code"] = 1
            elif report["exit_code"] == 0 and replay.get("warnings"):
                report["exit_code"] = 2
    return report


def write_sealed_bundle(
    case: dict[str, Any],
    bundle_path: str | Path,
    seal_record_path: str | Path | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Pack a case and write the bundle (and seal record) to disk."""
    archive, seal_record = pack_sealed_bundle(case, **kwargs)
    bundle_target = Path(bundle_path)
    bundle_target.parent.mkdir(parents=True, exist_ok=True)
    bundle_target.write_bytes(archive)
    if seal_record_path is not None:
        record_target = Path(seal_record_path)
        record_target.parent.mkdir(parents=True, exist_ok=True)
        record_target.write_text(
            json.dumps(seal_record, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return seal_record
