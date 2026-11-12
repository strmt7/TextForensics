"""Bundle packing and verification for case file bundles.

Provides a pack/verify system analogous to model-protocol-lab:
seal a case-file directory with a per-file SHA-256 manifest, archive it
into a ``.tar.gz`` or ``.zip`` bundle, and later verify bit-integrity.

The seal is unsigned — it proves bit-integrity, not attestation.
The bundle digest is kept separately so a consumer may store or supply it
out-of-band.
"""

from __future__ import annotations

import hashlib
import json
import tarfile
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

BUNDLE_SCHEMA = "textforensics.bundle-manifest/v1"


# ---------------------------------------------------------------------------
# Canonical helpers (reused from casefile.py concepts)
# ---------------------------------------------------------------------------


def _canonical_json_bytes(payload: Any) -> bytes:
    """Return canonical JSON bytes for deterministic hashing."""
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# Decompression-bomb guards. Bundles are sealed case files; a legitimate
# bundle is small. Anything exceeding these bounds is rejected rather
# than decompressed — a crafted archive must never exhaust memory.
MAX_BUNDLE_COMPRESSED_BYTES = 100 * 1024 * 1024  # archive file on disk
MAX_BUNDLE_FILE_BYTES = 10 * 1024 * 1024  # one member, decompressed
MAX_BUNDLE_TOTAL_BYTES = 100 * 1024 * 1024  # all members, decompressed
MAX_MANIFEST_BYTES = 1 * 1024 * 1024  # companion manifest JSON


def _read_capped(stream: Any, *, limit: int, what: str) -> bytes:
    """Read *stream* fully, raising if it exceeds *limit* bytes.

    Reads in 1 MiB chunks so a lying size header cannot make us allocate
    the claimed size up front.
    """
    data = bytearray()
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            return bytes(data)
        data += chunk
        if len(data) > limit:
            raise ValueError(f"{what} exceeds the {limit}-byte cap")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BundleManifest:
    """Per-file digests and total digest for a sealed bundle.

    The manifest itself is not part of the bundled archive — it lives in a
    companion ``.manifest.json`` file alongside the ``.tar.gz``/``.zip``
    bundle.  This separation means the digest can be communicated out-of-band.
    """

    schema: str = BUNDLE_SCHEMA
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    bundle_filename: str = ""
    format: str = ""  # "tar.gz" | "zip"
    per_file_digests: dict[str, str] = field(default_factory=dict)
    bundle_digest: str = ""  # SHA-256 of the archive bytes

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BundleManifest:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def to_canonical_json(self) -> bytes:
        return _canonical_json_bytes(asdict(self))


@dataclass(frozen=True)
class BundleVerificationResult:
    """Result of verifying a bundle against its manifest."""

    valid: bool
    per_file_status: dict[str, str] = field(default_factory=dict)
    bundle_digest_match: bool = False
    expected_digest: str = ""
    actual_digest: str = ""
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Core operations
# ---------------------------------------------------------------------------


def _detect_format(output_path: str | Path) -> str:
    path = str(output_path)
    if path.endswith(".tar.gz") or path.endswith(".tgz"):
        return "tar.gz"
    if path.endswith(".zip"):
        return "zip"
    raise ValueError(
        f"Unsupported bundle format for path: {output_path}\nUse .tar.gz or .zip extension."
    )


def _collect_files(case_file_path: str | Path) -> dict[str, bytes]:
    """Read a single case-file or a directory and return path->bytes mapping.

    When *case_file_path* is a directory, all files are collected recursively
    using sorted relative paths for determinism.
    """
    source = Path(case_file_path)
    files: dict[str, bytes] = {}

    if source.is_file():
        rel = source.name
        files[rel] = source.read_bytes()
    elif source.is_dir():
        for child in sorted(source.rglob("*")):
            if child.is_file():
                rel = str(child.relative_to(source))
                files[rel] = child.read_bytes()
    else:
        raise FileNotFoundError(f"Case file or directory not found: {source}")

    return files


def _create_archive(files: dict[str, bytes], output_path: str | Path, fmt: str) -> bytes:
    """Pack *files* into an archive and write it to *output_path*.

    Returns the raw bytes of the archive for digest computation.
    """
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "tar.gz":
        archive_bytes = _create_tar_gz(files)
        target.write_bytes(archive_bytes)
        return archive_bytes
    elif fmt == "zip":
        archive_bytes = _create_zip(files)
        target.write_bytes(archive_bytes)
        return archive_bytes
    else:
        raise ValueError(f"Unknown format: {fmt}")


def _create_tar_gz(files: dict[str, bytes]) -> bytes:
    """Create a deterministic tar.gz archive in memory.

    Uses fixed timestamp and mtime=0 to produce byte-identical archives
    across process invocations.
    """
    import gzip
    import io

    buf = io.BytesIO()
    # Create tar in memory first (without gzip)
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name in sorted(files):
            data = files[name]
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mtime = 0  # deterministic timestamp
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    tar_data = tar_buf.getvalue()

    # Compress with fixed mtime for deterministic gzip header
    with gzip.GzipFile(
        fileobj=buf,
        mode="wb",
        mtime=0,
        compresslevel=9,
    ) as gz:
        gz.write(tar_data)
    return buf.getvalue()


def _create_zip(files: dict[str, bytes]) -> bytes:
    """Create a deterministic zip archive in memory."""
    import io

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(files):
            info = zipfile.ZipInfo(filename=name, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, files[name])
    return buf.getvalue()


def pack_bundle(case_file_path: str | Path, output_path: str | Path) -> BundleManifest:
    """Seal a case file (or directory) into a bundle with a manifest.

    1. Collects all files from *case_file_path*.
    2. Creates a deterministic archive (.tar.gz or .zip based on extension).
    3. Computes per-file SHA-256 digests and an overall archive digest.
    4. Writes the manifest as a companion ``.manifest.json`` file.

    Returns the :class:`BundleManifest` so the caller may store the digest
    separately.
    """
    fmt = _detect_format(output_path)
    files = _collect_files(case_file_path)

    if not files:
        raise ValueError("No files found to bundle.")

    # Compute per-file digests (canonical for JSON files, raw for others)
    per_file: dict[str, str] = {}
    for rel, data in sorted(files.items()):
        if rel.endswith(".json"):
            try:
                obj = json.loads(data)
                per_file[rel] = _sha256(_canonical_json_bytes(obj))
            except (json.JSONDecodeError, ValueError):
                per_file[rel] = _sha256(data)
        else:
            per_file[rel] = _sha256(data)

    # Create archive and compute digest
    archive_bytes = _create_archive(files, output_path, fmt)
    archive_digest = _sha256(archive_bytes)

    bundle_filename = Path(output_path).name
    manifest = BundleManifest(
        schema=BUNDLE_SCHEMA,
        created_at=datetime.now(UTC).isoformat(),
        bundle_filename=bundle_filename,
        format=fmt,
        per_file_digests=per_file,
        bundle_digest=archive_digest,
    )

    # Write companion manifest
    manifest_path = Path(output_path).with_name(bundle_filename + ".manifest.json")
    manifest_path.write_text(
        json.dumps(manifest.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    return manifest


def _is_hex_digest(value: Any) -> bool:
    return (
        isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)
    )


def _validate_manifest_contract(manifest_data: Any) -> tuple[BundleManifest | None, list[str]]:
    """Validate the legacy bundle manifest contract (C18).

    Returns ``(manifest, errors)``.  The contract is checked FIRST,
    before the archive is opened: the schema must be the legacy
    bundle-manifest schema, the format one of the two supported
    values, the per-file map a non-empty dict of non-empty names to
    64-hex digests, and the bundle digest a 64-hex digest.  A
    legitimately empty bundle is NOT a supported artifact (the
    packer refuses to create one — ``pack_bundle`` raises on no
    files), so an empty per-file map is malformed, not a valid
    empty bundle.
    """
    errors: list[str] = []
    if not isinstance(manifest_data, dict):
        return None, ["Manifest is not a JSON object"]
    if manifest_data.get("schema") != BUNDLE_SCHEMA:
        errors.append(f"Manifest schema is not {BUNDLE_SCHEMA}: {manifest_data.get('schema')!r}")
    if manifest_data.get("format") not in ("tar.gz", "zip"):
        errors.append(f"Unsupported bundle format: {manifest_data.get('format')!r}")
    if not isinstance(manifest_data.get("bundle_filename"), str) or not manifest_data.get(
        "bundle_filename"
    ):
        errors.append("Manifest bundle_filename is missing or not a string")
    if not isinstance(manifest_data.get("created_at"), str) or not manifest_data.get("created_at"):
        errors.append("Manifest created_at is missing or not a string")
    per_file = manifest_data.get("per_file_digests")
    if not isinstance(per_file, dict):
        errors.append("Manifest per_file_digests is not an object")
    elif not per_file:
        errors.append("Manifest per_file_digests is empty: an empty bundle is not supported")
    else:
        for name, digest in per_file.items():
            if not isinstance(name, str) or not name:
                errors.append("Manifest per_file_digests has a non-string or empty file name")
            if not _is_hex_digest(digest):
                errors.append(f"Manifest digest for {name!r} is not a 64-character hex digest")
    if not _is_hex_digest(manifest_data.get("bundle_digest")):
        errors.append("Manifest bundle_digest is not a 64-character hex digest")
    if errors:
        return None, errors
    try:
        return BundleManifest.from_dict(manifest_data), []
    except (TypeError, ValueError) as exc:
        return None, [f"Failed to parse manifest: {exc}"]


def _list_archive_members(
    bundle_file: Path, fmt: str
) -> tuple[list[tuple[str, int]] | None, str | None]:
    """List ``(name, size)`` members of a bundle archive (C18).

    The container is opened and validated regardless of file-map
    contents — an empty map must never skip this step.  Returns
    ``(members, None)`` or ``(None, error)``.  Duplicate member
    names (exact or case-insensitive collisions) are an error: a
    duplicate would let one copy shadow another behind the manifest
    (the C05 ambiguity, applied to the legacy format).
    """
    try:
        if fmt == "tar.gz":
            with tarfile.open(bundle_file, "r:gz") as tar:
                members = [(m.name, m.size) for m in tar.getmembers() if m.isfile()]
        elif fmt == "zip":
            with zipfile.ZipFile(bundle_file, "r") as zf:
                members = [(info.filename, info.file_size) for info in zf.infolist()]
        else:  # pragma: no cover - format validated before this call
            return None, f"Unsupported format: {fmt}"
    except (tarfile.TarError, zipfile.BadZipFile, EOFError, OSError, ValueError) as exc:
        return None, f"Bundle is not a readable {fmt} archive: {exc}"
    names = [name for name, _ in members]
    seen: dict[str, str] = {}
    duplicates: list[str] = []
    for name in names:
        if name in seen and name not in duplicates:
            duplicates.append(name)
        seen[name] = name
    if duplicates:
        return None, "Duplicate member names in archive: " + ", ".join(sorted(duplicates))
    folded_seen: dict[str, str] = {}
    collisions: list[str] = []
    for name in names:
        folded = name.casefold()
        if folded in folded_seen and name not in collisions:
            collisions.append(name)
        folded_seen[folded] = name
    if collisions:
        return None, "Member names collide case-insensitively: " + ", ".join(sorted(collisions))
    return members, None


def verify_bundle(
    bundle_path: str | Path,
    expected_digest: str | None = None,
) -> BundleVerificationResult:
    """Verify a bundle against its companion manifest.

    Steps:
    1. Locate the ``.manifest.json`` next to the bundle.
    2. Validate the manifest contract (schema, format, file map,
       digests) — an empty file map is malformed, not a valid empty
       bundle.
    3. Re-hash the archive bytes and compare with *bundle_digest*.
    4. Open and validate the container regardless of file-map
       emptiness: the member set must match the manifest map exactly
       (no extra, missing, or duplicate members).
    5. Extract and verify each file's per-file digest.
    6. Optionally compare the archive digest with *expected_digest*.

    Returns a :class:`BundleVerificationResult`.
    """
    bundle_file = Path(bundle_path)
    if not bundle_file.exists():
        return BundleVerificationResult(
            valid=False,
            errors=[f"Bundle not found: {bundle_file}"],
        )

    if bundle_file.stat().st_size > MAX_BUNDLE_COMPRESSED_BYTES:
        return BundleVerificationResult(
            valid=False,
            errors=[f"Bundle exceeds the {MAX_BUNDLE_COMPRESSED_BYTES}-byte cap: {bundle_file}"],
        )

    # Locate manifest
    candidate = bundle_file.with_name(bundle_file.name + ".manifest.json")
    if not candidate.exists():
        return BundleVerificationResult(
            valid=False,
            errors=[f"Manifest not found: {candidate}"],
        )

    if candidate.stat().st_size > MAX_MANIFEST_BYTES:
        return BundleVerificationResult(
            valid=False,
            errors=[f"Manifest exceeds the {MAX_MANIFEST_BYTES}-byte cap: {candidate}"],
        )

    try:
        manifest_data = json.loads(candidate.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        return BundleVerificationResult(
            valid=False,
            errors=[f"Failed to parse manifest: {exc}"],
        )

    # 0. Validate the manifest contract first (C18).
    manifest, contract_errors = _validate_manifest_contract(manifest_data)
    if manifest is None:
        return BundleVerificationResult(
            valid=False,
            errors=contract_errors,
        )

    errors: list[str] = []
    per_file_status: dict[str, str] = {}

    # 1. Verify archive-level digest
    archive_bytes = bundle_file.read_bytes()
    actual_digest = _sha256(archive_bytes)
    bundle_match = actual_digest == manifest.bundle_digest
    if not bundle_match:
        errors.append(
            f"Archive digest mismatch: expected {manifest.bundle_digest}, got {actual_digest}"
        )

    # 2. Optional: compare against supplied expected digest
    if expected_digest is not None and actual_digest != expected_digest:
        errors.append(
            f"Digest does not match expected: expected {expected_digest}, got {actual_digest}"
        )

    # 3. Open and validate the container (C18): the member set must
    # match the manifest map exactly, and every member must respect
    # the per-file and total caps — before any member is read.
    fmt = manifest.format
    members, member_error = _list_archive_members(bundle_file, fmt)
    if member_error is not None:
        errors.append(member_error)
        return BundleVerificationResult(
            valid=False,
            per_file_status=per_file_status,
            bundle_digest_match=bundle_match,
            expected_digest=expected_digest or "",
            actual_digest=actual_digest,
            errors=errors,
        )
    assert members is not None
    member_sizes = dict(members)
    for name in sorted(set(member_sizes) - set(manifest.per_file_digests)):
        per_file_status[name] = "extra"
        errors.append(f"Archive contains {name}, which the manifest does not list")
    for name in sorted(set(manifest.per_file_digests) - set(member_sizes)):
        per_file_status[name] = "missing"
        errors.append(f"File not found in archive: {name}")
    for name, size in members:
        if size > MAX_BUNDLE_FILE_BYTES:
            per_file_status[name] = "error"
            errors.append(f"{name} exceeds the {MAX_BUNDLE_FILE_BYTES}-byte per-file cap")
    if sum(size for _, size in members) > MAX_BUNDLE_TOTAL_BYTES:
        errors.append(f"Bundle exceeds the {MAX_BUNDLE_TOTAL_BYTES}-byte total cap")

    # 4. Verify per-file digests
    total_decompressed = 0
    for rel, expected in sorted(manifest.per_file_digests.items()):
        if rel in per_file_status:
            continue
        try:
            if fmt == "tar.gz":
                with tarfile.open(bundle_file, "r:gz") as tar:
                    member = tar.getmember(rel)
                    if member.size > MAX_BUNDLE_FILE_BYTES:
                        per_file_status[rel] = "error"
                        errors.append(
                            f"{rel} exceeds the {MAX_BUNDLE_FILE_BYTES}-byte per-file cap"
                        )
                        continue
                    f = tar.extractfile(member)
                    if f is None:
                        per_file_status[rel] = "missing"
                        errors.append(f"Cannot extract {rel} (not a regular file)")
                        continue
                    data = _read_capped(f, limit=MAX_BUNDLE_FILE_BYTES, what=rel)
            elif fmt == "zip":
                with zipfile.ZipFile(bundle_file, "r") as zf:
                    info = zf.getinfo(rel)
                    if info.file_size > MAX_BUNDLE_FILE_BYTES:
                        per_file_status[rel] = "error"
                        errors.append(
                            f"{rel} exceeds the {MAX_BUNDLE_FILE_BYTES}-byte per-file cap"
                        )
                        continue
                    with zf.open(info) as f:
                        data = _read_capped(f, limit=MAX_BUNDLE_FILE_BYTES, what=rel)
            else:
                per_file_status[rel] = "unsupported_format"
                errors.append(f"Unsupported format: {fmt}")
                continue

            total_decompressed += len(data)
            if total_decompressed > MAX_BUNDLE_TOTAL_BYTES:
                per_file_status[rel] = "error"
                errors.append(f"Bundle exceeds the {MAX_BUNDLE_TOTAL_BYTES}-byte total cap")
                break

            # Compute digest
            if rel.endswith(".json"):
                try:
                    obj = json.loads(data)
                    file_digest = _sha256(_canonical_json_bytes(obj))
                except (json.JSONDecodeError, ValueError):
                    file_digest = _sha256(data)
            else:
                file_digest = _sha256(data)

            if file_digest == expected:
                per_file_status[rel] = "ok"
            else:
                per_file_status[rel] = "tampered"
                errors.append(
                    f"File digest mismatch for {rel}: expected {expected}, got {file_digest}"
                )
        except KeyError:
            per_file_status[rel] = "missing"
            errors.append(f"File not found in archive: {rel}")
        except Exception as exc:
            per_file_status[rel] = "error"
            errors.append(f"Error verifying {rel}: {exc}")

    return BundleVerificationResult(
        valid=len(errors) == 0,
        per_file_status=per_file_status,
        bundle_digest_match=bundle_match,
        expected_digest=expected_digest or "",
        actual_digest=actual_digest,
        errors=errors,
    )


def list_bundle(bundle_path: str | Path) -> list[dict[str, Any]]:
    """List the contents of a bundle archive with sizes.

    Returns a list of dicts with ``name``, ``size``, and ``compressed_size``.
    """
    bundle_file = Path(bundle_path)
    if not bundle_file.exists():
        raise FileNotFoundError(f"Bundle not found: {bundle_file}")

    if bundle_file.stat().st_size > MAX_BUNDLE_COMPRESSED_BYTES:
        raise ValueError(
            f"Bundle exceeds the {MAX_BUNDLE_COMPRESSED_BYTES}-byte cap: {bundle_file}"
        )

    entries: list[dict[str, Any]] = []
    name = bundle_file.name
    if name.endswith(".tar.gz") or name.endswith(".tgz"):
        with tarfile.open(bundle_file, "r:gz") as tar:
            total = 0
            for member in tar.getmembers():
                if member.size > MAX_BUNDLE_FILE_BYTES:
                    raise ValueError(
                        f"Member {member.name} exceeds the "
                        f"{MAX_BUNDLE_FILE_BYTES}-byte per-file cap"
                    )
                total += member.size
                if total > MAX_BUNDLE_TOTAL_BYTES:
                    raise ValueError(f"Bundle exceeds the {MAX_BUNDLE_TOTAL_BYTES}-byte total cap")
                entries.append(
                    {
                        "name": member.name,
                        "size": member.size,
                        "compressed_size": member.size,  # tar:gz doesn't expose per-member compressed
                    }
                )
    elif name.endswith(".zip"):
        with zipfile.ZipFile(bundle_file, "r") as zf:
            total = 0
            for info in zf.infolist():
                if info.file_size > MAX_BUNDLE_FILE_BYTES:
                    raise ValueError(
                        f"Member {info.filename} exceeds the "
                        f"{MAX_BUNDLE_FILE_BYTES}-byte per-file cap"
                    )
                total += info.file_size
                if total > MAX_BUNDLE_TOTAL_BYTES:
                    raise ValueError(f"Bundle exceeds the {MAX_BUNDLE_TOTAL_BYTES}-byte total cap")
                entries.append(
                    {
                        "name": info.filename,
                        "size": info.file_size,
                        "compressed_size": info.compress_size,
                    }
                )
    else:
        raise ValueError(f"Unsupported bundle format: {name}")

    return entries


def _unwrap_bundle_dict(data: Any) -> dict[str, Any] | None:
    """Return the forensic-bundle dict inside *data*, or None.

    Accepts a bare forensic bundle (a dict carrying ``schema``,
    ``consensus``, ``trust_map`` or ``detector_results``) or a sealed case
    file (a dict whose ``forensic_bundle`` member is a dict). Anything else
    returns None, so callers can distinguish "not a bundle" from a bundle
    that merely fails validation.
    """
    if not isinstance(data, dict):
        return None
    inner = data.get("forensic_bundle")
    if isinstance(inner, dict):
        return inner
    if any(key in data for key in ("schema", "consensus", "trust_map", "detector_results")):
        return data
    return None


def _try_parse_json(data: bytes) -> Any | None:
    """Parse *data* as JSON, returning None instead of raising on bad input."""
    try:
        return json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return None


def _read_bundle_from_archive(bundle_file: Path) -> dict[str, Any]:
    """Extract the first JSON member that parses to a bundle or case file.

    Members are scanned in archive order; non-JSON members are skipped.
    The same decompression-bomb caps as :func:`verify_bundle` apply.
    """
    name = bundle_file.name
    total = 0
    if name.endswith(".tar.gz") or name.endswith(".tgz"):
        with tarfile.open(bundle_file, "r:gz") as tar:
            for member in tar.getmembers():
                if not member.isfile() or not member.name.endswith(".json"):
                    continue
                if member.size > MAX_BUNDLE_FILE_BYTES:
                    raise ValueError(
                        f"Member {member.name} exceeds the "
                        f"{MAX_BUNDLE_FILE_BYTES}-byte per-file cap"
                    )
                stream = tar.extractfile(member)
                if stream is None:
                    continue
                data = _read_capped(stream, limit=MAX_BUNDLE_FILE_BYTES, what=member.name)
                total += len(data)
                if total > MAX_BUNDLE_TOTAL_BYTES:
                    raise ValueError(f"Bundle exceeds the {MAX_BUNDLE_TOTAL_BYTES}-byte total cap")
                bundle = _unwrap_bundle_dict(_try_parse_json(data))
                if bundle is not None:
                    return bundle
    elif name.endswith(".zip"):
        with zipfile.ZipFile(bundle_file, "r") as zf:
            for info in zf.infolist():
                if info.is_dir() or not info.filename.endswith(".json"):
                    continue
                if info.file_size > MAX_BUNDLE_FILE_BYTES:
                    raise ValueError(
                        f"Member {info.filename} exceeds the "
                        f"{MAX_BUNDLE_FILE_BYTES}-byte per-file cap"
                    )
                with zf.open(info) as stream:
                    data = _read_capped(stream, limit=MAX_BUNDLE_FILE_BYTES, what=info.filename)
                total += len(data)
                if total > MAX_BUNDLE_TOTAL_BYTES:
                    raise ValueError(f"Bundle exceeds the {MAX_BUNDLE_TOTAL_BYTES}-byte total cap")
                bundle = _unwrap_bundle_dict(_try_parse_json(data))
                if bundle is not None:
                    return bundle
    else:  # pragma: no cover - guarded by read_bundle's suffix check
        raise ValueError(f"Unsupported bundle format: {name}")
    raise ValueError(f"No forensic bundle found in archive: {bundle_file}")


def read_bundle(bundle_path: str | Path) -> dict[str, Any]:
    """Read a forensic bundle from a JSON file, a sealed case file, or a bundle archive.

    Accepts:
    - a forensic-bundle JSON file (as written by ``report --output``),
    - a sealed case file (as written by ``case export``; the inner
      ``forensic_bundle`` is returned),
    - a bundle archive (``.tar.gz`` / ``.zip`` as written by ``bundle pack``);
      the first JSON member that parses to a bundle or case file is returned.

    Raises ``FileNotFoundError`` for a missing path, ``ValueError`` when the
    file is too large, is not a bundle, or (for archives) contains no bundle,
    and ``json.JSONDecodeError`` for a malformed plain JSON file.
    """
    bundle_file = Path(bundle_path)
    if not bundle_file.exists():
        raise FileNotFoundError(f"Bundle not found: {bundle_file}")

    if bundle_file.stat().st_size > MAX_BUNDLE_COMPRESSED_BYTES:
        raise ValueError(
            f"Bundle exceeds the {MAX_BUNDLE_COMPRESSED_BYTES}-byte cap: {bundle_file}"
        )

    name = bundle_file.name
    if name.endswith(".tar.gz") or name.endswith(".tgz") or name.endswith(".zip"):
        return _read_bundle_from_archive(bundle_file)

    data = json.loads(bundle_file.read_text(encoding="utf-8"))
    bundle = _unwrap_bundle_dict(data)
    if bundle is None:
        raise ValueError(f"File does not contain a forensic bundle: {bundle_file}")
    return bundle
