"""Result serialization codec with schema validation and version migration.

This module provides a codec for serializing and deserializing forensic
results with schema validation, version detection, and automatic
migration for forward compatibility.

Features:
- Schema-validated encoding/decoding
- Automatic version detection and migration (via configured callbacks)
- Canonical JSON for deterministic hashing
- Bounded streaming for large results (the serialized byte string is
  never fully materialized)

Version-map contract (W5 item 5)
---------------------------------
:data:`_SCHEMA_VERSIONS` names exactly the formats the generic
validator (:mod:`textforensics.schema`) can validate: every key is a
packaged schema name and every non-``None`` version is one the shipped
schema accepts. Formats with no packaged JSON Schema — drift-report,
calibration, threshold-selection, bundle-manifest — are NOT listed:
encoding or decoding them raises :class:`CodecError` (unknown schema
name) instead of stamping a version nobody can validate. The
enterprise-policy schema is unversioned (no ``schema`` property), so
the codec transports it without stamping a version the schema forbids.
The trust map's current version is v3, matching the shipped schema.

Migration contract (W5 item 5)
-------------------------------
A legacy version outside a format's accepted set is migrated only by
a callback registered in :class:`CodecConfig.migrations`
(``migrations[from_version][to_version]``). A migration that cannot
run — no callback, a callback that raises, a non-object result, or a
result that does not declare the target version — raises
:class:`VersionMigrationError` loudly. It never warns and returns the
data unchanged: that would silently relabel an artifact the codec
cannot migrate. Strict mode rejects any non-current version before
callbacks are consulted.

Streaming contract (W5 item 5)
-------------------------------
:func:`ResultCodec.iter_encode` yields the canonical JSON in chunks of
at most ``chunk_size`` bytes without materializing the serialized byte
string; :func:`ResultCodec.stream_encode` returns a lazy binary stream
over the same iterator. The bound is on the serialized output: the
input dict is in memory (canonical JSON with sorted keys is a
whole-object operation), and a single indivisible string value is
re-chunked after encoding, so no yielded chunk exceeds the bound.
``decode`` still operates on an already-materialized payload — that is
an explicit limitation, not a streaming decode.
"""

from __future__ import annotations

import codecs
import io
import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .atomic_io import atomic_write_bytes
from .probe_metrics import reject_nonfinite_value, strict_json_dumps, strict_json_loads
from .schema import validate

__all__ = [
    "ResultCodec",
    "CodecError",
    "VersionMigrationError",
    "encode_result",
    "decode_result",
    "validate_result",
]


class CodecError(Exception):
    """Base exception for codec errors."""

    pass


class VersionMigrationError(CodecError):
    """Raised when version migration fails."""

    pass


@dataclass(frozen=True, slots=True)
class CodecConfig:
    """Configuration for the result codec."""

    validate_on_encode: bool = True
    validate_on_decode: bool = True
    canonical_json: bool = True
    strict_version: bool = False  # If True, reject unknown versions

    # Version migration callbacks, keyed ``migrations[from_version]``
    # ``[to_version]`` — each value is a callable taking the decoded
    # dict and returning the migrated dict, which MUST declare the
    # target version in its ``schema`` field (the codec never relabels
    # an artifact itself). A legacy version with no callback registered
    # fails loudly on decode; see :func:`_migrate_result`.
    migrations: dict[str, dict[str, callable]] = None  # type: ignore[assignment]

    def __post_init__(self):
        if self.migrations is None:
            object.__setattr__(self, "migrations", {})


# Default configuration
DEFAULT_CONFIG = CodecConfig()


# Schema version mapping — the CURRENT version of each format the
# generic validator can validate. The case file is v4 here (v4 is what
# the system produces everywhere else since the U2 not_reproducible
# follow-up: casefile.py seals v4 by default); the remaining v2 formats
# stay v2 (v2 is what the system produces everywhere else: report.py,
# trust.py); the trust map is v3 (v3 is what derive_trust_map produces
# now); the enterprise-policy schema is unversioned, so its entry is
# ``None`` — the codec stamps no version it does not have. The codec
# must not maintain a parallel v1 dialect of a current format:
# previously this map was v1-only, so decoding a current v2 artifact
# silently relabelled it v1. Legacy v1/v2/v3 artifacts still decode
# (with a migration callback, or via the accepted set); they keep
# their label — see decode().
#
# Deliberately NOT listed (W5 item 5): drift-report, calibration,
# threshold-selection, bundle-manifest. Those formats have no packaged
# JSON Schema, so the generic validator cannot validate them and the
# codec refuses to transport them — advertising them here used to
# stamp versions nobody could check.
_SCHEMA_VERSIONS: dict[str, str | None] = {
    "forensic-bundle": "textforensics.forensic-bundle/v2",
    "detector-result": "textforensics.detector-result/v2",
    "case-file": "textforensics.case-file/v4",
    "trust-map": "textforensics.trust-map/v3",
    "enterprise-policy": None,
}

# Names whose versions are all live simultaneously (W3: C23).  The
# trust map is the one format the codec must transport in every
# registry-supported version (v1/v2/v3 all appear inside bundles under
# the accepted pair table), so its accepted set comes from the schema
# registry.  Every other name keeps the single-current-version
# strictness pinned by tests/test_result_codec.py,
# tests/test_verify_consolidation.py, tests/test_mcp_tools_new.py and
# the W2 mutation kill grid: strict mode refuses any version other
# than the current one.
_MULTI_VERSION_NAMES = frozenset({"trust-map"})


def _accepted_versions(schema_name: str) -> frozenset[str]:
    """Versions the codec accepts for *schema_name* without relabelling."""
    current = _SCHEMA_VERSIONS.get(schema_name)
    if schema_name in _MULTI_VERSION_NAMES:
        try:
            from .schema import supported_versions

            registered = supported_versions(schema_name)
        except ValueError:
            registered = frozenset()
        if registered:
            return registered
    return frozenset({current}) if current else frozenset()


def _extract_schema_version(data: dict[str, Any]) -> str | None:
    """Extract schema version from data."""
    return data.get("schema")


def _migrate_result(
    data: dict[str, Any],
    from_version: str,
    to_version: str,
    migrations: dict[str, dict[str, callable]] | None = None,
) -> dict[str, Any]:
    """Migrate result data from one schema version to another.

    Dispatches to the callback registered as
    ``migrations[from_version][to_version]``. A migration that cannot
    run fails loudly with :class:`VersionMigrationError` — no callback
    registered, a callback that raises, a non-object result, or a
    result that does not declare the target version. It never warns
    and returns the data unchanged: that would silently relabel an
    artifact the codec cannot migrate.
    """
    if from_version == to_version:
        return data
    callback = (migrations or {}).get(from_version, {}).get(to_version)
    if callback is None:
        raise VersionMigrationError(
            f"No migration path from {from_version} to {to_version}: no "
            "migration callback is registered in CodecConfig.migrations. "
            "Refusing to return the data unchanged."
        )
    try:
        migrated = callback(dict(data))
    except VersionMigrationError:
        raise
    except Exception as exc:
        raise VersionMigrationError(
            f"Migration from {from_version} to {to_version} failed: {exc}"
        ) from exc
    if not isinstance(migrated, dict):
        raise VersionMigrationError(
            f"Migration from {from_version} to {to_version} did not produce an object."
        )
    if migrated.get("schema") != to_version:
        raise VersionMigrationError(
            f"Migration from {from_version} to {to_version} did not produce "
            f"the target version: got {migrated.get('schema')!r}. The codec "
            "does not silently relabel artifacts."
        )
    return migrated


class ResultCodec:
    """Codec for encoding/decoding forensic results with schema validation."""

    def __init__(self, config: CodecConfig | None = None):
        self.config = config or DEFAULT_CONFIG

    @staticmethod
    def _require_known_schema(schema_name: str) -> None:
        """Fail loudly for a schema name the codec does not transport.

        The version map is the authority: a name with no packaged JSON
        Schema cannot be validated, so the codec refuses it outright
        instead of stamping an uncheckable version.
        """
        if schema_name not in _SCHEMA_VERSIONS:
            raise CodecError(
                f"Unknown schema name {schema_name!r}. Available: "
                f"{', '.join(sorted(_SCHEMA_VERSIONS))}. The codec only "
                "transports formats with a packaged JSON Schema."
            )

    def _prepare_for_encode(
        self,
        data: dict[str, Any],
        schema_name: str,
        *,
        validate: bool | None = None,
    ) -> dict[str, Any]:
        """Reject nonfinite values, stamp the version, validate.

        Shared by :meth:`encode` and :meth:`iter_encode` so both fail
        identically — and eagerly, before any byte is produced.
        """
        self._require_known_schema(schema_name)
        if validate is None:
            validate = self.config.validate_on_encode

        # S22: nonfinite numerics are rejected at the transport
        # boundary, before schema validation and before serialisation
        # — a NaN is never valid JSON content, whatever the schema
        # says about the surrounding object.
        try:
            reject_nonfinite_value(data, "result")
        except ValueError as exc:
            raise CodecError(f"Non-finite numeric value: {exc}") from exc

        # Add schema version if not present (before validation).
        # Unversioned formats (enterprise-policy: None) get no stamp:
        # their schema forbids the property.
        current_version = _SCHEMA_VERSIONS[schema_name]
        if "schema" not in data and current_version is not None:
            data = dict(data)
            data["schema"] = current_version

        if validate:
            errors = self._validate(data, schema_name)
            if errors:
                raise CodecError(f"Validation failed: {'; '.join(errors)}")
        return data

    def encode(
        self,
        data: dict[str, Any],
        schema_name: str,
        *,
        validate: bool | None = None,
    ) -> bytes:
        """Encode a result dictionary to canonical JSON bytes.

        Args:
            data: Result dictionary to encode.
            schema_name: Schema name (e.g., "forensic-bundle").
            validate: Override validation setting.

        Returns:
            Canonical JSON bytes.

        Raises:
            CodecError: If validation fails or schema is unknown.
        """
        prepared = self._prepare_for_encode(data, schema_name, validate=validate)
        try:
            if self.config.canonical_json:
                return strict_json_dumps(
                    prepared,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            else:
                return strict_json_dumps(prepared, ensure_ascii=False).encode("utf-8")
        except ValueError as exc:
            raise CodecError(f"Non-finite numeric value: {exc}") from exc

    def iter_encode(
        self,
        data: dict[str, Any],
        schema_name: str,
        *,
        validate: bool | None = None,
        chunk_size: int = 65536,
    ) -> Iterator[bytes]:
        """Yield the canonical JSON encoding in bounded chunks.

        Every yielded chunk is at most ``chunk_size`` bytes, and the
        serialized byte string is never fully materialized — bytes are
        produced incrementally from ``json.JSONEncoder.iterencode`` and
        re-chunked after encoding, so even one huge string value is
        emitted in ``chunk_size`` slices. Validation, version
        stamping, and the unknown-schema check run eagerly (before the
        first chunk), exactly as in :meth:`encode`.
        """
        if not isinstance(chunk_size, int) or isinstance(chunk_size, bool) or chunk_size <= 0:
            raise CodecError(f"chunk_size must be a positive integer, got {chunk_size!r}.")
        prepared = self._prepare_for_encode(data, schema_name, validate=validate)
        return self._iter_encode_chunks(prepared, chunk_size=chunk_size)

    def _iter_encode_chunks(self, data: dict[str, Any], *, chunk_size: int) -> Iterator[bytes]:
        """Incrementally serialize ``data`` into ``chunk_size``-bounded chunks."""
        if self.config.canonical_json:
            encoder = json.JSONEncoder(
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        else:
            encoder = json.JSONEncoder(ensure_ascii=False, allow_nan=False)
        incremental = codecs.getincrementalencoder("utf-8")()
        pending = bytearray()
        # A single iterencode piece can be one huge string value; feed
        # the UTF-8 encoder in bounded slices (a character is at most
        # 4 bytes) so no single encode call can blow the chunk bound.
        step = max(1, chunk_size // 4)
        try:
            for piece in encoder.iterencode(data):
                for start in range(0, len(piece), step):
                    pending += incremental.encode(piece[start : start + step])
                    while len(pending) >= chunk_size:
                        yield bytes(pending[:chunk_size])
                        del pending[:chunk_size]
            tail = incremental.encode("", final=True)
        except ValueError as exc:
            raise CodecError(f"Non-finite numeric value: {exc}") from exc
        if tail:
            pending += tail
        while len(pending) >= chunk_size:
            yield bytes(pending[:chunk_size])
            del pending[:chunk_size]
        if pending:
            yield bytes(pending)

    def decode(
        self,
        data: bytes | str,
        schema_name: str,
        *,
        validate: bool | None = None,
    ) -> dict[str, Any]:
        """Decode JSON bytes to result dictionary.

        Args:
            data: JSON bytes or string to decode.
            schema_name: Expected schema name.
            validate: Override validation setting.

        Returns:
            Decoded and validated result dictionary.

        Raises:
            CodecError: If decoding or validation fails.
            VersionMigrationError: If the payload's version is outside
                the accepted set and no registered migration callback
                can move it to the current version.
        """
        self._require_known_schema(schema_name)
        if validate is None:
            validate = self.config.validate_on_decode

        if isinstance(data, bytes):
            data = data.decode("utf-8")

        try:
            # S22: strict parsing — literal NaN/Infinity tokens and
            # overflowing floats (1e999) are rejected here, before any
            # schema validation. This rejection is transport-level: it
            # applies even when validate=False, because a nonfinite
            # token is never valid JSON.
            result = strict_json_loads(data)
        except ValueError as exc:
            raise CodecError(f"Invalid JSON: {exc}") from exc

        if not isinstance(result, dict):
            raise CodecError("Decoded JSON must be an object")

        try:
            reject_nonfinite_value(result, "result")
        except ValueError as exc:
            raise CodecError(f"Non-finite numeric value: {exc}") from exc

        # Extract and check schema version.  A found version in the
        # accepted set for this format is kept as-is (no migration, no
        # relabelling): for trust-map that is v1/v2/v3 (W3: C23 — all
        # three appear inside bundles under the accepted pair table),
        # for every other format exactly the current version.  An
        # unaccepted version is refused under strict mode, and migrated
        # via a registered callback otherwise — a migration that cannot
        # run raises VersionMigrationError instead of warning and
        # returning the data unchanged (W5 item 5).
        found_version = _extract_schema_version(result)
        expected_version = _SCHEMA_VERSIONS.get(schema_name)
        accepted_versions = _accepted_versions(schema_name)

        if expected_version and found_version and found_version not in accepted_versions:
            if self.config.strict_version:
                raise VersionMigrationError(
                    f"Schema version mismatch: expected {expected_version}, got {found_version}"
                )
            result = _migrate_result(
                result, found_version, expected_version, self.config.migrations
            )

        if validate:
            errors = self._validate(result, schema_name)
            if errors:
                raise CodecError(f"Validation failed: {'; '.join(errors)}")

        return result

    def _validate(self, data: dict[str, Any], schema_name: str) -> list[str]:
        """Validate data against schema."""
        try:
            reject_nonfinite_value(data, "result")
        except ValueError as exc:
            return [f"Non-finite numeric value: {exc}"]
        try:
            return validate(data, schema_name)
        except ValueError as exc:
            return [f"Schema error: {exc}"]
        except RuntimeError as exc:
            return [f"Validation unavailable: {exc}"]

    def encode_file(
        self,
        data: dict[str, Any],
        path: str | Path,
        schema_name: str,
        *,
        validate: bool | None = None,
    ) -> None:
        """Encode and write result to file.

        Publication is atomic (W5 item 4): a failed write leaves the
        previous file untouched, never half-written.
        """
        encoded = self.encode(data, schema_name, validate=validate)
        atomic_write_bytes(path, encoded)

    def decode_file(
        self,
        path: str | Path,
        schema_name: str,
        *,
        validate: bool | None = None,
    ) -> dict[str, Any]:
        """Read and decode result from file."""
        data = Path(path).read_bytes()
        return self.decode(data, schema_name, validate=validate)

    def stream_encode(
        self,
        data: dict[str, Any],
        schema_name: str,
        *,
        validate: bool | None = None,
        chunk_size: int = 65536,
    ) -> io.RawIOBase:
        """Encode to a lazy binary stream.

        Returns a readable binary stream over :meth:`iter_encode`:
        reading it never materializes the whole byte string. Supports
        ``read(size)`` and ``readinto``; ``read()`` with no size
        consumes the rest (and so does materialize it — the caller's
        choice, not the stream's). Previously this returned a
        ``BytesIO`` holding the entire encoding; the return type is
        deliberately a lazy stream now (W5 item 5).
        """
        chunks = self.iter_encode(data, schema_name, validate=validate, chunk_size=chunk_size)
        return _ChunkedReader(chunks)


class _ChunkedReader(io.RawIOBase):
    """A readable binary stream backed by a bounded-chunk iterator.

    Pulls from the iterator only as the caller reads, so peak memory
    stays bounded by the chunk size plus one read buffer — never by
    the total encoded size.
    """

    def __init__(self, chunks: Iterator[bytes]):
        super().__init__()
        self._chunks = iter(chunks)
        self._pending = b""
        self._exhausted = False

    def readable(self) -> bool:
        return True

    def _fill(self) -> None:
        if self._pending or self._exhausted:
            return
        try:
            self._pending = next(self._chunks)
        except StopIteration:
            self._exhausted = True

    def readinto(self, buffer: bytearray | memoryview) -> int | None:
        if len(buffer) == 0:
            return 0
        self._fill()
        if not self._pending:
            return 0
        take = self._pending[: len(buffer)]
        buffer[: len(take)] = take
        self._pending = self._pending[len(take) :]
        return len(take)

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            parts = []
            if self._pending:
                parts.append(self._pending)
                self._pending = b""
            parts.extend(self._chunks)
            self._exhausted = True
            return b"".join(parts)
        if size == 0:
            return b""
        out = bytearray()
        while len(out) < size:
            if not self._pending:
                self._fill()
                if not self._pending:
                    break
            take = self._pending[: size - len(out)]
            out += take
            self._pending = self._pending[len(take) :]
        return bytes(out)


# Convenience functions for common operations


def encode_result(
    data: dict[str, Any],
    schema_name: str,
    *,
    config: CodecConfig | None = None,
) -> bytes:
    """Encode a result with default codec."""
    codec = ResultCodec(config)
    return codec.encode(data, schema_name)


def decode_result(
    data: bytes | str,
    schema_name: str,
    *,
    config: CodecConfig | None = None,
) -> dict[str, Any]:
    """Decode a result with default codec."""
    codec = ResultCodec(config)
    return codec.decode(data, schema_name)


def validate_result(
    data: dict[str, Any],
    schema_name: str,
) -> list[str]:
    """Validate a result against its schema."""
    codec = ResultCodec()
    return codec._validate(data, schema_name)
