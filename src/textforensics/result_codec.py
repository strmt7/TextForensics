"""Result serialization codec with schema validation and version migration.

This module provides a codec for serializing and deserializing forensic
results with schema validation, version detection, and automatic
migration for forward compatibility.

Features:
- Schema-validated encoding/decoding
- Automatic version detection and migration
- Canonical JSON for deterministic hashing
- Streaming support for large results
"""

from __future__ import annotations

import json
import warnings
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any

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

    # Version migration callbacks
    migrations: dict[str, dict[str, callable]] = None  # type: ignore[assignment]

    def __post_init__(self):
        if self.migrations is None:
            object.__setattr__(self, "migrations", {})


# Default configuration
DEFAULT_CONFIG = CodecConfig()


# Schema version mapping — the CURRENT version of each format. The case
# file is v3 here (v3 is what the system produces everywhere else since
# U2: casefile.py seals v3 by default); the remaining v2 formats stay v2
# (v2 is what the system produces everywhere else: report.py, trust.py);
# the formats with no v2 yet stay v1. The codec must not maintain a
# parallel v1 dialect of a current format: previously this map was
# v1-only, so decoding a current v2 artifact silently relabelled it
# v1. Legacy v1/v2 artifacts still decode (with a warning); they keep
# their label — see decode().
_SCHEMA_VERSIONS = {
    "forensic-bundle": "textforensics.forensic-bundle/v2",
    "detector-result": "textforensics.detector-result/v2",
    "case-file": "textforensics.case-file/v3",
    "trust-map": "textforensics.trust-map/v2",
    "enterprise-policy": "textforensics.enterprise-policy/v1",
    "drift-report": "textforensics.drift-report/v1",
    "calibration": "textforensics.calibration/v1",
    "threshold-selection": "textforensics.threshold-selection/v1",
    "bundle-manifest": "textforensics.bundle-manifest/v1",
}


def _extract_schema_version(data: dict[str, Any]) -> str | None:
    """Extract schema version from data."""
    return data.get("schema")


def _migrate_result(data: dict[str, Any], from_version: str, to_version: str) -> dict[str, Any]:
    """Migrate result data from one schema version to another.

    Currently only supports v1 -> v1 (identity). Future versions
    will implement migration logic here.
    """
    if from_version == to_version:
        return data

    # For now, just warn and return as-is
    warnings.warn(
        f"No migration path from {from_version} to {to_version}. Returning data unchanged.",
        UserWarning,
        stacklevel=2,
    )
    return data


class ResultCodec:
    """Codec for encoding/decoding forensic results with schema validation."""

    def __init__(self, config: CodecConfig | None = None):
        self.config = config or DEFAULT_CONFIG

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
        if validate is None:
            validate = self.config.validate_on_encode

        # Add schema version if not present (before validation)
        if "schema" not in data and schema_name in _SCHEMA_VERSIONS:
            data = dict(data)
            data["schema"] = _SCHEMA_VERSIONS[schema_name]

        if validate:
            errors = self._validate(data, schema_name)
            if errors:
                raise CodecError(f"Validation failed: {'; '.join(errors)}")

        if self.config.canonical_json:
            return json.dumps(
                data,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        else:
            return json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")

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
        """
        if validate is None:
            validate = self.config.validate_on_decode

        if isinstance(data, bytes):
            data = data.decode("utf-8")

        try:
            result = json.loads(data)
        except json.JSONDecodeError as exc:
            raise CodecError(f"Invalid JSON: {exc}") from exc

        if not isinstance(result, dict):
            raise CodecError("Decoded JSON must be an object")

        # Extract and check schema version
        found_version = _extract_schema_version(result)
        expected_version = _SCHEMA_VERSIONS.get(schema_name)

        if expected_version and found_version and found_version != expected_version:
            if self.config.strict_version:
                raise VersionMigrationError(
                    f"Schema version mismatch: expected {expected_version}, got {found_version}"
                )
            # Attempt migration. NOTE: there is no real v1<->v2 migration
            # yet (_migrate_result warns and returns the data unchanged),
            # so the found version label is KEPT — relabelling data the
            # codec cannot migrate would silently rewrite the artifact's
            # declared format. The data is validated as-is below (the
            # JSON schemas accept both v1 and v2 for these formats).
            result = _migrate_result(result, found_version, expected_version)

        if validate:
            errors = self._validate(result, schema_name)
            if errors:
                raise CodecError(f"Validation failed: {'; '.join(errors)}")

        return result

    def _validate(self, data: dict[str, Any], schema_name: str) -> list[str]:
        """Validate data against schema."""
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
        """Encode and write result to file."""
        encoded = self.encode(data, schema_name, validate=validate)
        Path(path).write_bytes(encoded)

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
    ) -> BytesIO:
        """Encode to a BytesIO stream for streaming."""
        encoded = self.encode(data, schema_name, validate=validate)
        return BytesIO(encoded)


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
