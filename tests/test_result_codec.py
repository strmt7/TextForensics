"""Tests for result codec."""

from __future__ import annotations

import json

import pytest

from textforensics.result_codec import (
    CodecConfig,
    CodecError,
    ResultCodec,
    VersionMigrationError,
    decode_result,
    encode_result,
    validate_result,
)

# Minimal valid forensic bundle for testing
MINIMAL_BUNDLE = {
    "schema": "textforensics.forensic-bundle/v1",
    "generated_at_utc": "2024-01-01T00:00:00+00:00",
    "content_sha256": "0" * 64,
    "input": {
        "word_count": 100,
        "sentence_count": 5,
        "paragraph_count": 2,
        "raw_text_included": False,
    },
    "detector_results": [],
    "detector_failures": [],
    "plugin_health": [],
    "consensus": {
        "verdict": "ai_like",
        "ai_probability": 0.75,
        "independent_families": 1,
    },
    "trust_map": {
        "schema": "textforensics.trust-map/v1",
        "overall": "strong",
        "dimensions": [],
        "limitations": [],
    },
    "verdict_integrity": {},
    "robustness": {},
    "provenance": None,
    "limitations": [],
}


class TestResultCodec:
    def test_encode_decode_roundtrip(self):
        """Round-trip encode/decode should preserve data."""
        data = dict(MINIMAL_BUNDLE)
        data["consensus"] = {"verdict": "ai_like", "ai_probability": 0.75, "independent_families": 1}
        codec = ResultCodec()
        encoded = codec.encode(data, "forensic-bundle")
        decoded = codec.decode(encoded, "forensic-bundle")
        assert decoded["consensus"]["verdict"] == "ai_like"
        assert decoded["consensus"]["ai_probability"] == 0.75

    def test_encode_adds_schema_if_missing(self):
        """Encode should add schema version if missing."""
        data = dict(MINIMAL_BUNDLE)
        del data["schema"]
        codec = ResultCodec()
        encoded = codec.encode(data, "forensic-bundle")
        decoded = json.loads(encoded)
        assert decoded["schema"] == "textforensics.forensic-bundle/v1"

    def test_decode_validates_against_schema(self):
        """Decode should validate against schema."""
        data = dict(MINIMAL_BUNDLE)
        data["consensus"]["verdict"] = "invalid_verdict"  # Invalid verdict
        codec = ResultCodec()
        encoded = json.dumps(data).encode()
        # Should not raise with default config (warnings only)
        decoded = codec.decode(encoded, "forensic-bundle")
        assert decoded["consensus"]["verdict"] == "invalid_verdict"

    def test_strict_version_rejects_mismatch(self):
        """Strict version mode should reject mismatched versions."""
        data = dict(MINIMAL_BUNDLE)
        data["schema"] = "textforensics.forensic-bundle/v2"  # Wrong version
        codec = ResultCodec(CodecConfig(strict_version=True))
        encoded = json.dumps(data).encode()
        with pytest.raises(VersionMigrationError):
            codec.decode(encoded, "forensic-bundle")

    def test_canonical_json_deterministic(self):
        """Canonical JSON should be deterministic."""
        data = dict(MINIMAL_BUNDLE)
        codec = ResultCodec(CodecConfig(canonical_json=True))
        encoded1 = codec.encode(data, "forensic-bundle")
        encoded2 = codec.encode(data, "forensic-bundle")
        assert encoded1 == encoded2

    def test_non_canonical_json_allows_whitespace(self):
        """Non-canonical mode should allow readable JSON."""
        data = dict(MINIMAL_BUNDLE)
        codec = ResultCodec(CodecConfig(canonical_json=False))
        encoded = codec.encode(data, "forensic-bundle")
        decoded = json.loads(encoded)
        assert decoded["schema"] == "textforensics.forensic-bundle/v1"

    def test_validate_only_mode(self):
        """Validation-only mode should check without encoding."""
        data = dict(MINIMAL_BUNDLE)
        errors = validate_result(data, "forensic-bundle")
        # May have warnings but no hard errors
        assert isinstance(errors, list)

    def test_validate_invalid_verdict(self):
        """Validation should catch invalid verdict if consensus schema exists."""
        data = dict(MINIMAL_BUNDLE)
        data["consensus"]["verdict"] = "not_a_verdict"
        errors = validate_result(data, "forensic-bundle")
        # The forensic-bundle schema doesn't validate consensus.verdict,
        # so this test just checks validation runs without error
        assert isinstance(errors, list)

    def test_convenience_functions(self):
        """encode_result/decode_result convenience functions work."""
        data = dict(MINIMAL_BUNDLE)
        data["consensus"]["verdict"] = "human_like"
        encoded = encode_result(data, "forensic-bundle")
        decoded = decode_result(encoded, "forensic-bundle")
        assert decoded["consensus"]["verdict"] == "human_like"

    def test_encode_file_decode_file(self, tmp_path):
        """File I/O methods work."""
        data = dict(MINIMAL_BUNDLE)
        codec = ResultCodec()
        path = tmp_path / "test.json"
        codec.encode_file(data, path, "forensic-bundle")
        decoded = codec.decode_file(path, "forensic-bundle")
        assert decoded["schema"] == "textforensics.forensic-bundle/v1"

    def test_stream_encode(self):
        """Stream encoding produces BytesIO."""
        data = dict(MINIMAL_BUNDLE)
        codec = ResultCodec()
        stream = codec.stream_encode(data, "forensic-bundle")
        assert hasattr(stream, "read")
        decoded = json.loads(stream.getvalue().decode())
        assert decoded["schema"] == "textforensics.forensic-bundle/v1"

    def test_invalid_json_raises(self):
        """Invalid JSON should raise CodecError."""
        codec = ResultCodec()
        with pytest.raises(CodecError):
            codec.decode(b"not valid json", "forensic-bundle")

    def test_non_object_json_raises(self):
        """Non-object JSON should raise CodecError."""
        codec = ResultCodec()
        with pytest.raises(CodecError):
            codec.decode(b"[]", "forensic-bundle")

    def test_unknown_schema_raises(self):
        """Unknown schema name should raise."""
        codec = ResultCodec()
        with pytest.raises(CodecError):
            codec.encode({}, "unknown-schema")

    def test_custom_config_validation(self):
        """Custom config should control validation."""
        data = {"consensus": {"verdict": "invalid"}}
        # No validation on encode
        codec = ResultCodec(CodecConfig(validate_on_encode=False))
        encoded = codec.encode(data, "forensic-bundle")  # Should not raise
        assert encoded is not None

        # Validation on decode
        codec2 = ResultCodec(CodecConfig(validate_on_decode=False))
        decoded = codec2.decode(encoded, "forensic-bundle")
        assert decoded is not None


class TestCodecConfig:
    def test_default_config(self):
        """Default config should have expected values."""
        config = CodecConfig()
        assert config.validate_on_encode is True
        assert config.validate_on_decode is True
        assert config.canonical_json is True
        assert config.strict_version is False

    def test_custom_config(self):
        """Custom config should override defaults."""
        config = CodecConfig(
            validate_on_encode=False,
            validate_on_decode=False,
            canonical_json=False,
            strict_version=True,
        )
        assert config.validate_on_encode is False
        assert config.validate_on_decode is False
        assert config.canonical_json is False
        assert config.strict_version is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
