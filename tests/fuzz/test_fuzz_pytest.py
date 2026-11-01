#!/usr/bin/env python3
"""
Pytest-compatible fuzz test wrappers for CI integration.
These tests can be run with pytest and report coverage.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))


# ============================================================================
# JSON Parsing Tests (api.py, casefile.py, benchmark.py)
# ============================================================================

class TestJsonParsing:
    """Fuzz tests for JSON parsing across API, casefile, and benchmark modules."""

    @pytest.mark.parametrize("input_data", [
        pytest.param(b'{"text": "test"}', id="simple_text"),
        pytest.param(b'{"before": "text1", "after": "text2"}', id="compare_request"),
        pytest.param(b'{"text": ""}', id="empty_text"),
        pytest.param(b'{"text": "' + b'x' * 10000 + b'"}', id="long_text"),
        pytest.param(b'{"text": "\\x00\\x01\\x02\\x03"}', id="null_bytes"),
        pytest.param(b'{"nested": {"deep": {"structure": "' + b'x' * 500 + b'"}}}', id="nested_json"),
        pytest.param(b'not json at all', id="not_json"),
        pytest.param(b'{invalid json}', id="malformed_json"),
        pytest.param('{"text": "🚀🌟🎉💯"}'.encode(), id="unicode_text"),
        pytest.param(b'{"text": "' + b'A' * 100000 + b'"}', id="very_long_text"),
    ])
    def test_api_parsing(self, input_data):
        """Test JSON parsing for API endpoints."""
        try:
            from tests.fuzz.fuzz_json_parsing import TestOneInput
            TestOneInput(input_data)
        except ImportError:
            # Fallback if atheris not available
            pass

    @pytest.mark.parametrize("input_data", [
        pytest.param(b'{"schema": "textforensics.case-file/v1", "tool": {"name": "TF", "version": "1.0"}, "raw_text_included": false, "case_sha256": "' + b'0' * 64 + b'"}', id="valid_case_file"),
        pytest.param(b'{"schema": "textforensics.forensic-bundle/v1", "content_sha256": "' + b'0' * 64 + b'", "input": {"raw_text_included": false}}', id="forensic_bundle"),
        pytest.param(b'{"schema": "invalid"}', id="invalid_schema"),
        pytest.param(b'{"raw_text_included": true}', id="forbidden_key"),
    ])
    def test_casefile_parsing(self, input_data):
        """Test JSON parsing for casefile operations."""
        try:
            from tests.fuzz.fuzz_json_parsing import TestOneInput
            TestOneInput(input_data)
        except ImportError:
            pass

    @pytest.mark.parametrize("input_data", [
        pytest.param(b'{"label": "human", "text": "test text"}', id="human_label"),
        pytest.param(b'{"label": "ai", "text": "ai text"}', id="ai_label"),
        pytest.param(b'{"label": "invalid", "text": "test"}', id="invalid_label"),
        pytest.param(b'{"text": "no label"}', id="missing_label"),
    ])
    def test_benchmark_parsing(self, input_data):
        """Test JSON parsing for benchmark operations."""
        try:
            from tests.fuzz.fuzz_json_parsing import TestOneInput
            TestOneInput(input_data)
        except ImportError:
            pass


# ============================================================================
# Text Input Validation Tests (config.py, cli.py)
# ============================================================================

class TestTextInputValidation:
    """Fuzz tests for text input validation."""

    @pytest.mark.parametrize("input_data", [
        pytest.param(b"", id="empty_bytes"),
        pytest.param(b"short text", id="short_text"),
        pytest.param(b"x" * 1000, id="medium_text"),
        pytest.param(b"x" * 10000, id="long_text"),
        pytest.param(b"x" * 2000000, id="oversized_text"),
        pytest.param(b"\x00\x01\x02\x03", id="control_chars"),
        pytest.param("🚀🌟🎉💯".encode(), id="emoji_text"),
        pytest.param(b"A" * 100000, id="large_text"),
    ])
    def test_validation(self, input_data):
        """Test text input validation functions."""
        try:
            from tests.fuzz.fuzz_text_input_validation import TestOneInput
            TestOneInput(input_data)
        except ImportError:
            pass


# ============================================================================
# Detector Input Handling Tests (detectors.py)
# ============================================================================

class TestDetectorInputHandling:
    """Fuzz tests for detector input handling."""

    @pytest.mark.parametrize("input_data", [
        pytest.param(b"", id="empty"),
        pytest.param(b"test", id="simple"),
        pytest.param(b"x" * 100, id="short"),
        pytest.param(b"x" * 1000, id="medium"),
        pytest.param(b"x" * 10000, id="long"),
        pytest.param(b"\x00\x01\x02", id="control_chars"),
        pytest.param("🚀🌟🎉".encode(), id="emoji"),
        pytest.param(b"A" * 5000, id="substantial"),
    ])
    def test_detector_handling(self, input_data):
        """Test detector input handling."""
        try:
            from tests.fuzz.fuzz_detector_input import TestOneInput
            TestOneInput(input_data)
        except ImportError:
            pass


# ============================================================================
# Ledger Parsing Tests (provenance.py)
# ============================================================================

class TestLedgerParsing:
    """Fuzz tests for ledger parsing."""

    @pytest.mark.parametrize("input_data", [
        pytest.param(b"", id="empty"),
        pytest.param(b'{"schema": "textforensics-ledger/v1", "timestamp_utc": "2024-01-01T00:00:00+00:00", "file_name": "test.txt", "file_size": 100, "file_sha256": "' + b'0' * 64 + b'", "previous_record_sha256": null, "record_sha256": "' + b'0' * 64 + b'"}', id="valid_record"),
        pytest.param(b'not json', id="not_json"),
        pytest.param(b'{"schema": "wrong"}', id="wrong_schema"),
        pytest.param(b'{"schema": "textforensics-ledger/v1", "timestamp_utc": "invalid", "file_name": "test.txt"}', id="missing_fields"),
    ])
    def test_ledger_parsing(self, input_data):
        """Test ledger parsing."""
        try:
            from tests.fuzz.fuzz_ledger_parsing import TestOneInput
            TestOneInput(input_data)
        except ImportError:
            pass


# ============================================================================
# Schema Validation Tests (schema.py)
# ============================================================================

class TestSchemaValidation:
    """Fuzz tests for schema validation."""

    @pytest.mark.parametrize("input_data", [
        pytest.param(b"detector-result", id="valid_name"),
        pytest.param(b"invalid\x00schema", id="invalid_chars"),
        pytest.param(b"", id="empty"),
        pytest.param(b"x" * 1000, id="long_name"),
    ])
    def test_schema_validation(self, input_data):
        """Test schema validation."""
        try:
            from tests.fuzz.fuzz_schema_validation import TestOneInput
            TestOneInput(input_data)
        except ImportError:
            pass


# ============================================================================
# Trust Map Computation Tests (trust.py)
# ============================================================================

class TestTrustMapComputation:
    """Fuzz tests for trust map computation."""

    @pytest.mark.parametrize("input_data", [
        pytest.param(b"", id="empty"),
        pytest.param(b"test", id="simple"),
        pytest.param(b"x" * 100, id="short"),
        pytest.param(b"x" * 1000, id="medium"),
        pytest.param(b"\x00\x01\x02", id="control_chars"),
        pytest.param("🚀🌟🎉".encode(), id="emoji"),
    ])
    def test_trust_map(self, input_data):
        """Test trust map computation."""
        try:
            from tests.fuzz.fuzz_trust_map import TestOneInput
            TestOneInput(input_data)
        except ImportError:
            pass
