#!/usr/bin/env python3
"""
Pytest-compatible fuzz test wrappers for CI integration.
These tests exercise fuzz targets with deterministic seed inputs and
report coverage without requiring atheris to be present at test time.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

# ---------------------------------------------------------------------------
# Import fuzz target TestOneInput functions (lazy — graceful skip if missing)
# ---------------------------------------------------------------------------

try:
    from tests.fuzz.fuzz_text_parsing import TestOneInput as TextParsingTest
except ImportError:
    TextParsingTest = None

try:
    from tests.fuzz.fuzz_json_parsing import TestOneInput as JsonParsingTest
except ImportError:
    JsonParsingTest = None

try:
    from tests.fuzz.fuzz_score_boundaries import TestOneInput as ScoreBoundariesTest
except ImportError:
    ScoreBoundariesTest = None

try:
    from tests.fuzz.fuzz_detector_input import TestOneInput as DetectorInputTest
except ImportError:
    DetectorInputTest = None

try:
    from tests.fuzz.fuzz_ledger_parsing import TestOneInput as LedgerParsingTest
except ImportError:
    LedgerParsingTest = None

try:
    from tests.fuzz.fuzz_schema_validation import TestOneInput as SchemaValidationTest
except ImportError:
    SchemaValidationTest = None

try:
    from tests.fuzz.fuzz_trust_map import TestOneInput as TrustMapTest
except ImportError:
    TrustMapTest = None

try:
    from tests.fuzz.fuzz_engine_analysis import TestOneInput as EngineAnalysisTest
except ImportError:
    EngineAnalysisTest = None

try:
    from tests.fuzz.fuzz_api_validation import TestOneInput as ApiValidationTest
except ImportError:
    ApiValidationTest = None

try:
    from tests.fuzz.fuzz_detector_registry import TestOneInput as DetectorRegistryTest
except ImportError:
    DetectorRegistryTest = None

# ---------------------------------------------------------------------------
# Shared test inputs
# ---------------------------------------------------------------------------

COMMON_INPUTS = [
    pytest.param(b"", id="empty"),
    pytest.param(b"test", id="simple"),
    pytest.param(b"x" * 100, id="short"),
    pytest.param(b"x" * 1000, id="medium"),
    pytest.param(b"\x00\x01\x02", id="control_chars"),
    pytest.param("🚀🌟🎉".encode(), id="emoji"),
]

TEXT_INPUTS = COMMON_INPUTS + [
    pytest.param(b"   \t\n   ", id="whitespace"),
    pytest.param(b"x" * 10000, id="long_text"),
    pytest.param(b"A" * 5000, id="substantial"),
    pytest.param(
        b"This is a paragraph. " * 20,
        id="paragraph_text",
    ),
]

JSON_INPUTS = [
    pytest.param(b'{"text": "test"}', id="simple_json"),
    pytest.param(b'{"before": "t1", "after": "t2"}', id="compare"),
    pytest.param(b'{"text": ""}', id="empty_text"),
    pytest.param(b'{"text": "' + b"x" * 5000 + b'"}', id="long_text"),
    pytest.param(b'{"text": "\\x00\\x01"}', id="null_bytes"),
    pytest.param(b'{"nested": {"deep": {"key": "val"}}}', id="nested"),
    pytest.param(b"not json", id="not_json"),
    pytest.param(b"{invalid}", id="malformed"),
    pytest.param('{"text": "🚀🌟"}'.encode(), id="unicode_json"),
]

SCORE_INPUTS = [
    pytest.param(b"", id="empty"),
    pytest.param(b"\x00\x00\x00\x00", id="zero_bytes"),
    pytest.param(b"\xff\xff\xff\xff", id="max_bytes"),
    pytest.param(b"nan", id="nan_text"),
    pytest.param(b"inf", id="inf_text"),
    pytest.param(b"-1.5e10", id="large_negative"),
    pytest.param(b"1e308", id="near_max_float"),
]

# ---------------------------------------------------------------------------
# 1. Text Parsing
# ---------------------------------------------------------------------------


class TestTextParsing:
    """Fuzz tests for text input parsing (UTF-8, null bytes, control chars)."""

    @pytest.mark.parametrize("input_data", TEXT_INPUTS)
    def test_text_parsing(self, input_data: bytes) -> None:
        if TextParsingTest is None:
            pytest.skip("fuzz_text_parsing module not available")
        TextParsingTest(input_data)


# ---------------------------------------------------------------------------
# 2. JSON Parsing
# ---------------------------------------------------------------------------


class TestJsonParsing:
    """Fuzz tests for JSON/YAML config parsing."""

    @pytest.mark.parametrize("input_data", JSON_INPUTS)
    def test_json_parsing(self, input_data: bytes) -> None:
        if JsonParsingTest is None:
            pytest.skip("fuzz_json_parsing module not available")
        JsonParsingTest(input_data)


# ---------------------------------------------------------------------------
# 3. Score Boundaries
# ---------------------------------------------------------------------------


class TestScoreBoundaries:
    """Fuzz tests for score boundary conditions (NaN, infinity, out-of-range)."""

    @pytest.mark.parametrize("input_data", SCORE_INPUTS)
    def test_score_boundaries(self, input_data: bytes) -> None:
        if ScoreBoundariesTest is None:
            pytest.skip("fuzz_score_boundaries module not available")
        ScoreBoundariesTest(input_data)


# ---------------------------------------------------------------------------
# 4. Detector Input
# ---------------------------------------------------------------------------


class TestDetectorInput:
    """Fuzz tests for detector input validation."""

    @pytest.mark.parametrize("input_data", TEXT_INPUTS)
    def test_detector_input(self, input_data: bytes) -> None:
        if DetectorInputTest is None:
            pytest.skip("fuzz_detector_input module not available")
        DetectorInputTest(input_data)


# ---------------------------------------------------------------------------
# 5. Ledger Parsing
# ---------------------------------------------------------------------------


class TestLedgerParsing:
    """Fuzz tests for ledger parsing."""

    @pytest.mark.parametrize(
        "input_data",
        [
            pytest.param(b"", id="empty"),
            pytest.param(b'{"schema": "textforensics-ledger/v1"}', id="minimal"),
            pytest.param(b"not json", id="not_json"),
            pytest.param(
                b'{"schema": "textforensics-ledger/v1", "timestamp_utc": "2024-01-01T00:00:00+00:00", "file_name": "test.txt", "file_size": 100, "file_sha256": "'
                + b"0" * 64
                + b'", "previous_record_sha256": null, "record_sha256": "'
                + b"0" * 64
                + b'"}',
                id="valid_record",
            ),
            pytest.param(b'{"schema": "wrong"}', id="wrong_schema"),
        ],
    )
    def test_ledger_parsing(self, input_data: bytes) -> None:
        if LedgerParsingTest is None:
            pytest.skip("fuzz_ledger_parsing module not available")
        LedgerParsingTest(input_data)


# ---------------------------------------------------------------------------
# 6. Schema Validation
# ---------------------------------------------------------------------------


class TestSchemaValidation:
    """Fuzz tests for schema validation."""

    @pytest.mark.parametrize(
        "input_data",
        [
            pytest.param(b"detector-result", id="valid_name"),
            pytest.param(b"invalid\x00schema", id="invalid_chars"),
            pytest.param(b"", id="empty"),
            pytest.param(b'{"schema": "unknown/v1"}', id="unknown_schema"),
        ],
    )
    def test_schema_validation(self, input_data: bytes) -> None:
        if SchemaValidationTest is None:
            pytest.skip("fuzz_schema_validation module not available")
        SchemaValidationTest(input_data)


# ---------------------------------------------------------------------------
# 7. Trust Map
# ---------------------------------------------------------------------------


class TestTrustMap:
    """Fuzz tests for trust map computation."""

    @pytest.mark.parametrize("input_data", COMMON_INPUTS)
    def test_trust_map(self, input_data: bytes) -> None:
        if TrustMapTest is None:
            pytest.skip("fuzz_trust_map module not available")
        TrustMapTest(input_data)


# ---------------------------------------------------------------------------
# 8. Engine Analysis
# ---------------------------------------------------------------------------


class TestEngineAnalysis:
    """Fuzz tests for engine analysis functions."""

    @pytest.mark.parametrize("input_data", TEXT_INPUTS)
    def test_engine_analysis(self, input_data: bytes) -> None:
        if EngineAnalysisTest is None:
            pytest.skip("fuzz_engine_analysis module not available")
        EngineAnalysisTest(input_data)


# ---------------------------------------------------------------------------
# 9. API Validation
# ---------------------------------------------------------------------------


class TestApiValidation:
    """Fuzz tests for API validation middleware."""

    @pytest.mark.parametrize(
        "input_data",
        COMMON_INPUTS
        + [
            pytest.param(b'{"text": "test"}', id="json_request"),
            pytest.param(b'{"text": "' + b"x" * 5000 + b"}", id="oversized_json"),
        ],
    )
    def test_api_validation(self, input_data: bytes) -> None:
        if ApiValidationTest is None:
            pytest.skip("fuzz_api_validation module not available")
        ApiValidationTest(input_data)


# ---------------------------------------------------------------------------
# 10. Detector Registry
# ---------------------------------------------------------------------------


class TestDetectorRegistry:
    """Fuzz tests for detector registry and plugin discovery."""

    @pytest.mark.parametrize(
        "input_data",
        COMMON_INPUTS
        + [
            pytest.param(b"textforensics/builtin-heuristic", id="builtin_id"),
            pytest.param((b"a" * 200), id="long_id"),
        ],
    )
    def test_detector_registry(self, input_data: bytes) -> None:
        if DetectorRegistryTest is None:
            pytest.skip("fuzz_detector_registry module not available")
        DetectorRegistryTest(input_data)
