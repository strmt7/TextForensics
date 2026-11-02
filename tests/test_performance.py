"""Performance regression tests using pytest-benchmark.

These tests measure and track performance of core operations:
- scan operation with various text sizes (100, 1000, 10000 words)
- report generation
- case file creation
- detector execution

Run with: pytest tests/test_performance.py --benchmark-only --benchmark-min-rounds=5

For regression detection, use --benchmark-compare to compare against a baseline:
pytest tests/test_performance.py --benchmark-only --benchmark-min-rounds=5 --benchmark-compare=baseline.json
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from textforensics.casefile import write_case_file
from textforensics.detectors import BuiltinHeuristicDetector, execute_detector
from textforensics.engine import analyze_text
from textforensics.report import build_forensic_bundle

# Deterministic, locale-neutral sample text for benchmarks
_SENTENCE = (
    "The technician recorded the voltage at each junction and noted "
    "which probes had drifted since the previous calibration run. "
)
_WORDS_PER_SENTENCE = len(_SENTENCE.split())


def make_text(words: int) -> str:
    """Return deterministic sample text with approximately `words` words."""
    sentences = max(1, (words + _WORDS_PER_SENTENCE - 1) // _WORDS_PER_SENTENCE)
    return " ".join([_SENTENCE] * sentences)


# Text sizes to benchmark (word counts)
TEXT_SIZES = [100, 1000, 10000]


@pytest.fixture(params=TEXT_SIZES, ids=lambda w: f"{w}_words")
def benchmark_text(request):
    """Fixture providing text samples of different sizes."""
    return make_text(request.param)


@pytest.fixture
def temp_dir():
    """Fixture providing a temporary directory for file operations."""
    with tempfile.TemporaryDirectory(prefix="textforensics-perf-") as tmp:
        yield Path(tmp)


class TestScanPerformance:
    """Benchmark the scan operation (analyze_text) with various text sizes."""

    def test_scan_100_words(self, benchmark):
        """Benchmark scan with ~100 words."""
        text = make_text(100)
        benchmark(analyze_text, text)

    def test_scan_1000_words(self, benchmark):
        """Benchmark scan with ~1000 words."""
        text = make_text(1000)
        benchmark(analyze_text, text)

    def test_scan_10000_words(self, benchmark):
        """Benchmark scan with ~10000 words."""
        text = make_text(10000)
        benchmark(analyze_text, text)


class TestReportPerformance:
    """Benchmark report generation (build_forensic_bundle)."""

    def test_report_100_words(self, benchmark):
        """Benchmark report generation with ~100 words."""
        text = make_text(100)
        benchmark(build_forensic_bundle, text)

    def test_report_1000_words(self, benchmark):
        """Benchmark report generation with ~1000 words."""
        text = make_text(1000)
        benchmark(build_forensic_bundle, text)

    def test_report_10000_words(self, benchmark):
        """Benchmark report generation with ~10000 words."""
        text = make_text(10000)
        benchmark(build_forensic_bundle, text)


class TestCaseFilePerformance:
    """Benchmark case file creation."""

    def test_case_export_100_words(self, benchmark, temp_dir):
        """Benchmark case file export with ~100 words."""
        text = make_text(100)

        def run():
            bundle = build_forensic_bundle(text)
            output_path = temp_dir / "case-100.json"
            write_case_file(output_path, bundle.to_dict())

        benchmark(run)

    def test_case_export_1000_words(self, benchmark, temp_dir):
        """Benchmark case file export with ~1000 words."""
        text = make_text(1000)

        def run():
            bundle = build_forensic_bundle(text)
            output_path = temp_dir / "case-1000.json"
            write_case_file(output_path, bundle.to_dict())

        benchmark(run)

    def test_case_export_10000_words(self, benchmark, temp_dir):
        """Benchmark case file export with ~10000 words."""
        text = make_text(10000)

        def run():
            bundle = build_forensic_bundle(text)
            output_path = temp_dir / "case-10000.json"
            write_case_file(output_path, bundle.to_dict())

        benchmark(run)


class TestDetectorExecutionPerformance:
    """Benchmark detector execution directly."""

    def test_detector_100_words(self, benchmark):
        """Benchmark BuiltinHeuristicDetector with ~100 words."""
        text = make_text(100)
        detector = BuiltinHeuristicDetector()

        def run():
            prediction, failure = execute_detector(detector, text)
            if failure is not None:
                raise RuntimeError(f"Detector execution failed: {failure.error_type}")

        benchmark(run)

    def test_detector_1000_words(self, benchmark):
        """Benchmark BuiltinHeuristicDetector with ~1000 words."""
        text = make_text(1000)
        detector = BuiltinHeuristicDetector()

        def run():
            prediction, failure = execute_detector(detector, text)
            if failure is not None:
                raise RuntimeError(f"Detector execution failed: {failure.error_type}")

        benchmark(run)

    def test_detector_10000_words(self, benchmark):
        """Benchmark BuiltinHeuristicDetector with ~10000 words."""
        text = make_text(10000)
        detector = BuiltinHeuristicDetector()

        def run():
            prediction, failure = execute_detector(detector, text)
            if failure is not None:
                raise RuntimeError(f"Detector execution failed: {failure.error_type}")

        benchmark(run)


# Performance regression thresholds (20% slower than baseline fails)
# These are defined as environment variables or can be configured via pytest.ini
# Format: TEST_NAME: max_ratio (e.g., 1.20 means 20% slower is failure)
#
# Example usage:
# pytest tests/test_performance.py --benchmark-only --benchmark-min-rounds=5
#   --benchmark-compare=performance_baseline.json --benchmark-compare-fail=mean:1.20
#
# Or set in pytest.ini:
# [pytest]
# benchmark_compare_fail = mean:1.20
# benchmark_compare = performance_baseline.json
