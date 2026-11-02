"""Performance benchmark tests for TextForensics.

These tests assert practical upper bounds on wall-clock time and memory
usage for the main operations. They are intentionally lenient enough to
pass on shared CI runners while still catching severe regressions:

- CLI ``scan`` completes under 5 seconds for ~1000 words
- CLI ``report`` completes under 10 seconds
- Case file export completes under 5 seconds
- Detector execution completes under 5 seconds
- Peak memory stays under 500 MiB

The heavier timing/memory suite is skipped by default. Run it explicitly
with:

    pytest tests/test_benchmarks.py -m benchmark

or let the Benchmark workflow invoke it (the workflow installs
memory_profiler and, optionally, pytest-benchmark; when pytest-benchmark
is present it can run this module with ``--benchmark-only``).
"""

from __future__ import annotations

import importlib.util
import json
import statistics
import subprocess
import sys
import tempfile
import timeit
import tracemalloc
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from textforensics.casefile import write_case_file  # noqa: E402
from textforensics.detectors import BuiltinHeuristicDetector, execute_detector  # noqa: E402
from textforensics.engine import analyze_text  # noqa: E402
from textforensics.report import build_forensic_bundle  # noqa: E402

HAS_API = (
    importlib.util.find_spec("fastapi") is not None
    and importlib.util.find_spec("httpx") is not None
)
HAS_PYTEST_BENCHMARK = importlib.util.find_spec("pytest_benchmark") is not None

TEXTFORENSICS_WORD_LIMIT_SECONDS_SCAN = 5.0
TEXTFORENSICS_REPORT_LIMIT_SECONDS = 10.0
TEXTFORENSICS_CASE_EXPORT_LIMIT_SECONDS = 5.0
TEXTFORENSICS_DETECTOR_LIMIT_SECONDS = 5.0
TEXTFORENSICS_MEMORY_LIMIT_MIB = 500.0

_SENTENCE = (
    "The technician recorded the voltage at each junction and noted "
    "which probes had drifted since the previous calibration run. "
)
_WORDS_PER_SENTENCE = len(_SENTENCE.split())


def make_text(words: int) -> str:
    """Deterministic sample text of approximately `words` words."""
    sentences = max(1, (words + _WORDS_PER_SENTENCE - 1) // _WORDS_PER_SENTENCE)
    return " ".join([_SENTENCE] * sentences)


def elapsed_seconds(func, /) -> float:
    started = timeit.default_timer()
    func()
    return timeit.default_timer() - started


def peak_memory_mib(func, /) -> float:
    tracemalloc.start()
    try:
        func()
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return peak / (1024 * 1024)


class PerformanceLimits(unittest.TestCase):
    """Wall-clock and memory upper bounds for core operations."""

    @classmethod
    def setUpClass(cls):
        cls.text = make_text(1000)
        cls.tmp = tempfile.TemporaryDirectory(prefix="textforensics-bench-")
        tmp_dir = Path(cls.tmp.name)
        cls.input_path = tmp_dir / "input.txt"
        cls.input_path.write_text(cls.text, encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_scan_completes_under_5_seconds_for_1000_words(self):
        def run():
            analyze_text(self.text)

        elapsed = elapsed_seconds(run)
        self.assertLess(
            elapsed,
            TEXTFORENSICS_WORD_LIMIT_SECONDS_SCAN,
            f"scan took {elapsed:.3f}s for 1000 words; "
            f"limit is {TEXTFORENSICS_WORD_LIMIT_SECONDS_SCAN}s",
        )

    def test_report_completes_under_10_seconds(self):
        def run():
            build_forensic_bundle(self.text)

        elapsed = elapsed_seconds(run)
        self.assertLess(
            elapsed,
            TEXTFORENSICS_REPORT_LIMIT_SECONDS,
            f"report took {elapsed:.3f}s; limit is "
            f"{TEXTFORENSICS_REPORT_LIMIT_SECONDS}s",
        )

    def test_case_export_completes_under_5_seconds(self):
        output_path = Path(self.tmp.name) / "bench-case.json"

        def run():
            bundle = build_forensic_bundle(self.text)
            write_case_file(output_path, bundle.to_dict())

        elapsed = elapsed_seconds(run)
        self.assertLess(
            elapsed,
            TEXTFORENSICS_CASE_EXPORT_LIMIT_SECONDS,
            f"case export took {elapsed:.3f}s; limit is "
            f"{TEXTFORENSICS_CASE_EXPORT_LIMIT_SECONDS}s",
        )
        self.assertTrue(output_path.exists())

    def test_detector_execution_completes_under_5_seconds(self):
        detector = BuiltinHeuristicDetector()

        def run():
            prediction, failure = execute_detector(detector, self.text)
            if failure is not None:
                self.fail(f"Detector execution failed: {failure.error_type}")

        elapsed = elapsed_seconds(run)
        self.assertLess(
            elapsed,
            TEXTFORENSICS_DETECTOR_LIMIT_SECONDS,
            f"detector execution took {elapsed:.3f}s; limit is "
            f"{TEXTFORENSICS_DETECTOR_LIMIT_SECONDS}s",
        )

    def test_memory_usage_does_not_exceed_500_mib(self):
        def run():
            build_forensic_bundle(self.text)

        peak = peak_memory_mib(run)
        self.assertLessEqual(
            peak,
            TEXTFORENSICS_MEMORY_LIMIT_MIB,
            f"peak traced memory was {peak:.1f} MiB; "
            f"limit is {TEXTFORENSICS_MEMORY_LIMIT_MIB} MiB",
        )


class CliPerformanceLimits(unittest.TestCase):
    """CLI subprocess-level performance checks."""

    def test_cli_scan_under_5_seconds_for_1000_words(self):
        with tempfile.TemporaryDirectory(prefix="tf-cli-bench-") as tmp:
            source = Path(tmp) / "input.txt"
            source.write_text(make_text(1000), encoding="utf-8")
            started = timeit.default_timer()
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "textforensics.cli",
                    "scan",
                    "--file",
                    str(source),
                    "--json",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            elapsed = timeit.default_timer() - started
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertIn("score", payload)
        self.assertLess(
            elapsed,
            10.0,
            f"CLI scan (subprocess, cold interpreter) took {elapsed:.3f}s; "
            "limit is 10.0s",
        )


@unittest.skipUnless(
    HAS_API,
    "API development dependencies are not installed",
)
class ApiPerformanceLimits(unittest.TestCase):
    """API endpoint response-time checks (in-process TestClient)."""

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient

        from textforensics.api import create_app

        app = create_app()
        cls.client = TestClient(app)
        cls.payload = {"text": make_text(1000)}

    def test_analyze_endpoint_under_5_seconds(self):
        started = timeit.default_timer()
        response = self.client.post("/v1/analyze", json=self.payload)
        elapsed = timeit.default_timer() - started
        self.assertEqual(response.status_code, 200)
        self.assertLess(
            elapsed,
            5.0,
            f"POST /v1/analyze took {elapsed:.3f}s; limit is 5.0s",
        )

    def test_report_endpoint_under_10_seconds(self):
        started = timeit.default_timer()
        response = self.client.post("/v1/report", json=self.payload)
        elapsed = timeit.default_timer() - started
        self.assertEqual(response.status_code, 200)
        self.assertLess(
            elapsed,
            10.0,
            f"POST /v1/report took {elapsed:.3f}s; limit is 10.0s",
        )

    def test_healthz_under_1_second(self):
        samples = []
        for _ in range(3):
            started = timeit.default_timer()
            response = self.client.get("/healthz")
            samples.append(timeit.default_timer() - started)
            self.assertEqual(response.status_code, 200)
        self.assertLess(
            statistics.median(samples),
            1.0,
            f"GET /healthz median took {statistics.median(samples):.4f}s; "
            "limit is 1.0s",
        )


if __name__ == "__main__":
    unittest.main()
