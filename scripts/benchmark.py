"""Standalone performance benchmark for TextForensics.

Measures wall-clock time (timeit) and, optionally, peak memory usage
(memory_profiler) for the main user-facing operations:

- CLI ``scan`` command
- CLI ``report`` command
- CLI ``case export`` command
- Detector execution (BuiltinHeuristicDetector)
- API endpoint response time (when the optional API extras are installed)

Output is a JSON document so results can be archived, compared across
commits, and uploaded as workflow artifacts.

Usage:
    python scripts/benchmark.py
    python scripts/benchmark.py --iterations 10 --measure-memory
    python scripts/benchmark.py --output results.json --words 1000
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import statistics
import sys
import timeit
import tracemalloc
from collections.abc import Callable
from pathlib import Path
from typing import Any

# Allow running from a source checkout without installation.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from textforensics.cli import _run, build_parser  # noqa: E402
from textforensics.config import Settings  # noqa: E402
from textforensics.detectors import BuiltinHeuristicDetector  # noqa: E402

try:
    from fastapi.testclient import TestClient  # type: ignore[import-not-found]

    HAS_API = True
except ImportError:  # pragma: no cover - optional dependency
    HAS_API = False

try:
    import memory_profiler  # type: ignore[import-not-found] # noqa: F401

    HAS_MEMORY_PROFILER = True
except ImportError:  # pragma: no cover - optional dependency
    HAS_MEMORY_PROFILER = False


BENCHMARK_SCHEMA = "textforensics.performance-benchmark/v1"

# Deterministic, locale-neutral sample text. Repeated to reach the
# requested word count so timing scales predictably with input size.
_SENTENCE = (
    "The technician recorded the voltage at each junction and noted "
    "which probes had drifted since the previous calibration run. "
)
_WORDS_PER_SENTENCE = len(_SENTENCE.split())


def make_text(words: int) -> str:
    """Return deterministic sample text with approximately `words` words."""
    sentences = max(1, (words + _WORDS_PER_SENTENCE - 1) // _WORDS_PER_SENTENCE)
    return " ".join([_SENTENCE] * sentences)


def time_callable(
    func: Callable[[], Any],
    *,
    repeat: int,
) -> dict[str, Any]:
    """Time `func` with `repeat` runs and return summary statistics.

    stdout is captured during timed runs so CLI output (scan/report JSON,
    case-file paths) does not flood the console; stderr is untouched.
    """
    samples: list[float] = []
    for _ in range(repeat):
        started = timeit.default_timer()
        with contextlib.redirect_stdout(io.StringIO()):
            func()
        samples.append(timeit.default_timer() - started)
    best = min(samples)
    return {
        "samples_seconds": [round(s, 6) for s in samples],
        "best_seconds": round(best, 6),
        "median_seconds": round(statistics.median(samples), 6),
        "mean_seconds": round(statistics.fmean(samples), 6),
        "max_seconds": round(max(samples), 6),
        "stdev_seconds": (
            round(statistics.stdev(samples), 6) if len(samples) > 1 else 0.0
        ),
        "repeat": repeat,
    }


def measure_peak_memory(func: Callable[[], Any]) -> dict[str, Any]:
    """Measure peak traced memory while running `func` once.

    stdout is captured so CLI output does not pollute the console.
    """
    tracemalloc.start()
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            func()
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return {
        "peak_bytes": peak,
        "peak_mib": round(peak / (1024 * 1024), 3),
        "method": "tracemalloc",
        "note": (
            "tracemalloc measures Python allocations made after tracing "
            "started; use memory_profiler for process-level RSS profiling."
        ),
    }


def benchmark_memory_profiler_peak(
    func: Callable[[], Any],
) -> dict[str, Any] | None:
    """Return process-level peak RSS delta via memory_profiler, if available."""
    if not HAS_MEMORY_PROFILER:
        return None
    from contextlib import redirect_stdout

    from memory_profiler import memory_usage

    buffer = io.StringIO()
    with redirect_stdout(buffer):
        usage = memory_usage(
            (func, (), {}),
            interval=0.05,
            timeout=None,
            max_usage=True,
        )
    peak = float(usage) if usage is not None else 0.0
    return {
        "peak_mib": round(peak, 3),
        "method": "memory_profiler.memory_usage",
    }


# ---------------------------------------------------------------------------
# Benchmark targets
# ---------------------------------------------------------------------------


def bench_cli_scan(text: str, tmp_dir: Path) -> Callable[[], Any]:
    """CLI `scan` command with JSON output, run in-process."""
    input_path = tmp_dir / "scan-input.txt"
    input_path.write_text(text, encoding="utf-8")

    def run() -> None:
        parser = build_parser()
        args = parser.parse_args(["scan", "--file", str(input_path), "--json"])
        _run(args, Settings.from_env())

    return run


def bench_cli_report(text: str, tmp_dir: Path) -> Callable[[], Any]:
    """CLI `report` command, run in-process."""
    input_path = tmp_dir / "report-input.txt"
    input_path.write_text(text, encoding="utf-8")

    def run() -> None:
        parser = build_parser()
        args = parser.parse_args(["report", "--file", str(input_path)])
        _run(args, Settings.from_env())

    return run


def bench_case_export(text: str, tmp_dir: Path) -> Callable[[], Any]:
    """CLI `case export` command, run in-process."""
    input_path = tmp_dir / "case-input.txt"
    output_path = tmp_dir / "case-output.json"
    input_path.write_text(text, encoding="utf-8")

    def run() -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "case",
                "export",
                "--file",
                str(input_path),
                "--output",
                str(output_path),
            ]
        )
        _run(args, Settings.from_env())

    return run


def bench_detector_execution(text: str) -> Callable[[], Any]:
    """Direct detector adapter execution (BuiltinHeuristicDetector)."""
    detector = BuiltinHeuristicDetector()

    def run() -> None:
        from textforensics.detectors import execute_detector

        prediction, failure = execute_detector(detector, text)
        if failure is not None:
            raise RuntimeError(f"Detector execution failed: {failure.error_type}")

    return run


def bench_api_endpoint(text: str) -> tuple[Callable[[], Any], dict[str, Any]] | None:
    """API endpoint response time via FastAPI TestClient (in-process)."""
    if not HAS_API:
        return None

    from textforensics.api import create_app

    app = create_app(
        Settings(
            host="127.0.0.1",
            port=8765,
            max_input_bytes=2_000_000,
            allow_remote=False,
            access_log=False,
            log_level="INFO",
        )
    )
    client = TestClient(app)
    payload = {"text": text}

    def run() -> None:
        response = client.post("/v1/analyze", json=payload)
        if response.status_code != 200:
            raise RuntimeError(f"API /v1/analyze returned {response.status_code}")

    return run, {"endpoint": "/v1/analyze", "method": "POST"}


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def run_benchmarks(
    *,
    words: int,
    repeat: int,
    measure_memory: bool,
    include_api: bool,
) -> dict[str, Any]:
    import tempfile

    text = make_text(words)
    results: dict[str, Any] = {
        "schema": BENCHMARK_SCHEMA,
        "input_words": words,
        "input_bytes": len(text.encode("utf-8")),
        "repeat": repeat,
        "measure_memory": measure_memory,
        "benchmarks": {},
    }

    with tempfile.TemporaryDirectory(prefix="textforensics-bench-") as tmp:
        tmp_dir = Path(tmp)

        targets: dict[str, Callable[[], Any]] = {
            "cli_scan": bench_cli_scan(text, tmp_dir),
            "cli_report": bench_cli_report(text, tmp_dir),
            "case_export": bench_case_export(text, tmp_dir),
            "detector_execution": bench_detector_execution(text),
        }

        api_bench = bench_api_endpoint(text) if include_api else None
        if api_bench is not None:
            targets["api_endpoint"] = api_bench[0]
            results["api_metadata"] = api_bench[1]

        for name, func in targets.items():
            timing = time_callable(func, repeat=repeat)
            entry: dict[str, Any] = {"timing": timing}

            if measure_memory:
                entry["memory"] = measure_peak_memory(func)
                mp_peak = benchmark_memory_profiler_peak(func)
                if mp_peak is not None:
                    entry["memory"]["memory_profiler"] = mp_peak

            results["benchmarks"][name] = entry

    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Measure TextForensics performance and emit JSON.",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=5,
        help="Number of timing repetitions per benchmark (default: 5).",
    )
    parser.add_argument(
        "--words",
        type=int,
        default=1000,
        help="Approximate word count of the sample text (default: 1000).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write JSON results here; also printed to stdout.",
    )
    parser.add_argument(
        "--measure-memory",
        action="store_true",
        help="Also report peak memory (tracemalloc; memory_profiler when installed).",
    )
    parser.add_argument(
        "--skip-api",
        action="store_true",
        help="Skip the API endpoint benchmark even when API extras are installed.",
    )
    args = parser.parse_args(argv)

    if args.iterations < 1:
        parser.error("--iterations must be at least 1.")
    if args.words < 1:
        parser.error("--words must be at least 1.")

    results = run_benchmarks(
        words=args.words,
        repeat=args.iterations,
        measure_memory=args.measure_memory,
        include_api=not args.skip_api,
    )
    results["benchmark_script_version"] = "1.0.0"

    try:
        from textforensics.version import get_version

        results["textforensics_version"] = get_version()
    except Exception:  # pragma: no cover - informational only
        results["textforensics_version"] = None

    rendered = json.dumps(results, indent=2, ensure_ascii=False)
    print(rendered)

    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
