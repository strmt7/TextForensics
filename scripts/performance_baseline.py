#!/usr/bin/env python
"""Performance baseline management for TextForensics.

This script helps create, update, and compare performance baselines.

Usage:
    python scripts/performance_baseline.py create --output performance_baseline.json
    python scripts/performance_baseline.py compare --baseline performance_baseline.json --current pytest-performance.json
    python scripts/performance_baseline.py update --baseline performance_baseline.json --current pytest-performance.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    """Load JSON file."""
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path, data: dict[str, Any]) -> None:
    """Save JSON file with pretty formatting."""
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def create_baseline(*, output: Path) -> int:
    """Create a new performance baseline from current pytest-benchmark results."""
    # Run pytest-benchmark and capture output
    import subprocess

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/test_performance.py",
            "--benchmark-only",
            "--benchmark-min-rounds=5",
            "--benchmark-json=-",  # Output to stdout
            "-q",
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print(f"Failed to run benchmarks: {result.stderr}", file=sys.stderr)
        return 1

    try:
        benchmark_data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"Failed to parse benchmark output: {e}", file=sys.stderr)
        print(f"stdout: {result.stdout[:500]}", file=sys.stderr)
        return 1

    # Save baseline
    save_json(output, benchmark_data)
    print(f"Created baseline: {output}")
    print(f"  Benchmarks: {len(benchmark_data.get('benchmarks', {}))}")
    return 0


def compare_baselines(*, baseline: Path, current: Path, threshold: float = 1.20) -> int:
    """Compare current results against baseline.

    Comparison is REQUIRED when this function is called: it fails
    (nonzero exit, explicit error) on a missing baseline file, on zero
    overlapping benchmark names, on a baseline benchmark missing from
    the current results (renamed/dropped), and on a missing mean in
    either file. It never reports "No significant changes detected"
    unless at least one benchmark was actually compared. The printed
    "Total benchmarks compared" is the matched (shared-name) count.
    """
    try:
        baseline_data = load_json(baseline)
    except FileNotFoundError:
        print(f"error: baseline file not found: {baseline}", file=sys.stderr)
        print(
            "error: baseline download failed or was never produced; "
            "comparison is required and cannot proceed",
            file=sys.stderr,
        )
        return 1
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read baseline file {baseline}: {exc}", file=sys.stderr)
        return 1
    try:
        current_data = load_json(current)
    except FileNotFoundError:
        print(f"error: current results file not found: {current}", file=sys.stderr)
        return 1
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read current results file {current}: {exc}", file=sys.stderr)
        return 1

    baseline_benchmarks = {b["name"]: b for b in baseline_data.get("benchmarks", [])}
    current_benchmarks = {b["name"]: b for b in current_data.get("benchmarks", [])}

    if not baseline_benchmarks:
        print("error: no benchmarks in baseline", file=sys.stderr)
        return 1

    if not current_benchmarks:
        print("error: no benchmarks in current results", file=sys.stderr)
        return 1

    # Matched workload identities are required: a baseline benchmark
    # that is absent from the current results is a missing/renamed
    # result, not a skipped comparison.
    shared_names = sorted(set(baseline_benchmarks) & set(current_benchmarks))
    missing_names = sorted(set(baseline_benchmarks) - set(current_benchmarks))
    extra_names = sorted(set(current_benchmarks) - set(baseline_benchmarks))
    if missing_names:
        for name in missing_names:
            print(
                f"error: benchmark '{name}' is in the baseline but missing "
                "from the current results (renamed or dropped?)",
                file=sys.stderr,
            )
    if extra_names:
        for name in extra_names:
            print(
                f"warning: benchmark '{name}' is in the current results "
                "but not in the baseline (new workload; not compared)",
            )
    if not shared_names:
        print(
            "error: zero overlapping benchmarks between baseline and "
            f"current results ({len(baseline_benchmarks)} baseline vs "
            f"{len(current_benchmarks)} current, 0 shared names); "
            "comparison is required and cannot report 'no significant changes'",
            file=sys.stderr,
        )
        return 1
    if missing_names:
        print(
            "error: comparison is incomplete — "
            f"{len(missing_names)} baseline benchmark(s) have no current "
            "result; failing rather than reporting on a partial overlap",
            file=sys.stderr,
        )
        return 1

    regressions = []
    improvements = []
    compared = 0

    for name in shared_names:
        base_stats = baseline_benchmarks[name].get("stats", {})
        curr_stats = current_benchmarks[name].get("stats", {})

        base_mean = base_stats.get("mean")
        curr_mean = curr_stats.get("mean")

        if base_mean is None or curr_mean is None:
            print(
                f"error: missing mean for '{name}' "
                f"(baseline mean={base_mean!r}, current mean={curr_mean!r}); "
                "a benchmark without a mean cannot be compared",
                file=sys.stderr,
            )
            return 1
        if base_mean == 0:
            print(
                f"error: baseline mean is 0 for '{name}'; "
                "a ratio against a zero baseline is undefined",
                file=sys.stderr,
            )
            return 1

        compared += 1
        ratio = curr_mean / base_mean
        pct_change = (ratio - 1) * 100

        if ratio > threshold:
            regressions.append((name, ratio, pct_change))
        elif ratio < 1 / threshold:
            improvements.append((name, ratio, pct_change))

    print(f"Comparison (threshold: {threshold:.2f}x = {threshold * 100 - 100:.0f}% slower)")
    print(f"  Baseline: {baseline}")
    print(f"  Current:  {current}")
    print(f"  Total benchmarks compared: {compared}")
    print()

    if regressions:
        print("REGRESSIONS (>20% slower):")
        for name, ratio, pct in regressions:
            print(f"  {name}: {pct:+.1f}% (ratio: {ratio:.3f})")
        print()

    if improvements:
        print("IMPROVEMENTS (>20% faster):")
        for name, ratio, pct in improvements:
            print(f"  {name}: {pct:+.1f}% (ratio: {ratio:.3f})")
        print()

    if not regressions and not improvements:
        print("No significant changes detected.")
        print()

    if regressions:
        print("::error::Performance regression detected!")
        return 1

    return 0


def resolve_baseline_requirement(
    *, event_name: str, baseline_ref_input: str | None
) -> tuple[str, str]:
    """Decide whether baseline comparison is required for a workflow event.

    Returns (status, baseline_ref) where status is one of the shared
    gate vocabulary values ``required`` / ``skipped``:

    - ``push`` / ``schedule``: comparison is REQUIRED; the baseline ref
      defaults to ``main`` (an immutable baseline artifact is resolved
      from the latest successful benchmark run on that ref).
    - ``workflow_dispatch`` with a non-empty ``baseline-ref`` input:
      comparison is REQUIRED against that ref.
    - ``workflow_dispatch`` with an explicitly empty ``baseline-ref``
      input: comparison is ``skipped`` (explicit opt-out, with reason) —
      never a pass. Any other event with an empty input is ``required``
      against ``main``.

    The workflow's compare step mirrors this decision table; the
    structural tests in tests/test_performance_baseline.py assert the
    two agree. ``baseline_ref_input=None`` means the event carries no
    ``baseline-ref`` input (push/schedule).
    """
    ref = (baseline_ref_input or "").strip()
    if event_name == "workflow_dispatch" and baseline_ref_input == "":
        return ("skipped", "")
    if ref:
        return ("required", ref)
    return ("required", "main")


def update_baseline(*, baseline: Path, current: Path) -> int:
    """Update baseline with current results."""
    current_data = load_json(current)
    save_json(baseline, current_data)
    print(f"Updated baseline: {baseline}")
    print(f"  Benchmarks: {len(current_data.get('benchmarks', {}))}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Manage performance baselines for TextForensics",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Create command
    create_parser = subparsers.add_parser("create", help="Create new baseline")
    create_parser.add_argument(
        "--output",
        type=Path,
        default=Path("performance_baseline.json"),
        help="Output baseline file (default: performance_baseline.json)",
    )

    # Compare command
    compare_parser = subparsers.add_parser("compare", help="Compare against baseline")
    compare_parser.add_argument(
        "--baseline",
        type=Path,
        required=True,
        help="Baseline JSON file",
    )
    compare_parser.add_argument(
        "--current",
        type=Path,
        required=True,
        help="Current benchmark JSON file",
    )
    compare_parser.add_argument(
        "--threshold",
        type=float,
        default=1.20,
        help="Regression threshold as ratio (default: 1.20 = 20% slower)",
    )

    # Update command
    update_parser = subparsers.add_parser("update", help="Update baseline with current results")
    update_parser.add_argument(
        "--baseline",
        type=Path,
        required=True,
        help="Baseline JSON file to update",
    )
    update_parser.add_argument(
        "--current",
        type=Path,
        required=True,
        help="Current benchmark JSON file",
    )

    args = parser.parse_args(argv)

    if args.command == "create":
        return create_baseline(output=args.output)
    elif args.command == "compare":
        return compare_baselines(
            baseline=args.baseline,
            current=args.current,
            threshold=args.threshold,
        )
    elif args.command == "update":
        return update_baseline(baseline=args.baseline, current=args.current)

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
