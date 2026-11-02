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
    """Compare current results against baseline."""
    baseline_data = load_json(baseline)
    current_data = load_json(current)

    baseline_benchmarks = {b["name"]: b for b in baseline_data.get("benchmarks", [])}
    current_benchmarks = {b["name"]: b for b in current_data.get("benchmarks", [])}

    if not baseline_benchmarks:
        print("No benchmarks in baseline", file=sys.stderr)
        return 1

    if not current_benchmarks:
        print("No benchmarks in current results", file=sys.stderr)
        return 1

    regressions = []
    improvements = []

    for name in baseline_benchmarks:
        if name not in current_benchmarks:
            print(f"Warning: Benchmark '{name}' not found in current results")
            continue

        base_stats = baseline_benchmarks[name].get("stats", {})
        curr_stats = current_benchmarks[name].get("stats", {})

        base_mean = base_stats.get("mean")
        curr_mean = curr_stats.get("mean")

        if base_mean is None or curr_mean is None:
            print(f"Warning: Missing mean for '{name}'")
            continue

        ratio = curr_mean / base_mean
        pct_change = (ratio - 1) * 100

        if ratio > threshold:
            regressions.append((name, ratio, pct_change))
        elif ratio < 1 / threshold:
            improvements.append((name, ratio, pct_change))

    print(f"Comparison (threshold: {threshold:.2f}x = {threshold * 100 - 100:.0f}% slower)")
    print(f"  Baseline: {baseline}")
    print(f"  Current:  {current}")
    print(f"  Total benchmarks compared: {len(baseline_benchmarks)}")
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