#!/usr/bin/env python
"""Performance baseline management for TextForensics.

This script helps create, update, and compare performance baselines.

Usage:
    python scripts/performance_baseline.py create --output performance_baseline.json
    python scripts/performance_baseline.py stamp --results pytest-performance.json
    python scripts/performance_baseline.py compare --baseline performance_baseline.json --current pytest-performance.json
    python scripts/performance_baseline.py update --baseline performance_baseline.json --current pytest-performance.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent


def _git_head_sha(*, repo_root: Path) -> str | None:
    """Best-effort HEAD SHA of the checkout; None outside a git tree."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    sha = result.stdout.strip()
    return sha or None


def _sha256_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def build_environment_identity(
    *, repo_root: Path | None = None, lockfile: Path | None = None
) -> dict[str, Any]:
    """Identity a benchmark run must carry to be comparable later.

    - ``code_sha``: the git HEAD the run measured (AGENTS.md benchmark
      discipline: every run captures its git SHA).
    - ``python_version``: the interpreter the run measured on.
    - ``lockfile`` / ``lockfile_sha256``: the pinned dependency lock
      the run measured against (``requirements-hashed.txt`` by
      default). A run whose lockfile cannot be hashed records None
      and is incomparable until the lockfile is present.
    """
    root = repo_root or REPO_ROOT
    lock = lockfile or (root / "requirements-hashed.txt")
    return {
        "code_sha": _git_head_sha(repo_root=root),
        "python_version": ".".join(str(v) for v in sys.version_info[:3]),
        "platform": sys.platform,
        "lockfile": lock.name,
        "lockfile_sha256": _sha256_file(lock),
    }


def extract_identity(data: dict[str, Any]) -> dict[str, Any]:
    """Read a benchmark document's identity, from either shape.

    The stamped ``environment`` block (written by `stamp`) wins; a
    raw pytest-benchmark document's native ``machine_info`` /
    ``commit_info`` fields are honoured too. Only present fields are
    returned: a missing field means that identity fact is unknown,
    never a default.
    """
    identity: dict[str, Any] = {}
    env = data.get("environment")
    if isinstance(env, dict):
        for key in ("code_sha", "python_version", "lockfile", "lockfile_sha256", "platform"):
            if env.get(key) is not None:
                identity[key] = env[key]
    commit_info = data.get("commit_info")
    if isinstance(commit_info, dict) and commit_info.get("id"):
        identity.setdefault("code_sha", commit_info["id"])
    machine_info = data.get("machine_info")
    if isinstance(machine_info, dict) and machine_info.get("python_version"):
        identity.setdefault("python_version", machine_info["python_version"])
    return identity


def stamp_identity(
    *, results: Path, repo_root: Path | None = None, lockfile: Path | None = None
) -> int:
    """Stamp a pytest-benchmark JSON file with its environment identity.

    The stamped file is what the workflow uploads as the baseline
    artifact, so a later comparison can prove the baseline was
    measured on identical pinned code/environment. Stamping is
    idempotent (re-stamping reproduces the same block). Refuses an
    empty benchmark list: a baseline with no workloads is not a
    baseline.
    """
    try:
        data = load_json(results)
    except FileNotFoundError:
        print(f"error: results file not found: {results}", file=sys.stderr)
        return 1
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read results file {results}: {exc}", file=sys.stderr)
        return 1
    if not data.get("benchmarks"):
        print(f"error: no benchmarks in {results}; refusing to stamp an empty run", file=sys.stderr)
        return 1
    data["environment"] = build_environment_identity(repo_root=repo_root, lockfile=lockfile)
    save_json(results, data)
    env = data["environment"]
    print(f"Stamped environment identity into {results}")
    print(f"  code_sha: {env['code_sha']}")
    print(f"  python_version: {env['python_version']}")
    print(f"  lockfile: {env['lockfile']} sha256={env['lockfile_sha256']}")
    return 0


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

    # Save baseline, stamped with the environment identity so a later
    # comparison can prove it was measured on identical pinned
    # code/environment (ENG-13).
    save_json(output, benchmark_data)
    stamp_identity(results=output)
    print(f"Created baseline: {output}")
    print(f"  Benchmarks: {len(benchmark_data.get('benchmarks', {}))}")
    return 0


def compare_baselines(
    *,
    baseline: Path,
    current: Path,
    threshold: float = 1.20,
    expected_benchmarks: list[str] | None = None,
    expected_baseline_code_sha: str | None = None,
) -> int:
    """Compare current results against baseline.

    Comparison is REQUIRED when this function is called: it fails
    (nonzero exit, explicit error) on a missing baseline file, on zero
    overlapping benchmark names, on a baseline benchmark missing from
    the current results (renamed/dropped), and on a missing mean in
    either file. It never reports "No significant changes detected"
    unless at least one benchmark was actually compared. The printed
    "Total benchmarks compared" is the matched (shared-name) count.

    ENG-13 (W7): a comparison is only valid for identical pinned
    code/environment and the predeclared slices. It additionally
    refuses when:

    - either file lacks environment identity (no ``python_version``),
      or the baseline's identity cannot prove the environment
      (no ``lockfile_sha256``) — a pre-stamp baseline is incomparable,
      not silently plotted;
    - the Python versions or pinned-lockfile digests differ — the
      baseline is stale for this environment;
    - ``expected_baseline_code_sha`` is given and the baseline's
      recorded code SHA is not that SHA — the artifact did not come
      from the resolved immutable run;
    - ``expected_benchmarks`` is given and any predeclared slice has
      no matched result — a slice missing from both files is still a
      failure, not a smaller comparison.

    The baseline and current code SHAs legitimately differ (the
    baseline is the older main commit; the comparison exists to
    detect regressions from code changes), so code-SHA equality
    between the two files is NOT required — only the environment
    must be identical.
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

    # Identical pinned code/environment (ENG-13): refuse an
    # incomparable pair before any timing is plotted.
    baseline_identity = extract_identity(baseline_data)
    current_identity = extract_identity(current_data)
    if "python_version" not in baseline_identity or "python_version" not in current_identity:
        print(
            "error: missing environment identity: both baseline and "
            "current results must record python_version (stamp the run "
            "with `performance_baseline.py stamp`); a comparison "
            "without identity is incomparable",
            file=sys.stderr,
        )
        return 1
    if baseline_identity["python_version"] != current_identity["python_version"]:
        print(
            "error: python_version mismatch: baseline measured on "
            f"{baseline_identity['python_version']!r}, current run on "
            f"{current_identity['python_version']!r}; refusing to "
            "compare across interpreter versions",
            file=sys.stderr,
        )
        return 1
    if "lockfile_sha256" not in baseline_identity or "lockfile_sha256" not in current_identity:
        print(
            "error: missing lockfile identity: both baseline and "
            "current results must record lockfile_sha256 (stamp the run "
            "with `performance_baseline.py stamp`); a baseline that "
            "cannot prove its pinned environment is incomparable "
            "(pre-stamp baselines: re-run the benchmark workflow on "
            "main to publish a stamped baseline)",
            file=sys.stderr,
        )
        return 1
    if baseline_identity["lockfile_sha256"] != current_identity["lockfile_sha256"]:
        print(
            "error: lockfile mismatch: baseline measured against "
            f"lockfile sha256 {baseline_identity['lockfile_sha256']}, "
            f"current run against {current_identity['lockfile_sha256']}; "
            "the baseline is stale for this pinned environment — "
            "re-publish the baseline from main instead of comparing",
            file=sys.stderr,
        )
        return 1
    if expected_baseline_code_sha is not None:
        baseline_sha = baseline_identity.get("code_sha")
        if baseline_sha is None:
            print(
                "error: baseline records no code_sha, so it cannot be "
                "proven to come from the resolved run "
                f"{expected_baseline_code_sha}; refusing the comparison",
                file=sys.stderr,
            )
            return 1
        if baseline_sha != expected_baseline_code_sha:
            print(
                "error: baseline code_sha mismatch: the baseline "
                f"artifact records code_sha {baseline_sha}, but the "
                "resolved baseline run is "
                f"{expected_baseline_code_sha}; the artifact did not "
                "come from the resolved immutable run — refusing",
                file=sys.stderr,
            )
            return 1
    print(
        "Baseline identity: code_sha="
        f"{baseline_identity.get('code_sha')} "
        f"python_version={baseline_identity['python_version']} "
        f"lockfile_sha256={baseline_identity['lockfile_sha256']}"
    )
    print(
        "Current identity: code_sha="
        f"{current_identity.get('code_sha')} "
        f"python_version={current_identity['python_version']} "
        f"lockfile_sha256={current_identity['lockfile_sha256']}"
    )

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

    # Predeclared slices (ENG-13): the compared set must cover the
    # declared slices. A slice absent from both files is invisible to
    # the overlap checks above and must still fail.
    if expected_benchmarks is not None:
        missing_expected = sorted(set(expected_benchmarks) - set(shared_names))
        if missing_expected:
            for name in missing_expected:
                print(
                    f"error: predeclared benchmark slice '{name}' has no "
                    "matched result in the comparison (missing from the "
                    "baseline, the current results, or both)",
                    file=sys.stderr,
                )
            print(
                "error: comparison does not cover the predeclared slices; "
                f"{len(missing_expected)} expected slice(s) uncompared — "
                "refusing rather than reporting on a reduced set",
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
    """Update baseline with current results.

    The current results must carry environment identity: a baseline
    without identity is incomparable by construction (ENG-13), so
    re-baselining from unidentified results is refused.
    """
    try:
        current_data = load_json(current)
    except FileNotFoundError:
        print(f"error: current results file not found: {current}", file=sys.stderr)
        return 1
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read current results file {current}: {exc}", file=sys.stderr)
        return 1
    if not current_data.get("benchmarks"):
        print(
            f"error: no benchmarks in {current}; refusing to update the baseline", file=sys.stderr
        )
        return 1
    identity = extract_identity(current_data)
    if "python_version" not in identity or "lockfile_sha256" not in identity:
        print(
            f"error: {current} carries no environment identity "
            "(python_version / lockfile_sha256); stamp it with "
            "`performance_baseline.py stamp` before re-baselining",
            file=sys.stderr,
        )
        return 1
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
    compare_parser.add_argument(
        "--expected-benchmarks",
        type=str,
        default=None,
        help="Comma-separated predeclared slice names that must all be compared",
    )
    compare_parser.add_argument(
        "--expected-benchmarks-file",
        type=Path,
        default=None,
        help="File listing predeclared slice names, one per line",
    )
    compare_parser.add_argument(
        "--expected-baseline-code-sha",
        type=str,
        default=None,
        help="Head SHA of the resolved baseline run; the baseline artifact must record it",
    )

    # Stamp command
    stamp_parser = subparsers.add_parser(
        "stamp", help="Stamp benchmark results with their environment identity"
    )
    stamp_parser.add_argument(
        "--results",
        type=Path,
        required=True,
        help="pytest-benchmark JSON file to stamp in place",
    )
    stamp_parser.add_argument(
        "--lockfile",
        type=Path,
        default=None,
        help="Pinned lockfile to hash (default: requirements-hashed.txt)",
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
        expected: list[str] | None = None
        if args.expected_benchmarks is not None and args.expected_benchmarks_file is not None:
            parser.error(
                "--expected-benchmarks and --expected-benchmarks-file are mutually exclusive"
            )
        if args.expected_benchmarks is not None:
            expected = [
                name.strip() for name in args.expected_benchmarks.split(",") if name.strip()
            ]
        elif args.expected_benchmarks_file is not None:
            try:
                expected = [
                    line.strip()
                    for line in args.expected_benchmarks_file.read_text(
                        encoding="utf-8"
                    ).splitlines()
                    if line.strip() and not line.strip().startswith("#")
                ]
            except OSError as exc:
                print(f"error: cannot read expected-benchmarks file: {exc}", file=sys.stderr)
                return 1
        return compare_baselines(
            baseline=args.baseline,
            current=args.current,
            threshold=args.threshold,
            expected_benchmarks=expected,
            expected_baseline_code_sha=args.expected_baseline_code_sha,
        )
    elif args.command == "stamp":
        return stamp_identity(results=args.results, lockfile=args.lockfile)
    elif args.command == "update":
        return update_baseline(baseline=args.baseline, current=args.current)

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
