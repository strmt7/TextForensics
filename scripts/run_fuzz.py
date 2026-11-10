#!/usr/bin/env python3
"""
Run fuzz targets for TextForensics using atheris + LibFuzzer.

Usage:
    python scripts/run_fuzz.py                          # run all targets, 5 min each
    python scripts/run_fuzz.py --target text_parsing    # run single target
    python scripts/run_fuzz.py --duration 10            # 10 min per target
    python scripts/run_fuzz.py --method direct          # use atheris directly (not pytest)
    python scripts/run_fuzz.py --regression             # seed from existing corpus (still explores)
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
FUZZ_DIR = REPO_ROOT / "tests" / "fuzz"
CORPUS_DIR = REPO_ROOT / "tests" / "fuzz" / "corpus"
ARTIFACTS_DIR = REPO_ROOT / "artifacts" / "fuzz"

# ---------------------------------------------------------------------------
# Target definitions: name -> module path (relative to repo root)
# ---------------------------------------------------------------------------


@dataclass
class FuzzTarget:
    name: str
    module: str
    corpus_subdir: str
    description: str = ""


FUZZ_TARGETS: dict[str, FuzzTarget] = {
    "text_parsing": FuzzTarget(
        name="text_parsing",
        module="tests/fuzz/fuzz_text_parsing.py",
        corpus_subdir="text_parsing",
        description="Text input parsing (UTF-8, null bytes, control chars)",
    ),
    "json_parsing": FuzzTarget(
        name="json_parsing",
        module="tests/fuzz/fuzz_json_parsing.py",
        corpus_subdir="json_parsing",
        description="JSON/YAML config parsing",
    ),
    "score_boundaries": FuzzTarget(
        name="score_boundaries",
        module="tests/fuzz/fuzz_score_boundaries.py",
        corpus_subdir="score_boundaries",
        description="Score boundary conditions (NaN, infinity, out-of-range)",
    ),
    "detector_input": FuzzTarget(
        name="detector_input",
        module="tests/fuzz/fuzz_detector_input.py",
        corpus_subdir="detector_input",
        description="Detector input validation",
    ),
    "calibration": FuzzTarget(
        name="calibration",
        module="tests/fuzz/fuzz_calibration.py",
        corpus_subdir="calibration",
        description="Calibration artifact parsing, validation, and threshold selection",
    ),
    "drift": FuzzTarget(
        name="drift",
        module="tests/fuzz/fuzz_drift.py",
        corpus_subdir="drift",
        description="DriftObservatory corpus loading, snapshot creation, and comparison",
    ),
    "enterprise_policy": FuzzTarget(
        name="enterprise_policy",
        module="tests/fuzz/fuzz_enterprise_policy.py",
        corpus_subdir="enterprise_policy",
        description="Enterprise policy parsing, validation, and revision floor",
    ),
    "web_ui": FuzzTarget(
        name="web_ui",
        module="tests/fuzz/fuzz_web_ui.py",
        corpus_subdir="web_ui",
        description="WebSocket message handling and REST API inputs",
    ),
    "mcp": FuzzTarget(
        name="mcp",
        module="tests/fuzz/fuzz_mcp.py",
        corpus_subdir="mcp",
        description="MCP tool inputs and serialization",
    ),
}


def ensure_dirs(target: FuzzTarget) -> tuple[Path, Path, Path]:
    """Create artifacts directories for a target. Returns (crashes, corpus_out, coverage)."""
    base = ARTIFACTS_DIR / target.name
    crashes = base / "crashes"
    corpus_out = base / "corpus"
    coverage = base / "coverage"
    for d in (crashes, corpus_out, coverage):
        d.mkdir(parents=True, exist_ok=True)
    return crashes, corpus_out, coverage


def _crash_files(crashes_dir: Path) -> list[Path]:
    """Crash artifacts in a directory, excluding marker files."""
    if not crashes_dir.exists():
        return []
    return [
        f for f in crashes_dir.iterdir() if f.is_file() and f.name not in (".gitkeep", "README.txt")
    ]


def run_atheris_target(target: FuzzTarget, duration_seconds: int, regression: bool) -> dict:
    """Run a single fuzz target via atheris in a subprocess.

    ``regression`` is accepted for CLI compatibility; it currently only
    seeds the corpus (see below) — replay-only mode is not implemented,
    so a regression run still explores new inputs for the duration.

    Returns a dict with summary info.
    """
    crashes_dir, corpus_out, _ = ensure_dirs(target)

    cmd = [
        sys.executable,
        "-c",
        f"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(r'{SRC_DIR}')))
import atheris
import importlib.util

spec = importlib.util.spec_from_file_location("fuzz_target", r'{REPO_ROOT / target.module}')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

def fuzz_test(data: bytes):
    mod.TestOneInput(data)

atheris.Setup(
    sys.argv,
    fuzz_test,
    enable_python_coverage=True,
)
atheris.Fuzz()
""",
        f"-max_total_time={duration_seconds}",
        f"-artifact_prefix={crashes_dir}/",
    ]

    # Seed with existing corpus if available and pass it positionally so
    # libFuzzer loads it.  It is NOT a dictionary: -dict= expects a
    # libFuzzer dict file, not a corpus directory (the old regression
    # branch passed the corpus dir via -dict=, which never seeded it).
    corpus_source = CORPUS_DIR / target.corpus_subdir
    if corpus_source.exists() and any(corpus_source.iterdir()):
        for f in corpus_source.iterdir():
            if f.is_file():
                shutil.copy2(f, corpus_out)

    if corpus_out.exists() and any(corpus_out.iterdir()):
        cmd.append(str(corpus_out))

    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_DIR)
    env["TFUZZ_DURATION_SECONDS"] = str(duration_seconds)

    print(f"\n{'=' * 60}")
    print(f"Target: {target.name} — {target.description}")
    print(f"Duration: {duration_seconds}s")
    print(f"Artifacts: {ARTIFACTS_DIR / target.name}")
    print(f"{'=' * 60}")

    result: dict = {
        "target": target.name,
        "crashes": 0,
        "hangs": 0,
        "timed_out": False,
        "error": None,
    }
    start = time.time()

    try:
        proc = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=(duration_seconds + 60),
            cwd=str(REPO_ROOT),
        )
        if proc.returncode != 0:
            # ENG-07(3): a nonzero child exit is an ERROR, not information.
            # A crash/hang exit is expected to leave a crash artifact; a
            # nonzero exit with no artifact is an instrumentation/startup
            # failure and must never read as "zero crashes, no error".
            print(
                f"  [error] atheris child exited with status {proc.returncode} "
                f"(crash artifacts are counted below)"
            )
            result["error"] = (
                f"atheris child exited with status {proc.returncode} without a crash artifact"
                if not _crash_files(crashes_dir)
                else (
                    f"atheris child exited with status {proc.returncode} (crash artifact present)"
                )
            )
        # Print atheris stats
        if proc.stdout:
            for line in proc.stdout.splitlines()[-10:]:
                if line.strip():
                    print(f"  {line.strip()}")
    except subprocess.TimeoutExpired:
        result["timed_out"] = True
        result["error"] = (
            f"atheris child did not exit within {duration_seconds + 60}s "
            "(timeout — treated as a failed execution, not a clean run)"
        )
        print(f"  [error] Target timed out after {duration_seconds + 60}s")
    except Exception as exc:
        result["error"] = str(exc)
        print(f"  [error] {exc}")

    elapsed = time.time() - start
    result["elapsed"] = round(elapsed, 1)

    # Count crash artifacts
    if crashes_dir.exists():
        crash_files = _crash_files(crashes_dir)
        result["crashes"] = len(crash_files)
        if crash_files:
            print(f"  Found {len(crash_files)} crash artifact(s):")
            for f in crash_files[:10]:
                print(f"    {f.name}")

    # ENG-07(3): a nonzero child exit with no crash artifact was already
    # recorded as an error above; if crash artifacts appeared only after
    # the exit-status branch ran, reconcile the message here so the
    # result never claims "no error" for a failed child.
    if result["error"] is None and result["crashes"]:
        result["error"] = (
            f"atheris child produced crash artifact(s) ({result['crashes']} in {crashes_dir})"
        )

    # Count new corpus entries
    if corpus_out.exists():
        new_corpus = [f for f in corpus_out.iterdir() if f.is_file()]
        result["corpus_count"] = len(new_corpus)

    return result


def run_pytest_targets() -> bool:
    """Run all fuzz targets via pytest for CI compatibility."""
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        str(FUZZ_DIR / "test_fuzz_pytest.py"),
        "-v",
        "--tb=short",
    ]

    print("\nRunning fuzz tests via pytest...")
    result = subprocess.run(cmd, cwd=str(REPO_ROOT))
    return result.returncode == 0


def generate_corpus() -> None:
    """Generate initial corpus if it doesn't exist."""
    if CORPUS_DIR.exists() and any(CORPUS_DIR.iterdir()):
        print(f"Corpus already exists at {CORPUS_DIR}")
        return

    print(f"Generating initial corpus in {CORPUS_DIR}")
    generator = FUZZ_DIR / "generate_corpus.py"
    if generator.exists():
        proc = subprocess.run(
            [sys.executable, str(generator), "--output-dir", str(CORPUS_DIR)],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(REPO_ROOT),
        )
        if proc.returncode != 0:
            print(f"  [warn] Corpus generation warning: {proc.stderr[:200]}")
        else:
            print("  Corpus generation complete.")
    else:
        print(f"  [warn] Corpus generator not found at {generator}")


def main() -> int:
    global ARTIFACTS_DIR

    parser = argparse.ArgumentParser(description="Run fuzz tests for TextForensics")
    parser.add_argument(
        "--target",
        type=str,
        default="all",
        help="Fuzz target to run (default: all). Available: " + ", ".join(FUZZ_TARGETS.keys()),
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=5,
        help="Duration in minutes per target (default: 5)",
    )
    parser.add_argument(
        "--method",
        type=str,
        default="pytest",
        choices=["pytest", "direct"],
        help="Execution method (pytest for CI, direct for atheris)",
    )
    parser.add_argument(
        "--regression",
        action="store_true",
        help="Seed from the existing corpus (replay-only mode is not implemented; direct fuzzing still explores new inputs)",
    )
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        default=ARTIFACTS_DIR,
        help="Directory for fuzz artifacts",
    )
    args = parser.parse_args()

    ARTIFACTS_DIR = args.artifacts_dir

    generate_corpus()

    # Determine targets to run
    if args.target == "all":
        targets = list(FUZZ_TARGETS.values())
    elif args.target in FUZZ_TARGETS:
        targets = [FUZZ_TARGETS[args.target]]
    else:
        print(f"Unknown target: {args.target}")
        print(f"Available: {', '.join(FUZZ_TARGETS.keys())}")
        return 1

    duration_seconds = args.duration * 60

    # Clear old artifacts
    if ARTIFACTS_DIR.exists():
        shutil.rmtree(ARTIFACTS_DIR)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    # Run
    if args.method == "pytest":
        success = run_pytest_targets()
        return 0 if success else 1

    # Direct atheris mode
    results = []
    for target in targets:
        result = run_atheris_target(target, duration_seconds, args.regression)
        results.append(result)

    # Summary
    print(f"\n{'=' * 60}")
    print("FUZZ SUMMARY")
    print(f"{'=' * 60}")
    total_crashes = 0
    total_errors = 0
    for r in results:
        status = "OK"
        if r["crashes"]:
            status = f"CRASH ({r['crashes']})"
            total_crashes += r["crashes"]
        if r["timed_out"]:
            status += " TIMEOUT"
        if r["error"]:
            status = f"ERROR ({r['error'][:80]})"
            total_errors += 1
        print(f"  {r['target']:25s}  {status:30s}  {r.get('elapsed', '?'):6.1f}s")

    if total_crashes:
        print(f"\n  *** {total_crashes} crash(es) found in {ARTIFACTS_DIR}/")
        print("  *** Reproduce: python scripts/run_fuzz.py --target <name> --method direct")
        return 1
    # ENG-07(3): a child error (nonzero exit without a crash artifact, a
    # timeout, or a runner exception) is a failed run, never a clean one.
    if total_errors:
        print(
            f"\n  *** {total_errors} target(s) errored (see ERROR above); "
            "the run did NOT complete cleanly."
        )
        return 1
    else:
        print("\n  No crashes detected.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
