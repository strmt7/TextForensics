#!/usr/bin/env python3
"""
Main fuzz test runner for TextForensics.
Orchestrates atheris-based fuzzing across multiple targets.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))


# Target definitions mapping to fuzz modules
FUZZ_TARGETS = {
    "json_parsing_api": "tests.fuzz.fuzz_json_parsing",
    "json_parsing_casefile": "tests.fuzz.fuzz_json_parsing",
    "json_parsing_benchmark": "tests.fuzz.fuzz_json_parsing",
    "text_input_validation_config": "tests.fuzz.fuzz_text_input_validation",
    "text_input_validation_cli": "tests.fuzz.fuzz_text_input_validation",
    "detector_input_handling": "tests.fuzz.fuzz_detector_input",
    "ledger_parsing_provenance": "tests.fuzz.fuzz_ledger_parsing",
    "schema_validation": "tests.fuzz.fuzz_schema_validation",
    "trust_map_computation": "tests.fuzz.fuzz_trust_map",
}

# Mapping of test cases to target modules
TARGET_MODULES = {
    "json_parsing_api": "tests.fuzz.fuzz_json_parsing",
    "json_parsing_casefile": "tests.fuzz.fuzz_json_parsing",
    "json_parsing_benchmark": "tests.fuzz.fuzz_json_parsing",
    "text_input_validation_config": "tests.fuzz.fuzz_text_input_validation",
    "text_input_validation_cli": "tests.fuzz.fuzz_text_input_validation",
    "detector_input_handling": "tests.fuzz.fuzz_detector_input",
    "ledger_parsing_provenance": "tests.fuzz.fuzz_ledger_parsing",
    "schema_validation": "tests.fuzz.fuzz_schema_validation",
    "trust_map_computation": "tests.fuzz.fuzz_trust_map",
}


def load_and_run_target(module_name: str, corpus_dir: Path, artifacts_dir: Path, duration_seconds: int) -> bool:
    """Load and run a fuzz target, return True if crashes found."""
    import importlib.util

    import atheris

    # Load the target module
    module_path = Path(__file__).parent / module_name.split(".")[-1] + ".py"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    crashes_dir = artifacts_dir / "crashes"
    artifacts_dir / "corpus"
    crashes_dir.mkdir(parents=True, exist_ok=True)

    print(f"Running fuzz target: {module_name}")
    print(f"  Duration: {duration_seconds} seconds")
    print(f"  Artifacts: {artifacts_dir}")

    start_time = time.time()

    try:
        # Create a custom test function that uses the corpus
        def fuzz_test(data: bytes) -> None:
            module.TestOneInput(data)

        # Configure atheris
        atheris.Setup(
            [sys.argv[0], f"-max_total_time={duration_seconds}"],
            fuzz_test,
            enable_python_coverage=True,
        )

        # Try to use existing corpus if available
        if corpus_dir.exists() and any(corpus_dir.iterdir()):
            # atheris will automatically pick up corpus files
            pass

        atheris.Fuzz()

    except Exception as e:
        print(f"  Error during fuzzing: {e}")

    elapsed = time.time() - start_time
    print(f"  Completed in {elapsed:.1f} seconds")

    # Check for crashes
    if crashes_dir.exists():
        crash_files = [f for f in crashes_dir.iterdir() if f.is_file() and f.name not in ("README.txt", ".gitkeep")]
        if crash_files:
            print(f"  Found {len(crash_files)} crashes!")
            for cf in crash_files[:5]:  # Show first 5
                print(f"    {cf.name}")
            return True

    return False


def run_fuzz_target(target_name: str, corpus_dir: Path, artifacts_dir: Path, duration_minutes: int) -> bool:
    """Run a single fuzz target via subprocess for isolation."""
    module_name = TARGET_MODULES.get(target_name)
    if not module_name:
        print(f"Unknown target: {target_name}")
        return False

    artifacts_dir.mkdir(parents=True, exist_ok=True)
    crashes_dir = artifacts_dir / "crashes"
    corpus_output_dir = artifacts_dir / "corpus"
    crashes_dir.mkdir(parents=True, exist_ok=True)
    corpus_output_dir.mkdir(parents=True, exist_ok=True)

    # Build the command
    cmd = [
        sys.executable,
        "-c",
        f"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path('.') / 'src'))
import atheris

# Load the target module
import importlib.util
spec = importlib.util.spec_from_file_location(
    "fuzz_target",
    Path("tests/fuzz/fuzz_{target_name.split('_')[1]}.py") if '{target_name}'.startswith('json_') else
    Path("tests/fuzz/fuzz_{'_'.join(target_name.split('_')[-2:])}.py") if 'validation' in '{target_name}' else
    Path("tests/fuzz/fuzz_{'_'.join(target_name.split('_')[0:2])}.py") if 'json' in '{target_name}' and 'casefile' in '{target_name}' else
    Path("tests/fuzz/fuzz_{'_'.join(target_name.split('_')[0:2])}.py")
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def fuzz_test(data: bytes):
    module.TestOneInput(data)

atheris.Setup(
    sys.argv,
    fuzz_test,
    enable_python_coverage=True,
)
atheris.Fuzz()
""",
        "-runs=0",
        f"-max_total_time={duration_minutes * 60}",
        f"-artifact_prefix={crashes_dir}/",
    ]

    env = os.environ.copy()
    env["TFUZZ_DURATION_MINUTES"] = str(duration_minutes)

    print(f"Running fuzz target: {target_name}")
    print(f"  Command: {' '.join(cmd[:3])}... -max_total_time={duration_minutes * 60}")

    try:
        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=(duration_minutes + 5) * 60,
            cwd=Path.cwd(),
        )

        if result.returncode != 0:
            print(f"  Target returned non-zero: {result.returncode}")
            if result.stderr:
                print(f"  stderr: {result.stderr[:1000]}")

        print(f"  stdout: {result.stdout[:500] if result.stdout else 'none'}")

    except subprocess.TimeoutExpired:
        print(f"  Target timed out after {duration_minutes} minutes")
    except Exception as e:
        print(f"  Error running target: {e}")

    # Check for crashes
    if crashes_dir.exists():
        crash_files = list(crashes_dir.glob("*"))
        crash_files = [f for f in crash_files if f.is_file() and f.name not in ("README.txt", ".gitkeep")]
        if crash_files:
            print(f"  Found {len(crash_files)} crashes!")
            return True

    return False


def simple_run_all_targets():
    """Run all targets using pytest for CI compatibility."""

    print("Running fuzz tests via pytest...")

    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "tests/fuzz/test_fuzz_pytest.py",
        "-v",
        "--tb=short",
        "-x",  # Fail fast for pytest wrapper tests
    ]

    result = subprocess.run(cmd, cwd=Path.cwd())
    return result.returncode == 0


def main():
    parser = argparse.ArgumentParser(description="Run fuzz tests for TextForensics")
    parser.add_argument(
        "--target",
        type=str,
        default="all",
        help="Fuzz target to run (default: all)",
    )
    parser.add_argument(
        "--corpus-dir",
        type=Path,
        default=Path("corpus"),
        help="Directory containing initial corpus",
    )
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        default=Path("artifacts"),
        help="Directory for fuzz artifacts",
    )
    parser.add_argument(
        "--duration-minutes",
        type=int,
        default=5,
        help="Duration to run each target (default: 5 minutes)",
    )
    parser.add_argument(
        "--skip-corpus-gen",
        action="store_true",
        help="Skip generating initial corpus",
    )
    parser.add_argument(
        "--method",
        type=str,
        default="pytest",
        choices=["pytest", "direct"],
        help="Execution method (pytest for CI compatibility, direct for atheris)",
    )

    args = parser.parse_args()

    # Generate initial corpus if needed
    if not args.skip_corpus_gen:
        corpus_path = args.corpus_dir
        if not corpus_path.exists() or not any(corpus_path.iterdir()):
            print(f"Generating initial corpus in {corpus_path}")
            generator_path = Path(__file__).parent / "generate_corpus.py"
            if generator_path.exists():
                try:
                    result = subprocess.run(
                        [sys.executable, str(generator_path), "--output-dir", str(corpus_path)],
                        capture_output=True,
                        text=True,
                        timeout=60,
                    )
                    if result.returncode != 0:
                        print(f"  Corpus generation warning: {result.stderr[:200]}")
                except Exception as e:
                    print(f"  Corpus generation error: {e}")

    # Determine targets to run
    if args.target == "all":
        targets = list(TARGET_MODULES.keys())
    elif args.target in TARGET_MODULES:
        targets = [args.target]
    else:
        print(f"Unknown target: {args.target}")
        print(f"Available targets: {list(TARGET_MODULES.keys())}")
        return 1

    print(f"Running fuzz tests for targets: {targets}")

    # Run via pytest for CI compatibility
    return 0 if simple_run_all_targets() else 1


if __name__ == "__main__":
    sys.exit(main())
