"""ENG-13 (W7): scripts/benchmark.py results must carry their identity.

A standalone benchmark result without code SHA / Python version /
pinned-lockfile digest cannot be compared honestly later: there is no
way to prove the run used the identical pinned code/environment. The
emitted JSON must record an `environment` block (AGENTS.md benchmark
discipline: every run captures git SHA, dependency/environment lock,
runtime).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"


def _load_benchmark_module():
    spec = importlib.util.spec_from_file_location("w7c_benchmark", SCRIPTS_DIR / "benchmark.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["w7c_benchmark"] = module
    spec.loader.exec_module(module)
    return module


def test_environment_identity_records_code_python_and_lockfile():
    module = _load_benchmark_module()
    identity = module._environment_identity(repo_root=REPO_ROOT)
    assert identity["python_version"].startswith("3.")
    assert identity["code_sha"], "code SHA must be recorded"
    assert len(identity["code_sha"]) == 40
    assert identity["lockfile"] == "requirements-hashed.txt"
    assert (
        identity["lockfile_sha256"]
        == hashlib.sha256((REPO_ROOT / "requirements-hashed.txt").read_bytes()).hexdigest()
    )


def test_benchmark_output_carries_environment_block(tmp_path):
    """The JSON a benchmark run emits must contain the environment
    block, so a later comparison can refuse a mismatched baseline."""
    module = _load_benchmark_module()
    out = tmp_path / "results.json"
    code = module.main(["--words", "10", "--iterations", "1", "--skip-api", "--output", str(out)])
    assert code == 0
    results = json.loads(out.read_text(encoding="utf-8"))
    env = results["environment"]
    assert env["python_version"].startswith("3.")
    assert env["code_sha"]
    assert env["lockfile_sha256"]
    assert set(results["benchmarks"]) == {
        "cli_scan",
        "cli_report",
        "case_export",
        "detector_execution",
    }
