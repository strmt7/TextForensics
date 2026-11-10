"""Tests for scripts/promotion_gate.py (ENG-04 / ENG-14 exact-SHA acceptance gate).

The gate decides whether a candidate source SHA may be promoted (release or
container promotion) by inspecting the GitHub check-runs recorded for that
exact SHA. Only ``pass`` at the exact SHA promotes; missing, skipped, failed,
stale-SHA or incomplete required results all block promotion.

All GitHub access is read-only (``gh api`` GET of check-runs) and is fully
mocked here: no test contacts GitHub.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"


def _load_gate_module():
    spec = importlib.util.spec_from_file_location(
        "promotion_gate", SCRIPTS_DIR / "promotion_gate.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["promotion_gate"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gate():
    return _load_gate_module()


SHA = "a" * 40
OTHER_SHA = "b" * 40


def _run(name, conclusion="success", status="completed", sha=SHA):
    return {"name": name, "status": status, "conclusion": conclusion, "head_sha": sha}


def _all_pass_runs(gate):
    """One passing check-run per required check (matrix jobs: two runs)."""
    runs = []
    for spec in gate.REQUIRED_CHECKS:
        runs.append(_run(spec["check"] + " 3.12"))
        if spec.get("matrix"):
            runs.append(_run(spec["check"] + " 3.11"))
    return runs


# --- evaluate_gate: happy path and each blocking class ---------------------


def test_all_required_pass_at_exact_sha_promotes(gate):
    result = gate.evaluate_gate(_all_pass_runs(gate), SHA)
    assert result["overall_pass"] is True
    assert all(g["status"] == "pass" for g in result["gates"].values())


def test_missing_required_check_blocks_promotion(gate):
    runs = [r for r in _all_pass_runs(gate) if "Claims" not in r["name"]]
    result = gate.evaluate_gate(runs, SHA)
    assert result["overall_pass"] is False
    assert result["gates"]["claims"]["status"] == "unavailable"


def test_skipped_required_check_blocks_promotion(gate):
    runs = _all_pass_runs(gate)
    for r in runs:
        if "Claims" in r["name"]:
            r["conclusion"] = "skipped"
    result = gate.evaluate_gate(runs, SHA)
    assert result["overall_pass"] is False
    assert result["gates"]["claims"]["status"] == "skipped"


def test_failed_required_check_blocks_promotion(gate):
    runs = _all_pass_runs(gate)
    for r in runs:
        if "pip-audit" in r["name"]:
            r["conclusion"] = "failure"
    result = gate.evaluate_gate(runs, SHA)
    assert result["overall_pass"] is False
    assert result["gates"]["pip-audit"]["status"] == "fail"


def test_stale_sha_check_blocks_promotion(gate):
    runs = _all_pass_runs(gate)
    for r in runs:
        if "Reproducibility" in r["name"]:
            r["head_sha"] = OTHER_SHA
    result = gate.evaluate_gate(runs, SHA)
    assert result["overall_pass"] is False
    assert result["gates"]["reproducibility"]["status"] == "fail"
    assert "stale" in result["gates"]["reproducibility"]["reason"].lower()


def test_incomplete_check_blocks_promotion(gate):
    runs = _all_pass_runs(gate)
    for r in runs:
        if "SBOM is not stale" in r["name"]:
            r["status"] = "in_progress"
            r["conclusion"] = None
    result = gate.evaluate_gate(runs, SHA)
    assert result["overall_pass"] is False
    assert result["gates"]["locked-sbom"]["status"] == "unavailable"


def test_one_failing_matrix_run_blocks_promotion(gate):
    runs = _all_pass_runs(gate)
    for r in runs:
        if r["name"].endswith("3.11") and "Core Python" in r["name"]:
            r["conclusion"] = "failure"
    result = gate.evaluate_gate(runs, SHA)
    assert result["overall_pass"] is False
    assert result["gates"]["full-pytest"]["status"] == "fail"


def test_unrelated_check_names_do_not_satisfy_required(gate):
    runs = [_run("CI / Some Unrelated Job"), _run("Other Workflow / Claims")]
    result = gate.evaluate_gate(runs, SHA)
    assert result["overall_pass"] is False
    assert all(g["status"] == "unavailable" for g in result["gates"].values())


@pytest.mark.parametrize(
    "conclusion", ["failure", "cancelled", "timed_out", "action_required", "skipped"]
)
def test_only_pass_conclusion_promotes(gate, conclusion):
    runs = _all_pass_runs(gate)
    for r in runs:
        if "Claims" in r["name"]:
            r["conclusion"] = conclusion
    result = gate.evaluate_gate(runs, SHA)
    assert result["overall_pass"] is False
    assert result["gates"]["claims"]["status"] != "pass"


def test_gate_status_vocabulary(gate):
    assert set(gate.GATE_STATUSES) == {
        "pass",
        "fail",
        "skipped",
        "unavailable",
        "not_applicable",
        "zero_work",
    }


def test_extra_required_check_is_enforced(gate):
    extra = [{"key": "candidate-build", "check": "Container / Candidate build"}]
    result = gate.evaluate_gate(_all_pass_runs(gate), SHA, required=extra)
    assert result["overall_pass"] is False
    assert result["gates"]["candidate-build"]["status"] == "unavailable"


# --- fetch_check_runs: read-only gh api ------------------------------------


def test_fetch_check_runs_uses_read_only_gh_api(gate):
    calls = []
    payload = {"check_runs": [_run("CI / Core Python 3.12"), _run("CI / Claims")]}

    def fake_runner(cmd, **kwargs):
        calls.append(cmd)

        class Result:
            stdout = json.dumps(payload)

        return Result()

    runs = gate.fetch_check_runs("strmt7", "TextForensics", SHA, runner=fake_runner)
    assert len(calls) == 1
    cmd = calls[0]
    assert cmd[0] == "gh" and cmd[1] == "api"
    assert "--method" not in cmd and "POST" not in cmd
    assert f"repos/strmt7/TextForensics/commits/{SHA}/check-runs" in cmd[2]
    assert runs[0]["name"] == "CI / Core Python 3.12"
    assert runs[0]["conclusion"] == "success"


def test_fetch_check_runs_failure_is_not_a_pass(gate):
    def failing_runner(cmd, **kwargs):
        raise RuntimeError("gh unavailable")

    with pytest.raises(gate.PromotionGateError):
        gate.fetch_check_runs("strmt7", "TextForensics", SHA, runner=failing_runner)


# --- CLI exit-code contract -------------------------------------------------


def test_main_exit_zero_when_all_pass(gate, monkeypatch):
    monkeypatch.setattr(gate, "fetch_check_runs", lambda *a, **k: _all_pass_runs(gate))
    assert gate.main(["--sha", SHA, "--repo", "strmt7/TextForensics"]) == 0


def test_main_exit_one_when_a_required_gate_blocks(gate, monkeypatch):
    runs = _all_pass_runs(gate)
    for r in runs:
        if "Claims" in r["name"]:
            r["conclusion"] = "failure"
    monkeypatch.setattr(gate, "fetch_check_runs", lambda *a, **k: runs)
    assert gate.main(["--sha", SHA, "--repo", "strmt7/TextForensics"]) == 1


def test_main_exit_two_when_check_runs_cannot_be_fetched(gate, monkeypatch):
    def boom(*a, **k):
        raise gate.PromotionGateError("gh api failed")

    monkeypatch.setattr(gate, "fetch_check_runs", boom)
    assert gate.main(["--sha", SHA, "--repo", "strmt7/TextForensics"]) == 2
