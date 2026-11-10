"""RED regression tests for ENG-13: benchmark comparison must be honest.

- Disjoint benchmark names must fail, never "No significant changes
  detected" with a compared count of 1 and zero shared benchmarks.
- Missing means / missing baseline benchmarks must fail when comparison
  is required.
- A missing baseline file must fail cleanly (exit 1, explicit error).
- Baseline comparison is REQUIRED by default on push/schedule/dispatch:
  the workflow condition logic is tested via resolve_baseline_requirement
  and via structural assertions on .github/workflows/benchmark.yml.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest
import yaml

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
REPO_ROOT = Path(__file__).parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "benchmark.yml"

# Validated 2026-11-10 with read-only `gh api
# repos/actions/download-artifact/commits/<sha>` (HTTP 200).
# The old pin cf430e030ddbb5b0abf93d22962f4752f3646cd9 is an
# upload-artifact commit: the same endpoint returns HTTP 422 for it
# in actions/download-artifact.
VALIDATED_DOWNLOAD_ARTIFACT_SHA = "37930b1c2abaa49bbe596cd826c3c89aef350131"  # v7.0.0
INVALID_DOWNLOAD_ARTIFACT_SHA = "cf430e030ddbb5b0abf93d22962f4752f3646cd9"


def _load_baseline_module():
    spec = importlib.util.spec_from_file_location(
        "performance_baseline", SCRIPTS_DIR / "performance_baseline.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["performance_baseline"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def baseline_mod():
    return _load_baseline_module()


def _write_json(path: Path, data: dict) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _bench(name: str, mean: float | None) -> dict:
    stats: dict = {}
    if mean is not None:
        stats["mean"] = mean
    return {"name": name, "stats": stats}


# ---------------------------------------------------------------------------
# compare_baselines: zero-overlap / missing / invalid results
# ---------------------------------------------------------------------------


def test_compare_zero_overlap_names_fails(baseline_mod, tmp_path, capsys):
    """ENG-13: wholly disjoint names must fail, not report 'no changes'."""
    base = _write_json(tmp_path / "baseline.json", {"benchmarks": [_bench("test_alpha", 1.0)]})
    curr = _write_json(tmp_path / "current.json", {"benchmarks": [_bench("test_beta", 1.0)]})
    code = baseline_mod.compare_baselines(baseline=base, current=curr)
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code != 0
    assert "zero" in out.lower() and "overlap" in out.lower()
    assert "No significant changes detected" not in out


def test_compare_missing_baseline_benchmark_in_current_fails(baseline_mod, tmp_path, capsys):
    """A baseline benchmark renamed/absent in current results must fail."""
    base = _write_json(
        tmp_path / "baseline.json",
        {"benchmarks": [_bench("test_alpha", 1.0), _bench("test_gamma", 2.0)]},
    )
    curr = _write_json(tmp_path / "current.json", {"benchmarks": [_bench("test_alpha", 1.0)]})
    code = baseline_mod.compare_baselines(baseline=base, current=curr)
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code != 0
    assert "test_gamma" in out


def test_compare_missing_mean_fails(baseline_mod, tmp_path, capsys):
    """A benchmark without a mean in either file must fail, not be skipped."""
    base = _write_json(tmp_path / "baseline.json", {"benchmarks": [_bench("test_alpha", 1.0)]})
    curr = _write_json(tmp_path / "current.json", {"benchmarks": [_bench("test_alpha", None)]})
    code = baseline_mod.compare_baselines(baseline=base, current=curr)
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code != 0
    assert "test_alpha" in out
    assert "mean" in out.lower()


def test_compare_missing_baseline_file_fails_cleanly(baseline_mod, tmp_path, capsys):
    """A failed/missing baseline download must fail with an explicit error."""
    curr = _write_json(tmp_path / "current.json", {"benchmarks": [_bench("test_alpha", 1.0)]})
    code = baseline_mod.compare_baselines(baseline=tmp_path / "no-such-baseline.json", current=curr)
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code != 0
    assert "baseline" in out.lower()


def test_compare_matching_names_reports_matched_count(baseline_mod, tmp_path, capsys):
    """Clean control: overlapping names compare, and the count is matched."""
    base = _write_json(
        tmp_path / "baseline.json",
        {"benchmarks": [_bench("test_alpha", 1.0), _bench("test_beta", 2.0)]},
    )
    curr = _write_json(
        tmp_path / "current.json",
        {"benchmarks": [_bench("test_alpha", 1.05), _bench("test_beta", 2.0)]},
    )
    code = baseline_mod.compare_baselines(baseline=base, current=curr)
    out = capsys.readouterr().out
    assert code == 0
    assert "Total benchmarks compared: 2" in out
    assert "No significant changes detected" in out


def test_compare_regression_still_fails(baseline_mod, tmp_path, capsys):
    """A >20% slowdown on a matched benchmark still fails the gate."""
    base = _write_json(tmp_path / "baseline.json", {"benchmarks": [_bench("test_alpha", 1.0)]})
    curr = _write_json(tmp_path / "current.json", {"benchmarks": [_bench("test_alpha", 1.5)]})
    code = baseline_mod.compare_baselines(baseline=base, current=curr)
    assert code != 0


# ---------------------------------------------------------------------------
# Event-payload logic: comparison required by default
# ---------------------------------------------------------------------------


def test_resolve_baseline_requirement_event_payloads(baseline_mod):
    """push/schedule/dispatch must require comparison by default.

    Only an explicit workflow_dispatch with baseline-ref '' opts out,
    and then the outcome is 'skipped' with a reason — never a pass.
    """
    resolve = baseline_mod.resolve_baseline_requirement
    assert resolve(event_name="push", baseline_ref_input=None) == ("required", "main")
    assert resolve(event_name="schedule", baseline_ref_input=None) == ("required", "main")
    assert resolve(event_name="workflow_dispatch", baseline_ref_input="main") == (
        "required",
        "main",
    )
    assert resolve(event_name="workflow_dispatch", baseline_ref_input="HEAD~1") == (
        "required",
        "HEAD~1",
    )
    status, _ref = resolve(event_name="workflow_dispatch", baseline_ref_input="")
    assert status == "skipped"
    # No event may resolve to "passed" without a baseline.
    for event in ("push", "schedule", "workflow_dispatch"):
        status, _ref = resolve(event_name=event, baseline_ref_input=None)
        assert status == "required"


# ---------------------------------------------------------------------------
# Workflow structure: benchmark.yml
# ---------------------------------------------------------------------------


def _workflow_steps():
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return data["jobs"]["benchmark"]["steps"]


def _step_by_name(name_fragment: str):
    for step in _workflow_steps():
        if name_fragment in str(step.get("name", "")):
            return step
    raise AssertionError(f"no step matching {name_fragment!r} in benchmark.yml")


def test_benchmark_download_pin_is_valid_download_artifact_commit():
    """ENG-13: the download step must pin a real download-artifact commit."""
    step = _step_by_name("Download performance baseline")
    uses = step["uses"]
    assert INVALID_DOWNLOAD_ARTIFACT_SHA not in uses
    assert uses == f"actions/download-artifact@{VALIDATED_DOWNLOAD_ARTIFACT_SHA}"


def test_benchmark_comparison_not_conditioned_on_dispatch_input():
    """ENG-13: comparison must run on push/schedule, not only on dispatch."""
    compare = _step_by_name("Compare performance against baseline")
    condition = str(compare.get("if", ""))
    assert "github.event.inputs.baseline-ref != ''" not in condition
    download = _step_by_name("Download performance baseline")
    assert "github.event.inputs.baseline-ref != ''" not in str(download.get("if", ""))


def test_benchmark_download_step_is_not_optional():
    """A failed baseline download must fail the job (no fail-on-error opt-out)."""
    step = _step_by_name("Download performance baseline")
    assert "continue-on-error" not in step
    assert step.get("with", {}).get("fail-on-error") is not False
    assert "fail-on-error" not in step.get("with", {})


def test_benchmark_compare_step_fails_when_baseline_missing():
    """ENG-13: missing baseline must fail, never 'Skipping comparison'."""
    step = _step_by_name("Compare performance against baseline")
    script = str(step.get("run", ""))
    assert "Skipping comparison" not in script
    assert "No baseline found" not in script
    assert "exit 1" in script
    assert "baseline" in script.lower()
