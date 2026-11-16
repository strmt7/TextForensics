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
VALIDATED_DOWNLOAD_ARTIFACT_SHA = "9000827ccba6bdab643e8b6fd33ac0654aef8333"  # v8.0.2
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


# ENG-13 (W7): a comparison is only meaningful for identical pinned
# code/environment. Fixtures carry a matching stamped identity block
# (the workflow stamps pytest-performance.json with
# `performance_baseline.py stamp` before comparing); tests that omit
# the identity must fail (see test_compare_*_identity_* below).
def _identity(
    code_sha: str = "a" * 40,
    python_version: str = "3.12.3",
    lockfile_sha256: str = "b" * 64,
) -> dict:
    return {
        "environment": {
            "code_sha": code_sha,
            "python_version": python_version,
            "lockfile": "requirements-hashed.txt",
            "lockfile_sha256": lockfile_sha256,
            "platform": "linux",
        }
    }


def _doc(benchmarks: list, **identity_overrides) -> dict:
    data: dict = {"benchmarks": benchmarks}
    data.update(_identity(**identity_overrides))
    return data


# ---------------------------------------------------------------------------
# compare_baselines: zero-overlap / missing / invalid results
# ---------------------------------------------------------------------------


def test_compare_zero_overlap_names_fails(baseline_mod, tmp_path, capsys):
    """ENG-13: wholly disjoint names must fail, not report 'no changes'."""
    base = _write_json(tmp_path / "baseline.json", _doc([_bench("test_alpha", 1.0)]))
    curr = _write_json(tmp_path / "current.json", _doc([_bench("test_beta", 1.0)]))
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
        _doc([_bench("test_alpha", 1.0), _bench("test_gamma", 2.0)]),
    )
    curr = _write_json(tmp_path / "current.json", _doc([_bench("test_alpha", 1.0)]))
    code = baseline_mod.compare_baselines(baseline=base, current=curr)
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code != 0
    assert "test_gamma" in out


def test_compare_missing_mean_fails(baseline_mod, tmp_path, capsys):
    """A benchmark without a mean in either file must fail, not be skipped."""
    base = _write_json(tmp_path / "baseline.json", _doc([_bench("test_alpha", 1.0)]))
    curr = _write_json(tmp_path / "current.json", _doc([_bench("test_alpha", None)]))
    code = baseline_mod.compare_baselines(baseline=base, current=curr)
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code != 0
    assert "test_alpha" in out
    assert "mean" in out.lower()


def test_compare_missing_baseline_file_fails_cleanly(baseline_mod, tmp_path, capsys):
    """A failed/missing baseline download must fail with an explicit error."""
    curr = _write_json(tmp_path / "current.json", _doc([_bench("test_alpha", 1.0)]))
    code = baseline_mod.compare_baselines(baseline=tmp_path / "no-such-baseline.json", current=curr)
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code != 0
    assert "baseline" in out.lower()


def test_compare_matching_names_reports_matched_count(baseline_mod, tmp_path, capsys):
    """Clean control: overlapping names compare, and the count is matched."""
    base = _write_json(
        tmp_path / "baseline.json",
        _doc([_bench("test_alpha", 1.0), _bench("test_beta", 2.0)]),
    )
    curr = _write_json(
        tmp_path / "current.json",
        _doc([_bench("test_alpha", 1.05), _bench("test_beta", 2.0)]),
    )
    code = baseline_mod.compare_baselines(baseline=base, current=curr)
    out = capsys.readouterr().out
    assert code == 0
    assert "Total benchmarks compared: 2" in out
    assert "No significant changes detected" in out


def test_compare_regression_still_fails(baseline_mod, tmp_path, capsys):
    """A >20% slowdown on a matched benchmark still fails the gate."""
    base = _write_json(tmp_path / "baseline.json", _doc([_bench("test_alpha", 1.0)]))
    curr = _write_json(tmp_path / "current.json", _doc([_bench("test_alpha", 1.5)]))
    code = baseline_mod.compare_baselines(baseline=base, current=curr)
    assert code != 0


# ---------------------------------------------------------------------------
# ENG-13 (W7): identical pinned code/environment is required
# ---------------------------------------------------------------------------


def test_compare_python_version_mismatch_fails(baseline_mod, tmp_path, capsys):
    """A baseline measured on a different Python is incomparable: refuse."""
    base = _write_json(
        tmp_path / "baseline.json", _doc([_bench("test_alpha", 1.0)], python_version="3.11.0")
    )
    curr = _write_json(
        tmp_path / "current.json", _doc([_bench("test_alpha", 1.0)], python_version="3.12.3")
    )
    code = baseline_mod.compare_baselines(baseline=base, current=curr)
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code != 0
    assert "python" in out.lower()


def test_compare_lockfile_mismatch_fails(baseline_mod, tmp_path, capsys):
    """A baseline measured against a different pinned lockfile is stale: refuse."""
    base = _write_json(
        tmp_path / "baseline.json", _doc([_bench("test_alpha", 1.0)], lockfile_sha256="b" * 64)
    )
    curr = _write_json(
        tmp_path / "current.json", _doc([_bench("test_alpha", 1.0)], lockfile_sha256="c" * 64)
    )
    code = baseline_mod.compare_baselines(baseline=base, current=curr)
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code != 0
    assert "lockfile" in out.lower()


def test_compare_missing_identity_fails(baseline_mod, tmp_path, capsys):
    """A baseline without any environment identity is incomparable: refuse."""
    base = _write_json(tmp_path / "baseline.json", {"benchmarks": [_bench("test_alpha", 1.0)]})
    curr = _write_json(tmp_path / "current.json", _doc([_bench("test_alpha", 1.0)]))
    code = baseline_mod.compare_baselines(baseline=base, current=curr)
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code != 0
    assert "identity" in out.lower()


def test_compare_baseline_without_lockfile_digest_fails(baseline_mod, tmp_path, capsys):
    """A pre-stamp baseline (no lockfile digest) cannot prove an identical
    environment: refuse, naming the remedy (re-publish a stamped baseline)."""
    baseline_data = _doc([_bench("test_alpha", 1.0)])
    del baseline_data["environment"]["lockfile_sha256"]
    base = _write_json(tmp_path / "baseline.json", baseline_data)
    curr = _write_json(tmp_path / "current.json", _doc([_bench("test_alpha", 1.0)]))
    code = baseline_mod.compare_baselines(baseline=base, current=curr)
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code != 0
    assert "lockfile" in out.lower()


def test_compare_expected_baseline_code_sha_mismatch_fails(baseline_mod, tmp_path, capsys):
    """The baseline must come from the resolved immutable run: a code SHA
    that is not the resolved run's head SHA is refused, not plotted."""
    base = _write_json(tmp_path / "baseline.json", _doc([_bench("test_alpha", 1.0)]))
    curr = _write_json(
        tmp_path / "current.json", _doc([_bench("test_alpha", 1.0)], code_sha="d" * 40)
    )
    code = baseline_mod.compare_baselines(
        baseline=base, current=curr, expected_baseline_code_sha="e" * 40
    )
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code != 0
    assert "code_sha" in out or "baseline" in out.lower()


def test_compare_expected_baseline_code_sha_match_passes(baseline_mod, tmp_path, capsys):
    """Control: baseline code SHA equal to the resolved run's SHA compares.
    (Baseline and current code SHAs legitimately differ: the baseline is
    the older main commit; only the environment must be identical.)"""
    base = _write_json(tmp_path / "baseline.json", _doc([_bench("test_alpha", 1.0)]))
    curr = _write_json(
        tmp_path / "current.json", _doc([_bench("test_alpha", 1.0)], code_sha="d" * 40)
    )
    code = baseline_mod.compare_baselines(
        baseline=base, current=curr, expected_baseline_code_sha="a" * 40
    )
    assert code == 0


def test_compare_pytest_benchmark_native_identity_is_read(baseline_mod, tmp_path, capsys):
    """Real pytest-benchmark JSON carries identity as machine_info /
    commit_info (no stamped block): that native identity is honoured."""
    base_data = {
        "machine_info": {"python_version": "3.12.3"},
        "commit_info": {"id": "a" * 40},
        "benchmarks": [_bench("test_alpha", 1.0)],
    }
    curr_data = {
        "machine_info": {"python_version": "3.12.3"},
        "commit_info": {"id": "d" * 40},
        "benchmarks": [_bench("test_alpha", 1.0)],
    }
    base = _write_json(tmp_path / "baseline.json", base_data)
    curr = _write_json(tmp_path / "current.json", curr_data)
    code = baseline_mod.compare_baselines(
        baseline=base, current=curr, expected_baseline_code_sha="a" * 40
    )
    # No lockfile digest in either file: the stamped lockfile check cannot
    # run, so this fails closed on the missing lockfile identity.
    assert code != 0
    captured = capsys.readouterr()
    assert "lockfile" in (captured.out + captured.err).lower()


# ---------------------------------------------------------------------------
# ENG-13 (W7): predeclared slices
# ---------------------------------------------------------------------------


def test_compare_missing_predeclared_slice_fails(baseline_mod, tmp_path, capsys):
    """A predeclared slice absent from BOTH files is still a failure: the
    compared set must cover the declared slices, not just the overlap."""
    base = _write_json(tmp_path / "baseline.json", _doc([_bench("test_alpha", 1.0)]))
    curr = _write_json(tmp_path / "current.json", _doc([_bench("test_alpha", 1.0)]))
    code = baseline_mod.compare_baselines(
        baseline=base, current=curr, expected_benchmarks=["test_alpha", "test_missing_slice"]
    )
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code != 0
    assert "test_missing_slice" in out


def test_compare_all_predeclared_slices_present_passes(baseline_mod, tmp_path, capsys):
    base = _write_json(
        tmp_path / "baseline.json",
        _doc([_bench("test_alpha", 1.0), _bench("test_beta", 2.0)]),
    )
    curr = _write_json(
        tmp_path / "current.json",
        _doc([_bench("test_alpha", 1.0), _bench("test_beta", 2.0)]),
    )
    code = baseline_mod.compare_baselines(
        baseline=base, current=curr, expected_benchmarks=["test_alpha", "test_beta"]
    )
    assert code == 0


def test_benchmark_slices_match_test_file():
    """The predeclared slice manifest must equal the benchmark tests in
    tests/test_performance.py, so the manifest cannot drift from the suite."""
    import re

    manifest = SCRIPTS_DIR / "benchmark-slices.txt"
    declared = {
        line.strip()
        for line in manifest.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    test_file = REPO_ROOT / "tests" / "test_performance.py"
    found = set(
        re.findall(r"def (test_\w+)\(self, benchmark", test_file.read_text(encoding="utf-8"))
    )
    assert declared, "slice manifest is empty"
    assert declared == found, (
        f"slice manifest drifted from tests/test_performance.py: "
        f"only-in-manifest={sorted(declared - found)}, only-in-tests={sorted(found - declared)}"
    )


# ---------------------------------------------------------------------------
# ENG-13 (W7): stamp subcommand records the identity
# ---------------------------------------------------------------------------


def test_stamp_records_identity(baseline_mod, tmp_path):
    """stamp adds an environment block with code SHA, Python and the
    pinned-lockfile digest, so the artifact is comparable later."""
    results = _write_json(
        tmp_path / "pytest-performance.json",
        {
            "machine_info": {"python_version": "3.12.3"},
            "commit_info": {"id": "a" * 40},
            "benchmarks": [_bench("test_alpha", 1.0)],
        },
    )
    code = baseline_mod.stamp_identity(results=results, repo_root=REPO_ROOT)
    assert code == 0
    stamped = json.loads(results.read_text(encoding="utf-8"))
    env = stamped["environment"]
    assert env["python_version"].startswith("3.")
    assert env["code_sha"]
    assert env["lockfile"] == "requirements-hashed.txt"
    import hashlib

    assert (
        env["lockfile_sha256"]
        == hashlib.sha256((REPO_ROOT / "requirements-hashed.txt").read_bytes()).hexdigest()
    )
    assert stamped["benchmarks"] == [_bench("test_alpha", 1.0)]


def test_stamp_is_idempotent(baseline_mod, tmp_path):
    results = _write_json(
        tmp_path / "pytest-performance.json",
        {"benchmarks": [_bench("test_alpha", 1.0)]},
    )
    assert baseline_mod.stamp_identity(results=results, repo_root=REPO_ROOT) == 0
    first = json.loads(results.read_text(encoding="utf-8"))
    assert baseline_mod.stamp_identity(results=results, repo_root=REPO_ROOT) == 0
    second = json.loads(results.read_text(encoding="utf-8"))
    assert first == second


def test_stamp_missing_file_fails(baseline_mod, tmp_path, capsys):
    assert baseline_mod.stamp_identity(results=tmp_path / "no-such.json", repo_root=REPO_ROOT) != 0
    captured = capsys.readouterr()
    assert "error" in (captured.out + captured.err).lower()


def test_stamp_empty_benchmarks_fails(baseline_mod, tmp_path, capsys):
    results = _write_json(tmp_path / "empty.json", {"benchmarks": []})
    assert baseline_mod.stamp_identity(results=results, repo_root=REPO_ROOT) != 0
    captured = capsys.readouterr()
    assert "benchmark" in (captured.out + captured.err).lower()


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


# ---------------------------------------------------------------------------
# Workflow structure (ENG-13, W7): the workflow must compare through the
# fail-closed helper, on a stamped identity, against a verified artifact.
# ---------------------------------------------------------------------------


def _step_index(name_fragment: str) -> int:
    for index, step in enumerate(_workflow_steps()):
        if name_fragment in str(step.get("name", "")):
            return index
    raise AssertionError(f"no step matching {name_fragment!r} in benchmark.yml")


def test_benchmark_download_step_skipped_when_comparison_skipped():
    """An explicit dispatch opt-out must not attempt a download: with an
    empty resolved run id the download would fail the job instead of
    skipping. The download step runs only when comparison is required."""
    step = _step_by_name("Download performance baseline")
    condition = str(step.get("if", ""))
    assert "resolve-baseline" in condition
    assert "required" in condition


def test_benchmark_resolve_step_verifies_baseline_artifact_and_sha():
    """Resolving a run id is not enough: the step must verify the
    performance-baseline-main artifact exists on that run and record
    the run's head SHA, so the comparison can prove the artifact came
    from the resolved immutable run."""
    step = _step_by_name("Resolve baseline run")
    script = str(step.get("run", ""))
    assert "artifacts" in script
    assert "performance-baseline-main" in script
    assert "baseline_sha=" in script
    assert "head_sha" in script


def test_benchmark_results_are_stamped_before_compare():
    """pytest-performance.json must carry its environment identity
    (code SHA, Python, pinned-lockfile digest) before it is compared
    or uploaded as a baseline, or the comparison cannot prove an
    identical environment."""
    stamp_index = _step_index("Stamp")
    compare_index = _step_index("Compare performance against baseline")
    upload_index = _step_index("Upload performance baseline")
    assert stamp_index < compare_index
    assert stamp_index < upload_index
    step = _step_by_name("Stamp")
    script = str(step.get("run", ""))
    assert "performance_baseline.py stamp" in script
    assert "pytest-performance.json" in script


def test_benchmark_compare_step_uses_fail_closed_helper():
    """The workflow's comparison must run the fail-closed helper FIRST
    (overlap / means / identity / predeclared slices / resolved-run
    SHA), before pytest-benchmark's own --benchmark-compare, whose
    zero-overlap result is a vacuous pass."""
    step = _step_by_name("Compare performance against baseline")
    script = str(step.get("run", ""))
    assert "performance_baseline.py compare" in script
    assert "--expected-benchmarks-file scripts/benchmark-slices.txt" in script
    assert "--expected-baseline-code-sha" in script
    helper_pos = script.index("performance_baseline.py compare")
    bench_pos = script.index("--benchmark-compare")
    assert helper_pos < bench_pos, "fail-closed helper must gate the pytest-benchmark compare"


def test_benchmark_compare_step_still_fails_on_regression():
    """The pytest-benchmark threshold comparison stays as the reporting
    pass: the helper gates comparability, --benchmark-compare-fail
    still gates the >20% regression."""
    step = _step_by_name("Compare performance against baseline")
    script = str(step.get("run", ""))
    assert "--benchmark-compare-fail=mean:1.20" in script
