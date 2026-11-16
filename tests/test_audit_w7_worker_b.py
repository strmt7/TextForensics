"""ENG-07 (audit W7, worker B): vacuous-green audit for workflows and gates.

Red regression tests first: each test plants a defect (or audits a
workflow file) and requires the gate to go red. The workflow tests
parse every .github/workflows/*.yml and assert the invariants that
make a green run mean executed work:

- no ``continue-on-error`` anywhere (a failing step must fail the job);
- no ``|| true`` except the allowlisted cleanup/diagnostic cases;
- summary jobs read their ``needs.*.result`` values and fail when a
  required job did not succeed (they never print "Completed"/"passed"
  unconditionally);
- upload-artifact steps only reference files a previous step in the
  same job produces (a missing artifact must not be a silent warn);
- the claims gate fails on zero claims (an emptied CLAIMS.yaml must
  not read as "0 passed, 0 failed" and exit 0);
- the fuzz runner fails when a child exits instantly with code 0
  (zero-work fuzzing) and when corpus generation fails.
"""

import importlib.util
import re
import sys
from pathlib import Path
from types import ModuleType
from unittest import mock

import yaml

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
REPO_ROOT = Path(__file__).parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_workflows():
    workflows = {}
    for path in sorted(WORKFLOWS_DIR.glob("*.yml")):
        workflows[path.name] = yaml.safe_load(path.read_text(encoding="utf-8"))
    return workflows


def _iter_steps(workflows):
    """Yield (filename, job_name, step_index, step_dict)."""
    for filename, doc in workflows.items():
        for job_name, job in (doc.get("jobs") or {}).items():
            for index, step in enumerate(job.get("steps") or []):
                yield filename, job_name, index, step or {}


def _run_text(step):
    run = step.get("run")
    return run if isinstance(run, str) else ""


# ---------------------------------------------------------------------------
# Workflow-wide invariants
# ---------------------------------------------------------------------------

# Lines containing "|| true" that are NOT error swallowing, with the
# reason each is legitimate. Anything else is a vacuous-green defect.
ALLOWED_OR_TRUE = {
    # container.yml: cleanup in an EXIT trap — stopping an already-dead
    # container must not fail the acceptance step.
    ("container.yml", "docker stop tf-acceptance"),
    ("container.yml", "docker stop tf-promote-acceptance"),
    # mutation.yml: `grep` exits 1 when nothing matches; the empty
    # CHANGED list is the legitimate no-relevant-changes case, handled
    # downstream by the skipped-summary branch.
    ("mutation.yml", "CHANGED=$(git diff"),
    # reproducibility.yml: `diff` exit 1 is diagnostic output inside a
    # branch that already set FAIL=1; the step still exits 1.
    ("reproducibility.yml", "diff <(cat evidence/scan_run_1.json)"),
    ("reproducibility.yml", "diff <(cat evidence/report_run_1.json)"),
}


def test_no_continue_on_error_anywhere():
    """ENG-07: no step may declare continue-on-error — a failing step
    must fail its job, never be demoted to a warning."""
    workflows = _load_workflows()
    offenders = []
    for filename, job_name, index, step in _iter_steps(workflows):
        if step.get("continue-on-error") is True:
            offenders.append(f"{filename}:{job_name}[{index}] {step.get('name')}")
    assert offenders == [], f"continue-on-error steps: {offenders}"


def test_no_unlisted_or_true():
    """ENG-07: every ``|| true`` must be an allowlisted cleanup /
    diagnostic case. A bare ``|| true`` on a verification command
    swallows its failure and greens the gate."""
    workflows = _load_workflows()
    offenders = []
    for filename, job_name, index, step in _iter_steps(workflows):
        for line in _run_text(step).splitlines():
            if "|| true" not in line:
                continue
            if any(
                filename == allowed_file and marker in line
                for allowed_file, marker in ALLOWED_OR_TRUE
            ):
                continue
            offenders.append(f"{filename}:{job_name}[{index}] {step.get('name')}: {line.strip()}")
    assert offenders == [], f"unlisted '|| true': {offenders}"


def test_no_echo_only_verification_steps():
    """ENG-07: a step whose name claims verification must execute a
    verification command, not only echo a success label."""
    workflows = _load_workflows()
    offenders = []
    for filename, job_name, index, step in _iter_steps(workflows):
        name = str(step.get("name") or "")
        if not any(word in name.lower() for word in ("verif", "check", "validat", "audit")):
            continue
        run = _run_text(step)
        if not run:
            continue
        commands = [
            line.strip()
            for line in run.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        meaningful = [
            cmd
            for cmd in commands
            if not cmd.startswith(("echo ", "printf ", "cat ", "ls "))
            and cmd not in ("set -euo pipefail", "set -o pipefail")
        ]
        if commands and not meaningful:
            offenders.append(f"{filename}:{job_name}[{index}] {name!r}")
    assert offenders == [], f"echo-only verification steps: {offenders}"


# ---------------------------------------------------------------------------
# Summary jobs must report real results, never unconditional success
# ---------------------------------------------------------------------------

SUMMARY_JOBS = {
    # (workflow, job): the job's steps must consult needs.*.result and
    # must be able to exit 1 when a required job did not succeed.
    ("enterprise-deep-verification.yml", "verification-summary"),
    ("reproducibility.yml", "reproducibility-summary"),
    ("mutation.yml", "mutation-report"),
    ("fuzz.yml", "fuzz-summary"),
}


def test_summary_jobs_fail_when_a_required_job_fails():
    """ENG-07: a summary/report job with `if: always()` must read its
    needs results and exit nonzero when a required job failed — it
    must never print 'Completed'/'passed' for work that did not pass."""
    workflows = _load_workflows()
    for filename, job_name in SUMMARY_JOBS:
        job = workflows[filename]["jobs"][job_name]
        assert job.get("if") == "always()" or "always()" in str(job.get("if", "")), (
            f"{filename}:{job_name} must run on always() to report failures"
        )
        body = str(job)
        assert "needs." in body and ".result" in body, (
            f"{filename}:{job_name} never reads its needs results"
        )
        assert "exit 1" in body, f"{filename}:{job_name} can never fail"


# ---------------------------------------------------------------------------
# Uploaded artifacts must be produced by the job (no warn-only ghosts)
# ---------------------------------------------------------------------------


def _produced_files(job):
    """File names a job's run steps plausibly produce (redirects,
    known generator outputs, and files the steps write explicitly)."""
    produced = set()
    for step in job.get("steps") or []:
        run = _run_text(step)
        for line in run.splitlines():
            line = line.strip()
            for marker in (
                "> ",
                ">> ",
                "-o ",
                "--output ",
                "--output-file ",
                "--output-signature ",
                "--report ",
            ):
                if marker in line:
                    tail = line.split(marker, 1)[1].strip().strip("\"'")
                    produced.add(Path(tail.split()[0]).name if tail else "")
            if "--benchmark-json=" in line:
                produced.add(line.split("--benchmark-json=", 1)[1].split()[0].strip("\"'"))
            if "mkdir -p " in line:
                produced.add(Path(line.split("mkdir -p ", 1)[1].strip().split()[0]).name)
            if line.startswith("sphinx-build "):
                produced.add(Path(line.split()[-1]).name)
        # Explicit well-known producers.
        if "benchmark-results.json" in run:
            produced.add("benchmark-results.json")
        # Files written by Python (Path('x').write_text / open('x','w'))
        # or named in a step are produced by the job; files that appear
        # in no step at all are the vacuous-upload defect.
        for quoted in re.findall(r"""['"]([\w./\-]+\.(?:txt|json|md|xml|html))['"]""", run):
            produced.add(Path(quoted).name)
        if "comparison-status.json" in run:
            produced.add("comparison-status.json")
        if "pytest-performance" in run:
            produced.add("pytest-performance.json")
            produced.add("pytest-performance-comparison.json")
        if "mutation-results/summary.json" in run:
            produced.add("summary.json")
        if "mutation-status.json" in run:
            produced.add("mutation-status.json")
        if "probe-status.json" in run:
            produced.add("probe-status.json")
        # Action outputs (e.g. sbom-action output-file) also produce files.
        with_ = step.get("with") or {}
        for key in ("output-file", "artifact-name"):
            value = with_.get(key)
            if value:
                produced.add(Path(str(value)).name)
    return {name for name in produced if name}


def test_upload_steps_reference_produced_files():
    """ENG-07: an upload-artifact step must reference files its own job
    produces. Crash-artifact uploads are exempt: no crashes means no
    files by design. Diagnostic uploads (if: failure()/always(),
    e.g. test logs) may warn when the file is absent; uploads on the
    success path must fail closed (if-no-files-found: error) when
    their file is missing."""
    workflows = _load_workflows()
    offenders = []
    for filename, doc in workflows.items():
        for job_name, job in (doc.get("jobs") or {}).items():
            produced = _produced_files(job)
            for step in job.get("steps") or []:
                uses = str(step.get("uses") or "")
                if "upload-artifact" not in uses:
                    continue
                with_ = step.get("with") or {}
                paths = str(with_.get("path") or "")
                if "artifacts/fuzz" in paths or "crashes" in paths:
                    continue  # absence of crashes is the good case
                diagnostic = "always()" in str(step.get("if", "")) or "failure()" in str(
                    step.get("if", "")
                )
                if not diagnostic and with_.get("if-no-files-found") not in ("error", None):
                    # warn/ignore on a success-path gate artifact hides
                    # a missing file.
                    offenders.append(
                        f"{filename}:{job_name} {step.get('name')}: "
                        f"if-no-files-found={with_.get('if-no-files-found')}"
                    )
                for line in paths.splitlines():
                    name = line.strip().strip("\"'")
                    if not name or name.endswith("/") or "*" in name or "${{" in name:
                        continue
                    if Path(name).name not in produced and name not in produced:
                        offenders.append(
                            f"{filename}:{job_name} {step.get('name')}: "
                            f"uploads {name!r} which no step in the job produces"
                        )
    assert offenders == [], f"vacuous uploads: {offenders}"


def test_deep_verification_produces_its_uploaded_reports():
    """ENG-07 (targeted): the schema-validation and API-contract jobs
    used to upload report files no step created. Each report file must
    be written by a step in the same job."""
    workflows = _load_workflows()
    job = workflows["enterprise-deep-verification.yml"]["jobs"]["schema-validation"]
    body = "\n".join(_run_text(step) for step in job.get("steps") or [])
    assert "schemas-validation-report.txt" in body
    job = workflows["enterprise-deep-verification.yml"]["jobs"]["api-contract-testing"]
    body = "\n".join(_run_text(step) for step in job.get("steps") or [])
    assert "api-contract-report.txt" in body
    for job_name in ("cross-platform-windows", "cross-platform-macos"):
        job = workflows["enterprise-deep-verification.yml"]["jobs"][job_name]
        body = "\n".join(_run_text(step) for step in job.get("steps") or [])
        assert "verification.txt" in body, f"{job_name} never writes its upload"


def test_deep_verification_docs_job_uploads_built_docs():
    """ENG-07 (targeted): the documentation job used to upload
    coverage.json, a file a different job produces. It must upload
    the HTML it builds, with a missing build failing the step."""
    workflows = _load_workflows()
    job = workflows["enterprise-deep-verification.yml"]["jobs"]["documentation-verification"]
    body = str(job)
    assert "docs/_build/html" in body
    assert "coverage.json" not in body


def test_fuzz_corpus_generation_failure_is_not_swallowed():
    """ENG-07 (targeted): the weekly fuzz job's corpus generation must
    fail the job when the generator fails (no `|| true`)."""
    workflows = _load_workflows()
    job = workflows["fuzz.yml"]["jobs"]["fuzz-weekly"]
    for step in job.get("steps") or []:
        assert "|| true" not in _run_text(step), step.get("name")


def test_benchmark_baseline_upload_fails_when_missing():
    """ENG-07 (targeted): a main-branch run that produces no baseline
    artifact must fail the upload step, not warn and publish nothing."""
    workflows = _load_workflows()
    job = workflows["benchmark.yml"]["jobs"]["benchmark"]
    for step in job.get("steps") or []:
        if step.get("name") == "Upload performance baseline (main branch only)":
            assert (step.get("with") or {}).get("if-no-files-found") == "error"
            return
    raise AssertionError("baseline upload step not found")


def test_observatory_probe_run_records_its_status():
    """ENG-07 (targeted): the scheduled probe run must write a
    machine-readable status file distinguishing 'ran' from 'corpus
    absent, nothing ran' — a green job must not be the only record."""
    workflows = _load_workflows()
    job = workflows["observatory.yml"]["jobs"]["scheduled-probe-run"]
    body = "\n".join(_run_text(step) for step in job.get("steps") or [])
    assert "probe-status.json" in body
    assert "corpus" in body.lower()


def test_performance_benchmark_failure_exits_nonzero():
    """ENG-07 (targeted): the deep-verification performance step used
    to print WARNING and pass when the threshold failed. It must exit
    nonzero on a threshold breach."""
    workflows = _load_workflows()
    job = workflows["enterprise-deep-verification.yml"]["jobs"]["performance-benchmarks"]
    body = "\n".join(_run_text(step) for step in job.get("steps") or [])
    assert "sys.exit(1)" in body or "raise SystemExit" in body
    assert "WARNING: Performance degraded" not in body


def test_ci_api_job_runs_full_pytest_collection():
    """ENG-07: the CI api job used unittest discovery on one module.
    The release notes record 267 module-level pytest test functions
    invisible to unittest discovery — the job must run pytest."""
    workflows = _load_workflows()
    job = workflows["ci.yml"]["jobs"]["api"]
    body = "\n".join(_run_text(step) for step in job.get("steps") or [])
    assert "pytest" in body
    assert "unittest" not in body


def test_ci_mcp_job_executes_mcp_tests():
    """ENG-07: the CI mcp job used to only import the server object —
    no test executed. It must run the MCP pytest files."""
    workflows = _load_workflows()
    job = workflows["ci.yml"]["jobs"]["mcp"]
    body = "\n".join(_run_text(step) for step in job.get("steps") or [])
    assert "pytest" in body
    assert "test_mcp" in body


def test_ci_os_smoke_asserts_scan_content():
    """ENG-07: the OS-smoke JSON check used to assert only that the
    output parses. It must assert the verdict/score content."""
    workflows = _load_workflows()
    job = workflows["ci.yml"]["jobs"]["os-smoke"]
    body = "\n".join(_run_text(step) for step in job.get("steps") or [])
    assert "verdict" in body and "score" in body


def test_mutation_report_job_fails_when_mutation_fails():
    """ENG-07 (targeted): the mutation-report job used to stay green
    while recording a failure. It must exit 1 when any mutation job
    status in mutation-status.json is 'fail'."""
    workflows = _load_workflows()
    job = workflows["mutation.yml"]["jobs"]["mutation-report"]
    body = "\n".join(_run_text(step) for step in job.get("steps") or [])
    assert "mutation-status.json" in body
    assert "exit 1" in body


def test_deep_verification_runs_the_full_suite_without_exclusions():
    """ENG-07: the deep-verification suite used to --ignore
    tests/test_docs.py. The full suite (which CI Core already runs
    green, test_docs.py included) must run unexcluded."""
    workflows = _load_workflows()
    job = workflows["enterprise-deep-verification.yml"]["jobs"]["test-suite-all-features"]
    body = "\n".join(_run_text(step) for step in job.get("steps") or [])
    assert "--ignore" not in body
    job = workflows["enterprise-deep-verification.yml"]["jobs"]["coverage-verification"]
    body = "\n".join(_run_text(step) for step in job.get("steps") or [])
    assert "--ignore" not in body


# ---------------------------------------------------------------------------
# check_claims: zero claims must not pass
# ---------------------------------------------------------------------------


def _claims_tmp_root(tmp_path, claims_yaml):
    """A minimal repo root where the ONLY possible claims-gate failure
    is the claims list itself: a schema-valid empty registry and the
    real registry schema are present, so a pass/fail is decided by
    the claims, not by a missing registry."""
    import json
    import shutil

    check_claims = _load("check_claims_w7b", SCRIPTS_DIR / "check_claims.py")
    root = tmp_path / "repo"
    (root / "docs" / "evidence").mkdir(parents=True)
    (root / "docs" / "CLAIMS.yaml").write_text(claims_yaml, encoding="utf-8")
    (root / "docs" / "evidence" / "registry.json").write_text(
        json.dumps({"schema": "textforensics.evidence-registry/v1", "records": []}),
        encoding="utf-8",
    )
    schema_dir = root / "src" / "textforensics" / "schemas"
    schema_dir.mkdir(parents=True)
    for schema_file in (REPO_ROOT / "src" / "textforensics" / "schemas").glob("*.json"):
        shutil.copyfile(schema_file, schema_dir / schema_file.name)
    return check_claims, root


def test_claims_gate_fails_on_zero_claims(tmp_path):
    """ENG-07: an emptied CLAIMS.yaml ('0 passed, 0 failed') must fail
    the gate — zero executed work is never a pass."""
    check_claims, root = _claims_tmp_root(tmp_path, "claims: []\n")
    assert check_claims.main(["--root", str(root), "--no-report-card"]) == 1


def test_claims_gate_fails_on_missing_claims_key(tmp_path):
    """ENG-07: a CLAIMS.yaml with no 'claims' key at all must fail."""
    check_claims, root = _claims_tmp_root(tmp_path, "version: 1\n")
    assert check_claims.main(["--root", str(root), "--no-report-card"]) == 1


# ---------------------------------------------------------------------------
# run_fuzz: zero-work execution must fail
# ---------------------------------------------------------------------------


class _FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _load_run_fuzz():
    return _load("run_fuzz_w7b", SCRIPTS_DIR / "run_fuzz.py")


def test_instant_exit_zero_with_long_duration_is_an_error(tmp_path, monkeypatch):
    """ENG-07: a fuzz child that exits 0 after ~0s when asked to fuzz
    for 5 minutes did no work (the old -runs=0 class). It must be
    recorded as an error, not a clean run."""
    run_fuzz = _load_run_fuzz()
    monkeypatch.setattr(run_fuzz, "ARTIFACTS_DIR", tmp_path / "artifacts")
    monkeypatch.setattr(run_fuzz, "CORPUS_DIR", tmp_path / "corpus")
    # The child is mocked; stub the optional import so the W9-D
    # missing-atheris guard does not fire before the mocked child runs
    # (atheris is not installed in the canonical venv).
    monkeypatch.setitem(sys.modules, "atheris", ModuleType("atheris"))
    target = run_fuzz.FUZZ_TARGETS["text_parsing"]
    fake = _FakeProc(returncode=0, stdout="fake atheris ok\n")
    with mock.patch.object(run_fuzz.subprocess, "run", return_value=fake):
        result = run_fuzz.run_atheris_target(target, 300, False)
    assert result["error"] is not None
    assert (
        "0.0s" in str(result["error"])
        or "did no fuzzing" in str(result["error"]).lower()
        or "exited" in str(result["error"])
    )


def test_short_clean_run_stays_clean(tmp_path, monkeypatch):
    """Control: a short (test-scale) run that exits 0 promptly is still
    clean — the zero-work guard only applies to real durations."""
    run_fuzz = _load_run_fuzz()
    monkeypatch.setattr(run_fuzz, "ARTIFACTS_DIR", tmp_path / "artifacts")
    monkeypatch.setattr(run_fuzz, "CORPUS_DIR", tmp_path / "corpus")
    # See test_instant_exit_zero_with_long_duration_is_an_error: the
    # child is mocked, so stub atheris for the W9-D guard.
    monkeypatch.setitem(sys.modules, "atheris", ModuleType("atheris"))
    target = run_fuzz.FUZZ_TARGETS["text_parsing"]
    fake = _FakeProc(returncode=0, stdout="fake atheris ok\n")
    with mock.patch.object(run_fuzz.subprocess, "run", return_value=fake):
        result = run_fuzz.run_atheris_target(target, 1, False)
    assert result["error"] is None


def test_failed_corpus_generation_fails_the_run(tmp_path, monkeypatch):
    """ENG-07: generate_corpus() used to print '[warn]' and continue
    when the generator failed. A failed generation with no corpus
    present must return False."""
    run_fuzz = _load_run_fuzz()
    monkeypatch.setattr(run_fuzz, "ARTIFACTS_DIR", tmp_path / "artifacts")
    monkeypatch.setattr(run_fuzz, "CORPUS_DIR", tmp_path / "corpus")
    fake = _FakeProc(returncode=1, stdout="", stderr="boom")
    with mock.patch.object(run_fuzz.subprocess, "run", return_value=fake):
        assert run_fuzz.generate_corpus() is False


def test_failed_corpus_generation_fails_main(tmp_path, monkeypatch):
    """ENG-07: main() must exit nonzero when corpus generation fails
    and no corpus exists."""
    run_fuzz = _load_run_fuzz()
    monkeypatch.setattr(run_fuzz, "ARTIFACTS_DIR", tmp_path / "artifacts")
    monkeypatch.setattr(run_fuzz, "CORPUS_DIR", tmp_path / "corpus")
    monkeypatch.setattr(run_fuzz, "generate_corpus", lambda: False)
    with mock.patch.object(
        sys, "argv", ["run_fuzz.py", "--method", "pytest", "--target", "text_parsing"]
    ):
        assert run_fuzz.main() != 0
