"""RED regression tests for ENG-07 workflow gates (W0).

Covers the workflow files, not live GitHub runs:
- repository-integrity.yml: no echo-only signature/attestation placeholders.
- enterprise-deep-verification.yml: no continue-on-error / || true
  suppression, no --forked without the plugin, no unquoted shell
  requirement ranges, schema validation installs the project and imports
  a symbol that exists.
- mutation.yml: the full-mutation skip on push is explicit and
  machine-checkable (status vocabulary, not a silent pass).
- fuzz.yml (companion to the run_fuzz.py fix): the direct fuzz step must
  not swallow run_fuzz.py's exit code with `|| true`.
"""

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
WORKFLOWS = REPO_ROOT / ".github" / "workflows"


def _load(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def _text(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def _steps(workflow: dict, job: str) -> list[dict]:
    return workflow["jobs"][job]["steps"]


# ---------------------------------------------------------------------------
# ENG-07(1): repository-integrity.yml
# ---------------------------------------------------------------------------


def test_integrity_no_placeholder_steps():
    text = _text("repository-integrity.yml")
    assert "placeholder" not in text.lower()


def test_integrity_signatures_are_really_verified():
    workflow = _load("repository-integrity.yml")
    step = next(s for s in _steps(workflow, "sigstore") if "signatures" in str(s.get("name", "")))
    run = str(step.get("run", ""))
    assert "cosign verify-blob" in run
    assert "exit 1" in run
    assert "integrity verified" not in run.lower()
    # A step that only echoes a success label without verification work
    # is a placeholder; the verification command must run before any
    # success label is printed.
    assert run.index("cosign verify-blob") < run.index("verified signatures:")


def test_integrity_attestations_are_really_verified():
    workflow = _load("repository-integrity.yml")
    step = next(s for s in _steps(workflow, "sigstore") if "attestation" in str(s.get("name", "")))
    run = str(step.get("run", ""))
    assert "gh attestation verify" in run
    assert "exit 1" in run


def test_integrity_fail_closed_when_no_release_exists():
    """No signed release => the step fails (unavailable), never passes."""
    workflow = _load("repository-integrity.yml")
    for step in _steps(workflow, "sigstore"):
        run = str(step.get("run", ""))
        if "verify" in str(step.get("name", "")).lower():
            assert "unavailable" in run.lower()
            assert "exit 1" in run


# ---------------------------------------------------------------------------
# ENG-07(2): enterprise-deep-verification.yml
# ---------------------------------------------------------------------------


def test_deep_verification_full_suite_failure_propagates():
    workflow = _load("enterprise-deep-verification.yml")
    step = next(
        s
        for s in _steps(workflow, "test-suite-all-features")
        if "pytest suite" in str(s.get("name", ""))
    )
    assert step.get("continue-on-error") is not True
    assert "continue-on-error" not in step


def test_deep_verification_sphinx_failure_propagates():
    text = _text("enterprise-deep-verification.yml")
    assert "|| true" not in text


def test_deep_verification_no_forked_without_plugin():
    text = _text("enterprise-deep-verification.yml")
    assert "--forked" not in text


def test_deep_verification_requirement_ranges_quoted():
    text = _text("enterprise-deep-verification.yml")
    for spec in ("pip-audit>=2,<3", "bandit>=1.7,<2", "httpx>=0.27,<1"):
        assert f'"{spec}"' in text, f"unquoted requirement range: {spec}"
        # No bare (unquoted) occurrence on a pip install line.
        for line in text.splitlines():
            stripped = line.strip()
            if spec in stripped and stripped.startswith(("python -m pip install", ".audit-env")):
                assert stripped.count(f'"{spec}"') == 1, line


def test_deep_verification_schema_job_installs_project_and_imports_real_symbol():
    workflow = _load("enterprise-deep-verification.yml")
    steps = _steps(workflow, "schema-validation")
    runs = [str(s.get("run", "")) for s in steps]
    joined = "\n".join(runs)
    assert "pip install -e" in joined
    assert "from textforensics.casefile import CaseFile" not in joined
    assert "import CaseFile" not in joined
    assert "load_schema" in joined


# ---------------------------------------------------------------------------
# ENG-07(6): mutation.yml — explicit, machine-checkable skip
# ---------------------------------------------------------------------------


def test_mutation_full_skip_is_explicit_and_machine_checkable():
    text = _text("mutation.yml")
    assert "not_applicable" in text
    assert "no full mutation work executed" in text
    workflow = _load("mutation.yml")
    report_steps = _steps(workflow, "mutation-report")
    runs = [str(s.get("run", "")) for s in report_steps]
    joined = "\n".join(runs)
    assert "mutation-status.json" in joined
    assert "mutation-full" in joined


def test_mutation_report_distinguishes_skipped_from_passed():
    workflow = _load("mutation.yml")
    report_steps = _steps(workflow, "mutation-report")
    joined = "\n".join(str(s.get("run", "")) for s in report_steps)
    assert "skipped" in joined.lower()
    assert "passed" in joined.lower()
    # The summary must carry a row for the full job even when it did not run.
    assert "mutation-results-full" in joined or "mutation-full" in joined


# ---------------------------------------------------------------------------
# ENG-07(3) companion: fuzz.yml must not swallow run_fuzz.py's exit code
# ---------------------------------------------------------------------------


def test_fuzz_direct_step_does_not_swallow_exit_code():
    text = _text("fuzz.yml")
    assert "run_fuzz.py --method direct" in text
    assert "run_fuzz.py --method direct --duration 5 --regression || true" not in text
    for line in text.splitlines():
        if "run_fuzz.py" in line:
            assert "|| true" not in line, line
