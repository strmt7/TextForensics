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


def test_mutation_job_status_cancelled_maps_to_fail_not_error():
    """A cancelled mutation job is "fail": attempted, did not succeed.

    The status file uses the shared gate vocabulary
    (pass / fail / skipped / unavailable / not_applicable / zero_work);
    "error" is not a member, so job_status must never emit it.
    """
    import re

    workflow = _load("mutation.yml")
    report_steps = _steps(workflow, "mutation-report")
    joined = "\n".join(str(s.get("run", "")) for s in report_steps)
    start = joined.index("def job_status")
    end = joined.index("diff_summary =")
    body = joined[start:end]
    statuses = re.findall(r'"(pass|fail|skipped|unavailable|not_applicable|zero_work|error)"', body)
    assert statuses, "no job_status return values found"
    assert set(statuses) <= {
        "pass",
        "fail",
        "skipped",
        "unavailable",
        "not_applicable",
        "zero_work",
    }, f"job_status emits a non-vocabulary status: {sorted(set(statuses))}"
    cancelled = body[body.index('result == "cancelled"') :]
    assert '("fail", 0, "mutation job was cancelled")' in cancelled


def test_artifact_action_pins_are_verified_upstream_shas():
    """Every artifact-action pin must be a SHA verified against upstream.

    Incident: the download-artifact v8.0.2 SHA (9000827...) was pasted
    into an upload-artifact pin in mutation.yml. That SHA is a real commit
    only in actions/download-artifact; it does not exist in
    actions/upload-artifact, so the Mutation Report Summary job failed at
    "Prepare all required actions" with "unable to find version". The two
    actions share no commits, so their pins must be locked separately.
    """
    import re

    # Verified upstream (gh api repos/actions/<repo>/commits/<sha> -> 200):
    # upload-artifact v7.0.2 is the latest upload-artifact release.
    upload_shas = {"cf430e030ddbb5b0abf93d22962f4752f3646cd9"}
    # download-artifact v7.0.0 and v8.0.2.
    download_shas = {
        "37930b1c2abaa49bbe596cd826c3c89aef350131",
        "9000827ccba6bdab643e8b6fd33ac0654aef8333",
    }
    pattern = re.compile(r"uses:\s*actions/(upload|download)-artifact@([0-9a-f]{40})")
    found = {"upload": set(), "download": set()}
    for path in sorted(WORKFLOWS.glob("*.yml")):
        for match in pattern.finditer(path.read_text(encoding="utf-8")):
            found[match.group(1)].add(match.group(2))
    assert found["upload"], "no upload-artifact pin found"
    assert found["download"], "no download-artifact pin found"
    assert found["upload"] <= upload_shas, (
        f"unverified upload-artifact pin(s): {sorted(found['upload'] - upload_shas)}"
    )
    assert found["download"] <= download_shas, (
        f"unverified download-artifact pin(s): {sorted(found['download'] - download_shas)}"
    )


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


# ---------------------------------------------------------------------------
# CI Core collection gate: the dev extra must cover the core suite's
# module-level imports (pydantic incident, 2026-11-12)
# ---------------------------------------------------------------------------


def _normalized_distribution_name(name: str) -> str:
    """PEP 503 normalization for distribution-name comparison."""
    import re

    return re.sub(r"[-_.]+", "-", name).lower()


def _dev_install_closure() -> set[str]:
    """Distribution names installable via ``pip install -e ".[dev]"``.

    The declared dev packages plus their transitive requirements,
    resolved from installed package metadata with environment markers
    evaluated (extras excluded: ``pip install -e ".[dev]"`` installs no
    dependency extras). This is the set of distributions CI Core has
    available when it collects the suite.
    """
    import tomllib
    from importlib.metadata import distribution

    from packaging.requirements import Requirement

    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared = {
        _normalized_distribution_name(Requirement(spec).name)
        for spec in project.get("dependencies", [])
    }
    declared |= {
        _normalized_distribution_name(Requirement(spec).name)
        for spec in project["project"]["optional-dependencies"]["dev"]
    }
    closure: set[str] = set()
    stack = sorted(declared)
    while stack:
        name = stack.pop()
        if name in closure:
            continue
        try:
            metadata = distribution(name)
        except Exception as exc:
            raise AssertionError(
                f"dev package {name!r} is not installed; the dev-install "
                "closure cannot be verified in this environment"
            ) from exc
        closure.add(name)
        for raw in metadata.requires or []:
            req = Requirement(raw)
            if req.marker is not None and not req.marker.evaluate():
                continue
            stack.append(_normalized_distribution_name(req.name))
    return closure


def _module_level_test_imports() -> dict[str, set[str]]:
    """Top-level module -> test files importing it at module level.

    Only direct children of a test module's body count: pytest executes
    those imports unconditionally at collection time. Imports inside
    functions, classes, or ``try/except ImportError`` blocks (the
    optional-extra pattern, e.g. atheris/fastapi) are excluded — they do
    not break collection when the extra is absent.
    """
    import ast
    import sys

    tests_dir = REPO_ROOT / "tests"
    in_repo = {p.stem for p in tests_dir.glob("*.py")}
    in_repo |= {
        p.name for p in tests_dir.iterdir() if p.is_dir() and not p.name.startswith(".")
    }
    in_repo |= {"tests", "textforensics"}
    found: dict[str, set[str]] = {}
    for path in sorted(tests_dir.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module.split(".")[0]]
            else:
                continue
            for name in names:
                if name in sys.stdlib_module_names or name in in_repo:
                    continue
                found.setdefault(name, set()).add(str(path.relative_to(REPO_ROOT)))
    return found


def test_dev_extra_covers_core_suite_module_level_imports():
    """Every module-level import in tests/ must be in the .[dev] closure.

    Incident (CI run 43286386301, main a907101): CI Core installs only
    ``pip install -e ".[dev]"`` and collects ``pytest tests``. Collection
    aborted with ``ModuleNotFoundError: No module named 'pydantic'`` at
    tests/test_execution_policy.py:20 because pydantic was imported at
    module level but declared in no dev dependency (it only reached the
    local venv transitively via the mcp extra). The same six jobs failed
    on the W1 head f1d8c83. A module-level import is executed
    unconditionally at collection time, so its distribution must be
    installable via .[dev] — either declared directly or a transitive
    requirement of a declared dev package.
    """
    from importlib.metadata import packages_distributions

    module_to_dist = packages_distributions()
    closure = _dev_install_closure()
    missing: dict[str, set[str]] = {}
    for module, files in sorted(_module_level_test_imports().items()):
        dists = module_to_dist.get(module) or [module]
        for dist in dists:
            normalized = _normalized_distribution_name(dist)
            if normalized not in closure:
                missing.setdefault(normalized, set()).update(files)
    assert not missing, (
        "module-level test imports not installable via pip install -e "
        f"'.[dev]': {sorted(missing)} "
        f"(files: { {k: sorted(v) for k, v in missing.items()} })"
    )


def test_pydantic_is_declared_in_dev_extra():
    """pydantic must be declared in the dev extra (see test above)."""
    import tomllib

    from packaging.requirements import Requirement

    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dev = {
        _normalized_distribution_name(Requirement(spec).name)
        for spec in project["project"]["optional-dependencies"]["dev"]
    }
    assert "pydantic" in dev, (
        "pydantic is imported at module level by tests/test_execution_policy.py "
        "but is not declared in the dev extra; CI Core (pip install -e "
        "'.[dev]') fails collection with ModuleNotFoundError"
    )
