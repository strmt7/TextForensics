"""W9 Worker D: container health + SBOM/attestation contracts.

Static contracts for the Dockerfile and the container workflow
(``.github/workflows/container.yml``), checked in the core suite so CI
locks them without needing a Docker daemon:

- HEALTHCHECK present with the exact documented parameters
  (``Dockerfile:75``: ``--interval=30s --timeout=3s --start-period=5s
  --retries=3``) and asserted in BOTH acceptance steps of the workflow,
  including a runtime poll for ``Health.Status == healthy``.
- Non-root execution: image USER is ``textforensics:textforensics`` and
  the runtime UID is non-zero; the image works ``--read-only``
  (``PYTHONDONTWRITEBYTECODE=1``, ``HOME=/tmp``).
- SBOM/attestation (ENG-14): the candidate SBOM scans the locally loaded
  image (B3 fix — never ``ghcr.io/...@`` with an empty digest), nothing
  is pushed from the candidate job, and promotion requires the signed
  release check plus a build-provenance attestation.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
DOCKERFILE = REPO_ROOT / "Dockerfile"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "container.yml"


def _dockerfile_text() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _job_steps(workflow: dict, job: str) -> list[dict]:
    return workflow["jobs"][job]["steps"]


def _acceptance_run(workflow: dict, job: str) -> str:
    for step in _job_steps(workflow, job):
        if step.get("name", "").startswith("Running-image acceptance"):
            return step["run"]
    raise AssertionError(f"no Running-image acceptance step in job {job!r}")


# ---------------------------------------------------------------------------
# Dockerfile: HEALTHCHECK + non-root + read-only posture
# ---------------------------------------------------------------------------


def test_dockerfile_healthcheck_has_exact_documented_parameters():
    """HEALTHCHECK must be interval=30s timeout=3s start-period=5s retries=3."""
    match = re.search(
        r"HEALTHCHECK\s+--interval=(\S+)\s+--timeout=(\S+)\s+--start-period=(\S+)\s+--retries=(\d+)",
        _dockerfile_text(),
    )
    assert match is not None, "Dockerfile has no HEALTHCHECK with the expected flags"
    assert match.group(1) == "30s"
    assert match.group(2) == "3s"
    assert match.group(3) == "5s"
    assert match.group(4) == "3"


def test_dockerfile_healthcheck_probes_the_health_endpoint():
    """The HEALTHCHECK command must probe /healthz on the configured port."""
    text = _dockerfile_text()
    assert "/healthz" in text
    assert "urllib.request.urlopen" in text
    assert "TEXTFORENSICS_PORT" in text


def test_dockerfile_runs_as_named_non_root_user():
    """The image must run as the dedicated non-root user, not root/0."""
    user_lines = re.findall(r"^USER\s+(\S+)\s*$", _dockerfile_text(), re.MULTILINE)
    assert user_lines, "Dockerfile sets no USER"
    assert user_lines[-1] == "textforensics:textforensics"


def test_dockerfile_supports_read_only_execution():
    """Read-only runs need no bytecode writes and a writable HOME."""
    text = _dockerfile_text()
    assert "PYTHONDONTWRITEBYTECODE=1" in text
    assert "HOME=/tmp" in text


# ---------------------------------------------------------------------------
# Workflow: HEALTHCHECK asserted in-container (both acceptance steps)
# ---------------------------------------------------------------------------


def test_candidate_acceptance_asserts_healthcheck_config():
    """Candidate acceptance must assert the image HEALTHCHECK parameters."""
    run = _acceptance_run(_workflow(), "build-candidate")
    assert "Config.Healthcheck.Interval" in run
    assert "30000000000" in run  # 30s in nanoseconds
    assert "Config.Healthcheck.Timeout" in run
    assert "3000000000" in run  # 3s in nanoseconds
    assert "Config.Healthcheck.StartPeriod" in run
    assert "5000000000" in run  # 5s in nanoseconds
    assert "Config.Healthcheck.Retries" in run
    assert '"3"' in run or "= \"3\"" in run or "== 3" in run or " = 3" in run


def test_candidate_acceptance_polls_for_healthy_status():
    """Candidate acceptance must poll until the in-container HEALTHCHECK reports healthy."""
    run = _acceptance_run(_workflow(), "build-candidate")
    assert "State.Health.Status" in run
    assert "healthy" in run


def test_candidate_acceptance_asserts_non_root_runtime_uid():
    """Candidate acceptance must prove the running container is not UID 0."""
    run = _acceptance_run(_workflow(), "build-candidate")
    assert "Config.User" in run
    assert "textforensics:textforensics" in run
    # Runtime UID probe: run `id -u` as the image entrypoint override.
    assert "--entrypoint id" in run
    assert '"-u"' in run or " -u" in run


def test_candidate_acceptance_runs_read_only():
    """Candidate acceptance must run the container with --read-only."""
    run = _acceptance_run(_workflow(), "build-candidate")
    assert "--read-only" in run
    assert "ReadonlyRootfs" in run


def test_promote_acceptance_asserts_healthcheck_config():
    """Promote acceptance must assert the same HEALTHCHECK parameters."""
    run = _acceptance_run(_workflow(), "promote")
    assert "Config.Healthcheck.Interval" in run
    assert "30000000000" in run
    assert "Config.Healthcheck.Timeout" in run
    assert "3000000000" in run
    assert "Config.Healthcheck.Retries" in run


def test_promote_acceptance_polls_for_healthy_status():
    """Promote acceptance must poll until the in-container HEALTHCHECK reports healthy."""
    run = _acceptance_run(_workflow(), "promote")
    assert "State.Health.Status" in run
    assert "healthy" in run


# ---------------------------------------------------------------------------
# Workflow: SBOM / attestation / no-push (ENG-14)
# ---------------------------------------------------------------------------


def test_candidate_job_never_pushes():
    """The candidate job builds only: every build-push step has push: false."""
    steps = _job_steps(_workflow(), "build-candidate")
    build_steps = [s for s in steps if "build-push-action" in str(s.get("uses", ""))]
    assert build_steps, "no build-push steps in build-candidate"
    for step in build_steps:
        assert step["with"].get("push") is False, f"{step['name']} may push"


def test_candidate_sbom_scans_locally_loaded_image():
    """SBOM (B3 fix) scans the locally loaded candidate, never a registry digest."""
    steps = _job_steps(_workflow(), "build-candidate")
    sbom_steps = [s for s in steps if "sbom-action" in str(s.get("uses", ""))]
    assert len(sbom_steps) == 1
    assert sbom_steps[0]["with"]["image"] == "textforensics:candidate"


def test_candidate_build_records_provenance():
    """The multi-arch candidate build must enable build provenance."""
    steps = _job_steps(_workflow(), "build-candidate")
    build = next(s for s in steps if s.get("name", "").startswith("Build multi-arch"))
    assert build["with"].get("provenance") is True


def test_promote_job_requires_signed_release_and_attests():
    """Promotion requires the signed-release check and publishes an attestation."""
    steps = _job_steps(_workflow(), "promote")
    assert any("verify_signed_release" in str(s.get("run", "")) for s in steps)
    assert any("attest-build-provenance" in str(s.get("uses", "")) for s in steps)
    sbom_steps = [s for s in steps if "sbom-action" in str(s.get("uses", ""))]
    assert len(sbom_steps) == 1
    assert "@${{ steps.build-push.outputs.digest }}" in sbom_steps[0]["with"]["image"]


def test_promote_sbom_scans_promoted_digest():
    """The promoted SBOM binds to the pushed image digest, not a tag."""
    steps = _job_steps(_workflow(), "promote")
    sbom_steps = [s for s in steps if "sbom-action" in str(s.get("uses", ""))]
    assert "steps.build-push.outputs.digest" in sbom_steps[0]["with"]["image"]
