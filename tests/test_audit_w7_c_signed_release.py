"""ENG-14 (W7 remainder): container promotion requires a SIGNED release.

W0 put promotion behind the exact-SHA acceptance gate, and the container
workflow never pushes on a main push. What was still missing: nothing
checked that a *signed release* exists for the candidate SHA before the
mutable tags are pushed. A candidate whose checks passed but which was
never published as a signed release could still be promoted to
`latest` / version / short-SHA tags.

scripts/verify_signed_release.py closes that gap (read-only `gh api`
GETs only): the tag v<version> must resolve to exactly the candidate
SHA, the release for that tag must exist and not be a draft, and it
must carry at least one signature/attestation asset (.sig / .bundle).
Exit 0 allows promotion, 1 refuses it, 2 means the gate itself could
not be evaluated.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import yaml

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
REPO_ROOT = Path(__file__).parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "container.yml"

REPO = "strmt7/TextForensics"
VERSION = "0.2.0"
CANDIDATE = "7" * 40
OTHER_SHA = "8" * 40


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "verify_signed_release", SCRIPTS_DIR / "verify_signed_release.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["verify_signed_release"] = module
    spec.loader.exec_module(module)
    return module


class _Result:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _fake_runner(responses: dict):
    """Build a subprocess.run-compatible fake from {endpoint: payload}.

    A payload of None means `gh api` exits 1 with a 404-style stderr.
    Any endpoint not in the map raises, so a test fails loudly if the
    script calls an unexpected endpoint."""

    def run(argv, **kwargs):
        assert argv[0] == "gh" and argv[1] == "api", argv
        endpoint = argv[2]
        if endpoint not in responses:
            raise AssertionError(f"unexpected gh api endpoint: {endpoint}")
        payload = responses[endpoint]
        if payload is None:
            return _Result(returncode=1, stdout="", stderr="HTTP 404 (Not Found)")
        import json

        return _Result(returncode=0, stdout=json.dumps(payload))

    return run


def _signed_release_responses(
    *, tag_sha: str = CANDIDATE, draft: bool = False, signed: bool = True
):
    assets = [{"name": "textforensics-sbom.cdx.json"}]
    if signed:
        assets.append({"name": "textforensics-sbom.cdx.json.sig"})
        assets.append({"name": "release-notes.md.bundle"})
    return {
        f"repos/{REPO}/git/ref/tags/v{VERSION}": {
            "ref": f"refs/tags/v{VERSION}",
            "object": {"sha": tag_sha, "type": "commit"},
        },
        f"repos/{REPO}/releases/tags/v{VERSION}": {
            "id": 123,
            "tag_name": f"v{VERSION}",
            "draft": draft,
            "target_commitish": CANDIDATE,
        },
        f"repos/{REPO}/releases/123/assets?per_page=100": assets,
    }


def test_refuses_when_no_release_record_exists(capsys):
    """The tag exists and points at the candidate, but no release record
    exists for it: promotion is refused (an unsigned candidate)."""
    module = _load_module()
    responses = {
        f"repos/{REPO}/git/ref/tags/v{VERSION}": {
            "ref": f"refs/tags/v{VERSION}",
            "object": {"sha": CANDIDATE, "type": "commit"},
        },
        f"repos/{REPO}/releases/tags/v{VERSION}": None,
    }
    code = module.main(
        ["--sha", CANDIDATE, "--repo", REPO, "--version", VERSION],
        runner=_fake_runner(responses),
    )
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code == 1
    assert "release" in out.lower()


def test_refuses_when_tag_missing(capsys):
    module = _load_module()
    responses = {f"repos/{REPO}/git/ref/tags/v{VERSION}": None}
    code = module.main(
        ["--sha", CANDIDATE, "--repo", REPO, "--version", VERSION],
        runner=_fake_runner(responses),
    )
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code == 1
    assert "v0.2.0" in out


def test_refuses_when_tag_points_elsewhere(capsys):
    """The tag exists but resolves to a different commit: refused."""
    module = _load_module()
    responses = _signed_release_responses(tag_sha=OTHER_SHA)
    code = module.main(
        ["--sha", CANDIDATE, "--repo", REPO, "--version", VERSION],
        runner=_fake_runner(responses),
    )
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code == 1
    assert OTHER_SHA[:7] in out or "does not point" in out


def test_refuses_draft_release(capsys):
    """A draft is not a published signed release: refused."""
    module = _load_module()
    responses = _signed_release_responses(draft=True)
    code = module.main(
        ["--sha", CANDIDATE, "--repo", REPO, "--version", VERSION],
        runner=_fake_runner(responses),
    )
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code == 1
    assert "draft" in out.lower()


def test_refuses_unsigned_release(capsys):
    """A published release with no .sig/.bundle asset is unsigned: refused."""
    module = _load_module()
    responses = _signed_release_responses(signed=False)
    code = module.main(
        ["--sha", CANDIDATE, "--repo", REPO, "--version", VERSION],
        runner=_fake_runner(responses),
    )
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code == 1
    assert "sign" in out.lower()


def test_allows_signed_release_for_candidate_sha(capsys):
    module = _load_module()
    responses = _signed_release_responses()
    code = module.main(
        ["--sha", CANDIDATE, "--repo", REPO, "--version", VERSION],
        runner=_fake_runner(responses),
    )
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code == 0
    assert "signed release" in out.lower()


def test_annotated_tag_is_dereferenced(capsys):
    """An annotated tag's ref points at a tag object, not the commit:
    the script must dereference it and compare the commit SHA."""
    module = _load_module()
    tag_object = "9" * 40
    responses = _signed_release_responses(tag_sha=tag_object)
    responses[f"repos/{REPO}/git/ref/tags/v{VERSION}"]["object"] = {
        "sha": tag_object,
        "type": "tag",
    }
    responses[f"repos/{REPO}/git/tags/{tag_object}"] = {"object": {"sha": CANDIDATE}}
    code = module.main(
        ["--sha", CANDIDATE, "--repo", REPO, "--version", VERSION],
        runner=_fake_runner(responses),
    )
    assert code == 0


def test_gate_error_when_gh_fails(capsys):
    """A `gh api` failure that is not a 404 means the gate could not be
    evaluated: exit 2, never a silent allow."""

    def failing_runner(argv, **kwargs):
        raise RuntimeError("gh not authenticated")

    module = _load_module()
    code = module.main(
        ["--sha", CANDIDATE, "--repo", REPO, "--version", VERSION],
        runner=failing_runner,
    )
    assert code == 2


# ---------------------------------------------------------------------------
# Workflow structure: container.yml
# ---------------------------------------------------------------------------


def _workflow_jobs():
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]


def _steps(job_name: str):
    return _workflow_jobs()[job_name]["steps"]


def test_promotion_gate_verifies_signed_release():
    """The acceptance gate refuses an unsigned candidate: the
    promotion-gate job runs the signed-release check."""
    scripts = [str(s.get("run", "")) for s in _steps("promotion-gate")]
    assert any("verify_signed_release.py" in script for script in scripts)


def test_promote_job_verifies_signed_release_before_push():
    """Defense in depth: the promote job itself re-verifies the signed
    release before any step that can push."""
    steps = _steps("promote")
    verify_index = next(
        i for i, s in enumerate(steps) if "verify_signed_release.py" in str(s.get("run", ""))
    )
    push_indices = [
        i
        for i, s in enumerate(steps)
        if str(s.get("with", {}).get("push", "")).lower() == "true"
        or "push: true" in str(s.get("with", ""))
    ]
    assert push_indices, "no push step found in promote job"
    assert verify_index < min(push_indices)


def test_candidate_build_never_pushes():
    """The candidate build still pushes nothing (ENG-14 boundary)."""
    for step in _steps("build-candidate"):
        with_block = step.get("with", {}) or {}
        assert str(with_block.get("push", "false")).lower() != "true"
