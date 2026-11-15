"""W6 Worker B regression tests: ENG-03 (reproducibility non-gating).

Red-first tests, written from the audit finding before the source fix:

- ENG-03: the reproducibility workflow builds twice and compares the
  wheel hashes, but the compare step only prints ``NOTE: Wheel builds
  differ (known limitation ...)`` and exits 0 — a differing build can
  never fail the job, so ``deterministic_builds`` was never established
  and the claim is unverified. The fix is an executable
  reproducibility check (``scripts/check_reproducibility.py``) that
  builds twice from independent clean source copies with
  ``SOURCE_DATE_EPOCH=1704067200``, compares bytes FATALLY, and
  explains member diffs instead of diagnosing every difference as a
  timestamp.

- The workflow's build-reproducibility job must invoke that check (no
  soft-fail, no ``|| true``, no ``continue-on-error`` on the compare).
"""

from __future__ import annotations

import importlib.util
import io
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "reproducibility.yml"
CHECK_SCRIPT = SCRIPTS_DIR / "check_reproducibility.py"


def _load_check_script():
    spec = importlib.util.spec_from_file_location(
        "check_reproducibility", CHECK_SCRIPT
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_reproducibility"] = module
    spec.loader.exec_module(module)
    return module


def _make_wheel(path: Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(members):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            archive.writestr(info, members[name])


def _make_sdist(path: Path, members: dict[str, bytes]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name in sorted(members):
            data = members[name]
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 1704067200
            archive.addfile(info, io.BytesIO(data))


@pytest.fixture(scope="module")
def check_module():
    return _load_check_script()


class TestCompareFunctions:
    def test_identical_wheels_compare_clean(self, tmp_path, check_module):
        members = {
            "pkg/__init__.py": b"print('x')\n",
            "pkg-0.2.0.dist-info/METADATA": b"Name: pkg\n",
        }
        a = tmp_path / "a.whl"
        b = tmp_path / "b.whl"
        _make_wheel(a, members)
        _make_wheel(b, members)
        assert check_module.compare_wheels(a, b) == []

    def test_differing_wheel_member_is_explained(self, tmp_path, check_module):
        a = tmp_path / "a.whl"
        b = tmp_path / "b.whl"
        _make_wheel(a, {"pkg/__init__.py": b"print('x')\n"})
        _make_wheel(b, {"pkg/__init__.py": b"print('y')\n"})
        diffs = check_module.compare_wheels(a, b)
        assert diffs, "a differing member must be reported, not hidden"
        assert any("pkg/__init__.py" in d for d in diffs)

    def test_missing_wheel_member_is_explained(self, tmp_path, check_module):
        a = tmp_path / "a.whl"
        b = tmp_path / "b.whl"
        _make_wheel(a, {"pkg/__init__.py": b"x", "pkg/extra.py": b"y"})
        _make_wheel(b, {"pkg/__init__.py": b"x"})
        diffs = check_module.compare_wheels(a, b)
        assert any("pkg/extra.py" in d for d in diffs)

    def test_identical_sdists_compare_clean(self, tmp_path, check_module):
        members = {"pkg-0.2.0/PKG-INFO": b"Name: pkg\n"}
        a = tmp_path / "a.tar.gz"
        b = tmp_path / "b.tar.gz"
        _make_sdist(a, members)
        _make_sdist(b, members)
        assert check_module.compare_sdists(a, b) == []

    def test_differing_sdist_member_is_explained(self, tmp_path, check_module):
        a = tmp_path / "a.tar.gz"
        b = tmp_path / "b.tar.gz"
        _make_sdist(a, {"pkg-0.2.0/setup.py": b"a"})
        _make_sdist(b, {"pkg-0.2.0/setup.py": b"b"})
        diffs = check_module.compare_sdists(a, b)
        assert diffs
        assert any("setup.py" in d for d in diffs)

    def test_compare_does_not_blame_timestamps_for_content_diffs(
        self, tmp_path, check_module
    ):
        # Member diffs must name the differing member and its bytes, not
        # diagnose every difference as a timestamp (the old workflow's
        # failure mode was to wave differences away as timestamps).
        a = tmp_path / "a.whl"
        b = tmp_path / "b.whl"
        _make_wheel(a, {"pkg/code.py": b"v1"})
        _make_wheel(b, {"pkg/code.py": b"v2"})
        diffs = check_module.compare_wheels(a, b)
        joined = "\n".join(diffs).lower()
        assert "pkg/code.py" in joined
        assert "timestamp" not in joined


class TestReproducibilityWorkflowIsFatal:
    def test_workflow_invokes_the_executable_check(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        assert "scripts/check_reproducibility.py" in text, (
            "the build-reproducibility job must run the executable "
            "reproducibility check, not an inline hash echo"
        )

    def test_workflow_has_no_soft_fail_compare(self):
        # Scoped to the build-reproducibility job: the CLI/detector
        # determinism jobs legitimately use `diff ... || true` to print
        # a diagnostic diff while recording failure separately in FAIL.
        # The build comparison itself must have no soft-fail path.
        data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        job = data["jobs"]["build-reproducibility"]
        job_text = "\n".join(str(step) for step in job["steps"])
        lowered = job_text.lower()
        assert "known limitation" not in lowered
        assert "note: wheel builds differ" not in lowered
        assert "|| true" not in job_text

    def test_build_reproducibility_job_is_gating(self):
        data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        job = data["jobs"]["build-reproducibility"]
        assert job.get("continue-on-error") is not True
        steps = job["steps"]
        assert any(
            "check_reproducibility.py" in str(step.get("run", ""))
            for step in steps
        ), "no step runs scripts/check_reproducibility.py"
        assert not any(
            step.get("continue-on-error") is True for step in steps
        ), "a compare step with continue-on-error cannot gate"

    def test_summary_job_fails_when_build_reproducibility_fails(self):
        data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        summary = data["jobs"]["reproducibility-summary"]
        assert "build-reproducibility" in summary["needs"]
        run_text = "\n".join(
            str(step.get("run", "")) for step in summary["steps"]
        )
        assert "build-reproducibility" in run_text
        assert "exit 1" in run_text
