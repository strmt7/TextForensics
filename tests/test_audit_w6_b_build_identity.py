"""W6 Worker B regression tests: ENG-02 (sdist provenance / build identity).

Red-first tests, written from the audit finding before the source fix:

- ENG-02: sdist provenance is lost; a wheel built from an sdist outside
  any Git worktree embeds ``source_commit: "unknown"`` and
  ``source_commit_verified: false``, yet ``verify_build_identity()``
  still reports ``valid: true`` (fail-open). Git queries run with the
  caller's cwd, so building inside an unrelated repository can pick up
  that repository's HEAD.

The fix must:
- capture immutable source/contract/build-input provenance (git SHA,
  contract digests) into the sdist at build time and preserve it in
  wheels derived from the sdist;
- bind Git queries to the actual source root (not cwd);
- make any failed required identity check return invalid (fail closed).

Test layout:
- ``TestVerifyBuildIdentityFailClosed``: pure unit tests on
  ``verify_build_identity`` (fast, no builds).
- ``TestGitQueriesBindToSourceRoot``: unit tests on the git helpers
  with synthetic repositories (fast, no builds).
- ``TestSdistCarriesProvenance`` / ``TestWheelFromSdistIdentity``:
  integration tests that build a real sdist + wheel. They share one
  module-scoped build venv (created once, pinned build tools installed
  from ``requirements-tools-hashed.txt`` with ``--require-hashes``) and
  skip when the venv cannot be created (e.g. no network for the pip
  install) so an offline run degrades to a skip, not a false failure.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

import pytest

import textforensics._build_info as build_info_mod
from textforensics._build_info import (
    get_build_info,
    verify_build_identity,
)

REPO_ROOT = Path(__file__).parent.parent
TOOLS_LOCKFILE = REPO_ROOT / "requirements-tools-hashed.txt"


def _failing_build_info(**overrides):
    """A BUILD_INFO dict in which every required identity check fails."""
    info = {
        "source_commit": "unknown",
        "source_commit_verified": False,
        "python_version": "3.12.0",
        "dependencies_sha256": "unavailable",
        "api_version": "0.2.0",
        "api_spec_sha256": "unavailable",
        "detector_adapter_api_sha256": "unavailable",
        "calibration_format_version": "1.0.0",
        "benchmark_format_version": "1.0.0",
        "contract_info": {},
    }
    info.update(overrides)
    return info


class TestVerifyBuildIdentityFailClosed:
    """Any failed required identity check must return invalid (ENG-02)."""

    def test_unverified_commit_is_invalid_without_expected_commit(
        self, monkeypatch
    ):
        # The CLI's default path calls verify_build_identity() with no
        # expected commit: before the fix this returned valid=True while
        # recording failed checks.
        monkeypatch.setattr(
            build_info_mod, "BUILD_INFO", _failing_build_info()
        )
        result = verify_build_identity()
        assert result["valid"] is False
        assert result["errors"], "a failing identity must explain itself"

    def test_unknown_source_commit_is_invalid(self, monkeypatch):
        monkeypatch.setattr(
            build_info_mod,
            "BUILD_INFO",
            _failing_build_info(
                source_commit_verified=True,
                dependencies_sha256="a" * 64,
                contract_info={"schemas_sha256": "b" * 64},
            ),
        )
        result = verify_build_identity()
        assert result["valid"] is False
        assert any("unknown" in e.lower() for e in result["errors"])

    def test_unavailable_dependencies_hash_is_invalid(self, monkeypatch):
        monkeypatch.setattr(
            build_info_mod,
            "BUILD_INFO",
            _failing_build_info(
                source_commit="a" * 40,
                source_commit_verified=True,
                contract_info={"schemas_sha256": "b" * 64},
            ),
        )
        result = verify_build_identity()
        assert result["valid"] is False

    def test_empty_contract_info_is_invalid(self, monkeypatch):
        monkeypatch.setattr(
            build_info_mod,
            "BUILD_INFO",
            _failing_build_info(
                source_commit="a" * 40,
                source_commit_verified=True,
                dependencies_sha256="c" * 64,
            ),
        )
        result = verify_build_identity()
        assert result["valid"] is False

    def test_valid_identity_still_passes(self, monkeypatch):
        # Control: a fully populated identity must stay valid, so the
        # fail-closed change does not turn every install red.
        monkeypatch.setattr(
            build_info_mod,
            "BUILD_INFO",
            _failing_build_info(
                source_commit="a" * 40,
                source_commit_verified=True,
                dependencies_sha256="c" * 64,
                contract_info={"schemas_sha256": "b" * 64},
            ),
        )
        result = verify_build_identity(expected_commit="a" * 40)
        assert result["valid"] is True
        assert result["errors"] == []

    def test_expected_commit_mismatch_is_invalid(self, monkeypatch):
        monkeypatch.setattr(
            build_info_mod,
            "BUILD_INFO",
            _failing_build_info(
                source_commit="a" * 40,
                source_commit_verified=True,
                dependencies_sha256="c" * 64,
                contract_info={"schemas_sha256": "b" * 64},
            ),
        )
        result = verify_build_identity(expected_commit="b" * 40)
        assert result["valid"] is False

    def test_failed_checks_are_all_recorded(self, monkeypatch):
        # Every failing check must appear in "checks" with passed=False
        # AND flip valid to False (before the fix, checks recorded the
        # failure but valid stayed True).
        monkeypatch.setattr(
            build_info_mod, "BUILD_INFO", _failing_build_info()
        )
        result = verify_build_identity()
        failed = [c for c in result["checks"] if not c["passed"]]
        assert len(failed) >= 3
        assert result["valid"] is False


class TestGitQueriesBindToSourceRoot:
    """Git queries must run against the source root, never the cwd."""

    @staticmethod
    def _init_repo(path: Path, filename: str = "marker.txt", content: str = "x\n") -> str:
        path.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-q", str(path)], check=True)
        subprocess.run(
            ["git", "-C", str(path), "config", "user.email", "test@example.invalid"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(path), "config", "user.name", "Test"],
            check=True,
        )
        (path / filename).write_text(content, encoding="utf-8")
        subprocess.run(["git", "-C", str(path), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(path), "commit", "-qm", "initial"], check=True
        )
        head = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        return head

    def test_git_commit_comes_from_source_root_not_cwd(self, tmp_path):
        # Unrelated repo B is the cwd; the source root is repo A.
        # Before the fix _get_source_commit() ran `git rev-parse HEAD`
        # in the cwd and would return B's HEAD.
        repo_a = tmp_path / "a"
        repo_b = tmp_path / "b"
        # Shape repo A as a TextForensics source root: the git helpers
        # only query git for a directory that looks like a source tree
        # (pyproject.toml + src/textforensics/__init__.py), never for
        # an arbitrary directory.
        (repo_a / "src" / "textforensics").mkdir(parents=True)
        (repo_a / "pyproject.toml").write_text(
            '[project]\nname = "textforensics"\nversion = "0.2.0"\n',
            encoding="utf-8",
        )
        (repo_a / "src" / "textforensics" / "__init__.py").write_text(
            '"""Test package."""\n', encoding="utf-8"
        )
        head_a = self._init_repo(repo_a, content="repo a\n")
        head_b = self._init_repo(repo_b, content="repo b\n")
        assert head_a != head_b
        old_cwd = os.getcwd()
        try:
            os.chdir(repo_b)
            commit, _verified = build_info_mod._get_source_commit(repo_a)
        finally:
            os.chdir(old_cwd)
        assert commit == head_a

    def test_directory_inside_unrelated_repo_is_unknown(self, tmp_path):
        # A source tree copied into an unrelated repository (no .git of
        # its own at the source root) must not inherit that repo's HEAD.
        repo_b = tmp_path / "b"
        self._init_repo(repo_b)
        plain = repo_b / "plain-copy"
        plain.mkdir()
        (plain / "pyproject.toml").write_text(
            '[project]\nname = "textforensics"\n', encoding="utf-8"
        )
        commit, verified = build_info_mod._get_source_commit(plain)
        assert commit == "unknown"
        assert verified is False

    def test_source_root_detection_rejects_installed_layout(self, tmp_path):
        # A directory that is not a TextForensics source root (no
        # src/textforensics/__init__.py + pyproject.toml) is not a
        # source root, even if a parent directory is a git checkout.
        repo_b = tmp_path / "b"
        self._init_repo(repo_b)
        fake_site_packages = repo_b / "lib" / "python3.12" / "site-packages"
        fake_site_packages.mkdir(parents=True)
        assert build_info_mod._source_root(fake_site_packages) is None


# ---------------------------------------------------------------------------
# Integration tests: real sdist / wheel builds.
# ---------------------------------------------------------------------------


def _run(cmd, cwd, env=None):
    merged = dict(os.environ)
    merged["PYTHONDONTWRITEBYTECODE"] = "1"
    if env:
        merged.update(env)
    result = subprocess.run(
        cmd, cwd=str(cwd), env=merged, capture_output=True, text=True
    )
    return result


@pytest.fixture(scope="module")
def build_venv(tmp_path_factory):
    """A venv with the pinned build tools from the tools lockfile.

    This is the exact audited build profile (ENG-10): build/setuptools/
    wheel as pinned in requirements-tools-hashed.txt. Skips the module
    when the venv cannot be built (e.g. no network for the pip install).
    """
    base = tmp_path_factory.mktemp("w6b-build-venv")
    venv = base / "venv"
    result = _run([sys.executable, "-m", "venv", str(venv)], cwd=base)
    if result.returncode != 0:
        pytest.skip(f"could not create build venv: {result.stderr[-500:]}")
    python = venv / "bin" / "python"
    if not python.exists():  # Windows layout
        python = venv / "Scripts" / "python.exe"
    result = _run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--quiet",
            "--require-hashes",
            "-r",
            str(TOOLS_LOCKFILE),
        ],
        cwd=base,
    )
    if result.returncode != 0:
        pytest.skip(
            "could not install pinned build tools from "
            f"requirements-tools-hashed.txt: {result.stderr[-800:]}"
        )
    return python


@pytest.fixture(scope="module")
def built_sdist(tmp_path_factory, build_venv):
    """Build a real sdist from the repo under test; return its path."""
    outdir = tmp_path_factory.mktemp("w6b-sdist")
    env = {
        "SOURCE_DATE_EPOCH": "1704067200",
        "PYTHONHASHSEED": "0",
    }
    result = _run(
        [
            str(build_venv),
            "-m",
            "build",
            "--no-isolation",
            "--sdist",
            "--outdir",
            str(outdir),
        ],
        cwd=REPO_ROOT,
        env=env,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    sdists = sorted(outdir.glob("*.tar.gz"))
    assert len(sdists) == 1, sdists
    return sdists[0]


def _read_provenance_from_sdist(sdist_path: Path) -> dict:
    with tarfile.open(sdist_path, "r:gz") as archive:
        names = archive.getnames()
        prov = [n for n in names if n.endswith("src/textforensics/_sdist_provenance.json")]
        assert len(prov) == 1, (
            "sdist must contain exactly one _sdist_provenance.json; "
            f"members matching: {prov}"
        )
        data = archive.extractfile(prov[0]).read()
    return json.loads(data.decode("utf-8"))


def _repo_head() -> str:
    return subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _expected_schemas_digest() -> str:
    """Recompute the aggregate schemas digest from the checkout."""
    schemas_dir = REPO_ROOT / "src" / "textforensics" / "schemas"
    hashes = {}
    for schema_file in sorted(schemas_dir.glob("*.json")):
        hashes[schema_file.name] = hashlib.sha256(
            schema_file.read_bytes()
        ).hexdigest()
    aggregate = hashlib.sha256()
    for name in sorted(hashes):
        aggregate.update(name.encode("utf-8"))
        aggregate.update(hashes[name].encode("utf-8"))
    return aggregate.hexdigest()


class TestSdistCarriesProvenance:
    def test_sdist_contains_provenance_file(self, built_sdist):
        provenance = _read_provenance_from_sdist(built_sdist)
        assert provenance["source_commit"] == _repo_head()
        assert provenance["provenance_status"] == "git"
        assert provenance["contract_info"]["schemas_sha256"] == (
            _expected_schemas_digest()
        )
        assert provenance["dependencies_sha256"] == hashlib.sha256(
            (REPO_ROOT / "pyproject.toml").read_bytes()
        ).hexdigest()

    def test_sdist_provenance_is_immutable_record(self, built_sdist):
        provenance = _read_provenance_from_sdist(built_sdist)
        for field in (
            "source_commit",
            "source_commit_verified",
            "dependencies_sha256",
            "contract_info",
            "provenance_status",
        ):
            assert field in provenance, f"provenance missing {field}"
        assert provenance["source_commit_verified"] in (True, False)


def _build_wheel_from_dir(source_dir: Path, build_venv: Path, outdir: Path) -> Path:
    env = {"SOURCE_DATE_EPOCH": "1704067200", "PYTHONHASHSEED": "0"}
    result = _run(
        [
            str(build_venv),
            "-m",
            "build",
            "--no-isolation",
            "--wheel",
            "--outdir",
            str(outdir),
        ],
        cwd=source_dir,
        env=env,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    wheels = sorted(outdir.glob("*.whl"))
    assert len(wheels) == 1, wheels
    return wheels[0]


def _install_wheel_and_read_build_info(wheel: Path, tmp_path: Path) -> dict:
    """Install the wheel into a fresh venv and read its build info."""
    venv = tmp_path / "install-venv"
    result = _run([sys.executable, "-m", "venv", str(venv)], cwd=tmp_path)
    assert result.returncode == 0, result.stderr[-500:]
    python = venv / "bin" / "python"
    if not python.exists():
        python = venv / "Scripts" / "python.exe"
    result = _run(
        [str(python), "-m", "pip", "install", "--quiet", "--no-deps", str(wheel)],
        cwd=tmp_path,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    probe = (
        "import json; from textforensics import get_build_info, "
        "verify_build_identity; print(json.dumps({"
        "'info': get_build_info(), "
        "'verify': verify_build_identity()}))"
    )
    result = _run([str(python), "-c", probe], cwd=tmp_path)
    assert result.returncode == 0, result.stderr[-2000:]
    return json.loads(result.stdout)


class TestWheelFromSdistIdentity:
    def test_wheel_built_outside_git_keeps_identity(
        self, tmp_path, built_sdist, build_venv
    ):
        """Unpack the sdist outside any Git worktree, build a wheel from
        it, install it, and assert the identity fields are correct."""
        unpack = tmp_path / "unpacked"
        unpack.mkdir()
        with tarfile.open(built_sdist, "r:gz") as archive:
            archive.extractall(unpack)
        source_dir = next(unpack.iterdir())
        assert not (source_dir / ".git").exists()
        wheel = _build_wheel_from_dir(
            source_dir, build_venv, tmp_path / "wheel-out"
        )
        payload = _install_wheel_and_read_build_info(wheel, tmp_path)
        info = payload["info"]
        assert info["source_commit"] == _repo_head()
        assert info["contract_info"]["schemas_sha256"] == (
            _expected_schemas_digest()
        )
        assert info["dependencies_sha256"] == hashlib.sha256(
            (REPO_ROOT / "pyproject.toml").read_bytes()
        ).hexdigest()
        assert payload["verify"]["valid"] is True

    def test_wheel_built_inside_unrelated_repo_keeps_identity(
        self, tmp_path, built_sdist, build_venv
    ):
        """Same, but the unpack directory sits inside an unrelated git
        repository with a different HEAD: the embedded commit must still
        be the TextForensics source commit, never the other repo's."""
        other = tmp_path / "unrelated"
        other.mkdir()
        subprocess.run(["git", "init", "-q", str(other)], check=True)
        subprocess.run(
            ["git", "-C", str(other), "config", "user.email", "t@example.invalid"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(other), "config", "user.name", "T"], check=True
        )
        (other / "other.txt").write_text("unrelated\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(other), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(other), "commit", "-qm", "unrelated"], check=True
        )
        other_head = subprocess.run(
            ["git", "-C", str(other), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        assert other_head != _repo_head()
        unpack = other / "unpacked"
        unpack.mkdir()
        with tarfile.open(built_sdist, "r:gz") as archive:
            archive.extractall(unpack)
        source_dir = next(unpack.iterdir())
        wheel = _build_wheel_from_dir(
            source_dir, build_venv, tmp_path / "wheel-out"
        )
        payload = _install_wheel_and_read_build_info(wheel, tmp_path)
        info = payload["info"]
        assert info["source_commit"] == _repo_head()
        assert info["source_commit"] != other_head
        assert payload["verify"]["valid"] is True

    def test_missing_provenance_fails_closed(self, tmp_path, built_sdist, build_venv):
        """Negative test: remove the provenance file from the unpacked
        sdist and build the wheel outside git — the installed package
        must report invalid, never valid."""
        unpack = tmp_path / "unpacked"
        unpack.mkdir()
        with tarfile.open(built_sdist, "r:gz") as archive:
            archive.extractall(unpack)
        source_dir = next(unpack.iterdir())
        prov = source_dir / "src" / "textforensics" / "_sdist_provenance.json"
        assert prov.exists()
        prov.unlink()
        wheel = _build_wheel_from_dir(
            source_dir, build_venv, tmp_path / "wheel-out"
        )
        payload = _install_wheel_and_read_build_info(wheel, tmp_path)
        info = payload["info"]
        assert info["source_commit"] == "unknown"
        assert info["source_commit_verified"] is False
        assert payload["verify"]["valid"] is False
        assert payload["verify"]["errors"]

    def test_corrupted_embedded_build_info_fails_closed(
        self, tmp_path, built_sdist, build_venv
    ):
        """Negative test: corrupt the embedded _build_info.json in the
        installed wheel — loading must fall back to an unverifiable
        identity and verify() must return invalid."""
        unpack = tmp_path / "unpacked"
        unpack.mkdir()
        with tarfile.open(built_sdist, "r:gz") as archive:
            archive.extractall(unpack)
        source_dir = next(unpack.iterdir())
        wheel = _build_wheel_from_dir(
            source_dir, build_venv, tmp_path / "wheel-out"
        )
        venv = tmp_path / "install-venv"
        result = _run([sys.executable, "-m", "venv", str(venv)], cwd=tmp_path)
        assert result.returncode == 0, result.stderr[-500:]
        python = venv / "bin" / "python"
        if not python.exists():
            python = venv / "Scripts" / "python.exe"
        result = _run(
            [str(python), "-m", "pip", "install", "--quiet", "--no-deps", str(wheel)],
            cwd=tmp_path,
        )
        assert result.returncode == 0, result.stderr[-2000:]
        site_packages = next(venv.glob("lib/python*/site-packages"))
        embedded = site_packages / "textforensics" / "_build_info.json"
        assert embedded.exists()
        embedded.write_text("{not valid json", encoding="utf-8")
        probe = (
            "import json; from textforensics import verify_build_identity; "
            "print(json.dumps(verify_build_identity()))"
        )
        result = _run([str(python), "-c", probe], cwd=tmp_path)
        assert result.returncode == 0, result.stderr[-2000:]
        payload = json.loads(result.stdout)
        assert payload["valid"] is False
        assert payload["errors"]

    def test_wheel_from_provenance_less_copy_fails_closed(
        self, tmp_path, build_venv
    ):
        """Negative test: a plain copy of the source tree with no .git
        and no provenance file must not verify as a known build."""
        source_dir = tmp_path / "plain-copy"
        shutil.copytree(
            REPO_ROOT / "src",
            source_dir / "src",
            ignore=shutil.ignore_patterns("__pycache__"),
        )
        for name in ("pyproject.toml", "setup.py", "README.md", "LICENSE"):
            shutil.copy2(REPO_ROOT / name, source_dir / name)
        assert not (source_dir / ".git").exists()
        assert not (
            source_dir / "src" / "textforensics" / "_sdist_provenance.json"
        ).exists()
        wheel = _build_wheel_from_dir(
            source_dir, build_venv, tmp_path / "wheel-out"
        )
        payload = _install_wheel_and_read_build_info(wheel, tmp_path)
        assert payload["info"]["source_commit"] == "unknown"
        assert payload["verify"]["valid"] is False
