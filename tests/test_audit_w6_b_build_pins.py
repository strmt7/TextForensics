"""W6 Worker B regression tests: ENG-10 (build-chain pin inconsistency).

Red-first tests, written from the audit finding before the source fix:

- ENG-10: the release build inputs are pinned in two different places
  at different versions — ``pyproject.toml`` carries broad
  build-system ranges, ``requirements-tools-hashed.txt`` pins the
  reproducibility toolchain at deliberately older versions (build
  1.2.2, setuptools 79.0.1, wheel 0.45.1) while the release/CI jobs
  build with the main lockfile's newer versions (build 1.6.1,
  setuptools 84.2.1, wheel 0.48.0). The reproducibility proof therefore
  does not cover the release build inputs.
- The tools lockfile also fails to install under ``--require-hashes``:
  its transitive dependencies are unpinned (``memory-profiler`` pulls
  an unpinned ``psutil`` that pip resolves to a direct download URL),
  so every job that installs it dies at install time.

The fix reconciles the pins (one exact release build profile, shared
by the tools lockfile and the main lockfile, inside the pyproject
ranges) and closes the tools lockfile under its transitive closure,
and documents the two roles (broad library ranges vs exact release
build inputs).
"""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
from packaging.specifiers import SpecifierSet
from packaging.version import Version

REPO_ROOT = Path(__file__).parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
TOOLS_LOCKFILE = REPO_ROOT / "requirements-tools-hashed.txt"
MAIN_LOCKFILE = REPO_ROOT / "requirements-hashed.txt"
MAIN_PINNED = REPO_ROOT / "requirements-pinned.txt"

# Direct tools-lockfile pins whose transitive dependencies must be
# closed in the lockfile (name -> required transitive dep). Kept as an
# explicit table: pip resolves these from the package metadata, and the
# lockfile must carry each one with hashes or the --require-hashes
# install fails.
KNOWN_TRANSITIVES = {
    "memory-profiler": {"psutil"},
    "build": {"packaging", "pyproject-hooks"},
}

# The exact release build profile: the build-backend packages whose
# versions must agree between the tools lockfile and the main lockfile.
BUILD_PROFILE_PACKAGES = ("build", "setuptools", "wheel")


def _parse_lockfile(path: Path) -> dict[str, str]:
    """Parse a hash-pinned lockfile into {normalized-name: version}."""
    pins: dict[str, str] = {}
    text = path.read_text(encoding="utf-8")
    for match in re.finditer(r"^([A-Za-z0-9_.\-]+)==([^\s\\]+)", text, re.M):
        pins[match.group(1).lower().replace("_", "-")] = match.group(2)
    return pins


def _lockfile_has_hashes(path: Path) -> dict[str, int]:
    """Count --hash lines per package in a hash-pinned lockfile."""
    text = path.read_text(encoding="utf-8")
    counts: dict[str, int] = {}
    current: str | None = None
    for line in text.splitlines():
        match = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s\\]+)", line)
        if match:
            current = match.group(1).lower().replace("_", "-")
            counts.setdefault(current, 0)
        elif line.strip().startswith("--hash=sha256:") and current:
            counts[current] += 1
    return counts


def _pyproject_build_requires() -> dict[str, SpecifierSet]:
    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        data = tomllib.load(handle)
    requires: dict[str, SpecifierSet] = {}
    for req in data["build-system"]["requires"]:
        match = re.match(r"^([A-Za-z0-9_.\-]+)\s*(.*)$", req.strip())
        assert match, req
        requires[match.group(1).lower()] = SpecifierSet(match.group(2).strip())
    return requires


class TestBuildProfileIsConsistent:
    def test_tools_lockfile_build_pins_match_main_lockfile(self):
        """The exact release build inputs must be one profile: the
        tools lockfile and the main lockfile must pin the same versions
        of build/setuptools/wheel."""
        tools = _parse_lockfile(TOOLS_LOCKFILE)
        main = _parse_lockfile(MAIN_LOCKFILE)
        for package in BUILD_PROFILE_PACKAGES:
            assert package in tools, f"{package} missing from tools lockfile"
            assert package in main, f"{package} missing from main lockfile"
            assert tools[package] == main[package], (
                f"{package}: tools lockfile pins {tools[package]} but the "
                f"main lockfile pins {main[package]} — the reproducibility "
                "proof would not cover the release build inputs (ENG-10)"
            )

    def test_build_pins_inside_pyproject_ranges(self):
        """The pinned build profile must satisfy the pyproject
        build-system ranges (the broad library role). Only setuptools
        and wheel are backend requirements in pyproject.toml; the
        ``build`` frontend is a workflow tool whose version is pinned
        by the lockfiles alone (agreement between lockfiles is covered
        by test_tools_lockfile_build_pins_match_main_lockfile)."""
        tools = _parse_lockfile(TOOLS_LOCKFILE)
        requires = _pyproject_build_requires()
        for package, spec in requires.items():
            assert package in tools, f"{package} missing from tools lockfile"
            version = Version(tools[package])
            assert version in spec, (
                f"{package}=={tools[package]} is outside the pyproject build-system range {spec}"
            )

    def test_every_tools_lockfile_entry_is_hash_pinned(self):
        counts = _lockfile_has_hashes(TOOLS_LOCKFILE)
        pins = _parse_lockfile(TOOLS_LOCKFILE)
        assert pins, "tools lockfile parsed to zero pins"
        for name in pins:
            assert counts.get(name, 0) >= 1, (
                f"{name}=={pins[name]} has no --hash entries in the tools "
                "lockfile (ENG-10: unpinned input)"
            )


class TestToolsLockfileClosure:
    def test_known_transitives_are_pinned_with_hashes(self):
        """Every known transitive dependency of a tools-lockfile direct
        pin must itself be pinned with hashes — otherwise pip under
        --require-hashes resolves it to an unhashed download URL and
        the install fails (the psutil failure)."""
        pins = _parse_lockfile(TOOLS_LOCKFILE)
        counts = _lockfile_has_hashes(TOOLS_LOCKFILE)
        for parent, transitives in KNOWN_TRANSITIVES.items():
            assert parent in pins, f"{parent} missing from tools lockfile"
            for dep in sorted(transitives):
                assert dep in pins, (
                    f"{dep} (transitive of {parent}) is not pinned in the tools lockfile"
                )
                assert counts.get(dep, 0) >= 1, f"{dep} has no --hash entries in the tools lockfile"

    def test_shared_packages_match_main_lockfile_versions(self):
        """Where a tools-lockfile package is also in the main lockfile,
        both must pin the same version (one version per package across
        the repo) — except the documented exceptions below, where the
        main-lockfile version is incompatible with a tools direct pin's
        own requirement and the tools lockfile installs into a separate
        venv, so the versions never mix."""
        tools = _parse_lockfile(TOOLS_LOCKFILE)
        main = _parse_lockfile(MAIN_LOCKFILE)
        shared = sorted(set(tools) & set(main))
        assert shared, "no shared packages between the lockfiles"
        mismatched = {
            name: (tools[name], main[name]) for name in shared if tools[name] != main[name]
        }
        # sphinx 8.2.3 requires docutils<0.22; the main lockfile pins
        # 0.23. The tools resolution therefore uses docutils 0.21.2.
        allowed = {"docutils"}
        unexpected = {name: v for name, v in mismatched.items() if name not in allowed}
        assert not unexpected, "version mismatch between lockfiles: " + str(unexpected)
        assert mismatched.keys() <= allowed

    def test_tools_lockfile_install_dry_run(self):
        """Executable check: pip must be able to resolve the tools
        lockfile under --require-hashes (this is the exact failure the
        Reproducibility job hits). A dry run installs nothing.

        A network failure skips (the install cannot be proven offline);
        a hash-mode or resolution failure fails the test.
        """
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--dry-run",
                "--require-hashes",
                "-r",
                str(TOOLS_LOCKFILE),
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        combined = (result.stdout + result.stderr).lower()
        if result.returncode != 0 and (
            "connection" in combined
            or "could not fetch" in combined
            or "temporary failure in name resolution" in combined
            or "no route to host" in combined
        ):
            pytest.skip("no network to PyPI; cannot prove the lockfile installs")
        assert result.returncode == 0, (
            "pip --dry-run --require-hashes -r requirements-tools-hashed.txt "
            f"failed (exit {result.returncode}):\n"
            f"{result.stdout[-1500:]}\n{result.stderr[-1500:]}"
        )


class TestNoWorkflowInstallsUnpinnedBuildInput:
    """Every workflow pip install from an index must be hash-pinned;
    local installs must be --no-deps (ENG-10, W7 side: the same rule
    the release profile depends on)."""

    @staticmethod
    def _pip_install_lines():
        lines = []
        for workflow in sorted(WORKFLOWS_DIR.glob("*.yml")):
            text = workflow.read_text(encoding="utf-8")
            for number, line in enumerate(text.splitlines(), start=1):
                if "pip install" in line and not line.strip().startswith("#"):
                    lines.append((workflow.name, number, line.strip()))
        return lines

    def test_all_index_installs_are_hash_pinned(self):
        bad = []
        for filename, number, line in self._pip_install_lines():
            if "-r " in line or "--requirement" in line:
                if "--require-hashes" not in line:
                    bad.append(
                        (filename, number, line, "lockfile install without --require-hashes")
                    )
            elif "-e " in line or "--editable" in line:
                # Local editable install: must not resolve from the index.
                if "--no-deps" not in line:
                    bad.append((filename, number, line, "editable install without --no-deps"))
            elif "dist/*.whl" in line:
                # Local wheel built earlier in the same workflow from
                # pinned inputs (documented cannot-be-fixed Scorecard
                # alert 291): the artifact itself is the build input,
                # and the wheel declares no dependencies, so nothing is
                # resolved from the index. Allowed as-is.
                continue
            else:
                bad.append((filename, number, line, "bare pip install of a named package"))
        assert not bad, "workflow installs an unpinned build input:\n" + "\n".join(
            f"  {f}:{n}: {why}\n    {line}" for f, n, line, why in bad
        )

    def test_workflows_build_from_a_pinned_lockfile(self):
        """Any job that builds a distribution (python -m build) must
        install a hash-pinned lockfile first, so the build inputs are
        the audited profile rather than ambient versions. Either
        lockfile qualifies: after the ENG-10 reconciliation both pin
        the same build/setuptools/wheel versions (see
        test_tools_lockfile_build_pins_match_main_lockfile)."""
        for workflow in sorted(WORKFLOWS_DIR.glob("*.yml")):
            text = workflow.read_text(encoding="utf-8")
            if "python -m build" not in text:
                continue
            has_pinned_install = (
                "--require-hashes -r requirements-hashed.txt" in text
                or "--require-hashes -r requirements-tools-hashed.txt" in text
            )
            assert has_pinned_install, (
                f"{workflow.name} runs `python -m build` without first "
                "installing a hash-pinned lockfile (ENG-10: the build "
                "inputs would be ambient, not the pinned profile)"
            )


class TestNoWorkflowBuildInputIsFloating:
    """ENG-10 (W7 remainder): the pip-install rule above is not the
    whole build chain. A workflow build input that resolves floating
    (a `:latest` container image, a locally built wheel re-installed
    with dependency resolution) is an unpinned build input too."""

    def test_local_wheel_installs_are_no_deps(self):
        """Re-installing a wheel built earlier in the same workflow must
        not resolve dependencies from the index: without --no-deps pip
        resolves the wheel's declared dependencies floating."""
        bad = []
        for workflow in sorted(WORKFLOWS_DIR.glob("*.yml")):
            text = workflow.read_text(encoding="utf-8")
            for number, line in enumerate(text.splitlines(), start=1):
                if "pip install" in line and "dist/*.whl" in line and "--no-deps" not in line:
                    bad.append((workflow.name, number, line.strip()))
        assert not bad, "workflow re-installs a local wheel without --no-deps:\\n" + "\\n".join(
            f"  {f}:{n}: {line}" for f, n, line in bad
        )

    def test_no_workflow_references_a_latest_image(self):
        """No workflow may reference a `:latest` image tag: the tag is
        mutable, so the build input changes without any repo change."""
        bad = []
        for workflow in sorted(WORKFLOWS_DIR.glob("*.yml")):
            text = workflow.read_text(encoding="utf-8")
            for number, line in enumerate(text.splitlines(), start=1):
                stripped = line.strip()
                if stripped.startswith("#") or ":latest" not in line:
                    continue
                bad.append((workflow.name, number, stripped))
        assert not bad, "workflow references a floating :latest image:\\n" + "\\n".join(
            f"  {f}:{n}: {line}" for f, n, line in bad
        )

    def test_buildkit_driver_image_is_digest_pinned(self):
        """The docker-container builder image is a build input: it must
        be pinned to an exact version AND digest (moby/buildkit), never
        a floating tag. setup-buildx-action itself is SHA-pinned; the
        image it pulls must be pinned too."""
        import re

        pattern = re.compile(r"image=(moby/buildkit:[^\s]+)")
        found: list[str] = []
        bad: list[str] = []
        for workflow in sorted(WORKFLOWS_DIR.glob("*.yml")):
            text = workflow.read_text(encoding="utf-8")
            for number, line in enumerate(text.splitlines(), start=1):
                for match in pattern.finditer(line):
                    value = match.group(1)
                    found.append(value)
                    if not re.fullmatch(r"moby/buildkit:v\d+\.\d+\.\d+@sha256:[0-9a-f]{64}", value):
                        bad.append((workflow.name, number, value))
        assert found, "no buildkit driver image found in any workflow"
        assert not bad, "buildkit driver image is not version+digest pinned:\\n" + "\\n".join(
            f"  {f}:{n}: {value}" for f, n, value in bad
        )
