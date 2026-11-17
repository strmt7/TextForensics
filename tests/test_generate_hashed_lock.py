"""Tests for scripts/generate_hashed_lock.py (hash-lockfile generation).

Red-first tests, written from the CI failure on main fefd81e (CI run
44017091376) before the source fix:

- Every 3.11 job died at install: ``backports.tarfile`` (required by
  ``jaraco-context`` when ``python_version < "3.12"``) resolved to an
  unhashed download URL because it was not pinned anywhere — the old
  generator (``~/workspace/gen_hashed_lock.py``, outside the repo)
  hash-pinned exactly the packages listed in ``requirements-pinned.txt``,
  and that file was frozen on Python 3.12 / Linux, so marker-gated
  transitives for other Pythons/platforms were never listed.
- Every Windows job died the same way on ``colorama`` (required by
  ``build`` / ``pytest`` / ``bandit`` on ``win32``).
- pip fails on the FIRST unpinned transitive it meets, so more missing
  deps hide behind the first failure (``importlib-metadata`` on 3.11,
  ``pywin32`` / ``pywin32-ctypes`` on Windows, and their transitives
  ``zipp`` / ``lazy-importer``). Closing the closure from one CI log at
  a time would take one red CI run per missing package.

The fix moves the generator into the repo and makes it verify the full
transitive closure across the CI environment grid (Python 3.11-3.15 x
Linux/Windows/macOS) before emitting anything, failing closed on any
missing transitive, any pinned version outside a parent's specifier,
and any package without hashes.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

import generate_hashed_lock as gen

REPO_ROOT = Path(__file__).parent.parent
PINNED_FILE = REPO_ROOT / "requirements-pinned.txt"
HASHED_FILE = REPO_ROOT / "requirements-hashed.txt"
GENERATOR = REPO_ROOT / "scripts" / "generate_hashed_lock.py"

# Marker-gated transitives that must be pinned with hashes: the exact
# table of the CI fix. Each entry is (name, version, marker) — the
# version pip's resolver picks (highest satisfying the parents'
# specifiers), the marker under which the parent requires it. Kept as
# an explicit table: the closure computation is what derives these,
# and the table pins the result so a future regeneration cannot
# silently drop one again.
KNOWN_MARKER_GATED_TRANSITIVES = {
    # jaraco-context; python_version < "3.12" (every 3.11 job).
    "backports-tarfile": ("1.2.0", 'python_version < "3.12"'),
    # build (os_name == "nt"), pytest / bandit (win32); every Windows job.
    "colorama": ("0.4.6", 'sys_platform == "win32"'),
    # keyring; python_version < "3.12" (3.11 only).
    "importlib-metadata": ("10.2.0", 'python_version < "3.12"'),
    # importlib-metadata; python_version < "3.15" — but importlib-metadata
    # itself is only installed on python_version < "3.12", so the
    # effective marker is python_version < "3.12".
    "lazy-importer": ("0.1.0", 'python_version < "3.12"'),
    # mcp; sys_platform == "win32" (Windows only).
    "pywin32": ("312", 'sys_platform == "win32"'),
    # keyring; sys_platform == "win32" (Windows only).
    "pywin32-ctypes": ("0.2.3", 'sys_platform == "win32"'),
    # importlib-metadata (no marker) — but importlib-metadata itself is
    # only installed on python_version < "3.12", so the effective
    # marker is python_version < "3.12".
    "zipp": ("4.1.2", 'python_version < "3.12"'),
}


def _make_fetch(packages: dict) -> object:
    """Build a stub PyPI fetcher from {(name, version): info-dict}.

    ``fetch(name, version)`` returns ``{"info": info, "urls": [...]}``
    for a pinned version and ``{"releases": {...}, "info": {...}}``
    for ``version=None`` (the package index, used for version
    selection). Missing entries raise, like a 404 from PyPI.
    """

    def fetch(name: str, version: str | None = None) -> dict:
        if version is None:
            key = (gen.normalize_name(name), None)
            if key not in packages:
                raise ValueError(f"no index for {name}")
            return packages[key]
        key = (gen.normalize_name(name), version)
        if key not in packages:
            raise ValueError(f"no metadata for {name}=={version}")
        return packages[key]

    return fetch


def _package(requires_dist: list[str], urls: list[dict] | None = None) -> dict:
    return {
        "info": {"requires_dist": requires_dist, "requires_python": ">=3.11"},
        "urls": urls if urls is not None else [],
    }


def _file(requires_python: str | None = ">=3.8") -> dict:
    return {
        "filename": "dummy-1.0-py3-none-any.whl",
        "requires_python": requires_python,
        "digests": {"sha256": "a" * 64},
    }


class TestClosureUnit:
    def test_closure_reports_marker_gated_missing_dep(self):
        """A transitive required only on some grid envs is reported
        with the exact pinned line to add (version pip would pick +
        the marker under which it is required)."""
        fetch = _make_fetch(
            {
                ("aaa", "1.0"): _package(['bbb>=2; python_version < "3.12"']),
                ("bbb", "2.0"): _package([]),
                ("bbb", None): {
                    "info": {},
                    "releases": {
                        "2.0": [_file(">=3.8")],
                        # 3.0 requires >=3.12: not installable where bbb
                        # is required (3.11), so pip would not pick it.
                        "3.0": [_file(">=3.12")],
                    },
                },
            }
        )
        _, violations, missing = gen.compute_closure([("aaa", "1.0", None)], fetch=fetch)
        assert violations == []
        assert set(missing) == {"bbb"}
        version, _specs, envs = missing["bbb"]
        assert version == "2.0"
        assert envs == {"py3.11-linux", "py3.11-win32", "py3.11-darwin"}
        assert gen.derive_marker(envs, gen.grid_environments()) == 'python_version < "3.12"'

    def test_closure_reports_windows_only_missing_dep(self):
        fetch = _make_fetch(
            {
                ("ccc", "1.0"): _package(['ddd; sys_platform == "win32"']),
                ("ddd", "1.0"): _package([]),
                ("ddd", None): {
                    "info": {},
                    "releases": {"1.0": [_file(">=3.8")]},
                },
            }
        )
        _, violations, missing = gen.compute_closure([("ccc", "1.0", None)], fetch=fetch)
        assert violations == []
        assert set(missing) == {"ddd"}
        version, _specs, envs = missing["ddd"]
        assert version == "1.0"
        assert envs == {f"py{py}-win32" for py in ("3.11", "3.12", "3.13", "3.14", "3.15")}
        assert gen.derive_marker(envs, gen.grid_environments()) == 'sys_platform == "win32"'

    def test_closure_complete_when_marker_gated_dep_is_pinned(self):
        fetch = _make_fetch(
            {
                ("aaa", "1.0"): _package(['bbb>=2; python_version < "3.12"']),
                ("bbb", "2.0"): _package([]),
            }
        )
        _, violations, missing = gen.compute_closure(
            [("aaa", "1.0", None), ("bbb", "2.0", 'python_version < "3.12"')],
            fetch=fetch,
        )
        assert violations == []
        assert missing == {}

    def test_closure_reports_specifier_violation(self):
        """A pinned version outside a parent's specifier is a hard
        error: pip would fail the resolution instead of installing it."""
        fetch = _make_fetch(
            {
                ("aaa", "1.0"): _package(["bbb>=2"]),
                ("bbb", "1.0"): _package([]),
            }
        )
        _, violations, missing = gen.compute_closure(
            [("aaa", "1.0", None), ("bbb", "1.0", None)], fetch=fetch
        )
        assert missing == {}
        assert violations
        assert ("bbb", "1.0", ">=2") in [
            (dep, pinned, spec) for _env, _parent, dep, pinned, spec in violations
        ]

    def test_excluded_pip_is_not_reported_missing(self):
        """``pip`` is installer-provided (pre-installed in every venv):
        a bare ``pip`` requirement from pip-api must not be reported
        as a missing transitive."""
        fetch = _make_fetch(
            {
                ("aaa", "1.0"): _package(["pip"]),
            }
        )
        _, violations, missing = gen.compute_closure([("aaa", "1.0", None)], fetch=fetch)
        assert violations == []
        assert missing == {}

    def test_transitive_of_missing_dep_is_walked(self):
        """A missing dep's own deps are walked too: importlib-metadata
        pulls zipp (unconditional) and lazy-importer (py<3.15), but
        both inherit the py<3.12 marker because importlib-metadata
        itself is only installed there."""
        fetch = _make_fetch(
            {
                ("keyring", "1.0"): _package(
                    ['importlib-metadata>=4.11.4; python_version < "3.12"']
                ),
                ("importlib-metadata", None): {
                    "info": {},
                    "releases": {"10.2.0": [_file(">=3.11")]},
                },
                ("importlib-metadata", "10.2.0"): _package(
                    ["zipp>=3.20", 'lazy-importer>=0.1; python_version < "3.15"']
                ),
                ("zipp", None): {
                    "info": {},
                    "releases": {"4.1.2": [_file(">=3.10")]},
                },
                ("zipp", "4.1.2"): _package([]),
                ("lazy-importer", None): {
                    "info": {},
                    "releases": {"0.1.0": [_file(">=3.11")]},
                },
                ("lazy-importer", "0.1.0"): _package([]),
            }
        )
        _, violations, missing = gen.compute_closure([("keyring", "1.0", None)], fetch=fetch)
        assert violations == []
        assert set(missing) == {"importlib-metadata", "zipp", "lazy-importer"}
        grid = gen.grid_environments()
        for dep in ("importlib-metadata", "zipp", "lazy-importer"):
            assert gen.derive_marker(missing[dep][2], grid) == 'python_version < "3.12"'

    def test_derive_marker(self):
        grid = gen.grid_environments()
        all_envs = {label for label, _ in grid}
        assert gen.derive_marker(all_envs, grid) is None
        py311 = {label for label in all_envs if label.startswith("py3.11-")}
        assert gen.derive_marker(py311, grid) == 'python_version < "3.12"'
        win32 = {label for label in all_envs if label.endswith("-win32")}
        assert gen.derive_marker(win32, grid) == 'sys_platform == "win32"'
        py313 = {label for label in all_envs if label.startswith("py3.13-")}
        assert gen.derive_marker(py313, grid) == 'python_version == "3.13"'
        with pytest.raises(ValueError, match="no simple marker"):
            gen.derive_marker({"py3.11-linux", "py3.12-win32"}, grid)

    def test_select_version_skips_fileless_and_prerelease(self):
        fetch = _make_fetch(
            {
                ("bbb", None): {
                    "info": {},
                    "releases": {
                        "2.0": [_file(">=3.8")],
                        "2.1": [],  # reserved version number, no files
                        "3.0a1": [_file(">=3.8")],  # pre-release
                    },
                },
            }
        )
        grid = gen.grid_environments()
        version = gen.select_version("bbb", set(), {"py3.11-linux"}, grid, fetch)
        assert version == "2.0"


class TestGenerateFailsClosed:
    def test_generate_fails_without_writing_when_hashes_missing(self, tmp_path, monkeypatch):
        """The old generator emitted an unhashed ``name==version``
        line when the hash fetch failed — how a silent gap ships.
        The new generator fails closed and writes nothing."""

        def failing_fetch(name: str, version: str | None = None) -> dict:
            if version is None:
                return {"info": {}, "releases": {}}
            if name == "bbb":
                raise ValueError("PyPI is down")
            return _package([])

        monkeypatch.setattr(gen, "pypi_json", failing_fetch)
        monkeypatch.setattr(gen, "PINNED_FILE", tmp_path / "requirements-pinned.txt")
        (tmp_path / "requirements-pinned.txt").write_text("aaa==1.0\nbbb==2.0\n", encoding="utf-8")
        output = tmp_path / "requirements-hashed.txt"
        with pytest.raises(ValueError, match="bbb"):
            gen.generate(output)
        assert not output.exists()


def _parse_hashed(path: Path) -> dict[str, dict]:
    """Parse a hashed lockfile into {name: {version, marker, hashes}}."""
    text = path.read_text(encoding="utf-8")
    entries: dict[str, dict] = {}
    current: str | None = None
    for line in text.splitlines():
        match = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s\\]+)(?:\s*;\s*(.+?))?\s*\\$", line)
        if match:
            current = match.group(1).lower().replace("_", "-")
            entries[current] = {
                "version": match.group(2),
                "marker": (match.group(3) or "").strip() or None,
                "hashes": [],
            }
        elif line.strip().startswith("--hash=sha256:") and current:
            entries[current]["hashes"].append(line.strip())
    return entries


def _parse_pinned(path: Path) -> dict[str, dict]:
    pins: dict[str, dict] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-e "):
            continue
        match = re.fullmatch(
            r"([A-Za-z0-9_.\-]+)==([^\s;#]+)(?:\s*;\s*(.+?))?\s*(?:#.*)?",
            line.split("#", 1)[0].strip(),
        )
        assert match is not None, f"not an exact == pin: {raw_line!r}"
        pins[match.group(1).lower().replace("_", "-")] = {
            "version": match.group(2),
            "marker": (match.group(3) or "").strip() or None,
        }
    return pins


class TestLockfilesAgree:
    def test_hashed_lockfile_covers_pinned_file(self):
        """Every pinned entry must appear in the hashed lockfile with
        the same version, the same marker, and at least one hash.
        A marker-gated entry whose marker is lost (or dropped) would
        install on environments its files do not support — or be
        missing where pip needs it."""
        pinned = _parse_pinned(PINNED_FILE)
        hashed = _parse_hashed(HASHED_FILE)
        assert pinned, "no pins in requirements-pinned.txt"
        assert hashed, "no entries in requirements-hashed.txt"
        assert set(hashed) == set(pinned), (
            "hashed lockfile and pinned file disagree on package set: "
            f"only in pinned: {sorted(set(pinned) - set(hashed))}, "
            f"only in hashed: {sorted(set(hashed) - set(pinned))}"
        )
        for name, pin in sorted(pinned.items()):
            entry = hashed[name]
            assert entry["version"] == pin["version"], (
                f"{name}: hashed pins {entry['version']} but pinned pins {pin['version']}"
            )
            assert entry["marker"] == pin["marker"], (
                f"{name}: hashed marker {entry['marker']!r} but pinned marker {pin['marker']!r}"
            )
            assert entry["hashes"], f"{name}=={pin['version']} has no --hash entries"

    def test_marker_gated_transitives_are_pinned(self):
        """The CI-fix table: every marker-gated transitive from the
        fefd81e install failures is pinned with hashes, at the exact
        version and marker, in both lockfiles."""
        pinned = _parse_pinned(PINNED_FILE)
        hashed = _parse_hashed(HASHED_FILE)
        for name, (version, marker) in sorted(KNOWN_MARKER_GATED_TRANSITIVES.items()):
            assert name in pinned, f"{name} missing from requirements-pinned.txt"
            assert name in hashed, f"{name} missing from requirements-hashed.txt"
            assert pinned[name]["version"] == version, (
                f"{name}: pinned {pinned[name]['version']}, expected {version}"
            )
            assert hashed[name]["version"] == version
            assert pinned[name]["marker"] == marker, (
                f"{name}: pinned marker {pinned[name]['marker']!r}, expected {marker!r}"
            )
            assert hashed[name]["marker"] == marker
            assert hashed[name]["hashes"], f"{name} has no --hash entries"

    def test_grid_matches_ci_matrix_and_requires_python(self):
        """The closure grid must match what CI actually runs: the
        core matrix Pythons in .github/workflows/ci.yml, the lower
        bound of requires-python, and the OS-smoke platforms."""
        with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
            project = tomllib.load(handle)["project"]
        requires_python = str(project["requires-python"])
        assert requires_python.startswith(">="), requires_python
        lower = requires_python[2:].strip().split(",")[0].strip()
        assert gen.GRID_PYTHONS[0] == lower, (
            f"grid starts at {gen.GRID_PYTHONS[0]} but requires-python is {requires_python}"
        )
        workflows = yaml.safe_load((REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text())
        core_matrix = workflows["jobs"]["core"]["strategy"]["matrix"]["python-version"]
        assert list(core_matrix) == list(gen.GRID_PYTHONS), (
            f"CI core matrix {core_matrix} != generator grid {gen.GRID_PYTHONS}"
        )
        ci_text = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text()
        assert "windows-latest" in ci_text
        assert "macos-latest" in ci_text


class TestLiveLockfile:
    def test_hashed_lockfile_install_dry_run(self):
        """Executable check: pip must be able to resolve the hashed
        lockfile under --require-hashes on this environment (this is
        the exact failure the 3.11/Windows jobs hit, for this env).
        A dry run installs nothing. A network failure skips (the
        install cannot be proven offline); a hash-mode or resolution
        failure fails the test."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--dry-run",
                "--require-hashes",
                "-r",
                str(HASHED_FILE),
            ],
            capture_output=True,
            text=True,
            timeout=600,
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
            "pip --dry-run --require-hashes -r requirements-hashed.txt "
            f"failed (exit {result.returncode}):\n"
            f"{result.stdout[-1500:]}\n{result.stderr[-1500:]}"
        )

    def test_live_closure_check(self):
        """Live regression test for the bug class: the generator's
        --check must pass on the real pinned file, i.e. the closure
        is complete on every grid environment. Runs against PyPI, so
        a network failure (including rate-limiting) skips."""
        result = subprocess.run(
            [sys.executable, str(GENERATOR), "--check"],
            capture_output=True,
            text=True,
            timeout=900,
        )
        combined = (result.stdout + result.stderr).lower()
        if result.returncode != 0 and (
            "connection" in combined
            or "could not fetch" in combined
            or "temporary failure in name resolution" in combined
            or "no route to host" in combined
            or "429" in combined
            or "too many requests" in combined
        ):
            pytest.skip("no network to PyPI; cannot prove the closure")
        assert result.returncode == 0, (
            "generate_hashed_lock.py --check failed:\n"
            f"{result.stdout[-2000:]}\n{result.stderr[-2000:]}"
        )
