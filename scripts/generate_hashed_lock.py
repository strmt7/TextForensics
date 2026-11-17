#!/usr/bin/env python3
"""Generate requirements-hashed.txt from requirements-pinned.txt.

The old generator (``~/workspace/gen_hashed_lock.py``, kept outside the
repo) hash-pinned exactly the packages listed in requirements-pinned.txt
— and nothing else. That file was frozen on Python 3.12 / Linux, so any
transitive dependency that only exists under an environment marker for
another supported Python or platform was never listed. ``pip install
--require-hashes`` refuses every unpinned transitive, so the install
died on exactly those environments:

* every 3.11 job: ``backports.tarfile`` (required by
  ``jaraco-context`` when ``python_version < "3.12"``) resolved to an
  unhashed download URL (CI run 44017091376, Core Python 3.11);
* every Windows job: ``colorama`` (required by ``build``/``pytest``/
  ``bandit`` on ``win32``) did the same (OS smoke windows-latest 3.15).

Worse, pip fails on the FIRST unpinned transitive it meets, so more
missing deps hide behind the first failure: closing the closure by hand
from one CI log at a time would take one red CI run per missing
package. This generator therefore verifies the FULL transitive closure
across the whole CI environment grid before it emits anything, using
the same PEP 508 marker semantics pip itself uses (``packaging``):

* the grid is Python 3.11-3.15 (the ``core`` matrix in
  ``.github/workflows/ci.yml``; ``requires-python = ">=3.11"``) crossed
  with Linux, Windows and macOS (the OS-smoke jobs);
* for every pinned package it reads ``Requires-Dist`` from the PyPI
  JSON API for the pinned version, evaluates each requirement's marker
  against every grid environment (with ``extra == ""``: the hashed
  lockfile is installed plain, with no extras), and collects every
  required package, its specifiers, its parents and the environments
  where it is required;
* a required package that is NOT pinned is a hard error: the generator
  prints the exact ``name==version; marker`` line to add to
  requirements-pinned.txt (version = the highest release satisfying
  all collected specifiers whose files are compatible with every
  environment where it is required — the version pip's resolver would
  pick) and exits 1 without writing anything. The pinned file stays
  the human-reviewed source of truth; the generator never invents pins
  silently. Re-run after adding the lines: exit 0 means the closure is
  complete on every grid environment.
* a pinned version that violates a parent's specifier is a hard error
  too (pip would fail the resolution instead of installing it).

``pip`` itself is the one deliberate exclusion (``EXCLUDED``): it is
the venv's installer, pre-installed in every venv, and ``pip-api``
requires it bare. It is never downloaded when already present and
satisfying, so it needs no hash — the same reasoning as
``scripts/generate_sbom.py``'s ``EXCLUDED_DISTRIBUTIONS`` and the
``requirements-pinned.txt`` header (``pip`` is deliberately NOT listed).

Every emitted package pins an exact version AND a ``--hash=sha256:``
for EVERY downloadable file of that version (wheels + sdist), so the
same lockfile works across platforms and Python versions. A package
whose hashes cannot be fetched (network failure, no files on PyPI) is
a hard error: the old generator emitted an unhashed ``name==version``
line for it, which is exactly how a silent gap ships.

Usage:
    python3 scripts/generate_hashed_lock.py [--check] [--output PATH]

``--check`` only verifies the closure and exits 0/1 (no file written).
Without ``--check`` the hashed lockfile is written to
``requirements-hashed.txt`` (or ``--output``). Network access to PyPI
is required (metadata + hash fetch). The output is deterministic for
fixed inputs: pinned-file order, hashes sorted.

Regenerate after any requirements-pinned.txt change, and after any
change to the grid (a new supported Python or platform in CI).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

from packaging.markers import Marker, default_environment
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

REPO_ROOT = Path(__file__).resolve().parent.parent
PINNED_FILE = REPO_ROOT / "requirements-pinned.txt"
DEFAULT_OUTPUT = REPO_ROOT / "requirements-hashed.txt"

# The CI environment grid the lockfile must install on. Python versions
# are the `core` matrix in .github/workflows/ci.yml; platforms are the
# OS-smoke jobs (ubuntu / windows / macos). Keep in sync with CI: if a
# Python or platform is added to or dropped from the matrix, update this
# grid in the same change and re-run with --check.
GRID_PYTHONS = ("3.11", "3.12", "3.13", "3.14", "3.15")
GRID_PLATFORMS = ("linux", "win32", "darwin")

# Packages that are required by metadata but must NOT be pinned: the
# name is the normalized (PEP 503) name, the value the reason. Keep
# this to installer-provided packages only; anything else that is
# required somewhere must be pinned like any other transitive.
EXCLUDED: dict[str, str] = {
    # The venv's installer, pre-installed everywhere; pip-api requires
    # it bare and pip never downloads it when already present.
    "pip": "installer-provided; see scripts/generate_sbom.py EXCLUDED_DISTRIBUTIONS",
}

PIN_RE = re.compile(r"^([A-Za-z0-9_.\-]+)==([^\s;#]+)(?:\s*;\s*([^#]*?))?\s*(?:#.*)?$")

USER_AGENT = "TextForensics-lockfile-gen/1.0"


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def grid_environments() -> list[tuple[str, dict]]:
    """Return [(label, marker-env)] for every grid environment."""
    base = default_environment()
    environments: list[tuple[str, dict]] = []
    platform_map = {
        "linux": ("posix", "Linux", "x86_64"),
        "win32": ("nt", "Windows", "AMD64"),
        "darwin": ("posix", "Darwin", "arm64"),
    }
    for python_version in GRID_PYTHONS:
        for platform in GRID_PLATFORMS:
            os_name, system, machine = platform_map[platform]
            env = dict(base)
            env.update(
                {
                    "python_version": python_version,
                    "python_full_version": python_version + ".9",
                    "implementation_version": python_version + ".9",
                    "sys_platform": platform,
                    "os_name": os_name,
                    "platform_system": system,
                    "platform_machine": machine,
                    "extra": "",
                }
            )
            environments.append((f"py{python_version}-{platform}", env))
    return environments


def parse_pinned(path: Path) -> list[tuple[str, str, str | None]]:
    """Parse requirements-pinned.txt into [(name, version, marker)]."""
    pins: list[tuple[str, str, str | None]] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-e "):
            continue
        match = PIN_RE.match(line.split("#", 1)[0].strip())
        if not match:
            raise ValueError(f"not an exact == pin in {path}: {raw_line!r}")
        marker = (match.group(3) or "").strip() or None
        pins.append((normalize_name(match.group(1)), match.group(2), marker))
    if not pins:
        raise ValueError(f"no pins in {path}")
    return pins


_PYPI_CACHE: dict[tuple[str, str | None], dict] = {}


def pypi_json(name: str, version: str | None = None) -> dict:
    """Fetch one package's PyPI JSON (pinned version, or the index).

    Results are cached in-memory for the run: the closure walk asks
    for the same (name, version) once per grid environment, and the
    metadata cannot change mid-run, so refetching would only multiply
    the request count (120 packages x 15 envs) and the wall time.
    """
    normalized = normalize_name(name)
    key = (normalized, version)
    if key in _PYPI_CACHE:
        return _PYPI_CACHE[key]
    url = (
        f"https://pypi.org/pypi/{normalized}/{version}/json"
        if version is not None
        else f"https://pypi.org/pypi/{normalized}/json"
    )
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = json.load(response)
    _PYPI_CACHE[key] = data
    return data


def _marker_matches_envs(marker: str | None, envs: set[str], grid: list[tuple[str, dict]]) -> bool:
    """Whether `marker` holds exactly on the grid envs in `envs`."""
    if marker is None:
        return envs == {label for label, _ in grid}
    parsed = Marker(marker)
    return {label for label, env in grid if parsed.evaluate(env)} == envs


def derive_marker(envs: set[str], grid: list[tuple[str, dict]]) -> str | None:
    """Derive the PEP 508 marker that holds exactly on `envs`.

    Tries the simple forms first (one Python condition, one platform
    condition, and their conjunction); the derived marker is verified
    against the exact env set, so a wrong derivation is impossible —
    if no simple form matches, the caller must write the marker by
    hand from the reported env set instead of getting a wrong one.
    """
    if not envs:
        raise ValueError("cannot derive a marker for an empty env set")
    if envs == {label for label, _ in grid}:
        return None
    python_versions = sorted({label.split("-")[0][2:] for label, _ in grid})
    # Range forms first: upstream packages write these conditions as
    # ranges (``python_version < "3.12"``, the atheris
    # ``>= "3.12" and < "3.15"``), and a range stays correct if the
    # grid later extends in the direction it already covers, where an
    # ``==`` form would silently stop matching. ``==`` is the fallback
    # for a single version no range form covers exactly.
    python_conditions = [
        'python_version < "3.12"',
        'python_version >= "3.12" and python_version < "3.15"',
    ]
    python_conditions += [f'python_version < "{v}"' for v in python_versions]
    python_conditions += [f'python_version >= "{v}"' for v in python_versions]
    python_conditions += [f'python_version == "{v}"' for v in python_versions]
    platform_conditions = [
        f'sys_platform == "{platform}"' for platform in ("linux", "win32", "darwin")
    ] + ['os_name == "nt"']
    candidates = python_conditions + platform_conditions
    candidates += [
        f"{python_condition} and {platform_condition}"
        for python_condition in python_conditions
        for platform_condition in platform_conditions
    ]
    for candidate in candidates:
        try:
            if _marker_matches_envs(candidate, envs, grid):
                return candidate
        except Exception:  # noqa: BLE001 - an invalid candidate is skipped
            continue
    raise ValueError(
        f"no simple marker covers exactly the environments {sorted(envs)}; write the marker by hand"
    )


def select_version(
    name: str,
    specifiers: set[str],
    envs: set[str],
    grid: list[tuple[str, dict]],
    fetch=pypi_json,
) -> str:
    """Pick the version pip's resolver would pick for a missing dep.

    Highest release satisfying every collected specifier, with files on
    PyPI, whose ``requires_python`` allows every grid Python where the
    package is required. Pre-releases and file-less releases (a version
    number reserved with no files) are skipped, as pip skips them.
    """
    specifier = SpecifierSet(",".join(sorted(s for s in specifiers if s)))
    data = fetch(name)
    needed_pythons = sorted({label.split("-")[0][2:] for label in envs})
    candidates: list[Version] = []
    for version_string, files in data["releases"].items():
        if not files:
            continue
        try:
            version = Version(version_string)
        except Exception:  # noqa: BLE001 - a non-PEP 440 version is skipped
            continue
        if version.is_prerelease or version not in specifier:
            continue
        requires_python = {f.get("requires_python") for f in files if f.get("requires_python")}
        if requires_python and not all(
            any(Version(f"{python}.9") in SpecifierSet(rp) for rp in requires_python if rp)
            for python in needed_pythons
        ):
            continue
        candidates.append(version)
    if not candidates:
        raise ValueError(
            f"no PyPI release of {name} satisfies {sorted(specifiers)} on Python {needed_pythons}"
        )
    return str(max(candidates))


def compute_closure(
    pins: list[tuple[str, str, str | None]],
    fetch=pypi_json,
) -> tuple[
    dict[str, dict],
    list[tuple[str, str, str, str, str]],
    dict[str, tuple[str, set[str], set[str]]],
]:
    """Compute the transitive closure over the grid.

    Returns ``(required, violations, missing)``:

    * ``required`` maps every required normalized name to
      ``{"specs": set, "parents": set, "envs": set}``;
    * ``violations`` is a list of ``(env, parent, dep, pinned, spec)``
      where a pinned version falls outside a parent's specifier;
    * ``missing`` maps every required-but-unpinned name to
      ``(version, specifiers, envs)`` — the version pip would pick and
      the marker's env set (derive the marker with :func:`derive_marker`).
    """
    grid = grid_environments()
    by_name = {name: (version, marker) for name, version, marker in pins}
    required: dict[str, dict] = {}
    violations: list[tuple[str, str, str, str, str]] = []
    selected: dict[str, str] = {}

    def record(dep: str, spec: str, parent: str, env_label: str) -> None:
        entry = required.setdefault(dep, {"specs": set(), "parents": set(), "envs": set()})
        entry["specs"].add(spec)
        entry["parents"].add(parent)
        entry["envs"].add(env_label)

    for _round in range(10):
        new_missing: dict[str, set[str]] = {}
        for env_label, env in grid:
            # Roots for this env: pins whose own marker holds, plus
            # already-selected missing packages — but only in the envs
            # where they are actually required.
            queue: list[tuple[str, str]] = []
            for name, version, marker in pins:
                if marker is not None and not Marker(marker).evaluate(env):
                    continue
                queue.append((name, version))
            for name, version in selected.items():
                if env_label in required.get(name, {}).get("envs", set()):
                    queue.append((name, version))
            seen: set[str] = set()
            while queue:
                package, version = queue.pop()
                if package in seen:
                    continue
                seen.add(package)
                try:
                    data = fetch(package, version)
                except Exception as exc:  # noqa: BLE001 - recorded as missing data
                    raise ValueError(
                        f"cannot fetch metadata for {package}=={version}: {exc}"
                    ) from exc
                for req_string in data["info"].get("requires_dist") or []:
                    try:
                        req = Requirement(req_string)
                    except Exception:  # noqa: BLE001 - unparsable metadata is ignored
                        continue
                    if req.marker is not None and not req.marker.evaluate(env):
                        continue
                    dep = normalize_name(req.name)
                    if dep in EXCLUDED:
                        continue
                    spec = str(req.specifier) if str(req.specifier) else ""
                    record(dep, spec, package, env_label)
                    if dep in by_name:
                        pinned_version, pinned_marker = by_name[dep]
                        if spec and Version(pinned_version) not in SpecifierSet(spec):
                            violations.append((env_label, package, dep, pinned_version, spec))
                        if pinned_marker is not None and not Marker(pinned_marker).evaluate(env):
                            continue
                        queue.append((dep, pinned_version))
                    elif dep in selected:
                        queue.append((dep, selected[dep]))
                    else:
                        new_missing.setdefault(dep, set()).add(spec)
        if not new_missing:
            break
        for dep, specs in sorted(new_missing.items()):
            if dep in selected:
                continue
            envs = required[dep]["envs"]
            selected[dep] = select_version(dep, specs, envs, grid, fetch)
    else:
        raise ValueError("closure did not converge after 10 rounds")

    missing = {
        dep: (version, required[dep]["specs"], required[dep]["envs"])
        for dep, version in sorted(selected.items())
    }
    return required, violations, missing


def check_closure(
    pins: list[tuple[str, str, str | None]],
) -> tuple[list[str], list[tuple[str, str, str, str, str]]]:
    """Verify the closure; return (suggested pinned lines, violations).

    The suggested lines are the exact ``name==version; marker`` lines
    to add to requirements-pinned.txt, one per missing package, each
    with a comment naming the parents and environments that require
    it. An empty list means the closure is complete on every grid
    environment. If no simple marker covers a package's environments,
    only a comment is suggested (never a marker-less pin: installing
    it everywhere could break environments its files do not support).
    """
    grid = grid_environments()
    required, violations, missing = compute_closure(pins)
    suggestions: list[str] = []
    for dep, (version, _specs, envs) in sorted(missing.items()):
        parents = ", ".join(sorted(required[dep]["parents"]))
        comment = f"# required by {parents} on {', '.join(sorted(envs))}"
        try:
            marker = derive_marker(envs, grid)
        except ValueError as exc:
            suggestions.append(f"# {dep}=={version}: {exc} (envs: {sorted(envs)})")
            suggestions.append(f"# {comment}")
            continue
        line = f"{dep}=={version}"
        if marker is not None:
            line += f"; {marker}"
        suggestions.append(f"{line}  {comment}")
    return suggestions, violations


def fetch_hashes(name: str, version: str) -> list[str]:
    """Return the sorted sha256 --hash lines for one pinned version."""
    files = pypi_json(name, version)["urls"]
    hashes = sorted(
        {f"    --hash=sha256:{f['digests']['sha256']}" for f in files if f["digests"].get("sha256")}
    )
    if not hashes:
        raise ValueError(f"{name}=={version}: no sha256 hashes on PyPI")
    return hashes


def generate(output: Path) -> list[tuple[str, str, str | None]]:
    """Verify the closure, then write the hashed lockfile. Fail closed."""
    pins = parse_pinned(PINNED_FILE)
    suggestions, violations = check_closure(pins)
    problems: list[str] = []
    if violations:
        problems.append(
            "pinned versions outside a parent's specifier:\n"
            + "\n".join(
                f"  {env}: {parent} requires {dep}{spec}, pinned {pinned}"
                for env, parent, dep, pinned, spec in sorted(set(violations))
            )
        )
    if suggestions:
        problems.append(
            "transitive dependencies required on some grid environment "
            "but not pinned in requirements-pinned.txt "
            "(pip --require-hashes refuses these):\n"
            + "\n".join(f"  {line}" for line in suggestions)
            + "\nadd the lines above to requirements-pinned.txt and re-run."
        )
    if problems:
        raise ValueError("\n\n".join(problems))

    lines: list[str] = []
    lines.append("# requirements-hashed.txt — HASH-PINNED LOCKFILE (Scorecard Pinned-Dependencies)")
    lines.append("# Generated from requirements-pinned.txt via:")
    lines.append("#   python3 scripts/generate_hashed_lock.py")
    lines.append("# Every package pins an exact version AND every downloadable file hash")
    lines.append("# (sha256) for that version, so `pip install --require-hashes -r")
    lines.append("# requirements-hashed.txt` verifies each download against PyPI.")
    lines.append("# All files for the pinned version are listed (wheels + sdist) so the")
    lines.append("# same lockfile works across platforms and Python versions.")
    lines.append("#")
    lines.append("# The generator verifies the full transitive closure across the CI")
    lines.append("# environment grid (Python 3.11-3.15 x Linux/Windows/macOS) before")
    lines.append("# emitting anything: a transitive dependency that is required only")
    lines.append("# under an environment marker (e.g. backports.tarfile on Python")
    lines.append("# < 3.12, colorama on Windows) must be pinned here with its marker,")
    lines.append("# or pip --require-hashes refuses it on that environment. See")
    lines.append("# scripts/generate_hashed_lock.py. Regenerate after any")
    lines.append("# requirements-pinned.txt change with the command above; use")
    lines.append("# --check to verify the closure without writing.")
    lines.append("")
    for name, version, marker in pins:
        hashes = fetch_hashes(name, version)
        first = f"{name}=={version}"
        if marker is not None:
            first += f"; {marker}"
        lines.append(first + " \\")
        for index, hash_line in enumerate(hashes):
            suffix = " \\" if index < len(hashes) - 1 else ""
            lines.append(hash_line + suffix)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return pins


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the transitive closure across the grid; write nothing",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="where to write the hashed lockfile (default: requirements-hashed.txt)",
    )
    args = parser.parse_args(argv)
    if args.check:
        try:
            pins = parse_pinned(PINNED_FILE)
            suggestions, violations = check_closure(pins)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if violations:
            print(
                "error: pinned versions outside a parent's specifier:\n"
                + "\n".join(
                    f"  {env}: {parent} requires {dep}{spec}, pinned {pinned}"
                    for env, parent, dep, pinned, spec in sorted(set(violations))
                ),
                file=sys.stderr,
            )
            return 1
        if suggestions:
            print(
                "error: transitive dependencies required on some grid environment "
                "but not pinned in requirements-pinned.txt:\n"
                + "\n".join(f"  {line}" for line in suggestions)
                + "\nadd the lines above to requirements-pinned.txt and re-run.",
                file=sys.stderr,
            )
            return 1
        print(
            f"closure complete: {len(pins)} pins cover every grid environment "
            f"({len(GRID_PYTHONS)} Pythons x {len(GRID_PLATFORMS)} platforms)",
            file=sys.stderr,
        )
        return 0
    try:
        pins = generate(args.output)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {args.output} ({len(pins)} packages)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
