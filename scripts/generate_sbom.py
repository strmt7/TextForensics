#!/usr/bin/env python3
"""Generate the checked-in, reproducible CycloneDX SBOM for TextForensics.

Scope
-----
The SBOM lists the *resolved dependency closure of requirements-pinned.txt*
as installed: the extras named on that file's editable ``-e .[...]`` line,
plus every package named directly in the file (e.g. ``atheris``,
``bandit``, ``pip-audit``, which are not part of any pyproject extra),
plus their transitive ``Requires-Dist`` closure. Since 2026-11-10 the
file is an exact-pin lockfile naming the whole closure, so the root
component's ``dependsOn`` lists the full locked closure; the true
direct/transitive graph is in the per-component ``dependsOn`` edges.
The project itself is the ``metadata.component`` (``textforensics``). Install tooling appears only
where it is genuinely required: ``setuptools`` and ``wheel`` are direct
pins in requirements-pinned.txt. ``pip`` is EXCLUDED from the closure
(see ``EXCLUDED_DISTRIBUTIONS``): it enters only as a transitive edge
(``pip-audit`` depends on ``pip-api``, which requires ``pip``), but the
version recorded would be the venv's bundled installer pip, which
requirements-pinned.txt does not pin (24.0 in a fresh canonical venv
against 26.3 in the worker's environment) — including it made ``--check``
fail in the canonical environment and flap on runner-image pip updates.

Why stdlib only
---------------
No new dependency is introduced. The CycloneDX document is plain JSON
with a fixed schema shape (``bomFormat``/``specVersion``/``serialNumber``/
``metadata``/``components``/``dependencies``), so emitting it with
``json.dumps(..., sort_keys=True)`` is exact and auditable. The
``cyclonedx-python-lib`` already present in the dev/audit environment is
used only as an independent cross-check in ``tests/test_generate_sbom.py``
(``Bom.from_json(...).validate()``), never as a generation input, because
its CLI embeds wall-clock timestamps and tool versions that vary per run,
and it resolves from the requirements file rather than from the installed
environment whose versions the SBOM records.

Reproducibility
---------------
Same inputs produce byte-identical output:

* components and ``dependsOn`` lists are sorted by normalized name;
* ``metadata.timestamp`` is OMITTED on purpose. CycloneDX makes it
  optional, and a wall-clock timestamp would change the output on every
  run. No source-commit field is embedded either: the commit a SBOM was
  generated from would change on every commit by construction, so a
  staleness check could never pass. Provenance is the git history of the
  SBOM file itself (``git log -- sbom/textforensics.cdx.json``), and
  ``requirementsPinnedSha256`` / ``pyprojectSha256`` pin the repo inputs.
  Those two 64-hex values are flagged by ``detect-secrets`` as Hex High
  Entropy Strings; they are recorded as audited false positives in
  ``.secrets.baseline``, and a regeneration that changes them must update
  those two baseline entries in the same commit (add only the two SBOM
  entries — a blanket ``detect-secrets scan --baseline`` rewrites the
  whole baseline).

A live install IS still needed: exact versions are read from the installed
environment (``importlib.metadata``), not parsed out of the file.
requirements-pinned.txt is an exact-pin lockfile (every entry
``name==version``, direct and transitive), so a fresh install from it is
deterministic. The canonical generation environment is
``pip install -r requirements-pinned.txt`` (the same install the
``pinned`` CI job performs). Before 2026-11-10 the file contained version
*ranges*, so a fresh install could resolve to newer upstream releases and
stale the SBOM with no repo change; the lockfile decision is recorded in
SECURITY.md ("Python dependency pinning policy"). Regenerating in a
partial environment does not fail: uninstalled root packages are omitted
from ``components`` and listed in ``metadata.properties`` as
``unresolvedDependencies``, so the output stays honest and the CI
staleness check (which runs in the full install) will report it stale.

Usage
-----
    python scripts/generate_sbom.py [--output sbom/textforensics.cdx.json]
    python scripts/generate_sbom.py --check        # CI staleness check
    python scripts/generate_sbom.py --freeze-file freeze.txt

``--freeze-file`` takes ``pip freeze`` output (``name==version`` lines,
``name @ url`` lines for editable installs) and overrides the versions
seen in the live environment; it exists for offline/testing use.
"""

import argparse
import difflib
import hashlib
import importlib.metadata
import json
import re
import sys
import tomllib
import uuid
from dataclasses import dataclass, field
from pathlib import Path

GENERATOR_VERSION = "1.0.1"
GENERATOR_NAME = "generate_sbom.py"
SPEC_VERSION = "1.6"
PROJECT_URL = "https://github.com/strmt7/TextForensics"
DEFAULT_OUTPUT = Path("sbom/textforensics.cdx.json")
# Distributions that are install tooling, not shipped dependencies, and
# whose version is environment noise rather than project data. ``pip``
# enters the closure only as a transitive edge (``pip-audit`` depends on
# ``pip-api``, which requires ``pip``), but the version recorded is the
# venv's bundled installer pip, which requirements-pinned.txt does not
# pin: 24.0 in a fresh ``pip install -r requirements-pinned.txt`` venv
# against 26.3 in the worker's environment. Including it made ``--check``
# fail in the canonical environment and flap on runner-image pip
# updates, so it is excluded from the closure (components and edges).
# Consistent with the pip-audit reasoning that pip is the installer,
# not a shipped dependency (pip-audit-baseline.toml treats pip 24.0
# exactly that way).
EXCLUDED_DISTRIBUTIONS = frozenset({"pip"})
NAME_SPLIT_RE = re.compile(r"[<>=!~\s;\[]")
EXTRAS_RE = re.compile(r"\[\s*([^\]]*?)\s*\]")


@dataclass
class Distribution:
    """One installed distribution as seen by the generator."""

    name: str  # Display name from the distribution metadata.
    version: str
    requires: list[str] = field(default_factory=list)  # Normalized names.
    license_expression: str | None = None


def normalize_name(name: str) -> str:
    """Normalize a package name per PEP 503 (lowercase, runs of -_. to -)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirement_name(spec: str) -> str:
    """Return the normalized package name of a requirement specifier."""
    before_marker = spec.split(";", 1)[0].strip()
    name = NAME_SPLIT_RE.split(before_marker, 1)[0].strip()
    return normalize_name(name) if name else ""


def sha256_file(path: Path) -> str:
    """Return the hex SHA-256 of a file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_pinned_requirements(path: Path) -> tuple[set[str], set[str]]:
    """Parse requirements-pinned.txt.

    Returns ``(extras, pinned_names)``: the extras from the editable
    ``-e .[...]`` line and the normalized names of every other entry.
    """
    extras: set[str] = set()
    pinned_names: set[str] = set()
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-e ") or line.startswith("-e\t"):
            match = EXTRAS_RE.search(line)
            if match:
                extras.update(item.strip() for item in match.group(1).split(",") if item.strip())
            continue
        if line.startswith("-"):
            raise ValueError(
                f"Unsupported line in {path}: {raw_line!r} "
                "(only the '-e .[...]' line may start with '-')"
            )
        name = parse_requirement_name(line)
        if name:
            pinned_names.add(name)
    return extras, pinned_names


def load_pyproject(path: Path) -> dict:
    """Load pyproject.toml and return its ``[project]`` table."""
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    project = data.get("project", {})
    if not isinstance(project, dict) or not project.get("name"):
        raise ValueError(f"{path} has no [project] name")
    return project


def root_requirement_names(project: dict, extras: set[str], pinned_names: set[str]) -> set[str]:
    """Return the normalized names that seed the dependency closure."""
    names = set(pinned_names)
    for spec in project.get("dependencies", []) or []:
        name = parse_requirement_name(str(spec))
        if name:
            names.add(name)
    optional = project.get("optional-dependencies", {}) or {}
    for extra in sorted(extras):
        if extra not in optional:
            raise ValueError(
                f"Extra {extra!r} from requirements-pinned.txt is not in pyproject.toml"
            )
        for spec in optional[extra] or []:
            name = parse_requirement_name(str(spec))
            if name:
                names.add(name)
    return names


def live_distributions() -> dict[str, Distribution]:
    """Return installed distributions keyed by normalized name."""
    installed: dict[str, Distribution] = {}
    for dist in importlib.metadata.distributions():
        metadata = dist.metadata
        display = metadata.get("Name")
        if not display:
            continue
        name = normalize_name(display)
        requires: list[str] = []
        for req in dist.requires or []:
            parsed = parse_requirement_name(req)
            if parsed:
                requires.append(parsed)
        expression = metadata.get("License-Expression")
        installed[name] = Distribution(
            name=display,
            version=dist.version,
            requires=sorted(set(requires)),
            license_expression=expression or None,
        )
    return installed


def parse_freeze_file(path: Path) -> dict[str, str | None]:
    """Parse ``pip freeze`` output into {normalized name: version or None}.

    ``name==version`` lines carry an exact version; ``name @ url`` lines
    (editable installs) carry no version and resolve from the live
    environment (or, for the project itself, from pyproject.toml).
    Any other version operator fails: a freeze file must be exact.
    """
    frozen: dict[str, str | None] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-e "):
            fragment = line.split("#egg=", 1)[-1] if "#egg=" in line else ""
            name = normalize_name(fragment.split("[", 1)[0]) if fragment else ""
            if not name:
                raise ValueError(f"Cannot parse editable freeze line: {raw_line!r}")
            frozen[name] = None
            continue
        if "==" in line:
            name, _, version = line.partition("==")
            name = normalize_name(name.strip())
            version = version.strip().split(";", 1)[0].strip()
            if not name or not version:
                raise ValueError(f"Cannot parse freeze line: {raw_line!r}")
            frozen[name] = version
            continue
        if " @ " in line:
            name = normalize_name(line.split(" @ ", 1)[0].strip())
            if not name:
                raise ValueError(f"Cannot parse freeze line: {raw_line!r}")
            frozen[name] = None
            continue
        raise ValueError(
            f"Freeze file entries must be 'name==version' or 'name @ url': {raw_line!r}"
        )
    return frozen


def apply_freeze(
    installed: dict[str, Distribution],
    frozen: dict[str, str | None],
    project_name: str,
    project_version: str,
) -> dict[str, Distribution]:
    """Override installed versions with a freeze file (offline/testing)."""
    merged = dict(installed)
    for name, version in frozen.items():
        if version is not None:
            if name in merged:
                existing = merged[name]
                merged[name] = Distribution(
                    name=existing.name,
                    version=version,
                    requires=existing.requires,
                    license_expression=existing.license_expression,
                )
            else:
                merged[name] = Distribution(name=name, version=version)
        elif name in merged:
            continue
        elif name == normalize_name(project_name):
            merged[name] = Distribution(name=project_name, version=project_version)
        else:
            raise ValueError(
                f"Freeze entry {name!r} has no version and is not installed; "
                "use 'name==version' in the freeze file"
            )
    return merged


def dependency_closure(
    roots: set[str], installed: dict[str, Distribution]
) -> tuple[set[str], set[str]]:
    """Walk Requires-Dist edges from ``roots`` over installed packages.

    Returns ``(included, unresolved)``: normalized names in the closure
    and *root* names that are not installed. A transitive edge is followed
    only when its target is installed, which is also how environment
    markers are honoured (a marker-false dependency is not installed).
    A missing transitive target is therefore never "unresolved": it is an
    optional extra or a marker-guarded dependency of an installed
    package (setuptools alone declares ~50 such ``extra == "test"``
    edges), and omitting it is correct. Only a missing *root* — a package
    requirements-pinned.txt or pyproject.toml declares — is reported.
    """
    included: set[str] = set()
    unresolved: set[str] = set()
    queue = sorted(roots)
    seen: set[str] = set()
    while queue:
        name = queue.pop(0)
        if name in seen:
            continue
        seen.add(name)
        # Install tooling, not a shipped dependency: excluded from the
        # closure entirely (no component, no edges), even when a root
        # requires it. See EXCLUDED_DISTRIBUTIONS.
        if name in EXCLUDED_DISTRIBUTIONS:
            continue
        dist = installed.get(name)
        if dist is None:
            if name in roots:
                unresolved.add(name)
            continue
        included.add(name)
        for dep in dist.requires:
            if dep not in seen:
                queue.append(dep)
    return included, unresolved


def purl(name: str, version: str) -> str:
    """Return the Package URL for a PyPI distribution."""
    return f"pkg:pypi/{normalize_name(name)}@{version}"


def bom_ref(name: str, version: str) -> str:
    """Return the deterministic bom-ref for a component."""
    return f"{normalize_name(name)}@{version}"


def build_bom(
    *,
    project_name: str,
    project_version: str,
    project_license: str,
    roots: set[str],
    included: set[str],
    unresolved: set[str],
    installed: dict[str, Distribution],
    pinned_sha256: str,
    pyproject_sha256: str,
) -> dict:
    """Build the CycloneDX 1.6 BOM document (without the serial number)."""
    root_ref = bom_ref(project_name, project_version)
    components = []
    dependencies = []
    direct_refs = sorted(
        bom_ref(name, installed[name].version) for name in roots if name in included
    )
    dependencies.append({"ref": root_ref, "dependsOn": direct_refs})
    for name in sorted(included):
        dist = installed[name]
        ref = bom_ref(name, dist.version)
        component: dict = {
            "type": "library",
            "bom-ref": ref,
            "name": dist.name,
            "version": dist.version,
            "purl": purl(name, dist.version),
            "scope": "required",
        }
        if dist.license_expression:
            component["licenses"] = [{"expression": dist.license_expression}]
        components.append(component)
        dependencies.append(
            {
                "ref": ref,
                "dependsOn": sorted(
                    bom_ref(dep, installed[dep].version) for dep in dist.requires if dep in included
                ),
            }
        )
    dependencies.sort(key=lambda entry: entry["ref"])
    properties = [
        {"name": "generator", "value": f"{GENERATOR_NAME} {GENERATOR_VERSION}"},
        {
            "name": "scope",
            "value": "resolved dependency closure of requirements-pinned.txt as installed",
        },
        {"name": "requirementsPinnedSha256", "value": pinned_sha256},
        {"name": "pyprojectSha256", "value": pyproject_sha256},
    ]
    if unresolved:
        properties.append(
            {"name": "unresolvedDependencies", "value": ", ".join(sorted(unresolved))}
        )
    properties.sort(key=lambda entry: entry["name"])
    bom: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            # No "timestamp": CycloneDX leaves it optional, and a wall-clock
            # value would break byte-reproducibility. No source-commit
            # field either: it would make every commit stale by
            # construction (see the module docstring). Provenance is the
            # git history of the SBOM file itself.
            "tools": [
                {
                    "vendor": "TextForensics",
                    "name": GENERATOR_NAME,
                    "version": GENERATOR_VERSION,
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": project_name,
                "version": project_version,
                "purl": purl(project_name, project_version),
                "licenses": [{"license": {"id": project_license}}],
            },
            "properties": properties,
        },
        "components": components,
        "dependencies": dependencies,
    }
    canonical = json.dumps(bom, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"{PROJECT_URL}#sbom:{digest}")
    bom["serialNumber"] = f"urn:uuid:{serial}"
    return bom


def render_bom(bom: dict) -> str:
    """Render the BOM deterministically (sorted keys, 2-space indent)."""
    return json.dumps(bom, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def generate(root: Path, freeze_file: Path | None = None) -> tuple[str, int, set[str]]:
    """Generate the SBOM text; returns (text, component count, unresolved)."""
    pinned_path = root / "requirements-pinned.txt"
    pyproject_path = root / "pyproject.toml"
    extras, pinned_names = parse_pinned_requirements(pinned_path)
    project = load_pyproject(pyproject_path)
    project_name = str(project["name"])
    project_version = str(project["version"])
    license_value = project.get("license", {})
    project_license = (
        license_value.get("text", "AGPL-3.0-or-later")
        if isinstance(license_value, dict)
        else "AGPL-3.0-or-later"
    )
    roots = root_requirement_names(project, extras, pinned_names)
    project_key = normalize_name(project_name)
    roots.discard(project_key)
    installed = live_distributions()
    if freeze_file is not None:
        installed = apply_freeze(
            installed, parse_freeze_file(freeze_file), project_name, project_version
        )
    included, unresolved = dependency_closure(roots, installed)
    bom = build_bom(
        project_name=project_name,
        project_version=project_version,
        project_license=project_license,
        roots=roots,
        included=included,
        unresolved=unresolved,
        installed=installed,
        pinned_sha256=sha256_file(pinned_path),
        pyproject_sha256=sha256_file(pyproject_path),
    )
    return render_bom(bom), len(included), unresolved


def main(argv: list[str] | None = None) -> int:
    """Entry point: generate the SBOM or fail if the committed copy is stale."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Repository root (default: parent of the scripts directory).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output path (default: sbom/textforensics.cdx.json under --root).",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Regenerate and fail (exit 1) if the committed SBOM differs.",
    )
    parser.add_argument(
        "--freeze-file",
        type=Path,
        default=None,
        help="pip freeze output overriding installed versions (offline/testing).",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    output = (root / DEFAULT_OUTPUT) if args.output is None else args.output
    try:
        text, count, unresolved = generate(root, args.freeze_file)
    except (ValueError, FileNotFoundError, OSError) as exc:
        print(f"generate_sbom: {exc}", file=sys.stderr)
        return 1
    if unresolved:
        print(
            "generate_sbom: warning: unresolved dependencies (not installed, "
            f"omitted from components): {', '.join(sorted(unresolved))}",
            file=sys.stderr,
        )
    if args.check:
        if not output.exists():
            print(f"generate_sbom: stale: {output} does not exist", file=sys.stderr)
            return 1
        committed = output.read_text(encoding="utf-8")
        if committed == text:
            print(f"SBOM is up to date: {output} ({count} components)")
            return 0
        diff = difflib.unified_diff(
            committed.splitlines(keepends=True),
            text.splitlines(keepends=True),
            fromfile=f"a/{output.name} (committed)",
            tofile=f"b/{output.name} (regenerated)",
        )
        sys.stdout.writelines(diff)
        print(
            "generate_sbom: stale: committed SBOM differs from regeneration; "
            f"run 'python scripts/generate_sbom.py' and commit {output}",
            file=sys.stderr,
        )
        return 1
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")
    print(f"Wrote {output} ({count} components)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
