#!/usr/bin/env python3
"""Generate the checked-in, reproducible CycloneDX SBOM for TextForensics.

Scope
-----
The SBOM lists the *resolved dependency closure of requirements-pinned.txt*
for the ACTUAL selected platform and extras (ENG-12): the extras named
on that file's editable ``-e .[...]`` line, plus every package named
directly in the file (e.g. ``atheris``, ``bandit``, ``pip-audit``,
which are not part of any pyproject extra), plus their transitive
``Requires-Dist`` closure evaluated with FULL PEP 508 marker semantics
against the target environment (Python version, platform, and the
extras requested for each package). A requirement applies only when
its marker holds for the environment and, for ``extra == ...`` markers,
when that extra was requested for the package that declares it -- so
``fastapi[standard]``-only or ``setuptools[test]``-only edges never
enter the closure merely because the target happens to be installed
(the old name-only traversal wrongly included typer, opentelemetry-sdk
and friends whenever they were present in the generating environment).
A mandatory transitive that is missing, or an installed version that
does not satisfy an applicable specifier, FAILS generation (exit 1):
a partial-environment SBOM is not a release bill of materials merely
because generation succeeds. Since 2026-11-10 the file is an exact-pin
lockfile naming the whole closure, so the root component's
``dependsOn`` lists the full locked closure; the true direct/transitive
graph is in the per-component ``dependsOn`` edges. The project itself
is the ``metadata.component`` (``textforensics``). In addition, the
SBOM lists the third-party assets vendored into the shipped package
(ENG-15; see ``VENDORED_ASSETS``): Chart.js and the @kurkle/color it
bundles, as ``library`` components with npm purls, SPDX licences, the
SHA-256 of the shipped bytes, and ``vendored`` properties. Install
tooling appears only where it is genuinely required: ``setuptools``
and ``wheel`` are direct pins in requirements-pinned.txt. ``pip`` is
EXCLUDED from the closure (see ``EXCLUDED_DISTRIBUTIONS``): it enters
only as a transitive edge (``pip-audit`` depends on ``pip-api``, which
requires ``pip``), but the version recorded would be the venv's
bundled installer pip, which requirements-pinned.txt does not pin
(24.0 in a fresh canonical venv against 26.3 in the worker's
environment) -- including it made ``--check`` fail in the canonical
environment and flap on runner-image pip updates. The SBOM records
the target environment it was generated for (``targetEnvironment``
property: Python version, platform, machine, implementation, selected
extras) and the root requirements excluded by marker evaluation
(``markerExcludedRequirements``), so the closure is auditable without
re-running the generator.

Why packaging, not stdlib only
------------------------------
PEP 508 requirement parsing and marker evaluation are exactly what
the ``packaging`` library implements (and what pip uses); a hand-rolled
marker evaluator would be a second, divergent implementation of a
subtle grammar. ``packaging`` is pinned in requirements-pinned.txt
(and present in every venv pip creates), so the generator depends on
it with no new dependency. The CycloneDX document itself is still
plain JSON with a fixed schema shape (``bomFormat``/``specVersion``/
``serialNumber``/``metadata``/``components``/``dependencies``), so
emitting it with ``json.dumps(..., sort_keys=True)`` is exact and
auditable. The ``cyclonedx-python-lib`` already present in the dev/audit
environment is used only as an independent cross-check in
``tests/test_generate_sbom.py`` (``Bom.from_json(...).validate()``),
never as a generation input, because its CLI embeds wall-clock
timestamps and tool versions that vary per run, and it resolves from
the requirements file rather than from the installed environment
whose versions the SBOM records.

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
partial environment FAILS (ENG-12): a missing mandatory dependency or
an unsatisfiable specifier exits 1 with the missing package named, so
no partial SBOM is ever written or checked in.

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

from packaging.markers import default_environment
from packaging.requirements import InvalidRequirement, Requirement
from packaging.version import InvalidVersion, Version

GENERATOR_VERSION = "1.1.0"
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
    # Raw ``Requires-Dist`` strings, as declared in the distribution
    # metadata. The closure evaluates these with full PEP 508 marker
    # semantics (ENG-12); ``requires`` is the name-only fallback used
    # when raw strings are unavailable (synthetic/test distributions).
    requirements: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class VendoredAsset:
    """One third-party asset vendored into the shipped package (ENG-15)."""

    name: str  # Upstream package name (npm name for JS assets).
    version: str
    license_id: str  # SPDX license id.
    purl: str
    path: str  # Path of the shipped file, relative to the repo root.
    bundles: tuple[str, ...] = ()  # Names of assets bundled in the same file.


# Third-party code shipped inside the installed package. The single
# file chart.umd.min.js is jsDelivr's minified serving of Chart.js's
# dist/chart.umd.js and bundles @kurkle/color; both libraries are
# MIT-licensed and their exact full licence texts ship as package data
# in THIRD-PARTY-NOTICES.txt next to the file. Versions are verified
# against the vendored file's own banners and the upstream npm
# tarballs (chart.js@4.4.1, @kurkle/color@0.3.2). app.js and style.css
# in the same directory are first-party TextForensics code, not vendored.
VENDORED_ASSETS: tuple[VendoredAsset, ...] = (
    VendoredAsset(
        name="chart.js",
        version="4.4.1",
        license_id="MIT",
        purl="pkg:npm/chart.js@4.4.1",
        path="src/textforensics/web_ui/static/chart.umd.min.js",
        bundles=("@kurkle/color",),
    ),
    VendoredAsset(
        name="@kurkle/color",
        version="0.3.2",
        license_id="MIT",
        purl="pkg:npm/%40kurkle/color@0.3.2",
        path="src/textforensics/web_ui/static/chart.umd.min.js",
    ),
)


def vendored_bom_ref(asset: VendoredAsset) -> str:
    """Return the deterministic bom-ref for a vendored asset."""
    return f"npm:{asset.name}@{asset.version}"


def vendored_components(root: Path) -> tuple[list[dict], list[dict]]:
    """Build SBOM components for vendored assets present under ``root``.

    Returns ``(components, dependencies)``: one ``library`` component
    per asset whose file exists, with its npm purl, SPDX licence, the
    SHA-256 of the shipped bytes, and ``vendored`` properties, plus a
    dependency entry per asset (chart.js depends on the @kurkle/color
    it bundles). Assets whose file is absent are skipped: synthetic
    test repos have no vendored files. That skip is fail-closed in
    practice, not silent: the real repo asserts the components'
    presence (``tests/test_installed_web_resources.py`` and
    ``tests/test_generate_sbom.py::test_real_repo_generation``), so a
    missing vendored file fails the suite instead of quietly dropping
    the component from the SBOM.
    """
    by_name = {asset.name: asset for asset in VENDORED_ASSETS}
    components: list[dict] = []
    dependencies: list[dict] = []
    for asset in VENDORED_ASSETS:
        asset_path = root / asset.path
        if not asset_path.exists():
            continue
        ref = vendored_bom_ref(asset)
        components.append(
            {
                "type": "library",
                "bom-ref": ref,
                "name": asset.name,
                "version": asset.version,
                "purl": asset.purl,
                "scope": "required",
                "licenses": [{"license": {"id": asset.license_id}}],
                "hashes": [{"alg": "SHA-256", "content": sha256_file(asset_path)}],
                "properties": [
                    {"name": "vendored", "value": "true"},
                    {"name": "vendored-path", "value": asset.path},
                ],
            }
        )
        dependencies.append(
            {
                "ref": ref,
                "dependsOn": sorted(
                    vendored_bom_ref(by_name[name]) for name in asset.bundles if name in by_name
                ),
            }
        )
    return components, dependencies


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


def pinned_requirements(path: Path) -> list[Requirement]:
    """Parse requirements-pinned.txt into full PEP 508 requirements.

    Unlike :func:`parse_pinned_requirements` this keeps version
    specifiers and markers (ENG-12): a pinned line whose marker is
    false on the target platform is not part of the closure. Inline
    ``#`` comments are stripped before parsing.
    """
    requirements: list[Requirement] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("-e ") or line.startswith("-e\t"):
            continue
        if line.startswith("-"):
            raise ValueError(
                f"Unsupported line in {path}: {raw_line!r} "
                "(only the '-e .[...]' line may start with '-')"
            )
        try:
            requirements.append(Requirement(line))
        except InvalidRequirement as exc:
            raise ValueError(f"Cannot parse pinned requirement {raw_line!r}: {exc}") from exc
    return requirements


def target_environment() -> dict[str, str]:
    """Return the marker environment of the generating interpreter.

    This is the ACTUAL platform the closure is generated for: the
    live interpreter's Python version, platform, machine and
    implementation (``packaging.markers.default_environment``). The
    canonical SBOM is generated in a fresh Python 3.12.3 / Linux /
    x86_64 venv, so the recorded target is that platform.
    """
    return default_environment()


def requirement_applies(
    requirement: Requirement, requested_extras: set[str] | frozenset[str], environment: dict
) -> bool:
    """Whether a PEP 508 requirement applies to the selected closure.

    A requirement without a marker always applies. A requirement with
    a marker applies when the marker holds for the environment with
    ``extra`` set to one of the extras requested for the package that
    declares it (or to ``""`` for unconditional evaluation): this is
    pip's semantics — ``extra == "test"`` on one of setuptools'
    requirements means "needed when setuptools[test] is requested",
    not "needed when the root project requests the test extra".
    """
    if requirement.marker is None:
        return True
    candidates = set(requested_extras) | {""}
    return any(
        requirement.marker.evaluate({**environment, "extra": extra})
        for extra in candidates
    )


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


def root_requirements(
    project: dict,
    extras: set[str],
    pinned: list[Requirement],
    environment: dict,
) -> tuple[dict[str, set[str]], set[str]]:
    """Return the marker-aware closure roots (ENG-12).

    Returns ``(requested, marker_excluded)``: ``requested`` maps each
    normalized root name to the extras requested for it (from the
    requirement that pulled it in), and ``marker_excluded`` is the set
    of root names whose every declaring requirement has a marker that
    is false for the selected platform/extras — e.g. atheris on
    Python 3.11/3.15, where its ``python_version`` marker is false.
    A name that is excluded in one context but included in another
    is included (it is not marker-excluded).
    """
    requested: dict[str, set[str]] = {}
    excluded: set[str] = set()

    def _add(requirement: Requirement, declaring_extras: set[str]) -> None:
        name = normalize_name(requirement.name)
        if name in EXCLUDED_DISTRIBUTIONS:
            return
        if requirement_applies(requirement, declaring_extras, environment):
            requested.setdefault(name, set()).update(requirement.extras)
        else:
            excluded.add(name)

    for spec in project.get("dependencies", []) or []:
        _add(Requirement(str(spec)), {""})
    optional = project.get("optional-dependencies", {}) or {}
    for extra in sorted(extras):
        if extra not in optional:
            raise ValueError(
                f"Extra {extra!r} from requirements-pinned.txt is not in pyproject.toml"
            )
        for spec in optional[extra] or []:
            _add(Requirement(str(spec)), {extra})
    for requirement in pinned:
        _add(requirement, {""})
    marker_excluded = {name for name in excluded if name not in requested}
    return requested, marker_excluded


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
        raw_requirements = list(dist.requires or [])
        for req in raw_requirements:
            parsed = parse_requirement_name(req)
            if parsed:
                requires.append(parsed)
        expression = metadata.get("License-Expression")
        installed[name] = Distribution(
            name=display,
            version=dist.version,
            requires=sorted(set(requires)),
            license_expression=expression or None,
            requirements=raw_requirements,
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
                    requirements=existing.requirements,
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


def _requirement_strings(distribution: Distribution) -> list[str]:
    """Return the raw requirement strings for a distribution.

    Prefers the recorded ``Requires-Dist`` strings (full PEP 508);
    falls back to the name-only ``requires`` list for synthetic
    distributions that carry no raw strings.
    """
    if distribution.requirements:
        return list(distribution.requirements)
    return list(distribution.requires)


def _version_satisfies(version: str, requirement: Requirement) -> bool:
    """Whether an installed version satisfies a requirement specifier."""
    if not requirement.specifier:
        return True
    try:
        return Version(version) in requirement.specifier
    except InvalidVersion as exc:
        raise ValueError(
            f"Installed version {version!r} for {requirement.name} is not a valid version"
        ) from exc


def dependency_closure(
    roots: set[str] | dict[str, set[str]],
    installed: dict[str, Distribution],
    *,
    environment: dict | None = None,
) -> tuple[set[str], set[str]]:
    """Walk Requires-Dist edges from ``roots`` over installed packages.

    ``roots`` is either a set of names (no extras requested for any
    root) or a mapping of name -> extras requested for that root (the
    marker-aware form produced by :func:`root_requirements`).
    ``environment`` is the target marker environment (default: the
    live interpreter's, see :func:`target_environment`).

    Returns ``(included, unresolved)``: normalized names in the
    closure and names of MANDATORY dependencies that are missing —
    roots and transitives alike. A requirement is mandatory when its
    full PEP 508 marker holds for the target environment and for the
    extras requested for the package that declares it; a marker-false
    requirement (unselected extra, other platform, other Python) is
    not a dependency of the selected closure and its absence is not
    unresolved. Raises ValueError on an unparseable requirement or
    on an installed version that does not satisfy an applicable
    specifier — either is a broken closure, and the caller (see
    :func:`generate`) fails the gate instead of emitting a partial
    SBOM.
    """
    env = environment if environment is not None else target_environment()
    if isinstance(roots, dict):
        requested_extras: dict[str, set[str]] = {
            normalize_name(name): set(extras) for name, extras in roots.items()
        }
    else:
        requested_extras = {normalize_name(name): set() for name in roots}
    included: set[str] = set()
    unresolved: set[str] = set()
    violations: list[str] = []
    # Fixpoint over requested extras: following an edge can request
    # new extras for its target (``foo[bar]``), which can in turn
    # activate that target's ``extra == "bar"`` requirements.
    processed: dict[str, frozenset[str]] = {}
    queue = sorted(requested_extras)
    while queue:
        name = queue.pop(0)
        current = frozenset(requested_extras.get(name, set()))
        if processed.get(name) == current:
            continue
        processed[name] = current
        # Install tooling, not a shipped dependency: excluded from the
        # closure entirely (no component, no edges), even when a root
        # requires it. See EXCLUDED_DISTRIBUTIONS.
        if name in EXCLUDED_DISTRIBUTIONS:
            continue
        dist = installed.get(name)
        if dist is None:
            unresolved.add(name)
            continue
        included.add(name)
        for req_string in _requirement_strings(dist):
            try:
                requirement = Requirement(req_string)
            except InvalidRequirement as exc:
                raise ValueError(
                    f"Unparseable requirement {req_string!r} declared by {name}: {exc}"
                ) from exc
            target = normalize_name(requirement.name)
            if target in EXCLUDED_DISTRIBUTIONS:
                continue
            if not requirement_applies(requirement, current, env):
                continue
            target_dist = installed.get(target)
            if target_dist is None:
                unresolved.add(target)
                continue
            if not _version_satisfies(target_dist.version, requirement):
                violations.append(
                    f"{name} requires {requirement} but {target}=={target_dist.version} "
                    "is installed"
                )
            before = set(requested_extras.get(target, set()))
            requested_extras.setdefault(target, set()).update(requirement.extras)
            if requested_extras[target] != before or target not in processed:
                queue.append(target)
    if violations:
        raise ValueError(
            "SBOM closure has unsatisfiable requirements: " + "; ".join(sorted(violations))
        )
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
    vendored: tuple[list[dict], list[dict]] = ([], []),
    environment: dict | None = None,
    extras: set[str] = frozenset(),
    marker_excluded: set[str] = frozenset(),
) -> dict:
    """Build the CycloneDX 1.6 BOM document (without the serial number)."""
    root_ref = bom_ref(project_name, project_version)
    vendored_components, vendored_dependencies = vendored
    components = []
    dependencies = []
    direct_refs = sorted(
        bom_ref(name, installed[name].version) for name in roots if name in included
    )
    # Vendored assets ship inside the application itself, so the root
    # component depends on them directly (ENG-15).
    direct_refs = sorted(direct_refs + [c["bom-ref"] for c in vendored_components])
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
    components.extend(vendored_components)
    dependencies.extend(vendored_dependencies)
    # One sorted component order (by normalized name) for the whole BOM,
    # PyPI and vendored alike, so the ordering is deterministic and the
    # sorted-names assertions in tests/test_generate_sbom.py hold.
    components.sort(key=lambda c: normalize_name(str(c["name"])))
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
    if environment is not None:
        # The actual selected platform/extras identity this closure
        # was generated for (ENG-12) — not the ambient developer
        # environment's versions or wall clock.
        target = "; ".join(
            [
                f"python_version={environment.get('python_version', '')}",
                f"sys_platform={environment.get('sys_platform', '')}",
                f"platform_machine={environment.get('platform_machine', '')}",
                f"implementation_name={environment.get('implementation_name', '')}",
                f"extras={','.join(sorted(extras))}",
            ]
        )
        properties.append({"name": "targetEnvironment", "value": target})
    if marker_excluded:
        properties.append(
            {
                "name": "markerExcludedRequirements",
                "value": ", ".join(sorted(marker_excluded)),
            }
        )
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
    """Generate the SBOM text; returns (text, component count, unresolved).

    ENG-12: raises ValueError when the closure is incomplete — a
    missing mandatory dependency (root or transitive) or an installed
    version that does not satisfy an applicable specifier. A partial
    SBOM is never returned: callers (see :func:`main`) fail the gate.
    On success ``unresolved`` is empty.
    """
    pinned_path = root / "requirements-pinned.txt"
    pyproject_path = root / "pyproject.toml"
    extras, _pinned_names = parse_pinned_requirements(pinned_path)
    project = load_pyproject(pyproject_path)
    project_name = str(project["name"])
    project_version = str(project["version"])
    license_value = project.get("license", {})
    project_license = (
        license_value.get("text", "AGPL-3.0-or-later")
        if isinstance(license_value, dict)
        else "AGPL-3.0-or-later"
    )
    environment = target_environment()
    requested, marker_excluded = root_requirements(
        project, extras, pinned_requirements(pinned_path), environment
    )
    project_key = normalize_name(project_name)
    requested.pop(project_key, None)
    installed = live_distributions()
    if freeze_file is not None:
        installed = apply_freeze(
            installed, parse_freeze_file(freeze_file), project_name, project_version
        )
    included, unresolved = dependency_closure(requested, installed, environment=environment)
    if unresolved:
        raise ValueError(
            "SBOM closure is incomplete: missing mandatory dependencies: "
            + ", ".join(sorted(unresolved))
            + " (install the full requirements-pinned.txt closure; a "
            "partial environment cannot produce a release SBOM)"
        )
    vendored = vendored_components(root)
    bom = build_bom(
        project_name=project_name,
        project_version=project_version,
        project_license=project_license,
        roots=set(requested),
        included=included,
        unresolved=unresolved,
        installed=installed,
        pinned_sha256=sha256_file(pinned_path),
        pyproject_sha256=sha256_file(pyproject_path),
        vendored=vendored,
        environment=environment,
        extras=extras,
        marker_excluded=marker_excluded,
    )
    return render_bom(bom), len(included) + len(vendored[0]), unresolved


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
