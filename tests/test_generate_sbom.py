"""Tests for scripts/generate_sbom.py (checked-in reproducible SBOM).

Most tests run against a synthetic repo in tmp_path (fake pyproject.toml,
requirements-pinned.txt and freeze file) so generation is deterministic and
offline. One test runs the real generator against the real repo and skips
when the full requirements-pinned install is not present (the CI staleness
job, which installs -r requirements-pinned.txt, is the real-repo coverage).
"""

import hashlib
import importlib.util
import json
import re
import sys
import tomllib
from pathlib import Path

import pytest
from packaging.specifiers import SpecifierSet
from packaging.version import Version

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
REPO_ROOT = Path(__file__).parent.parent


def _load_module():
    spec = importlib.util.spec_from_file_location("generate_sbom", SCRIPTS_DIR / "generate_sbom.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["generate_sbom"] = module
    spec.loader.exec_module(module)
    return module


sbom = _load_module()

FAKE_PYPROJECT = """\
[project]
name = "textforensics"
version = "0.2.0"
license = {text = "AGPL-3.0-or-later"}
dependencies = []

[project.optional-dependencies]
dev = ["aaa>=1,<2", "bbb>=2,<3"]
api = ["ccc>=3,<4"]
"""

FAKE_PINNED = """\
# Pinned requirements for CI reproducibility
-e .[dev,api]

# Direct pins
ddd>=4,<5
"""

FAKE_FREEZE = """\
aaa==1.0.0
bbb==2.0.0
ccc==3.0.0
ddd==4.0.0
eee==5.0.0
"""


def _fake_repo(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_text(FAKE_PYPROJECT, encoding="utf-8")
    (tmp_path / "requirements-pinned.txt").write_text(FAKE_PINNED, encoding="utf-8")
    freeze = tmp_path / "freeze.txt"
    freeze.write_text(FAKE_FREEZE, encoding="utf-8")
    return freeze


def test_parse_requirement_name():
    assert sbom.parse_requirement_name("pytest>=8.4.2,<10") == "pytest"
    assert sbom.parse_requirement_name("PyYAML[extra]>=6") == "pyyaml"
    assert sbom.parse_requirement_name("aiohttp>=3.9,<4; python_version<'3.13'") == "aiohttp"
    assert sbom.parse_requirement_name("jaraco.classes==3.4.0") == "jaraco-classes"
    assert sbom.parse_requirement_name("  rich  ") == "rich"


def test_parse_pinned_requirements(tmp_path):
    pinned = tmp_path / "requirements-pinned.txt"
    pinned.write_text(FAKE_PINNED, encoding="utf-8")
    extras, names = sbom.parse_pinned_requirements(pinned)
    assert extras == {"dev", "api"}
    assert names == {"ddd"}


def test_parse_pinned_requirements_rejects_includes(tmp_path):
    pinned = tmp_path / "requirements-pinned.txt"
    pinned.write_text("-r other.txt\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported line"):
        sbom.parse_pinned_requirements(pinned)


def _specifier_part(spec: str) -> str:
    """Return the version-specifier part of a requirement string."""
    match = re.search(r"[<>=!~]", spec)
    return spec[match.start() :].split(";", 1)[0].strip() if match else ""


def test_real_pinned_file_is_exact_lock():
    """requirements-pinned.txt is an exact-pin lockfile (decision 2026-11-10).

    Every requirement line must be an exact ``name==version`` pin (no
    ranges, no bare names), and every direct pin must lie inside its
    pyproject.toml range. Transitive lines have no pyproject range and are
    only checked for the ``==`` form. The lockfile is what stops upstream
    releases from staling the checked-in SBOM on their own: with ranges,
    filelock 4.2.9 -> 4.2.10 and typer 0.28.0 -> 0.29.0 failed the CI
    staleness gate with no repo change (2026-11-09).
    """
    pinned_path = REPO_ROOT / "requirements-pinned.txt"
    pinned: dict[str, str] = {}
    for raw_line in pinned_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-e "):
            continue
        # An exact ``name==version`` pin, optionally followed by an
        # environment marker (``; python_version >= "3.12" ...``) — the
        # atheris line carries one (ENG-09: 3.1.0 has wheels only for
        # cp312/cp313/cp314, so pip must skip it on 3.11/3.15).
        match = re.fullmatch(
            r"([A-Za-z0-9_.\-]+)==([^\s;#]+)(?:\s*;\s*.+)?",
            line.split("#", 1)[0].strip(),
        )
        assert match is not None, f"not an exact == pin: {raw_line!r}"
        pinned[sbom.normalize_name(match.group(1))] = match.group(2)
    assert pinned, "no pins found"
    assert "pip" not in pinned  # installer, not a shipped dependency
    assert "textforensics" not in pinned  # installed via the -e line

    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        data = tomllib.load(handle)
    ranges: dict[str, list[str]] = {}
    for spec in data.get("build-system", {}).get("requires", []):
        name = sbom.parse_requirement_name(str(spec))
        ranges.setdefault(name, []).append(_specifier_part(str(spec)))
    project = data.get("project", {})
    for spec in project.get("dependencies", []) or []:
        name = sbom.parse_requirement_name(str(spec))
        ranges.setdefault(name, []).append(_specifier_part(str(spec)))
    for deps in (project.get("optional-dependencies", {}) or {}).values():
        for spec in deps or []:
            name = sbom.parse_requirement_name(str(spec))
            ranges.setdefault(name, []).append(_specifier_part(str(spec)))
    for name, version in sorted(pinned.items()):
        for specifier in ranges.get(name, []):
            assert Version(version) in SpecifierSet(specifier), (
                f"{name}=={version} is outside its pyproject range {specifier!r}"
            )


def test_atheris_marker_matches_wheel_coverage():
    """The atheris marker is identical in all three places (ENG-09).

    atheris 3.1.0 ships wheels only for cp312/cp313/cp314 and no sdist,
    so the marker ``python_version >= "3.12" and python_version < "3.15"``
    must appear on the pinned line, on the hash-pinned lockfile entry
    (with the same three wheel hashes), and on the pyproject ``fuzzing``
    extra — otherwise pip fails the install on 3.11/3.15 instead of
    skipping atheris there.
    """
    from packaging.requirements import Requirement

    expected_marker = 'python_version >= "3.12" and python_version < "3.15"'

    pinned_lines = (REPO_ROOT / "requirements-pinned.txt").read_text(encoding="utf-8").splitlines()
    pinned_req = next(
        Requirement(line.strip()) for line in pinned_lines if line.strip().startswith("atheris==")
    )
    assert str(pinned_req.specifier) == "==3.1.0"
    assert pinned_req.marker is not None
    assert str(pinned_req.marker) == expected_marker

    hashed_text = (REPO_ROOT / "requirements-hashed.txt").read_text(encoding="utf-8")
    # Join backslash continuations, then find the atheris entry; strip
    # the --hash options before parsing it as a requirement.
    joined = hashed_text.replace("\\\n", "")
    atheris_line = next(
        line for line in joined.splitlines() if line.strip().startswith("atheris==")
    )
    hashed_req = Requirement(atheris_line.split("--hash=")[0].strip())
    assert str(hashed_req.specifier) == "==3.1.0"
    assert hashed_req.marker is not None
    assert str(hashed_req.marker) == expected_marker
    # The three --hash lines directly under the atheris entry are its
    # three cp312/cp313/cp314 wheel hashes; no other package's hashes.
    hashed_lines = hashed_text.splitlines()
    start = next(i for i, line in enumerate(hashed_lines) if line.startswith("atheris=="))
    block = [hashed_lines[start]]
    for line in hashed_lines[start + 1 :]:
        if line.strip().startswith("--hash="):
            block.append(line)
        else:
            break
    hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", "\n".join(block))
    assert len(hashes) == 3, f"atheris entry must carry exactly 3 hashes, got {len(hashes)}"
    assert len(set(hashes)) == 3

    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle)["project"]
    fuzzing = project["optional-dependencies"]["fuzzing"]
    fuzzing_req = next(Requirement(spec) for spec in fuzzing if Requirement(spec).name == "atheris")
    assert fuzzing_req.marker is not None
    assert str(fuzzing_req.marker) == expected_marker


def test_root_requirement_names(tmp_path):
    (tmp_path / "pyproject.toml").write_text(FAKE_PYPROJECT, encoding="utf-8")
    project = sbom.load_pyproject(tmp_path / "pyproject.toml")
    roots = sbom.root_requirement_names(project, {"dev", "api"}, {"ddd"})
    assert roots == {"aaa", "bbb", "ccc", "ddd"}
    with pytest.raises(ValueError, match="not in pyproject.toml"):
        sbom.root_requirement_names(project, {"nope"}, set())


def test_dependency_closure_missing_transitive_is_unresolved():
    """ENG-12: a missing transitive is UNRESOLVED, not silently skipped.
    The old contract treated every absent transitive as an optional /
    marker-false dependency and omitted it; a mandatory transitive that
    is absent must be reported so generation can fail closed."""
    installed = {
        "aaa": sbom.Distribution(
            "aaa", "1.0.0", ["bbb", "missing-dep"], requirements=["bbb>=2", "missing-dep>=1"]
        ),
        "bbb": sbom.Distribution("bbb", "2.0.0", ["aaa"], requirements=["aaa>=1"]),
        "zzz": sbom.Distribution("zzz", "9.0.0", []),
    }
    included, unresolved = sbom.dependency_closure({"aaa", "gone"}, installed)
    assert included == {"aaa", "bbb"}
    # Both the missing root and the missing mandatory transitive are
    # unresolved; only a marker-false edge may be skipped (see below).
    assert unresolved == {"gone", "missing-dep"}
    assert "zzz" not in included


def test_dependency_closure_marker_false_transitive_is_skipped():
    """ENG-12: a transitive required only under a false marker (here an
    unselected extra) is NOT unresolved — it is correctly absent from
    the selected platform/extras closure."""
    installed = {
        "aaa": sbom.Distribution(
            "aaa",
            "1.0.0",
            ["bbb", "test-only"],
            requirements=["bbb>=2", 'test-only>=1; extra == "test"'],
        ),
        "bbb": sbom.Distribution("bbb", "2.0.0", [], requirements=[]),
    }
    included, unresolved = sbom.dependency_closure({"aaa"}, installed)
    assert included == {"aaa", "bbb"}
    assert unresolved == set()
    # The same edge applies when the declaring package's "test" extra
    # IS requested: then the missing target is unresolved.
    included, unresolved = sbom.dependency_closure({"aaa": {"test"}}, installed)
    assert included == {"aaa", "bbb"}
    assert unresolved == {"test-only"}


def test_dependency_closure_platform_marker_false_is_skipped():
    """ENG-12: a transitive required only on another platform is not
    unresolved on this platform."""
    installed = {
        "aaa": sbom.Distribution(
            "aaa",
            "1.0.0",
            ["win-only"],
            requirements=['win-only>=1; sys_platform == "win32"'],
        ),
    }
    included, unresolved = sbom.dependency_closure({"aaa"}, installed)
    assert included == {"aaa"}
    assert unresolved == set()


def test_dependency_closure_excludes_pip():
    # pip is install tooling, not a shipped dependency: even when it is
    # installed and required by a root (pip-audit -> pip-api -> pip),
    # it must not enter the closure — no component, no edges. Its
    # version is the venv's bundled installer pip, unpinned by
    # requirements-pinned.txt (24.0 in a fresh venv vs 26.3 in the
    # worker's environment), so including it made --check flap.
    installed = {
        "aaa": sbom.Distribution("aaa", "1.0.0", ["pip"]),
        "pip": sbom.Distribution("pip", "26.3", []),
    }
    included, unresolved = sbom.dependency_closure({"aaa"}, installed)
    assert included == {"aaa"}
    assert unresolved == set()


def test_generate_fake_repo_is_deterministic(tmp_path):
    freeze = _fake_repo(tmp_path)
    text1, count1, unresolved1 = sbom.generate(tmp_path, freeze)
    text2, count2, unresolved2 = sbom.generate(tmp_path, freeze)
    assert text1 == text2
    assert count1 == count2 == 4  # aaa, bbb, ccc, ddd; eee is not required by any root
    assert unresolved1 == unresolved2 == set()
    bom = json.loads(text1)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert bom["version"] == 1
    assert "timestamp" not in bom["metadata"]
    names = [c["name"] for c in bom["components"]]
    assert names == sorted(names, key=str.lower)
    assert names == ["aaa", "bbb", "ccc", "ddd"]
    assert bom["components"][0]["purl"] == "pkg:pypi/aaa@1.0.0"
    assert bom["components"][0]["bom-ref"] == "aaa@1.0.0"
    assert bom["metadata"]["component"]["name"] == "textforensics"
    assert bom["metadata"]["component"]["licenses"] == [{"license": {"id": "AGPL-3.0-or-later"}}]
    assert bom["serialNumber"].startswith("urn:uuid:")
    assert text1.endswith("\n")
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert "sourceCommit" not in props  # a commit field would stale every commit
    assert "timestamp" not in bom["metadata"]
    assert (
        props["requirementsPinnedSha256"] == hashlib.sha256(FAKE_PINNED.encode("utf-8")).hexdigest()
    )
    assert "unresolvedDependencies" not in props
    root_dep = next(d for d in bom["dependencies"] if d["ref"] == "textforensics@0.2.0")
    assert root_dep["dependsOn"] == ["aaa@1.0.0", "bbb@2.0.0", "ccc@3.0.0", "ddd@4.0.0"]


def test_serial_number_changes_with_content(tmp_path):
    freeze = _fake_repo(tmp_path)
    text1, _, _ = sbom.generate(tmp_path, freeze)
    (tmp_path / "freeze.txt").write_text(
        FAKE_FREEZE.replace("aaa==1.0.0", "aaa==1.0.1"), encoding="utf-8"
    )
    text2, _, _ = sbom.generate(tmp_path, freeze)
    assert json.loads(text1)["serialNumber"] != json.loads(text2)["serialNumber"]


def test_missing_mandatory_transitive_fails_generation(tmp_path):
    """ENG-12: a deliberately dropped mandatory transitive fails the
    gate — generate() raises and main() exits 1 instead of emitting an
    SBOM that silently omits it."""
    freeze = _fake_repo(tmp_path)
    # Fake a mandatory edge aaa -> dropped-dep by monkeypatching the
    # live distributions the generator sees: aaa requires a package
    # that is neither installed nor frozen.
    original = sbom.live_distributions
    try:
        sbom.live_distributions = lambda: {  # type: ignore[method-assign]
            "aaa": sbom.Distribution(
                "aaa", "1.0.0", ["dropped-dep"], requirements=["dropped-dep>=1"]
            ),
            "bbb": sbom.Distribution("bbb", "2.0.0", []),
            "ccc": sbom.Distribution("ccc", "3.0.0", []),
            "ddd": sbom.Distribution("ddd", "4.0.0", []),
        }
        with pytest.raises(ValueError, match="dropped-dep"):
            sbom.generate(tmp_path, freeze)
        assert sbom.main(["--root", str(tmp_path), "--freeze-file", str(freeze)]) == 1
    finally:
        sbom.live_distributions = original


def test_unresolved_dependencies_fail_generation(tmp_path):
    """ENG-12: unresolved roots are a failed gate, not a warning with
    an emitted SBOM. (Replaces the old 'listed not hidden' contract,
    which emitted a partial SBOM and exited 0.)"""
    freeze = _fake_repo(tmp_path)
    (tmp_path / "freeze.txt").write_text("aaa==1.0.0\n", encoding="utf-8")
    with pytest.raises(ValueError, match="bbb"):
        sbom.generate(tmp_path, freeze)
    assert sbom.main(["--root", str(tmp_path), "--freeze-file", str(freeze)]) == 1


def test_specifier_violation_fails_generation(tmp_path, monkeypatch):
    """ENG-12: an installed version that does not satisfy an applicable
    requirement specifier is a broken closure and fails the gate.
    (The requirement excludes the frozen bbb 2.0.0, so the freeze
    override cannot mask the violation.)"""
    freeze = _fake_repo(tmp_path)
    monkeypatch.setattr(
        sbom,
        "live_distributions",
        lambda: {
            "aaa": sbom.Distribution(
                "aaa", "1.0.0", ["bbb"], requirements=["bbb>=3"]
            ),
            "bbb": sbom.Distribution("bbb", "2.0.0", []),
            "ccc": sbom.Distribution("ccc", "3.0.0", []),
            "ddd": sbom.Distribution("ddd", "4.0.0", []),
        },
    )
    with pytest.raises(ValueError, match="bbb"):
        sbom.generate(tmp_path, freeze)


def test_marker_false_requirement_excluded_from_roots(tmp_path, monkeypatch):
    """ENG-12: a pinned requirement whose marker is false on the target
    platform is not a root of the closure (atheris on 3.11/3.15)."""
    freeze = _fake_repo(tmp_path)
    (tmp_path / "requirements-pinned.txt").write_text(
        "-e .[dev,api]\n"
        "ddd>=4,<5\n"
        'win-only==1.0.0; sys_platform == "win32"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sbom,
        "live_distributions",
        lambda: {
            "aaa": sbom.Distribution("aaa", "1.0.0", []),
            "bbb": sbom.Distribution("bbb", "2.0.0", []),
            "ccc": sbom.Distribution("ccc", "3.0.0", []),
            "ddd": sbom.Distribution("ddd", "4.0.0", []),
            "win-only": sbom.Distribution("win-only", "1.0.0", []),
        },
    )
    text, count, unresolved = sbom.generate(tmp_path, freeze)
    assert unresolved == set()
    names = [c["name"] for c in json.loads(text)["components"]]
    assert names == ["aaa", "bbb", "ccc", "ddd"]
    props = {p["name"]: p["value"] for p in json.loads(text)["metadata"]["properties"]}
    assert "win-only" in props.get("markerExcludedRequirements", "")


def test_bom_records_target_environment(tmp_path):
    """ENG-12: the SBOM records the actual selected platform/extras
    identity it was generated for, not the ambient developer env."""
    freeze = _fake_repo(tmp_path)
    text, _, _ = sbom.generate(tmp_path, freeze)
    props = {p["name"]: p["value"] for p in json.loads(text)["metadata"]["properties"]}
    target = props["targetEnvironment"]
    assert "python_version=3.12" in target
    assert "sys_platform=linux" in target
    assert "extras=api,dev" in target


def test_check_mode_passes_when_fresh_and_fails_when_stale(tmp_path, capsys):
    freeze = _fake_repo(tmp_path)
    out = tmp_path / "sbom" / "textforensics.cdx.json"
    assert sbom.main(["--root", str(tmp_path), "--freeze-file", str(freeze)]) == 0
    assert sbom.main(["--root", str(tmp_path), "--freeze-file", str(freeze), "--check"]) == 0
    out.write_text(
        out.read_text(encoding="utf-8").replace("aaa@1.0.0", "aaa@9.9.9"), encoding="utf-8"
    )
    assert sbom.main(["--root", str(tmp_path), "--freeze-file", str(freeze), "--check"]) == 1
    captured = capsys.readouterr()
    assert "aaa@9.9.9" in captured.out  # the diff is printed
    out.unlink()
    assert sbom.main(["--root", str(tmp_path), "--freeze-file", str(freeze), "--check"]) == 1


def test_generated_bom_validates_with_cyclonedx_lib(tmp_path):
    pytest.importorskip("cyclonedx")
    from cyclonedx.model.bom import Bom

    freeze = _fake_repo(tmp_path)
    text, _, _ = sbom.generate(tmp_path, freeze)
    parsed = Bom.from_json(json.loads(text))
    assert parsed is not None
    assert parsed.validate()


def test_vendored_assets_included_when_file_present(tmp_path):
    """A vendored file under the root yields SBOM components (ENG-15)."""
    freeze = _fake_repo(tmp_path)
    vendored = tmp_path / "src" / "textforensics" / "web_ui" / "static" / "chart.umd.min.js"
    vendored.parent.mkdir(parents=True)
    vendored.write_bytes(b"/*! Chart.js v4.4.1 */ fake bundle\n")
    text, count, unresolved = sbom.generate(tmp_path, freeze)
    assert count == 6  # aaa, bbb, ccc, ddd + chart.js + @kurkle/color
    assert unresolved == set()
    bom = json.loads(text)
    by_name = {c["name"]: c for c in bom["components"]}
    expected_sha = hashlib.sha256(b"/*! Chart.js v4.4.1 */ fake bundle\n").hexdigest()
    for name, version, purl in (
        ("chart.js", "4.4.1", "pkg:npm/chart.js@4.4.1"),
        ("@kurkle/color", "0.3.2", "pkg:npm/%40kurkle/color@0.3.2"),
    ):
        component = by_name[name]
        assert component["version"] == version
        assert component["purl"] == purl
        assert component["licenses"] == [{"license": {"id": "MIT"}}]
        assert component["hashes"] == [{"alg": "SHA-256", "content": expected_sha}]
        props = {p["name"]: p["value"] for p in component["properties"]}
        assert props["vendored"] == "true"
        assert props["vendored-path"] == "src/textforensics/web_ui/static/chart.umd.min.js"
    root_dep = next(d for d in bom["dependencies"] if d["ref"] == "textforensics@0.2.0")
    assert "npm:chart.js@4.4.1" in root_dep["dependsOn"]
    assert "npm:@kurkle/color@0.3.2" in root_dep["dependsOn"]
    chart_dep = next(d for d in bom["dependencies"] if d["ref"] == "npm:chart.js@4.4.1")
    assert chart_dep["dependsOn"] == ["npm:@kurkle/color@0.3.2"]


def test_real_repo_generation(tmp_path):
    """Real-repo run; skips unless the full pinned install is present."""
    installed = sbom.live_distributions()
    extras, pinned_names = sbom.parse_pinned_requirements(REPO_ROOT / "requirements-pinned.txt")
    project = sbom.load_pyproject(REPO_ROOT / "pyproject.toml")
    roots = sbom.root_requirement_names(project, extras, pinned_names)
    missing = sorted(name for name in roots if name not in installed)
    if missing:
        pytest.skip(f"full requirements-pinned install not present; missing: {missing}")
    out = tmp_path / "sbom.cdx.json"
    assert sbom.main(["--root", str(REPO_ROOT), "--output", str(out)]) == 0
    bom = json.loads(out.read_text(encoding="utf-8"))
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert "timestamp" not in bom["metadata"]
    assert len(bom["components"]) > 20
    names = [sbom.normalize_name(c["name"]) for c in bom["components"]]
    assert names == sorted(names)
    # Display names keep the distribution's own spelling (pip_audit),
    # while sorting, purls and bom-refs use the normalized name (pip-audit).
    assert "pip-audit" in names
    assert "pytest" in names
    # pip is excluded from the closure (install tooling, not a shipped
    # dependency; its version is the venv's bundled installer pip).
    assert "pip" not in names
    assert "textforensics" not in names  # the project is metadata.component
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert props["requirementsPinnedSha256"] == sbom.sha256_file(
        REPO_ROOT / "requirements-pinned.txt"
    )
    assert props["pyprojectSha256"] == sbom.sha256_file(REPO_ROOT / "pyproject.toml")
    assert "unresolvedDependencies" not in props
    # Vendored assets (ENG-15): the Chart.js bundle and the
    # @kurkle/color it bundles, with MIT licences, npm purls, and the
    # SHA-256 of the shipped file; the root component depends on them.
    assert len(bom["components"]) == 122  # 120 locked packages + 2 vendored
    vendored_file = REPO_ROOT / "src" / "textforensics" / "web_ui" / "static" / "chart.umd.min.js"
    vendored_sha = hashlib.sha256(vendored_file.read_bytes()).hexdigest()
    by_name = {c["name"]: c for c in bom["components"]}
    for name, version, purl in (
        ("chart.js", "4.4.1", "pkg:npm/chart.js@4.4.1"),
        ("@kurkle/color", "0.3.2", "pkg:npm/%40kurkle/color@0.3.2"),
    ):
        component = by_name[name]
        assert component["version"] == version
        assert component["purl"] == purl
        assert component["licenses"] == [{"license": {"id": "MIT"}}]
        assert component["hashes"] == [{"alg": "SHA-256", "content": vendored_sha}]
    root_dep = next(d for d in bom["dependencies"] if d["ref"] == "textforensics@0.2.0")
    assert "npm:chart.js@4.4.1" in root_dep["dependsOn"]
    assert "npm:@kurkle/color@0.3.2" in root_dep["dependsOn"]
    # The real BOM (including the vendored components) must validate
    # as CycloneDX 1.6 when the library is available.
    pytest.importorskip("cyclonedx")
    from cyclonedx.model.bom import Bom

    parsed = Bom.from_json(bom)
    assert parsed is not None
    assert parsed.validate()
