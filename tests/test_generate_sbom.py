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
import sys
from pathlib import Path

import pytest

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


def test_root_requirement_names(tmp_path):
    (tmp_path / "pyproject.toml").write_text(FAKE_PYPROJECT, encoding="utf-8")
    project = sbom.load_pyproject(tmp_path / "pyproject.toml")
    roots = sbom.root_requirement_names(project, {"dev", "api"}, {"ddd"})
    assert roots == {"aaa", "bbb", "ccc", "ddd"}
    with pytest.raises(ValueError, match="not in pyproject.toml"):
        sbom.root_requirement_names(project, {"nope"}, set())


def test_dependency_closure_follows_only_installed():
    installed = {
        "aaa": sbom.Distribution("aaa", "1.0.0", ["bbb", "missing-dep"]),
        "bbb": sbom.Distribution("bbb", "2.0.0", ["aaa"]),
        "zzz": sbom.Distribution("zzz", "9.0.0", []),
    }
    included, unresolved = sbom.dependency_closure({"aaa", "gone"}, installed)
    assert included == {"aaa", "bbb"}
    # Only missing *roots* are unresolved; a missing transitive edge
    # (missing-dep, an optional/marker-guarded dep of aaa) is skipped.
    assert unresolved == {"gone"}
    assert "zzz" not in included


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


def test_unresolved_dependencies_are_listed_not_hidden(tmp_path):
    freeze = _fake_repo(tmp_path)
    (tmp_path / "freeze.txt").write_text("aaa==1.0.0\n", encoding="utf-8")
    text, count, unresolved = sbom.generate(tmp_path, freeze)
    assert count == 1
    assert unresolved == {"bbb", "ccc", "ddd"}
    props = {p["name"]: p["value"] for p in json.loads(text)["metadata"]["properties"]}
    assert props["unresolvedDependencies"] == "bbb, ccc, ddd"


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
    assert "textforensics" not in names  # the project is metadata.component
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert props["requirementsPinnedSha256"] == sbom.sha256_file(
        REPO_ROOT / "requirements-pinned.txt"
    )
    assert props["pyprojectSha256"] == sbom.sha256_file(REPO_ROOT / "pyproject.toml")
    assert "unresolvedDependencies" not in props
