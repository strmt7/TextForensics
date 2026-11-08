"""Tests for scripts/check_pip_audit.py (pip-audit failing gate).

The comparison logic is exercised against fabricated pip-audit JSON so
no network or installed environment is needed. One test loads the
real checked-in baseline and validates it. Live runs (clean pass,
planted new finding) are proven by the gate itself, not here.
"""

import importlib.util
import json
import sys
from datetime import date
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
REPO_ROOT = Path(__file__).parent.parent


def _load_gate_module():
    spec = importlib.util.spec_from_file_location(
        "check_pip_audit", SCRIPTS_DIR / "check_pip_audit.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_pip_audit"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gate():
    return _load_gate_module()


TODAY = date(2026, 11, 8)

PIP_ENTRY = {
    "package": "pip",
    "vuln_id": "PYSEC-2026-1795",
    "aliases": ["CVE-2025-8869", "GHSA-4xh5-x5gv-qwph"],
    "affected_versions": ["24.0"],
    "fixed_in": "25.3",
    "reason": "dev venv installer, not a shipped dependency",
    "review_by": "2027-02-06",
}


def _baseline_toml(entries):
    lines = []
    for entry in entries:
        lines.append("[[finding]]")
        for key, value in entry.items():
            lines.append(f"{key} = {json.dumps(value)}")
    return "\n".join(lines) + "\n"


def _audit_json(packages):
    """Build a pip-audit --format json dict from (name, version, vulns)."""
    dependencies = []
    for name, version, vulns in packages:
        dependencies.append(
            {
                "name": name,
                "version": version,
                "vulns": [
                    {
                        "id": vuln_id,
                        "fix_versions": fix_versions,
                        "aliases": aliases,
                        "description": "test",
                    }
                    for vuln_id, fix_versions, aliases in vulns
                ],
            }
        )
    return {"dependencies": dependencies, "fixes": []}


def test_parse_dedupes_duplicate_reports(gate):
    """pip-audit reports the same vuln twice (two advisory sources);
    the gate counts it once but keeps the raw count."""
    data = _audit_json(
        [
            (
                "pip",
                "24.0",
                [
                    ("PYSEC-2026-1795", ["25.3"], ["CVE-2025-8869"]),
                    ("PYSEC-2026-1795", ["25.3"], ["CVE-2025-8869"]),
                    ("PYSEC-2026-3721", ["26.2"], ["CVE-2026-13346"]),
                    ("PYSEC-2026-3721", ["26.2.0"], ["CVE-2026-13346"]),
                ],
            )
        ]
    )
    findings, raw = gate.parse_pip_audit_json(data)
    assert raw == 4
    assert len(findings) == 2
    assert {f.vuln_id for f in findings} == {"PYSEC-2026-1795", "PYSEC-2026-3721"}


def test_parse_empty_and_malformed(gate):
    findings, raw = gate.parse_pip_audit_json({"dependencies": [], "fixes": []})
    assert findings == [] and raw == 0
    with pytest.raises(gate.GateError):
        gate.parse_pip_audit_json({"nope": True})


def test_baselined_finding_passes(gate, tmp_path):
    baseline_path = tmp_path / "baseline.toml"
    baseline_path.write_text(_baseline_toml([PIP_ENTRY]), encoding="utf-8")
    baseline = gate.load_baseline(baseline_path)
    data = _audit_json([("pip", "24.0", [("PYSEC-2026-1795", ["25.3"], ["CVE-2025-8869"])])])
    findings, _ = gate.parse_pip_audit_json(data)
    result = gate.classify(findings, baseline, TODAY)
    assert len(result.baselined) == 1
    assert result.new == []
    assert result.dormant == []
    assert result.expired == []


def test_alias_match_covers_source_variation(gate, tmp_path):
    """The same vulnerability reported under its GHSA id still matches
    the PYSEC-keyed baseline entry."""
    baseline_path = tmp_path / "baseline.toml"
    baseline_path.write_text(_baseline_toml([PIP_ENTRY]), encoding="utf-8")
    baseline = gate.load_baseline(baseline_path)
    data = _audit_json([("pip", "24.0", [("GHSA-4xh5-x5gv-qwph", ["25.3"], ["PYSEC-2026-1795"])])])
    findings, _ = gate.parse_pip_audit_json(data)
    result = gate.classify(findings, baseline, TODAY)
    assert len(result.baselined) == 1
    assert result.new == []


def test_new_package_is_new_finding(gate, tmp_path):
    baseline_path = tmp_path / "baseline.toml"
    baseline_path.write_text(_baseline_toml([PIP_ENTRY]), encoding="utf-8")
    baseline = gate.load_baseline(baseline_path)
    data = _audit_json([("cryptography", "42.0.8", [("PYSEC-2024-1234", ["43.0.1"], [])])])
    findings, _ = gate.parse_pip_audit_json(data)
    result = gate.classify(findings, baseline, TODAY)
    assert len(result.new) == 1
    assert result.new[0].package == "cryptography"


def test_same_vuln_new_version_is_new_finding(gate, tmp_path):
    """An entry covers exact affected versions only: pip 24.1 with the
    same vuln id must fail until a human extends the entry."""
    baseline_path = tmp_path / "baseline.toml"
    baseline_path.write_text(_baseline_toml([PIP_ENTRY]), encoding="utf-8")
    baseline = gate.load_baseline(baseline_path)
    data = _audit_json([("pip", "24.1", [("PYSEC-2026-1795", ["25.3"], ["CVE-2025-8869"])])])
    findings, _ = gate.parse_pip_audit_json(data)
    result = gate.classify(findings, baseline, TODAY)
    assert len(result.new) == 1
    assert len(result.dormant) == 1  # the 24.0 entry matched nothing


def test_dormant_entry_is_reported_not_failed(gate, tmp_path):
    """A fixed finding leaves its entry dormant: reported, exit 0."""
    baseline_path = tmp_path / "baseline.toml"
    baseline_path.write_text(_baseline_toml([PIP_ENTRY]), encoding="utf-8")
    baseline = gate.load_baseline(baseline_path)
    findings, _ = gate.parse_pip_audit_json({"dependencies": [], "fixes": []})
    result = gate.classify(findings, baseline, TODAY)
    assert len(result.dormant) == 1
    assert result.new == [] and result.expired == []


def test_expired_entry_fails_when_finding_present(gate, tmp_path):
    entry = dict(PIP_ENTRY, review_by="2026-11-07")
    baseline_path = tmp_path / "baseline.toml"
    baseline_path.write_text(_baseline_toml([entry]), encoding="utf-8")
    baseline = gate.load_baseline(baseline_path)
    data = _audit_json([("pip", "24.0", [("PYSEC-2026-1795", ["25.3"], ["CVE-2025-8869"])])])
    findings, _ = gate.parse_pip_audit_json(data)
    result = gate.classify(findings, baseline, TODAY)
    assert len(result.expired) == 1
    assert result.new == []


def test_expired_entry_does_not_fail_when_dormant(gate, tmp_path):
    """An expired entry whose finding is already fixed is dormant, not
    an expiry failure: there is nothing left to re-check."""
    entry = dict(PIP_ENTRY, review_by="2026-11-07")
    baseline_path = tmp_path / "baseline.toml"
    baseline_path.write_text(_baseline_toml([entry]), encoding="utf-8")
    baseline = gate.load_baseline(baseline_path)
    findings, _ = gate.parse_pip_audit_json({"dependencies": [], "fixes": []})
    result = gate.classify(findings, baseline, TODAY)
    assert result.expired == []
    assert len(result.dormant) == 1


def test_baseline_validation_rejects_bad_files(gate, tmp_path):
    baseline_path = tmp_path / "baseline.toml"

    baseline_path.write_text("not toml [[", encoding="utf-8")
    with pytest.raises(gate.GateError):
        gate.load_baseline(baseline_path)

    baseline_path.write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(gate.GateError):
        gate.load_baseline(baseline_path)

    missing = dict(PIP_ENTRY)
    del missing["reason"]
    baseline_path.write_text(_baseline_toml([missing]), encoding="utf-8")
    with pytest.raises(gate.GateError):
        gate.load_baseline(baseline_path)

    bad_date = dict(PIP_ENTRY, review_by="tomorrow")
    baseline_path.write_text(_baseline_toml([bad_date]), encoding="utf-8")
    with pytest.raises(gate.GateError):
        gate.load_baseline(baseline_path)

    empty_versions = dict(PIP_ENTRY, affected_versions=[])
    baseline_path.write_text(_baseline_toml([empty_versions]), encoding="utf-8")
    with pytest.raises(gate.GateError):
        gate.load_baseline(baseline_path)

    baseline_path.write_text(_baseline_toml([PIP_ENTRY, PIP_ENTRY]), encoding="utf-8")
    with pytest.raises(gate.GateError):
        gate.load_baseline(baseline_path)

    with pytest.raises(gate.GateError):
        gate.load_baseline(tmp_path / "does-not-exist.toml")


def test_real_baseline_loads_and_is_current(gate):
    """The checked-in baseline parses, validates, and covers the six
    known pip 24.0 findings with future review dates."""
    baseline = gate.load_baseline(REPO_ROOT / "pip-audit-baseline.toml")
    assert len(baseline) == 6
    assert all(e.package == "pip" for e in baseline)
    assert all(e.affected_versions == ["24.0"] for e in baseline)
    assert all(e.review_by is not None and e.review_by > TODAY for e in baseline)
    assert all(e.reason for e in baseline)
    assert len({e.vuln_id for e in baseline}) == 6


def test_main_exit_codes_with_mocked_audits(gate, tmp_path, monkeypatch):
    """main() returns 0 on a clean run and 2 on a new finding, without
    running pip-audit (mocked at the run boundary)."""
    baseline_path = tmp_path / "baseline.toml"
    baseline_path.write_text(_baseline_toml([PIP_ENTRY]), encoding="utf-8")

    def _clean(requirements, source):
        data = _audit_json([("pip", "24.0", [("PYSEC-2026-1795", ["25.3"], ["CVE-2025-8869"])])])
        findings, raw = gate.parse_pip_audit_json(data)
        return gate.AuditResult(source=source, findings=findings, raw_findings=raw)

    def _dirty(requirements, source):
        data = _audit_json(
            [
                ("pip", "24.0", [("PYSEC-2026-1795", ["25.3"], ["CVE-2025-8869"])]),
                ("cryptography", "42.0.8", [("PYSEC-2024-1234", ["43.0.1"], [])]),
            ]
        )
        findings, raw = gate.parse_pip_audit_json(data)
        return gate.AuditResult(source=source, findings=findings, raw_findings=raw)

    monkeypatch.setattr(gate, "run_pip_audit", _clean)
    assert gate.main(["--baseline", str(baseline_path), "--no-requirements"]) == 0

    monkeypatch.setattr(gate, "run_pip_audit", _dirty)
    assert gate.main(["--baseline", str(baseline_path), "--no-requirements"]) == 2


def test_main_writes_report(gate, tmp_path, monkeypatch):
    baseline_path = tmp_path / "baseline.toml"
    baseline_path.write_text(_baseline_toml([PIP_ENTRY]), encoding="utf-8")
    report_path = tmp_path / "report.json"

    def _clean(requirements, source):
        return gate.AuditResult(source=source, findings=[], raw_findings=0)

    monkeypatch.setattr(gate, "run_pip_audit", _clean)
    assert (
        gate.main(
            [
                "--baseline",
                str(baseline_path),
                "--no-requirements",
                "--report",
                str(report_path),
            ]
        )
        == 0
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["new"] == 0
    assert report["dormant_baseline_entries"] == 1
    assert report["schema"] == "textforensics.pip-audit-gate/v1"
