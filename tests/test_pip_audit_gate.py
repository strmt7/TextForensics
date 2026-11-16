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
    running pip-audit (mocked at the run boundary). Mocked audits carry
    full coverage (ENG-11: no coverage data fails closed)."""
    baseline_path = tmp_path / "baseline.toml"
    baseline_path.write_text(_baseline_toml([PIP_ENTRY]), encoding="utf-8")

    def _coverage(data):
        return gate.parse_pip_audit_coverage(data)

    def _clean(requirements, source):
        data = _audit_json([("pip", "24.0", [("PYSEC-2026-1795", ["25.3"], ["CVE-2025-8869"])])])
        findings, raw = gate.parse_pip_audit_json(data)
        return gate.AuditResult(
            source=source, findings=findings, raw_findings=raw, coverage=_coverage(data)
        )

    def _dirty(requirements, source):
        data = _audit_json(
            [
                ("pip", "24.0", [("PYSEC-2026-1795", ["25.3"], ["CVE-2025-8869"])]),
                ("cryptography", "42.0.8", [("PYSEC-2024-1234", ["43.0.1"], [])]),
            ]
        )
        findings, raw = gate.parse_pip_audit_json(data)
        return gate.AuditResult(
            source=source, findings=findings, raw_findings=raw, coverage=_coverage(data)
        )

    monkeypatch.setattr(gate, "run_pip_audit", _clean)
    assert gate.main(["--baseline", str(baseline_path), "--no-requirements"]) == 0

    monkeypatch.setattr(gate, "run_pip_audit", _dirty)
    assert gate.main(["--baseline", str(baseline_path), "--no-requirements"]) == 2


def test_main_writes_report(gate, tmp_path, monkeypatch):
    baseline_path = tmp_path / "baseline.toml"
    baseline_path.write_text(_baseline_toml([PIP_ENTRY]), encoding="utf-8")
    report_path = tmp_path / "report.json"

    def _clean(requirements, source):
        data = {"dependencies": [], "fixes": []}
        return gate.AuditResult(
            source=source,
            findings=[],
            raw_findings=0,
            coverage=gate.parse_pip_audit_coverage(data),
        )

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
    assert report["schema"] == "textforensics.pip-audit-gate/v2"
    assert report["sources"][0]["packages_total"] == 0


# ---------------------------------------------------------------------------
# ENG-11 (audit W7, worker B): skipped/private/editable/unresolved
# packages are visible coverage states, never silently zero findings.
# These tests are RED until scripts/check_pip_audit.py implements them.
# ---------------------------------------------------------------------------

SKIP_ENTRY = {
    "package": "textforensics",
    "reason": "not published on PyPI; pip-audit cannot audit a package with no PyPI advisory record",
    "review_by": "2027-02-06",
}


def _baseline_toml_with_skip(entries, skips):
    text = _baseline_toml(entries)
    for skip in skips:
        text += "[[skip]]\n"
        for key, value in skip.items():
            text += f"{key} = {json.dumps(value)}\n"
    return text


def _audit_json_with_skip():
    """The audit's own shape, measured 2026-11-16 (dev venv, pip-audit
    2.10.1): the editable project itself is reported with a skip_reason
    and no vulns list."""
    return {
        "dependencies": [
            {"name": "pip", "version": "24.0", "vulns": []},
            {
                "name": "textforensics",
                "version": "0.2.0",
                "skip_reason": (
                    "Dependency not found on PyPI and could not be audited: "
                    "textforensics (0.2.0)"
                ),
            },
        ],
        "fixes": [],
    }


def test_coverage_lists_skipped_package_instead_of_silence(gate):
    """ENG-11: a skip_reason dependency is a reported coverage state,
    not zero findings. The old parser returned 0 findings and no error."""
    coverage = gate.parse_pip_audit_coverage(_audit_json_with_skip())
    assert coverage.total == 2
    assert coverage.audited == 1
    assert coverage.skipped == 1
    assert coverage.unresolved == 0
    assert coverage.total == coverage.audited + coverage.skipped + coverage.unresolved
    skipped = [p for p in coverage.packages if p.state == "skipped"]
    assert len(skipped) == 1
    assert skipped[0].name == "textforensics"
    assert "not found on PyPI" in skipped[0].skip_reason


def test_coverage_unresolved_entry_is_a_state_not_silence(gate):
    """ENG-11: a dependency entry with a name but no vulns, no version
    and no skip_reason is 'unresolved' — counted, never dropped."""
    data = {
        "dependencies": [
            {"name": "mystery-pkg"},
            {"name": "pip", "version": "24.0", "vulns": []},
        ],
        "fixes": [],
    }
    coverage = gate.parse_pip_audit_coverage(data)
    assert coverage.total == 2
    assert coverage.unresolved == 1
    assert [p.name for p in coverage.packages if p.state == "unresolved"] == ["mystery-pkg"]


def test_coverage_malformed_entries_fail_closed(gate):
    """ENG-11: a non-dict dependency, a missing name, or a vuln entry
    without an id is a GateError — the old parser silently skipped them."""
    with pytest.raises(gate.GateError):
        gate.parse_pip_audit_coverage({"dependencies": ["not-a-dict"], "fixes": []})
    with pytest.raises(gate.GateError):
        gate.parse_pip_audit_coverage({"dependencies": [{"version": "1.0", "vulns": []}]})
    with pytest.raises(gate.GateError):
        gate.parse_pip_audit_json(
            {"dependencies": [{"name": "pip", "version": "24.0", "vulns": [{"aliases": []}]}]}
        )
    with pytest.raises(gate.GateError):
        gate.parse_pip_audit_json(
            {"dependencies": [{"name": "", "version": "24.0", "vulns": []}]}
        )


def test_unexpected_skip_fails_the_gate(gate, tmp_path, monkeypatch):
    """ENG-11: a skipped package with no recorded [[skip]] entry fails
    (exit 1) — it must be an explicit, recorded state to pass."""
    baseline_path = tmp_path / "baseline.toml"
    baseline_path.write_text(_baseline_toml([PIP_ENTRY]), encoding="utf-8")

    def _audit_with_skip(requirements, source):
        data = _audit_json_with_skip()
        findings, raw = gate.parse_pip_audit_json(data)
        coverage = gate.parse_pip_audit_coverage(data)
        return gate.AuditResult(
            source=source, findings=findings, raw_findings=raw, coverage=coverage
        )

    monkeypatch.setattr(gate, "run_pip_audit", _audit_with_skip)
    assert gate.main(["--baseline", str(baseline_path), "--no-requirements"]) == 1


def test_recorded_skip_passes_and_is_reported(gate, tmp_path, monkeypatch):
    """ENG-11: a skip recorded as [[skip]] in the baseline passes, is
    listed as expected, and appears in the report's coverage block."""
    baseline_path = tmp_path / "baseline.toml"
    baseline_path.write_text(
        _baseline_toml_with_skip([PIP_ENTRY], [SKIP_ENTRY]), encoding="utf-8"
    )
    report_path = tmp_path / "report.json"

    def _audit_with_skip(requirements, source):
        data = _audit_json_with_skip()
        findings, raw = gate.parse_pip_audit_json(data)
        coverage = gate.parse_pip_audit_coverage(data)
        return gate.AuditResult(
            source=source, findings=findings, raw_findings=raw, coverage=coverage
        )

    monkeypatch.setattr(gate, "run_pip_audit", _audit_with_skip)
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
    assert report["schema"] == "textforensics.pip-audit-gate/v2"
    source_report = report["sources"][0]
    assert source_report["packages_total"] == 2
    assert source_report["packages_audited"] == 1
    assert source_report["packages_skipped"] == 1
    assert source_report["packages_unresolved"] == 0
    assert source_report["packages_total"] == (
        source_report["packages_audited"]
        + source_report["packages_skipped"]
        + source_report["packages_unresolved"]
    )
    assert report["expected_skips"] == ["textforensics"]
    assert report["unexpected_skips"] == []


def test_unresolved_package_fails_the_gate(gate, tmp_path, monkeypatch):
    """ENG-11: an 'unresolved' coverage state fails (exit 1)."""
    baseline_path = tmp_path / "baseline.toml"
    baseline_path.write_text(_baseline_toml([PIP_ENTRY]), encoding="utf-8")

    def _audit_unresolved(requirements, source):
        data = {
            "dependencies": [
                {"name": "mystery-pkg"},
                {"name": "pip", "version": "24.0", "vulns": []},
            ],
            "fixes": [],
        }
        findings, raw = gate.parse_pip_audit_json(data)
        coverage = gate.parse_pip_audit_coverage(data)
        return gate.AuditResult(
            source=source, findings=findings, raw_findings=raw, coverage=coverage
        )

    monkeypatch.setattr(gate, "run_pip_audit", _audit_unresolved)
    assert gate.main(["--baseline", str(baseline_path), "--no-requirements"]) == 1


def test_missing_coverage_data_fails_closed(gate, tmp_path, monkeypatch):
    """ENG-11: an audit result with no coverage data at all cannot
    pass — coverage must be measured, not assumed."""
    baseline_path = tmp_path / "baseline.toml"
    baseline_path.write_text(_baseline_toml([PIP_ENTRY]), encoding="utf-8")

    def _audit_no_coverage(requirements, source):
        return gate.AuditResult(source=source, findings=[], raw_findings=0)

    monkeypatch.setattr(gate, "run_pip_audit", _audit_no_coverage)
    assert gate.main(["--baseline", str(baseline_path), "--no-requirements"]) == 1


def test_skip_entry_validation_rejects_bad_files(gate, tmp_path):
    """ENG-11: [[skip]] entries are validated as strictly as findings."""
    baseline_path = tmp_path / "baseline.toml"
    missing_reason = {"package": "textforensics", "review_by": "2027-02-06"}
    baseline_path.write_text(_baseline_toml_with_skip([PIP_ENTRY], [missing_reason]))
    with pytest.raises(gate.GateError):
        gate.load_skip_entries(baseline_path)
    bad_date = dict(SKIP_ENTRY, review_by="tomorrow")
    baseline_path.write_text(_baseline_toml_with_skip([PIP_ENTRY], [bad_date]))
    with pytest.raises(gate.GateError):
        gate.load_skip_entries(baseline_path)
    baseline_path.write_text(_baseline_toml_with_skip([PIP_ENTRY], [SKIP_ENTRY, SKIP_ENTRY]))
    with pytest.raises(gate.GateError):
        gate.load_skip_entries(baseline_path)


def test_expired_skip_entry_fails_when_skip_present(gate, tmp_path, monkeypatch):
    """ENG-11: an expected skip past its review_by fails (exit 1),
    like an expired finding — a recorded skip can never rot."""
    entry = dict(SKIP_ENTRY, review_by="2026-11-01")
    baseline_path = tmp_path / "baseline.toml"
    baseline_path.write_text(_baseline_toml_with_skip([PIP_ENTRY], [entry]), encoding="utf-8")

    def _audit_with_skip(requirements, source):
        data = _audit_json_with_skip()
        findings, raw = gate.parse_pip_audit_json(data)
        coverage = gate.parse_pip_audit_coverage(data)
        return gate.AuditResult(
            source=source, findings=findings, raw_findings=raw, coverage=coverage
        )

    monkeypatch.setattr(gate, "run_pip_audit", _audit_with_skip)
    assert gate.main(["--baseline", str(baseline_path), "--no-requirements"]) == 1


def test_from_json_mode_validates_coverage(gate, tmp_path):
    """ENG-11: --from-json validates an existing pip-audit JSON file's
    coverage (used by the deep-verification job, which runs pip-audit
    directly): unexpected skips fail, a clean file passes."""
    baseline_path = tmp_path / "baseline.toml"
    baseline_path.write_text(
        _baseline_toml_with_skip([PIP_ENTRY], [SKIP_ENTRY]), encoding="utf-8"
    )
    audit_path = tmp_path / "audit.json"
    audit_path.write_text(json.dumps(_audit_json_with_skip()), encoding="utf-8")
    assert gate.main(["--baseline", str(baseline_path), "--from-json", str(audit_path)]) == 0
    audit_path.write_text(
        json.dumps(
            {
                "dependencies": [
                    {"name": "private-pkg", "version": "1.0", "skip_reason": "not on PyPI"},
                    {"name": "pip", "version": "24.0", "vulns": []},
                ],
                "fixes": [],
            }
        ),
        encoding="utf-8",
    )
    assert gate.main(["--baseline", str(baseline_path), "--from-json", str(audit_path)]) == 1


def test_real_baseline_records_the_project_skip(gate):
    """ENG-11: the checked-in baseline records textforensics itself as
    the one expected skip (editable, not on PyPI) with a future review."""
    skips = gate.load_skip_entries(REPO_ROOT / "pip-audit-baseline.toml")
    assert [s.package for s in skips] == ["textforensics"]
    assert all(s.review_by is not None and s.review_by > TODAY for s in skips)
    assert all(s.reason for s in skips)
