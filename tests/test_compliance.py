"""Tests for Compliance Reporting module."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from textforensics.compliance import (
    ComplianceCheck,
    ComplianceFramework,
    ComplianceReport,
    ComplianceReportBuilder,
    ComplianceStatus,
    generate_ai_act_report,
    generate_gdpr_report,
)


class TestComplianceEnums:
    def test_framework_values(self):
        """Framework enum values should be correct."""
        assert ComplianceFramework.GDPR.value == "gdpr"
        assert ComplianceFramework.AI_ACT.value == "ai_act"
        assert ComplianceFramework.SOC2.value == "soc2"
        assert ComplianceFramework.INTERNAL.value == "internal"

    def test_status_values(self):
        """Status enum values should be correct."""
        assert ComplianceStatus.COMPLIANT.value == "compliant"
        assert ComplianceStatus.PARTIAL.value == "partial"
        assert ComplianceStatus.NON_COMPLIANT.value == "non_compliant"
        assert ComplianceStatus.NOT_APPLICABLE.value == "not_applicable"


class TestComplianceCheck:
    def test_check_creation(self):
        """Check creation should work."""
        check = ComplianceCheck(
            requirement_id="test.1",
            title="Test Requirement",
            description="A test requirement.",
            status=ComplianceStatus.COMPLIANT,
            evidence=["Evidence 1"],
        )
        assert check.requirement_id == "test.1"
        assert check.status == ComplianceStatus.COMPLIANT

    def test_check_to_dict(self):
        """Check serialization should work."""
        check = ComplianceCheck(
            requirement_id="test.1",
            title="Test Requirement",
            description="A test requirement.",
            status=ComplianceStatus.PARTIAL,
            evidence=["Evidence 1"],
            remediation="Fix it",
        )
        d = check.to_dict()
        assert d["requirement_id"] == "test.1"
        assert d["status"] == "partial"
        assert d["remediation"] == "Fix it"


class TestComplianceReport:
    def test_report_summary(self):
        """Report summary should calculate correctly."""
        report = ComplianceReport(
            framework=ComplianceFramework.GDPR,
            generated_at="2024-01-01T00:00:00+00:00",
            operation_context={},
            checks=[
                ComplianceCheck("r1", "T1", "D1", ComplianceStatus.COMPLIANT),
                ComplianceCheck("r2", "T2", "D2", ComplianceStatus.COMPLIANT),
                ComplianceCheck("r3", "T3", "D3", ComplianceStatus.PARTIAL),
                ComplianceCheck("r4", "T4", "D4", ComplianceStatus.NON_COMPLIANT),
            ],
        )
        summary = report.summary()
        assert summary["report_type"] == "transparency_note"
        assert summary["total_checks"] == 4
        assert summary["compliant"] == 2
        assert summary["partial"] == 1
        assert summary["non_compliant"] == 1
        # Score: (2 + 0.5) / 4 = 0.625 — a transparency score over
        # self-assessed statuses, not a compliance certification score.
        assert summary["transparency_score"] == 0.625

    def test_report_summary_all_compliant(self):
        """All compliant should give score 1.0."""
        report = ComplianceReport(
            framework=ComplianceFramework.GDPR,
            generated_at="2024-01-01T00:00:00+00:00",
            operation_context={},
            checks=[
                ComplianceCheck("r1", "T1", "D1", ComplianceStatus.COMPLIANT),
            ],
        )
        summary = report.summary()
        assert summary["transparency_score"] == 1.0

    def test_report_roundtrip(self):
        """Report save/load roundtrip should preserve data."""
        report = ComplianceReport(
            framework=ComplianceFramework.GDPR,
            generated_at="2024-01-01T00:00:00+00:00",
            operation_context={"purpose": "test"},
            checks=[
                ComplianceCheck("r1", "T1", "D1", ComplianceStatus.COMPLIANT, ["ev"]),
            ],
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            report.save(path)
            loaded = ComplianceReport.load(path)

            assert loaded.framework == report.framework
            assert loaded.checks[0].requirement_id == "r1"
            # The saved note labels itself a transparency note, with the
            # self-assessment disclaimer — and a load round-trips it.
            assert report.to_dict()["report_type"] == "transparency_note"
            assert "Not an independent audit" in report.to_dict()["disclaimer"]
            assert loaded.to_dict()["report_type"] == "transparency_note"


class TestComplianceReportBuilder:
    def test_gdpr_builder(self):
        """GDPR builder should produce GDPR checks."""
        builder = ComplianceReportBuilder(ComplianceFramework.GDPR)
        builder.set_context(
            raw_text_included=False,
            stated_purpose="Forensic audit",
            retention_days=90,
            encrypted_storage=True,
            audit_log_enabled=True,
        )
        report = builder.build()

        assert report.framework == ComplianceFramework.GDPR
        assert len(report.checks) == 5
        assert any(c.requirement_id == "gdpr.art5.1c" for c in report.checks)

    def test_gdpr_compliant_context(self):
        """Fully compliant GDPR context should score high."""
        report = generate_gdpr_report(
            {
                "raw_text_included": False,
                "stated_purpose": "Forensic audit",
                "retention_days": 90,
                "encrypted_storage": True,
                "audit_log_enabled": True,
            }
        )
        summary = report.summary()
        assert summary["transparency_score"] == 1.0
        assert summary["non_compliant"] == 0

    def test_gdpr_partial_context(self):
        """Partial GDPR context should score lower."""
        report = generate_gdpr_report(
            {
                "raw_text_included": True,  # Violates data minimization
            }
        )
        summary = report.summary()
        assert summary["transparency_score"] < 1.0
        assert summary["partial"] > 0

    def test_ai_act_builder(self):
        """AI Act builder should produce AI Act checks."""
        builder = ComplianceReportBuilder(ComplianceFramework.AI_ACT)
        builder.set_context(
            detector_versions={"builtin": "0.1.0"},
            human_oversight=True,
            risk_classification="limited",
            calibration_validated=True,
            abstention_enabled=True,
        )
        report = builder.build()

        assert report.framework == ComplianceFramework.AI_ACT
        assert len(report.checks) == 5
        assert any(c.requirement_id == "aiact.art13" for c in report.checks)

    def test_ai_act_compliant_context(self):
        """Fully compliant AI Act context should score 1.0."""
        report = generate_ai_act_report(
            {
                "detector_versions": {"builtin": "0.1.0"},
                "human_oversight": True,
                "risk_classification": "limited",
                "calibration_validated": True,
                "abstention_enabled": True,
            }
        )
        summary = report.summary()
        assert summary["transparency_score"] == 1.0

    def test_soc2_builder(self):
        """SOC 2 builder should produce SOC 2 checks."""
        builder = ComplianceReportBuilder(ComplianceFramework.SOC2)
        builder.set_context(
            audit_log_enabled=True,
            access_control=True,
            change_management=True,
        )
        report = builder.build()

        assert report.framework == ComplianceFramework.SOC2
        assert len(report.checks) == 3

    def test_internal_builder(self):
        """Internal builder should produce internal quality checks."""
        builder = ComplianceReportBuilder(ComplianceFramework.INTERNAL)
        builder.set_context(
            raw_text_included=False,
            calibration_validated=True,
            abstention_enabled=True,
            human_fpr_monitoring=True,
        )
        report = builder.build()

        assert report.framework == ComplianceFramework.INTERNAL
        assert len(report.checks) == 4
        assert any(c.requirement_id == "internal.raw_text" for c in report.checks)

    def test_internal_raw_text_violation(self):
        """Raw text inclusion should be non-compliant for internal framework."""
        builder = ComplianceReportBuilder(ComplianceFramework.INTERNAL)
        builder.set_context(raw_text_included=True)
        report = builder.build()

        raw_check = next(c for c in report.checks if c.requirement_id == "internal.raw_text")
        assert raw_check.status == ComplianceStatus.NON_COMPLIANT

    def test_unknown_framework_raises(self):
        """Unknown framework should raise error."""
        with pytest.raises(ValueError):
            ComplianceReportBuilder("unknown_framework").build()


class TestConvenienceFunctions:
    def test_generate_gdpr_report(self):
        """GDPR report convenience function should work."""
        report = generate_gdpr_report({"raw_text_included": False})
        assert report.framework == ComplianceFramework.GDPR
        assert len(report.checks) > 0

    def test_generate_ai_act_report(self):
        """AI Act report convenience function should work."""
        report = generate_ai_act_report({"detector_versions": {"d": "1"}})
        assert report.framework == ComplianceFramework.AI_ACT
        assert len(report.checks) > 0


class TestComplianceEvidence:
    def test_evidence_strings(self):
        """Evidence strings should be meaningful."""
        report = generate_gdpr_report({"raw_text_included": False})
        minimization = next(c for c in report.checks if c.requirement_id == "gdpr.art5.1c")
        assert len(minimization.evidence) > 0
        assert "Raw text excluded" in minimization.evidence[0]

    def test_remediation_for_partial(self):
        """Partial checks should have remediation guidance."""
        report = generate_gdpr_report({})
        partial_checks = [c for c in report.checks if c.status == ComplianceStatus.PARTIAL]
        for check in partial_checks:
            assert check.remediation is not None
            assert len(check.remediation) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
