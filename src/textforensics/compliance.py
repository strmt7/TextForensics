"""Compliance reporting for TextForensics forensic operations.

Generates compliance reports for regulatory frameworks:
- GDPR (data minimization, purpose limitation, audit trail)
- EU AI Act (transparency, human oversight, risk classification)
- SOC 2 (audit logging, access control evidence)
- Internal forensic quality standards

Each report documents how forensic operations satisfy (or fall short of)
specific compliance requirements.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

__all__ = [
    "ComplianceFramework",
    "ComplianceStatus",
    "ComplianceCheck",
    "ComplianceReport",
    "ComplianceReportBuilder",
    "generate_gdpr_report",
    "generate_ai_act_report",
]


class ComplianceFramework(StrEnum):
    """Supported compliance frameworks."""

    GDPR = "gdpr"
    AI_ACT = "ai_act"
    SOC2 = "soc2"
    INTERNAL = "internal"


class ComplianceStatus(StrEnum):
    """Compliance check status."""

    COMPLIANT = "compliant"
    PARTIAL = "partial"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class ComplianceCheck:
    """A single compliance requirement check."""

    requirement_id: str
    title: str
    description: str
    status: ComplianceStatus
    evidence: list[str] = field(default_factory=list)
    remediation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "requirement_id": self.requirement_id,
            "title": self.title,
            "description": self.description,
            "status": self.status.value,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class ComplianceReport:
    """A full compliance report for a framework."""

    framework: ComplianceFramework
    generated_at: str
    operation_context: dict[str, Any]
    checks: list[ComplianceCheck] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework.value,
            "generated_at": self.generated_at,
            "operation_context": self.operation_context,
            "checks": [c.to_dict() for c in self.checks],
            "metadata": self.metadata,
        }

    def summary(self) -> dict[str, Any]:
        """Get a summary of compliance status."""
        status_counts = {s.value: 0 for s in ComplianceStatus}
        for check in self.checks:
            status_counts[check.status.value] += 1

        total = len(self.checks)
        compliant = status_counts["compliant"]
        partial = status_counts["partial"]
        non_compliant = status_counts["non_compliant"]
        not_applicable = status_counts["not_applicable"]

        # Overall score: compliant=1, partial=0.5, non_compliant=0, n/a excluded
        applicable = total - not_applicable
        score = (compliant + 0.5 * partial) / applicable if applicable > 0 else 1.0

        return {
            "framework": self.framework.value,
            "total_checks": total,
            "compliant": compliant,
            "partial": partial,
            "non_compliant": non_compliant,
            "not_applicable": not_applicable,
            "compliance_score": round(score, 3),
        }

    def save(self, path: str | Path) -> None:
        """Save report to JSON file."""
        Path(path).write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: str | Path) -> ComplianceReport:
        """Load report from JSON file."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            framework=ComplianceFramework(data["framework"]),
            generated_at=data["generated_at"],
            operation_context=data.get("operation_context", {}),
            checks=[
                ComplianceCheck(
                    requirement_id=c["requirement_id"],
                    title=c["title"],
                    description=c["description"],
                    status=ComplianceStatus(c["status"]),
                    evidence=c.get("evidence", []),
                    remediation=c.get("remediation"),
                )
                for c in data.get("checks", [])
            ],
            metadata=data.get("metadata", {}),
        )


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


class ComplianceReportBuilder:
    """Builder for generating compliance reports.

    Analyzes the configuration and behavior of forensic operations
    against a specific compliance framework.
    """

    def __init__(self, framework: ComplianceFramework):
        self.framework = framework
        self.checks: list[ComplianceCheck] = []
        self.operation_context: dict[str, Any] = {}

    def set_context(self, **context: Any) -> ComplianceReportBuilder:
        """Set operation context for the report."""
        self.operation_context.update(context)
        return self

    def build(self) -> ComplianceReport:
        """Build the compliance report."""
        if self.framework == ComplianceFramework.GDPR:
            self._add_gdpr_checks()
        elif self.framework == ComplianceFramework.AI_ACT:
            self._add_ai_act_checks()
        elif self.framework == ComplianceFramework.SOC2:
            self._add_soc2_checks()
        elif self.framework == ComplianceFramework.INTERNAL:
            self._add_internal_checks()
        else:
            raise ValueError(f"Unknown framework: {self.framework}")

        return ComplianceReport(
            framework=self.framework,
            generated_at=_now_iso(),
            operation_context=self.operation_context,
            checks=self.checks,
        )

    def _add_gdpr_checks(self) -> None:
        """Add GDPR compliance checks."""
        # Data minimization
        raw_text_included = self.operation_context.get("raw_text_included", True)
        self.checks.append(
            ComplianceCheck(
                requirement_id="gdpr.art5.1c",
                title="Data Minimization (Art. 5(1)(c))",
                description="Processing must be limited to what is necessary.",
                status=ComplianceStatus.COMPLIANT
                if not raw_text_included
                else ComplianceStatus.PARTIAL,
                evidence=[
                    "Raw text excluded from portable case files by default"
                    if not raw_text_included
                    else "Raw text included in outputs; consider hashing-only mode"
                ],
                remediation=None if not raw_text_included else "Set raw_text_included=False",
            )
        )

        # Purpose limitation
        purpose = self.operation_context.get("stated_purpose")
        self.checks.append(
            ComplianceCheck(
                requirement_id="gdpr.art5.1b",
                title="Purpose Limitation (Art. 5(1)(b))",
                description="Data must be collected for specified, explicit purposes.",
                status=ComplianceStatus.COMPLIANT if purpose else ComplianceStatus.PARTIAL,
                evidence=[f"Stated purpose: {purpose}"]
                if purpose
                else ["No stated purpose documented"],
                remediation=None if purpose else "Document the processing purpose",
            )
        )

        # Storage limitation
        retention_days = self.operation_context.get("retention_days")
        self.checks.append(
            ComplianceCheck(
                requirement_id="gdpr.art5.1e",
                title="Storage Limitation (Art. 5(1)(e))",
                description="Data must be kept no longer than necessary.",
                status=ComplianceStatus.COMPLIANT if retention_days else ComplianceStatus.PARTIAL,
                evidence=[f"Retention period: {retention_days} days"]
                if retention_days
                else ["No retention policy documented"],
                remediation=None if retention_days else "Define and document retention period",
            )
        )

        # Integrity and confidentiality
        encrypted = self.operation_context.get("encrypted_storage", False)
        self.checks.append(
            ComplianceCheck(
                requirement_id="gdpr.art32",
                title="Security of Processing (Art. 32)",
                description="Appropriate technical measures must ensure data security.",
                status=ComplianceStatus.COMPLIANT if encrypted else ComplianceStatus.PARTIAL,
                evidence=["Encrypted storage enabled"]
                if encrypted
                else ["Encrypted storage not confirmed"],
                remediation=None if encrypted else "Enable encrypted storage for sensitive data",
            )
        )

        # Audit trail
        audit_log = self.operation_context.get("audit_log_enabled", False)
        self.checks.append(
            ComplianceCheck(
                requirement_id="gdpr.art5.2",
                title="Accountability (Art. 5(2))",
                description="Controller must be able to demonstrate compliance.",
                status=ComplianceStatus.COMPLIANT if audit_log else ComplianceStatus.PARTIAL,
                evidence=["Audit log enabled"] if audit_log else ["No audit logging configured"],
                remediation=None if audit_log else "Enable tamper-evident audit logging",
            )
        )

    def _add_ai_act_checks(self) -> None:
        """Add EU AI Act compliance checks."""
        # Transparency
        detector_versions = self.operation_context.get("detector_versions")
        self.checks.append(
            ComplianceCheck(
                requirement_id="aiact.art13",
                title="Transparency (Art. 13)",
                description="AI systems must be interpretable; versions must be traceable.",
                status=ComplianceStatus.COMPLIANT
                if detector_versions
                else ComplianceStatus.PARTIAL,
                evidence=[f"Detector versions: {detector_versions}"]
                if detector_versions
                else ["No detector version tracking"],
                remediation=None
                if detector_versions
                else "Record detector/model versions in outputs",
            )
        )

        # Human oversight
        human_oversight = self.operation_context.get("human_oversight", False)
        self.checks.append(
            ComplianceCheck(
                requirement_id="aiact.art14",
                title="Human Oversight (Art. 14)",
                description="AI systems must allow for human oversight.",
                status=ComplianceStatus.COMPLIANT if human_oversight else ComplianceStatus.PARTIAL,
                evidence=["Human oversight configured"]
                if human_oversight
                else ["No human oversight mechanism"],
                remediation=None
                if human_oversight
                else "Implement review workflow for detector verdicts",
            )
        )

        # Risk classification
        risk_classified = self.operation_context.get("risk_classification")
        self.checks.append(
            ComplianceCheck(
                requirement_id="aiact.art6",
                title="Risk Classification (Art. 6)",
                description="AI systems must be classified by risk level.",
                status=ComplianceStatus.COMPLIANT if risk_classified else ComplianceStatus.PARTIAL,
                evidence=[f"Risk classification: {risk_classified}"]
                if risk_classified
                else ["No risk classification"],
                remediation=None
                if risk_classified
                else "Classify the system per AI Act risk categories",
            )
        )

        # Accuracy/robustness
        calibration = self.operation_context.get("calibration_validated", False)
        self.checks.append(
            ComplianceCheck(
                requirement_id="aiact.art15",
                title="Accuracy and Robustness (Art. 15)",
                description="AI systems must be accurate and robust.",
                status=ComplianceStatus.COMPLIANT if calibration else ComplianceStatus.PARTIAL,
                evidence=["Calibration validated"]
                if calibration
                else ["Calibration not validated"],
                remediation=None if calibration else "Validate calibration with held-out dataset",
            )
        )

        # Abstention capability
        abstention = self.operation_context.get("abstention_enabled", False)
        self.checks.append(
            ComplianceCheck(
                requirement_id="aiact.art15.5",
                title="Abstention (Art. 15(5) spirit)",
                description="Systems should indicate when confidence is insufficient.",
                status=ComplianceStatus.COMPLIANT if abstention else ComplianceStatus.PARTIAL,
                evidence=["Abstention enabled"] if abstention else ["No abstention policy"],
                remediation=None if abstention else "Enable abstention for out-of-scope inputs",
            )
        )

    def _add_soc2_checks(self) -> None:
        """Add SOC 2 compliance checks."""
        # Audit logging
        audit_log = self.operation_context.get("audit_log_enabled", False)
        self.checks.append(
            ComplianceCheck(
                requirement_id="soc2.cc7.2",
                title="System Monitoring (CC7.2)",
                description="System changes and access must be monitored.",
                status=ComplianceStatus.COMPLIANT if audit_log else ComplianceStatus.PARTIAL,
                evidence=["Audit logging enabled"] if audit_log else ["No audit logging"],
                remediation=None if audit_log else "Enable audit logging",
            )
        )

        # Access control
        access_control = self.operation_context.get("access_control", False)
        self.checks.append(
            ComplianceCheck(
                requirement_id="soc2.cc6.1",
                title="Access Control (CC6.1)",
                description="Access to systems must be controlled.",
                status=ComplianceStatus.COMPLIANT if access_control else ComplianceStatus.PARTIAL,
                evidence=["Access control enabled"] if access_control else ["No access control"],
                remediation=None if access_control else "Implement access controls",
            )
        )

        # Change management
        change_mgmt = self.operation_context.get("change_management", False)
        self.checks.append(
            ComplianceCheck(
                requirement_id="soc2.cc8.1",
                title="Change Management (CC8.1)",
                description="Changes must be authorized and tested.",
                status=ComplianceStatus.COMPLIANT if change_mgmt else ComplianceStatus.PARTIAL,
                evidence=["Change management enabled"] if change_mgmt else ["No change management"],
                remediation=None if change_mgmt else "Implement change management process",
            )
        )

    def _add_internal_checks(self) -> None:
        """Add internal forensic quality standard checks."""
        # Raw text exclusion
        raw_excluded = not self.operation_context.get("raw_text_included", True)
        self.checks.append(
            ComplianceCheck(
                requirement_id="internal.raw_text",
                title="Raw Text Exclusion",
                description="Raw text must be excluded from portable artifacts.",
                status=ComplianceStatus.COMPLIANT
                if raw_excluded
                else ComplianceStatus.NON_COMPLIANT,
                evidence=["Raw text excluded"]
                if raw_excluded
                else ["Raw text included — violates AGENTS.md rule 22"],
                remediation=None if raw_excluded else "Exclude raw text from case files",
            )
        )

        # Score is not a probability
        calibrated = self.operation_context.get("calibration_validated", False)
        self.checks.append(
            ComplianceCheck(
                requirement_id="internal.no_uncalibrated_prob",
                title="No Uncalibrated Probabilities",
                description="AI-authorship probability requires calibration artifact.",
                status=ComplianceStatus.COMPLIANT if calibrated else ComplianceStatus.PARTIAL,
                evidence=["Calibration validated"]
                if calibrated
                else ["Calibration not validated — score may be misread as probability"],
                remediation=None
                if calibrated
                else "Add calibration artifact before emitting probability",
            )
        )

        # Abstention preserved
        abstention = self.operation_context.get("abstention_enabled", False)
        self.checks.append(
            ComplianceCheck(
                requirement_id="internal.abstention",
                title="Abstention Preserved",
                description="Abstention for unsupported inputs must be preserved.",
                status=ComplianceStatus.COMPLIANT if abstention else ComplianceStatus.PARTIAL,
                evidence=["Abstention enabled"] if abstention else ["Abstention not configured"],
                remediation=None if abstention else "Enable abstention policies",
            )
        )

        # False positive monitoring
        fpr_monitoring = self.operation_context.get("human_fpr_monitoring", False)
        self.checks.append(
            ComplianceCheck(
                requirement_id="internal.fpr_gate",
                title="Human FPR Release Gate",
                description="Human false positive rate must be monitored (release gate).",
                status=ComplianceStatus.COMPLIANT if fpr_monitoring else ComplianceStatus.PARTIAL,
                evidence=["FPR monitoring enabled"] if fpr_monitoring else ["No FPR monitoring"],
                remediation=None
                if fpr_monitoring
                else "Enable drift monitoring with human slice FPR",
            )
        )


def generate_gdpr_report(context: dict[str, Any]) -> ComplianceReport:
    """Generate a GDPR compliance report for the given operation context."""
    builder = ComplianceReportBuilder(ComplianceFramework.GDPR)
    builder.set_context(**context)
    return builder.build()


def generate_ai_act_report(context: dict[str, Any]) -> ComplianceReport:
    """Generate an EU AI Act compliance report for the given operation context."""
    builder = ComplianceReportBuilder(ComplianceFramework.AI_ACT)
    builder.set_context(**context)
    return builder.build()
