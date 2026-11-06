"""Capability Ledger Policy Engine.

This module provides a policy rule engine for the Capability Ledger,
allowing organizations to define rules about what capability claims
are required for specific operations or detector usage.

Example policies:
- "detector X can only be used for production if it has VALIDATED language_coverage"
- "report generation requires TOOL_BACKED trust_map claims for all dimensions"
- "calibration artifacts must have EXECUTED evidence for probability outputs"
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .capability_ledger import CapabilityLedger


class PolicyResult:
    """Result of a policy evaluation."""

    def __init__(
        self,
        passed: bool,
        rule_id: str,
        message: str,
        missing_claims: list[str] = None,
        evidence_gaps: list[str] = None,
    ):
        self.passed = passed
        self.rule_id = rule_id
        self.message = message
        self.missing_claims = missing_claims or []
        self.evidence_gaps = evidence_gaps or []

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "rule_id": self.rule_id,
            "message": self.message,
            "missing_claims": self.missing_claims,
            "evidence_gaps": self.evidence_gaps,
        }


@dataclass(frozen=True, slots=True)
class CapabilityPolicy:
    """A policy requiring specific capability claims.

    Attributes:
        rule_id: Unique identifier for this policy rule.
        description: Human-readable description.
        detector_pattern: Optional pattern to match detector IDs (glob-style).
        required_capabilities: List of (capability_name, min_tier) tuples.
        action_on_failure: "warn", "reject", or "abstain"
    """

    rule_id: str
    description: str
    required_capabilities: list[tuple[str, str]]  # [(capability, min_tier)]
    detector_pattern: str = "*"
    action_on_failure: str = "reject"  # "warn", "reject", "abstain"


class CapabilityPolicyEngine:
    """Evaluates capability claims against policy rules."""

    def __init__(self):
        self.policies: list[CapabilityPolicy] = []

    def add_policy(self, policy: CapabilityPolicy) -> None:
        """Add a policy rule to the engine."""
        if policy.action_on_failure not in ("warn", "reject", "abstain"):
            raise ValueError(f"Invalid action_on_failure: {policy.action_on_failure}")
        self.policies.append(policy)

    def evaluate(
        self,
        ledger: CapabilityLedger,
        detector_id: str,
        operation: str = "use",
    ) -> list[PolicyResult]:
        """Evaluate all applicable policies for a detector operation.

        Returns list of PolicyResult objects, one per matching policy.
        """

        results: list[PolicyResult] = []

        for policy in self.policies:
            # Check if policy applies to this detector
            if not self._matches_pattern(detector_id, policy.detector_pattern):
                continue

            missing = []
            gaps = []

            for capability, min_tier_str in policy.required_capabilities:
                claim = ledger.get(detector_id, capability)
                if claim is None:
                    missing.append(f"{capability} (required: {min_tier_str}+)")
                    continue

                # Check tier meets minimum
                tier_order = {
                    "readable": 0,
                    "tool_backed": 1,
                    "validated": 2,
                }
                claim_tier = claim.tier.value if hasattr(claim.tier, "value") else str(claim.tier)
                min_tier = min_tier_str.lower()

                if tier_order.get(claim_tier, -1) < tier_order.get(min_tier, -1):
                    gaps.append(f"{capability}: claim tier={claim_tier}, required={min_tier}+")

            passed = len(missing) == 0 and len(gaps) == 0
            action = "PASS" if passed else policy.action_on_failure.upper()

            result = PolicyResult(
                passed=passed,
                rule_id=policy.rule_id,
                message=f"[{action}] {policy.description}",
                missing_claims=missing,
                evidence_gaps=gaps,
            )
            results.append(result)

        return results

    def _matches_pattern(self, detector_id: str, pattern: str) -> bool:
        """Simple glob-style pattern matching."""
        if pattern == "*":
            return True
        if "*" not in pattern:
            return detector_id == pattern
        # Simple prefix/suffix matching
        if pattern.startswith("*") and pattern.endswith("*"):
            return pattern[1:-1] in detector_id
        elif pattern.startswith("*"):
            return detector_id.endswith(pattern[1:])
        elif pattern.endswith("*"):
            return detector_id.startswith(pattern[:-1])
        return False


# Pre-defined policy bundles for common use cases
def create_production_policy() -> CapabilityPolicyEngine:
    """Create a policy engine for production use.

    Requires VALIDATED claims for core capabilities.
    """
    engine = CapabilityPolicyEngine()
    engine.add_policy(
        CapabilityPolicy(
            rule_id="prod-language-coverage",
            description="Production use requires VALIDATED language coverage claim",
            detector_pattern="*",
            required_capabilities=[("language_coverage", "validated")],
            action_on_failure="reject",
        )
    )
    engine.add_policy(
        CapabilityPolicy(
            rule_id="prod-length-robustness",
            description="Production use requires TOOL_BACKED length robustness",
            detector_pattern="*",
            required_capabilities=[("length_robustness", "tool_backed")],
            action_on_failure="warn",
        )
    )
    engine.add_policy(
        CapabilityPolicy(
            rule_id="prod-domain-accuracy",
            description="Production use requires TOOL_BACKED domain accuracy",
            detector_pattern="*",
            required_capabilities=[("domain_accuracy", "tool_backed")],
            action_on_failure="warn",
        )
    )
    return engine


def create_report_generation_policy() -> CapabilityPolicyEngine:
    """Create a policy engine for report generation.

    Ensures reports have minimum trust backing.
    """
    engine = CapabilityPolicyEngine()
    engine.add_policy(
        CapabilityPolicy(
            rule_id="report-trust-map",
            description="Report generation requires trust map claims",
            detector_pattern="*",
            required_capabilities=[("trust_map_generation", "tool_backed")],
            action_on_failure="abstain",
        )
    )
    return engine


def create_calibration_policy() -> CapabilityPolicyEngine:
    """Create a policy engine for calibrated probability outputs.

    Ensures calibrated outputs have EXECUTED evidence.
    """
    engine = CapabilityPolicyEngine()
    engine.add_policy(
        CapabilityPolicy(
            rule_id="cal-probability-output",
            description="Calibrated AI probability requires EXECUTED calibration evidence",
            detector_pattern="*",
            required_capabilities=[("probability_calibration", "validated")],
            action_on_failure="reject",
        )
    )
    return engine


def create_minimum_viable_policy() -> CapabilityPolicyEngine:
    """Create a minimal policy for basic operation.

    Requires READABLE claims as documentation.
    """
    engine = CapabilityPolicyEngine()
    engine.add_policy(
        CapabilityPolicy(
            rule_id="min-documentation",
            description="All detectors must have documented claims",
            detector_pattern="*",
            required_capabilities=[
                ("language_coverage", "readable"),
                ("length_robustness", "readable"),
            ],
            action_on_failure="warn",
        )
    )
    return engine
