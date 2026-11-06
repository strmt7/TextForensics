"""Tests for capability ledger policy engine."""

from __future__ import annotations

import pytest

from textforensics.policy import (
    CapabilityClaim,
    CapabilityLedger,
    CapabilityPolicy,
    CapabilityPolicyEngine,
    EvidenceLabel,
    EvidenceRef,
    EvidenceTier,
    PolicyResult,
    create_calibration_policy,
    create_minimum_viable_policy,
    create_production_policy,
    create_report_generation_policy,
)


class TestPolicyResult:
    def test_policy_result_creation(self):
        result = PolicyResult(
            passed=True,
            rule_id="test-rule",
            message="Test passed",
            missing_claims=[],
            evidence_gaps=[],
        )
        assert result.passed is True
        assert result.rule_id == "test-rule"

    def test_policy_result_to_dict(self):
        result = PolicyResult(
            passed=False,
            rule_id="test-rule",
            message="Test failed",
            missing_claims=["cap1"],
            evidence_gaps=["cap2: tier mismatch"],
        )
        d = result.to_dict()
        assert d["passed"] is False
        assert d["rule_id"] == "test-rule"
        assert d["missing_claims"] == ["cap1"]
        assert d["evidence_gaps"] == ["cap2: tier mismatch"]


class TestCapabilityPolicy:
    def test_policy_creation(self):
        policy = CapabilityPolicy(
            rule_id="test-rule",
            description="Test policy",
            required_capabilities=[("language_coverage", "validated")],
        )
        assert policy.rule_id == "test-rule"
        assert policy.required_capabilities == [("language_coverage", "validated")]

    def test_invalid_action_raises(self):
        with pytest.raises(ValueError):
            engine = CapabilityPolicyEngine()
            policy = CapabilityPolicy(
                rule_id="test",
                description="Test",
                required_capabilities=[],
                action_on_failure="invalid_action",
            )
            engine.add_policy(policy)  # Validation happens on add


class TestCapabilityPolicyEngine:
    def test_engine_creation(self):
        engine = CapabilityPolicyEngine()
        assert len(engine.policies) == 0

    def test_add_policy(self):
        engine = CapabilityPolicyEngine()
        policy = CapabilityPolicy(
            rule_id="test-rule",
            description="Test",
            required_capabilities=[("cap1", "validated")],
        )
        engine.add_policy(policy)
        assert len(engine.policies) == 1

    def test_matches_wildcard(self):
        engine = CapabilityPolicyEngine()
        assert engine._matches_pattern("any/detector", "*") is True

    def test_matches_exact(self):
        engine = CapabilityPolicyEngine()
        assert engine._matches_pattern("exact/detector", "exact/detector") is True

    def test_matches_prefix(self):
        engine = CapabilityPolicyEngine()
        assert engine._matches_pattern("prefix/detector", "prefix*") is True

    def test_matches_suffix(self):
        engine = CapabilityPolicyEngine()
        assert engine._matches_pattern("some/detector", "*detector") is True

    def test_matches_contains(self):
        engine = CapabilityPolicyEngine()
        assert engine._matches_pattern("some/middle/detector", "*middle*") is True


class TestPolicyEvaluation:
    def test_evaluate_no_policies(self):
        """Empty engine should return empty results."""
        engine = CapabilityPolicyEngine()
        ledger = CapabilityLedger()
        results = engine.evaluate(ledger, "test/detector")
        assert results == []

    def test_evaluate_matching_policy_passes(self):
        """Policy passes when claim meets requirements."""
        engine = CapabilityPolicyEngine()
        engine.add_policy(
            CapabilityPolicy(
                rule_id="test-rule",
                description="Test",
                required_capabilities=[("language_coverage", "validated")],
            )
        )

        ledger = CapabilityLedger()
        ledger.register(
            CapabilityClaim(
                detector_id="test/detector",
                capability="language_coverage",
                tier=EvidenceTier.VALIDATED,
                evidence=[
                    EvidenceRef(
                        label=EvidenceLabel.EXECUTED,
                        tier=EvidenceTier.VALIDATED,
                        artifact="run-123",
                    )
                ],
            )
        )

        results = engine.evaluate(ledger, "test/detector")
        assert len(results) == 1
        assert results[0].passed is True
        assert results[0].rule_id == "test-rule"

    def test_evaluate_missing_claim_fails(self):
        """Policy fails when required claim is missing."""
        engine = CapabilityPolicyEngine()
        engine.add_policy(
            CapabilityPolicy(
                rule_id="test-rule",
                description="Test",
                required_capabilities=[("language_coverage", "validated")],
            )
        )

        ledger = CapabilityLedger()  # No claims registered

        results = engine.evaluate(ledger, "test/detector")
        assert len(results) == 1
        assert results[0].passed is False
        assert len(results[0].missing_claims) == 1
        assert "language_coverage" in results[0].missing_claims[0]

    def test_evaluate_insufficient_tier_fails(self):
        """Policy fails when claim tier is below minimum."""
        engine = CapabilityPolicyEngine()
        engine.add_policy(
            CapabilityPolicy(
                rule_id="test-rule",
                description="Test",
                required_capabilities=[("language_coverage", "validated")],
            )
        )

        ledger = CapabilityLedger()
        ledger.register(
            CapabilityClaim(
                detector_id="test/detector",
                capability="language_coverage",
                tier=EvidenceTier.TOOL_BACKED,  # Below VALIDATED
                evidence=[
                    EvidenceRef(
                        label=EvidenceLabel.CALCULATED,
                        tier=EvidenceTier.TOOL_BACKED,
                        artifact="calc-123",
                    )
                ],
            )
        )

        results = engine.evaluate(ledger, "test/detector")
        assert len(results) == 1
        assert results[0].passed is False
        assert len(results[0].evidence_gaps) == 1

    def test_evaluate_wildcard_applies_to_all(self):
        """Wildcard pattern applies to any detector."""
        engine = CapabilityPolicyEngine()
        engine.add_policy(
            CapabilityPolicy(
                rule_id="test-rule",
                description="Test",
                detector_pattern="*",
                required_capabilities=[("language_coverage", "readable")],
            )
        )

        ledger = CapabilityLedger()
        ledger.register(
            CapabilityClaim(
                detector_id="detector/a",
                capability="language_coverage",
                tier=EvidenceTier.READABLE,
                evidence=[],
            )
        )
        ledger.register(
            CapabilityClaim(
                detector_id="detector/b",
                capability="language_coverage",
                tier=EvidenceTier.READABLE,
                evidence=[],
            )
        )

        results_a = engine.evaluate(ledger, "detector/a")
        results_b = engine.evaluate(ledger, "detector/b")

        assert len(results_a) == 1
        assert len(results_b) == 1
        assert results_a[0].passed is True
        assert results_b[0].passed is True

    def test_evaluate_non_matching_pattern_skips(self):
        """Non-matching pattern should not be evaluated."""
        engine = CapabilityPolicyEngine()
        engine.add_policy(
            CapabilityPolicy(
                rule_id="test-rule",
                description="Test",
                detector_pattern="specific/detector",
                required_capabilities=[("language_coverage", "readable")],
            )
        )

        ledger = CapabilityLedger()
        results = engine.evaluate(ledger, "other/detector")
        assert len(results) == 0  # No matching policies

    def test_evaluate_multiple_policies(self):
        """Engine evaluates all matching policies."""
        engine = CapabilityPolicyEngine()
        engine.add_policy(
            CapabilityPolicy(
                rule_id="rule-1",
                description="Rule 1",
                required_capabilities=[("cap_a", "readable")],
            )
        )
        engine.add_policy(
            CapabilityPolicy(
                rule_id="rule-2",
                description="Rule 2",
                required_capabilities=[("cap_b", "tool_backed")],
            )
        )

        ledger = CapabilityLedger()
        ledger.register(
            CapabilityClaim(
                detector_id="test/detector",
                capability="cap_a",
                tier=EvidenceTier.READABLE,
                evidence=[],
            )
        )
        ledger.register(
            CapabilityClaim(
                detector_id="test/detector",
                capability="cap_b",
                tier=EvidenceTier.TOOL_BACKED,
                evidence=[],
            )
        )

        results = engine.evaluate(ledger, "test/detector")
        assert len(results) == 2
        assert results[0].passed is True
        assert results[1].passed is True


class TestPredefinedPolicies:
    def test_create_production_policy(self):
        engine = create_production_policy()
        assert len(engine.policies) >= 3

    def test_create_report_generation_policy(self):
        engine = create_report_generation_policy()
        assert len(engine.policies) >= 1

    def test_create_calibration_policy(self):
        engine = create_calibration_policy()
        assert len(engine.policies) >= 1

    def test_create_minimum_viable_policy(self):
        engine = create_minimum_viable_policy()
        assert len(engine.policies) >= 1

    def test_production_policy_enforces_validated(self):
        """Production policy should reject non-validated language coverage."""
        engine = create_production_policy()
        ledger = CapabilityLedger()

        # Only READABLE claim
        ledger.register(
            CapabilityClaim(
                detector_id="test/detector",
                capability="language_coverage",
                tier=EvidenceTier.READABLE,
                evidence=[],
            )
        )

        results = engine.evaluate(ledger, "test/detector")
        # Should have at least one reject (language_coverage needs validated)
        assert any(r.passed is False for r in results)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
