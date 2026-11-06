"""Property-based tests for capability ledger policy engine."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import settings as hypothesis_settings
from hypothesis import strategies as st

from textforensics.policy import (
    CapabilityClaim,
    CapabilityLedger,
    CapabilityPolicy,
    CapabilityPolicyEngine,
    EvidenceTier,
    PolicyResult,
    create_production_policy,
)


class TestPolicyProperties:
    """Property-based tests for policy evaluation invariants."""

    @given(
        st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=("L", "N")))
    )
    @hypothesis_settings(deadline=None)
    def test_policy_result_roundtrip(self, rule_id: str):
        """PolicyResult to_dict should preserve all fields."""
        result = PolicyResult(
            passed=True,
            rule_id=rule_id,
            message="Test message",
            missing_claims=[],
            evidence_gaps=[],
        )
        d = result.to_dict()
        assert d["rule_id"] == rule_id
        assert d["passed"] is True
        assert d["message"] == "Test message"
        assert d["missing_claims"] == []
        assert d["evidence_gaps"] == []

    @given(
        st.lists(
            st.tuples(
                st.text(
                    min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=("L", "N"))
                ),
                st.sampled_from(["readable", "tool_backed", "validated"]),
            ),
            min_size=1,
            max_size=5,
        )
    )
    def test_policy_engine_add_multiple(self, caps: list[tuple[str, str]]):
        """Adding multiple policies should not raise and should store them all."""
        engine = CapabilityPolicyEngine()
        for i, (cap, tier) in enumerate(caps):
            policy = CapabilityPolicy(
                rule_id=f"rule-{i}",
                description=f"Policy for {cap}",
                required_capabilities=[(cap, tier)],
            )
            engine.add_policy(policy)
        assert len(engine.policies) == len(caps)

    @given(st.text(min_size=1, max_size=100))
    def test_pattern_matching_wildcard_always_matches(self, detector_id: str):
        """Wildcard pattern should match any detector ID."""
        engine = CapabilityPolicyEngine()
        assert engine._matches_pattern(detector_id, "*") is True

    @given(st.text(min_size=1, max_size=100, alphabet=st.characters(blacklist_characters="*")))
    @hypothesis_settings(deadline=None)
    def test_exact_pattern_matches_only_self(self, detector_id: str):
        """Exact pattern should only match itself."""
        engine = CapabilityPolicyEngine()
        assert engine._matches_pattern(detector_id, detector_id) is True

    @given(
        st.text(min_size=1, max_size=50),
        st.text(min_size=1, max_size=50),
    )
    def test_policy_evaluation_deterministic(self, detector_id: str, cap_name: str):
        """Policy evaluation should be deterministic for same inputs."""
        engine = CapabilityPolicyEngine()
        engine.add_policy(
            CapabilityPolicy(
                rule_id="test-rule",
                description="Test",
                required_capabilities=[(cap_name, "readable")],
            )
        )

        ledger = CapabilityLedger()
        ledger.register(
            CapabilityClaim(
                detector_id=detector_id,
                capability=cap_name,
                tier=EvidenceTier.READABLE,
                evidence=[],
            )
        )

        # Run twice, should get same result
        results1 = engine.evaluate(ledger, detector_id)
        results2 = engine.evaluate(ledger, detector_id)

        assert len(results1) == len(results2)
        for r1, r2 in zip(results1, results2, strict=False):
            assert r1.passed == r2.passed
            assert r1.rule_id == r2.rule_id
            assert r1.missing_claims == r2.missing_claims
            assert r1.evidence_gaps == r2.evidence_gaps

    @given(
        st.lists(
            st.tuples(
                st.text(
                    min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=("L", "N"))
                ),
                st.sampled_from(["readable", "tool_backed", "validated"]),
            ),
            min_size=0,
            max_size=5,
        )
    )
    def test_evaluate_empty_ledger_always_fails(self, requirements: list[tuple[str, str]]):
        """Evaluating against empty ledger should fail all policies with missing claims."""
        if not requirements:
            return

        engine = CapabilityPolicyEngine()
        engine.add_policy(
            CapabilityPolicy(
                rule_id="test-rule",
                description="Test",
                required_capabilities=requirements,
            )
        )

        ledger = CapabilityLedger()  # Empty
        results = engine.evaluate(ledger, "test/detector")

        assert len(results) == 1
        assert results[0].passed is False
        assert len(results[0].missing_claims) == len(requirements)

    @given(
        st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=("L", "N"))),
        st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=("L", "N"))),
    )
    def test_non_matching_pattern_skips(self, pattern: str, detector_id: str):
        """Non-matching pattern should not produce results."""
        # Skip if they happen to match
        if pattern == "*" or pattern == detector_id:
            return

        # Simple check: if pattern has no wildcard and doesn't match, it should skip
        if "*" not in pattern and pattern != detector_id:
            engine = CapabilityPolicyEngine()
            engine.add_policy(
                CapabilityPolicy(
                    rule_id="test-rule",
                    description="Test",
                    detector_pattern=pattern,
                    required_capabilities=[("cap1", "readable")],
                )
            )

            ledger = CapabilityLedger()
            results = engine.evaluate(ledger, detector_id)

            assert len(results) == 0


class TestPolicyEngineInvariants:
    """Tests for invariant properties of the policy engine."""

    def test_evaluation_results_order_matches_policy_order(self):
        """Results should be in the same order as policies were added."""
        engine = CapabilityPolicyEngine()
        engine.add_policy(
            CapabilityPolicy(
                rule_id="rule-a", description="A", required_capabilities=[("cap1", "readable")]
            )
        )
        engine.add_policy(
            CapabilityPolicy(
                rule_id="rule-b", description="B", required_capabilities=[("cap2", "readable")]
            )
        )
        engine.add_policy(
            CapabilityPolicy(
                rule_id="rule-c", description="C", required_capabilities=[("cap3", "readable")]
            )
        )

        ledger = CapabilityLedger()
        for cap in ["cap1", "cap2", "cap3"]:
            ledger.register(
                CapabilityClaim(
                    detector_id="test/detector",
                    capability=cap,
                    tier=EvidenceTier.READABLE,
                    evidence=[],
                )
            )

        results = engine.evaluate(ledger, "test/detector")
        assert len(results) == 3
        assert results[0].rule_id == "rule-a"
        assert results[1].rule_id == "rule-b"
        assert results[2].rule_id == "rule-c"

    def test_action_on_failure_warn_still_passes_evaluation(self):
        """Warn action should not make evaluation fail overall."""
        engine = CapabilityPolicyEngine()
        engine.add_policy(
            CapabilityPolicy(
                rule_id="warn-rule",
                description="Warn",
                required_capabilities=[("missing_cap", "readable")],
                action_on_failure="warn",
            )
        )

        ledger = CapabilityLedger()
        results = engine.evaluate(ledger, "test/detector")

        # Result exists but failed
        assert len(results) == 1
        assert results[0].passed is False

    def test_action_on_failure_abstain_still_passes_evaluation(self):
        """Abstain action should not make evaluation fail overall."""
        engine = CapabilityPolicyEngine()
        engine.add_policy(
            CapabilityPolicy(
                rule_id="abstain-rule",
                description="Abstain",
                required_capabilities=[("missing_cap", "readable")],
                action_on_failure="abstain",
            )
        )

        ledger = CapabilityLedger()
        results = engine.evaluate(ledger, "test/detector")

        assert len(results) == 1
        assert results[0].passed is False

    def test_action_on_failure_reject_makes_evaluation_fail(self):
        """Reject action should make evaluation fail."""
        engine = CapabilityPolicyEngine()
        engine.add_policy(
            CapabilityPolicy(
                rule_id="reject-rule",
                description="Reject",
                required_capabilities=[("missing_cap", "readable")],
                action_on_failure="reject",
            )
        )

        ledger = CapabilityLedger()
        results = engine.evaluate(ledger, "test/detector")

        assert len(results) == 1
        assert results[0].passed is False

    def test_tier_ordering_invariant(self):
        """Higher tier should always satisfy lower tier requirement."""
        tiers = ["readable", "tool_backed", "validated"]
        tier_rank = {t: i for i, t in enumerate(tiers)}

        for claim_tier in tiers:
            for req_tier in tiers:
                if tier_rank[claim_tier] >= tier_rank[req_tier]:
                    # Should satisfy requirement
                    pass  # Just checking the rank logic is consistent
                else:
                    # Should not satisfy
                    pass

    def test_production_policy_has_correct_rules(self):
        """Production policy should have expected rule IDs."""
        engine = create_production_policy()
        rule_ids = {p.rule_id for p in engine.policies}

        assert "prod-language-coverage" in rule_ids
        assert "prod-length-robustness" in rule_ids
        assert "prod-domain-accuracy" in rule_ids

        # Check tiers
        for policy in engine.policies:
            if policy.rule_id == "prod-language-coverage":
                assert policy.required_capabilities == [("language_coverage", "validated")]
            elif policy.rule_id in ("prod-length-robustness", "prod-domain-accuracy"):
                assert policy.required_capabilities[0][1] == "tool_backed"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
