"""Property-based tests for bundle consistency checking."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import settings as hypothesis_settings
from hypothesis import strategies as st

from textforensics.bundle_consistency import (
    ConsistencyIssue,
    ConsistencyReport,
    bundle_hash,
    check_bundle_consistency,
)


class TestBundleConsistencyProperties:
    """Property-based tests for bundle consistency invariants."""

    @given(
        st.dictionaries(
            st.sampled_from([
                "schema", "consensus", "trust_map", "detector_results",
                "input", "content_sha256", "generated_at_utc"
            ]),
            st.one_of(
                st.text(max_size=20),
                st.integers(),
                st.floats(allow_nan=False, allow_infinity=False),
                st.booleans(),
                st.lists(st.text(max_size=20), max_size=5),
                st.dictionaries(st.text(max_size=10), st.text(max_size=20), max_size=3),
            ),
            max_size=7,
        )
    )
    @hypothesis_settings(deadline=None)
    def test_check_consistency_never_crashes(self, bundle: dict):
        """check_bundle_consistency should never raise for any dict input."""
        report = check_bundle_consistency(bundle)
        assert isinstance(report, ConsistencyReport)

    @given(st.text(min_size=1, max_size=100, alphabet=st.characters(whitelist_categories=("L", "N"))))
    @hypothesis_settings(deadline=None)
    def test_bundle_hash_deterministic_for_same_content(self, text: str):
        """Bundle hash should be deterministic for same content."""
        bundle = {
            "schema": "textforensics.forensic-bundle/v1",
            "consensus": {"verdict": "ai_like"},
            "input": {"word_count": len(text)},
        }
        hash1 = bundle_hash(bundle)
        hash2 = bundle_hash(bundle)
        assert hash1 == hash2

    @given(st.text(min_size=1, max_size=100, alphabet=st.characters(whitelist_categories=("L", "N"))))
    @hypothesis_settings(deadline=None)
    def test_bundle_hash_excludes_timestamp(self, timestamp: str):
        """Bundle hash should not depend on generated_at_utc."""
        bundle1 = {
            "schema": "textforensics.forensic-bundle/v1",
            "consensus": {"verdict": "ai_like"},
            "generated_at_utc": timestamp,
        }
        bundle2 = {
            "schema": "textforensics.forensic-bundle/v1",
            "consensus": {"verdict": "ai_like"},
            "generated_at_utc": "different_timestamp",
        }
        assert bundle_hash(bundle1) == bundle_hash(bundle2)

    @given(
        st.lists(
            st.tuples(
                st.text(min_size=1, max_size=30, alphabet=st.characters(whitelist_categories=("L", "N"))),
                st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
            ),
            min_size=0,
            max_size=10,
        )
    )
    @hypothesis_settings(deadline=None)
    def test_detector_results_order_independent(self, detectors: list[tuple[str, float]]):
        """Detector results should be handled regardless of order."""
        bundle1 = {
            "schema": "textforensics.forensic-bundle/v1",
            "detector_results": [
                {"detector_id": det_id, "score": score}
                for det_id, score in detectors
            ],
        }
        bundle2 = {
            "schema": "textforensics.forensic-bundle/v1",
            "detector_results": [
                {"detector_id": det_id, "score": score}
                for det_id, score in reversed(detectors)
            ],
        }
        # Hash should be same regardless of order (hash uses sorted keys)
        # But we check the consistency report is the same
        report1 = check_bundle_consistency(bundle1)
        report2 = check_bundle_consistency(bundle2)
        assert report1.is_consistent == report2.is_consistent

    @given(st.integers(min_value=0, max_value=1000))
    @hypothesis_settings(deadline=None)
    def test_word_count_non_negative(self, word_count: int):
        """Word count validation should accept non-negative values."""
        bundle = {
            "schema": "textforensics.forensic-bundle/v1",
            "input": {"word_count": word_count},
        }
        report = check_bundle_consistency(bundle)
        assert report.is_consistent is True

    @given(st.integers(min_value=-1000, max_value=-1))
    @hypothesis_settings(deadline=None)
    def test_negative_word_count_fails(self, word_count: int):
        """Negative word count should fail."""
        bundle = {
            "schema": "textforensics.forensic-bundle/v1",
            "input": {"word_count": word_count},
        }
        report = check_bundle_consistency(bundle)
        assert report.is_consistent is False
        assert any("word_count" in i.field for i in report.issues)

    @given(
        st.floats(min_value=-10.0, max_value=10.0, allow_nan=False, allow_infinity=False)
    )
    @hypothesis_settings(deadline=None)
    def test_ai_probability_range(self, prob: float):
        """AI probability outside [0,1] should warn but not fail."""
        bundle = {
            "schema": "textforensics.forensic-bundle/v1",
            "consensus": {"verdict": "ai_like", "ai_probability": prob},
        }
        report = check_bundle_consistency(bundle)
        if prob < 0.0 or prob > 1.0:
            # Should produce a warning
            assert any("ai_probability" in i.field for i in report.issues)

    @given(
        st.sampled_from(["ai_like", "human_like", "abstain", "insufficient_evidence", "mixed", "invalid"])
    )
    @hypothesis_settings(deadline=None)
    def test_verdict_validation(self, verdict: str):
        """Verdict validation should warn for invalid values."""
        bundle = {
            "schema": "textforensics.forensic-bundle/v1",
            "consensus": {"verdict": verdict},
        }
        report = check_bundle_consistency(bundle)
        if verdict not in ("ai_like", "human_like", "abstain", "insufficient_evidence", "mixed"):
            assert any("verdict" in i.field for i in report.issues)

    @given(st.text(min_size=0, max_size=100))
    @hypothesis_settings(deadline=None)
    def test_sha256_length_validation(self, sha256: str):
        """SHA256 length validation."""
        bundle = {
            "schema": "textforensics.forensic-bundle/v1",
            "content_sha256": sha256,
        }
        report = check_bundle_consistency(bundle)
        if len(sha256) != 64:
            assert not report.is_consistent
            assert any(i.field == "content_sha256" for i in report.issues)


class TestConsistencyReportInvariants:
    """Tests for invariant properties of ConsistencyReport."""

    def test_report_structure(self):
        """Report should always have expected structure."""
        bundle = {"schema": "textforensics.forensic-bundle/v1"}
        report = check_bundle_consistency(bundle)

        assert hasattr(report, "is_consistent")
        assert hasattr(report, "issues")
        assert hasattr(report, "checked_fields")
        assert isinstance(report.is_consistent, bool)
        assert isinstance(report.issues, list)
        assert isinstance(report.checked_fields, list)

    def test_issue_structure(self):
        """ConsistencyIssue should have expected fields."""
        issue = ConsistencyIssue(
            field="test.field",
            issue_type="invalid",
            message="Test message",
            severity="warning",
        )
        assert issue.field == "test.field"
        assert issue.issue_type == "invalid"
        assert issue.message == "Test message"
        assert issue.severity == "warning"

    def test_critical_issues_always_fail(self):
        """Report with critical issues should never be consistent."""
        bundle = {
            "schema": "textforensics.forensic-bundle/v1",
            "content_sha256": "invalid",  # Causes critical error
        }
        report = check_bundle_consistency(bundle)
        assert report.is_consistent is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
