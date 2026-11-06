"""Tests for bundle consistency checking."""

from __future__ import annotations

from textforensics.bundle_consistency import (
    ConsistencyIssue,
    ConsistencyReport,
    bundle_hash,
    check_bundle_consistency,
)


class TestBundleConsistency:
    def test_valid_bundle_passes(self):
        """A properly formed bundle should pass consistency check."""
        bundle = {
            "schema": "textforensics.forensic-bundle/v1",
            "consensus": {
                "verdict": "ai_like",
                "ai_probability": 0.75,
                "independent_families": 1,
            },
            "detector_results": [
                {
                    "detector_id": "test/detector-1",
                    "detector_version": "1.0.0",
                    "detector_family": "stylometric",
                    "score": 0.8,
                    "score_semantics": "higher_means_more_machine_like",
                    "verdict": "ai_like",
                }
            ],
            "trust_map": {
                "overall": "strong",
                "dimensions": [
                    {"dimension": "language_coverage", "state": "supported", "reason": "Test text"}
                ],
            },
            "input": {"word_count": 100, "sentence_count": 5, "paragraph_count": 2},
            "content_sha256": "0123456789abcdef" * 4,
        }
        report = check_bundle_consistency(bundle)
        assert report.is_consistent is True
        assert len(report.issues) == 0

    def test_missing_schema_fails(self):
        """Bundle without schema should fail."""
        bundle = {"consensus": {"verdict": "ai_like"}}
        report = check_bundle_consistency(bundle)
        assert report.is_consistent is False
        assert any(i.field == "schema" and i.severity == "error" for i in report.issues)

    def test_invalid_verdict_warns(self):
        """Invalid verdict value should produce a warning."""
        bundle = {
            "schema": "textforensics.forensic-bundle/v1",
            "consensus": {"verdict": "invalid_verdict"},
        }
        report = check_bundle_consistency(bundle)
        assert report.is_consistent is True  # Warning doesn't fail
        assert any(i.field == "consensus.verdict" for i in report.issues)

    def test_ai_probability_range(self):
        """AI probability must be between 0 and 1."""
        bundle = {
            "schema": "textforensics.forensic-bundle/v1",
            "consensus": {"ai_probability": 1.5},
        }
        report = check_bundle_consistency(bundle)
        assert report.is_consistent is True  # Range warning doesn't fail
        assert any("ai_probability" in i.field for i in report.issues)

    def test_duplicate_detector_ids_warns(self):
        """Duplicate detector IDs should produce a warning."""
        bundle = {
            "schema": "textforensics.forensic-bundle/v1",
            "detector_results": [
                {
                    "detector_id": "test/detector",
                    "score": 0.5,
                },
                {
                    "detector_id": "test/detector",  # Duplicate
                    "score": 0.6,
                },
            ],
        }
        report = check_bundle_consistency(bundle)
        assert any("detector_id" in i.field for i in report.issues)

    def test_invalid_sha256_fails(self):
        """Invalid SHA-256 format should fail."""
        bundle = {
            "schema": "textforensics.forensic-bundle/v1",
            "content_sha256": "not-a-valid-hash",
        }
        report = check_bundle_consistency(bundle)
        assert report.is_consistent is False
        assert any(i.field == "content_sha256" for i in report.issues)

    def test_negative_word_count_fails(self):
        """Negative word count should fail."""
        bundle = {
            "schema": "textforensics.forensic-bundle/v1",
            "input": {"word_count": -10},
        }
        report = check_bundle_consistency(bundle)
        assert report.is_consistent is False
        assert any(i.field == "input.word_count" for i in report.issues)

    def test_word_count_sentence_count_mismatch(self):
        """Non-zero word count with zero sentences should warn."""
        bundle = {
            "schema": "textforensics.forensic-bundle/v1",
            "input": {"word_count": 100, "sentence_count": 0},
        }
        report = check_bundle_consistency(bundle)
        assert any("sentence_count" in i.field for i in report.issues)

    def test_bundle_hash_is_deterministic(self):
        """Bundle hash should be consistent for same content."""
        bundle = {
            "schema": "textforensics.forensic-bundle/v1",
            "consensus": {"verdict": "ai_like"},
            "input": {"word_count": 100},
        }
        hash1 = bundle_hash(bundle)
        hash2 = bundle_hash(bundle)
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 is 64 hex chars

    def test_bundle_hash_excludes_timestamps(self):
        """Bundle hash should exclude timestamps that may vary."""
        bundle1 = {
            "schema": "textforensics.forensic-bundle/v1",
            "consensus": {"verdict": "ai_like"},
            "generated_at_utc": "2024-01-01T00:00:00Z",
        }
        bundle2 = {
            "schema": "textforensics.forensic-bundle/v1",
            "consensus": {"verdict": "ai_like"},
            "generated_at_utc": "2025-06-01T12:00:00Z",  # Different timestamp
        }
        assert bundle_hash(bundle1) == bundle_hash(bundle2)

    def test_consistency_report_structure(self):
        """Report should have expected fields."""
        bundle = {"schema": "textforensics.forensic-bundle/v1"}
        report = check_bundle_consistency(bundle)

        assert isinstance(report, ConsistencyReport)
        assert hasattr(report, "is_consistent")
        assert hasattr(report, "issues")
        assert hasattr(report, "checked_fields")

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

    def test_trust_map_overall_accepts_aggregate_states(self):
        """trust_map.overall is the aggregate verdict, not a dimension state.

        Regression test: the overall check used to allow only the dimension
        states {"supported", "partial", "unknown", "out_of_scope"}, so every
        real bundle (overall is "strong" / "mixed" / "insufficient" per
        trust.TrustMap) was flagged with a spurious warning.
        """
        for overall in ("strong", "mixed", "insufficient"):
            bundle = {
                "schema": "textforensics.forensic-bundle/v1",
                "trust_map": {"overall": overall, "dimensions": []},
            }
            report = check_bundle_consistency(bundle)
            assert not any(i.field == "trust_map.overall" for i in report.issues), (
                f"overall={overall!r} should not be flagged"
            )

    def test_trust_map_overall_rejects_dimension_states(self):
        """A dimension state in trust_map.overall is invalid and warns."""
        bundle = {
            "schema": "textforensics.forensic-bundle/v1",
            "trust_map": {"overall": "supported", "dimensions": []},
        }
        report = check_bundle_consistency(bundle)
        assert report.is_consistent is True  # Warning doesn't fail
        assert any(
            i.field == "trust_map.overall" and i.severity == "warning" for i in report.issues
        )
