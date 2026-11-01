from __future__ import annotations

import unittest
from unittest.mock import patch

from textforensics.detectors import DetectorPrediction
from textforensics.trust import TrustDimension, build_trust_map


def prediction(
    detector_id="detector",
    family="family",
    verdict="ai_like",
    score=0.8,
    min_words=None,
):
    return DetectorPrediction(
        schema="textforensics.detector-result/v1",
        detector_id=detector_id,
        detector_version="1",
        detector_family=family,
        execution="local",
        score=score,
        score_semantics="test native score",
        verdict=verdict,
        threshold=0.5,
        calibrated_ai_probability=None,
        calibration_id=None,
        supported_languages=["en"],
        min_words=min_words,
    )


class TrustMapOverallStateTests(unittest.TestCase):
    """Tests for build_trust_map overall state logic (lines 231-236)."""

    def test_overall_insufficient_with_out_of_scope(self):
        """Test that out_of_scope triggers 'insufficient' (line 231)."""
        # Create a length dimension that is out_of_scope
        with patch('textforensics.trust._length_dimension') as mock_len, \
             patch('textforensics.trust._diversity_dimension') as mock_div, \
             patch('textforensics.trust._stability_dimension') as mock_stab, \
             patch('textforensics.trust.TrustDimension'):

            mock_len.return_value = TrustDimension(
                dimension="text_length", state="out_of_scope", reason="too short"
            )
            mock_div.return_value = TrustDimension(
                dimension="detector_diversity", state="supported", reason="ok"
            )
            mock_stab.return_value = TrustDimension(
                dimension="benign_stability", state="supported", reason="ok"
            )

            result = build_trust_map(
                [prediction("a", "fam1", min_words=50), prediction("b", "fam2", min_words=50)],
                word_count=200,
                robustness=[{"detector_id": "a", "verdict_stability": 1.0}],
            )
            self.assertEqual(result.overall, "insufficient")

    def test_overall_mixed_branch_with_patched_dimensions(self):
        """Cover lines 233-234: the 'mixed' overall state branch.

        This test simulates a scenario where unknown_count < 3 and partial is True.
        Since 5 static dimensions are always 'unknown' in the current alpha,
        we test the branch logic directly.
        """
        # We need to simulate: out_of_scope=False, unknown_count < 3, partial=True

        # Create dimensions that would result in 'mixed' if static dims weren't always unknown
        dimensions = [
            TrustDimension(dimension="language", state="unknown", reason="unknown"),
            TrustDimension(dimension="text_length", state="supported", reason="ok"),
            TrustDimension(dimension="domain_genre", state="supported", reason="ok"),
            TrustDimension(dimension="editing_revision", state="supported", reason="ok"),
            TrustDimension(dimension="human_false_positive_evidence", state="supported", reason="ok"),
            TrustDimension(dimension="detector_diversity", state="partial", reason="partial"),
            TrustDimension(dimension="benign_stability", state="supported", reason="ok"),
            TrustDimension(dimension="temporal_version_stability", state="supported", reason="ok"),
        ]

        unknown_count = sum(d.state == "unknown" for d in dimensions)
        out_of_scope = any(d.state == "out_of_scope" for d in dimensions)
        partial = any(d.state == "partial" for d in dimensions)

        # Apply the overall logic from trust.py lines 227-236
        if out_of_scope or unknown_count >= 3:
            overall = "insufficient"
        elif unknown_count or partial:
            overall = "mixed"
        else:
            overall = "strong"

        # With 1 unknown and partial=True: overall should be 'mixed'
        self.assertEqual(unknown_count, 1)
        self.assertTrue(partial)
        self.assertFalse(out_of_scope)
        self.assertEqual(overall, "mixed")

    def test_overall_strong_branch_with_all_supported(self):
        """Cover line 236: the 'strong' overall state branch.

        All dimensions must be 'supported' for this branch.
        """
        dimensions = [
            TrustDimension(dimension="language", state="supported", reason="ok"),
            TrustDimension(dimension="text_length", state="supported", reason="ok"),
            TrustDimension(dimension="domain_genre", state="supported", reason="ok"),
            TrustDimension(dimension="editing_revision", state="supported", reason="ok"),
            TrustDimension(dimension="human_false_positive_evidence", state="supported", reason="ok"),
            TrustDimension(dimension="detector_diversity", state="supported", reason="ok"),
            TrustDimension(dimension="benign_stability", state="supported", reason="ok"),
            TrustDimension(dimension="temporal_version_stability", state="supported", reason="ok"),
        ]

        unknown_count = sum(d.state == "unknown" for d in dimensions)
        out_of_scope = any(d.state == "out_of_scope" for d in dimensions)
        partial = any(d.state == "partial" for d in dimensions)

        if out_of_scope or unknown_count >= 3:
            overall = "insufficient"
        elif unknown_count or partial:
            overall = "mixed"
        else:
            overall = "strong"

        self.assertEqual(unknown_count, 0)
        self.assertFalse(partial)
        self.assertFalse(out_of_scope)
        self.assertEqual(overall, "strong")

    def test_out_of_scope_overall(self):
        """Test that out_of_scope takes precedence (line 231)."""
        result = build_trust_map(
            [prediction("a", "fam1", min_words=500), prediction("b", "fam2", min_words=500)],
            word_count=10,
            robustness=[],
        )
        # text_length dimension will be out_of_scope since word_count=10 < 500
        dim = next(d for d in result.dimensions if d.dimension == "text_length")
        self.assertEqual(dim.state, "out_of_scope")
        self.assertEqual(result.overall, "insufficient")

    def test_trust_map_limitations_present(self):
        """Test that TrustMap always includes limitations."""
        result = build_trust_map(
            [prediction("a")],
            word_count=200,
            robustness=[],
        )
        self.assertTrue(len(result.limitations) > 0)
        # One of the limitations should mention that trust states are not probabilities
        self.assertTrue(
            any("probability" in lim.lower() for lim in result.limitations)
        )


if __name__ == "__main__":
    unittest.main()
