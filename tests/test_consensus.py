from __future__ import annotations

import unittest

from textforensics.consensus import (
    FamilyVote,
    family_balanced_consensus,
)
from textforensics.detectors import DetectorPrediction


def prediction(
    detector_id="detector",
    family="family",
    verdict="ai_like",
    score=0.8,
    probability=None,
    calibration_id=None,
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
        calibrated_ai_probability=probability,
        calibration_id=calibration_id,
    )


class ConsensusContractTests(unittest.TestCase):
    def test_empty_predictions_abstain(self):
        result = family_balanced_consensus([])
        self.assertEqual(result.verdict, "abstain")
        self.assertEqual(result.independent_families, 0)
        self.assertEqual(result.voting_families, 0)
        self.assertIsNone(result.family_agreement)

    def test_single_family_does_not_vote(self):
        result = family_balanced_consensus(
            [prediction("a", "transformer", "ai_like")]
        )
        self.assertEqual(result.verdict, "abstain")
        self.assertEqual(result.independent_families, 1)
        self.assertTrue(
            any("multiple" in w.lower() for w in result.warnings)
        )

    def test_family_balancing_prevents_duplicate_family_vote_inflation(self):
        result = family_balanced_consensus(
            [
                prediction("a1", "transformer", "ai_like"),
                prediction("a2", "transformer", "ai_like"),
                prediction("b1", "likelihood", "human_like"),
            ]
        )
        self.assertEqual(result.independent_families, 2)
        self.assertEqual(result.verdict, "abstain")
        self.assertEqual(len(result.family_votes), 2)
        self.assertEqual(
            sum(vote.detector_count for vote in result.family_votes), 3
        )
        transformer = next(
            vote for vote in result.family_votes if vote.family == "transformer"
        )
        self.assertEqual(transformer.detector_count, 2)

    def test_component_probabilities_are_not_averaged_into_ensemble(self):
        result = family_balanced_consensus(
            [
                prediction("a", "transformer", "ai_like", probability=0.9, calibration_id="a-cal"),
                prediction("b", "likelihood", "ai_like", probability=0.8, calibration_id="b-cal"),
            ]
        )
        self.assertIsNone(result.calibrated_ai_probability)
        self.assertTrue(
            any("separately" in warning.lower() for warning in result.warnings)
        )

    def test_top_level_probability_requires_ensemble_calibration(self):
        with self.assertRaises(ValueError):
            family_balanced_consensus(
                [prediction("a", "transformer", "ai_like")],
                ensemble_probability=0.75,
            )
        result = family_balanced_consensus(
            [prediction("a", "transformer", "ai_like")],
            ensemble_probability=0.75,
            ensemble_calibration_id="ensemble-v1",
        )
        self.assertEqual(result.calibrated_ai_probability, 0.75)
        self.assertEqual(result.ensemble_calibration_id, "ensemble-v1")

    def test_ensemble_probability_out_of_range_is_rejected(self):
        with self.assertRaises(ValueError):
            family_balanced_consensus(
                [prediction("a", "transformer", "ai_like")],
                ensemble_probability=1.5,
                ensemble_calibration_id="x",
            )

    def test_consensus_requires_probability_and_id_together(self):
        with self.assertRaises(ValueError):
            family_balanced_consensus(
                [prediction("a", "transformer", "ai_like")],
                ensemble_calibration_id="x",
            )

    def test_majority_family_wins_when_agreement_is_strong(self):
        result = family_balanced_consensus(
            [
                prediction("a1", "transformer", "ai_like"),
                prediction("b1", "likelihood", "ai_like"),
                prediction("c1", "statistical", "ai_like"),
            ]
        )
        self.assertEqual(result.verdict, "ai_like")
        self.assertEqual(result.family_agreement, 1.0)

    def test_minority_disagreement_warns(self):
        result = family_balanced_consensus(
            [
                prediction("a1", "transformer", "ai_like"),
                prediction("b1", "likelihood", "human_like"),
                prediction("c1", "statistical", "ai_like"),
            ]
        )
        self.assertEqual(result.verdict, "ai_like")
        self.assertLess(result.family_agreement, 1.0)
        self.assertTrue(
            any("disagree" in w.lower() for w in result.warnings)
        )

    def test_family_with_only_abstentions_is_not_a_voter(self):
        result = family_balanced_consensus(
            [
                prediction("a1", "transformer", "abstain"),
                prediction("b1", "likelihood", "ai_like"),
            ]
        )
        self.assertEqual(result.voting_families, 1)
        self.assertEqual(result.verdict, "abstain")

    def test_single_member_family_carries_component_probability(self):
        result = family_balanced_consensus(
            [
                prediction("a", "transformer", "ai_like", probability=0.6, calibration_id="a-cal"),
            ]
        )
        self.assertEqual(result.family_votes[0].calibrated_ai_probability, 0.6)

    def test_consensus_result_serializes(self):
        result = family_balanced_consensus(
            [
                prediction("a", "transformer", "ai_like"),
                prediction("b", "likelihood", "human_like"),
            ]
        )
        data = result.to_dict()
        self.assertIsInstance(data, dict)
        self.assertIn("family_votes", data)
        self.assertIsInstance(result.family_votes[0], FamilyVote)


if __name__ == "__main__":
    unittest.main()
