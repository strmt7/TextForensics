from __future__ import annotations

import unittest

from textforensics.consensus import (
    AgreementMatrix,
    ConsensusResult,
    FamilyVote,
    PairwiseAgreement,
    _family_vote,
    _interpret_kappa,
    _is_abstain,
    build_agreement_matrix,
    cohens_kappa,
    family_balanced_consensus,
    fleiss_kappa,
    percent_agreement,
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
        result = family_balanced_consensus([prediction("a", "transformer", "ai_like")])
        self.assertEqual(result.verdict, "abstain")
        self.assertEqual(result.independent_families, 1)
        self.assertTrue(any("multiple" in w.lower() for w in result.warnings))

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
        self.assertEqual(sum(vote.detector_count for vote in result.family_votes), 3)
        transformer = next(vote for vote in result.family_votes if vote.family == "transformer")
        self.assertEqual(transformer.detector_count, 2)

    def test_component_probabilities_are_not_averaged_into_ensemble(self):
        result = family_balanced_consensus(
            [
                prediction("a", "transformer", "ai_like", probability=0.9, calibration_id="a-cal"),
                prediction("b", "likelihood", "ai_like", probability=0.8, calibration_id="b-cal"),
            ]
        )
        self.assertIsNone(result.calibrated_ai_probability)
        self.assertTrue(any("separately" in warning.lower() for warning in result.warnings))

    def test_family_with_probability_and_without_probability_warns(self):
        # Line 57: Warning when a family has mixed probability availability
        # (multiple predictions, at least one with probability, but not all)
        result = family_balanced_consensus(
            [
                prediction(
                    "a1", "transformer", "ai_like", probability=0.9, calibration_id="a1-cal"
                ),
                prediction("a2", "transformer", "human_like"),  # No probability
                prediction("b1", "likelihood", "ai_like"),
            ]
        )
        # No ensemble probability since only one family has votes
        self.assertIsNone(result.calibrated_ai_probability)
        # Should have warning about probability not being fused
        self.assertTrue(any("probability" in w.lower() for w in result.warnings))

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
        self.assertTrue(any("disagree" in w.lower() for w in result.warnings))

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


class ConsensusMutationKillTests(unittest.TestCase):
    """Behaviour tests that distinguish the original consensus.py from each
    surviving cosmic-ray mutant in the Phase 5 mutation-survivors batch.

    Every test asserts real, observable behaviour — a verdict, an exact
    statistic, a warning, an error message, or a raised exception — never
    merely that a call succeeds. The agreement statistics (percent
    agreement, Cohen's kappa, Fleiss' kappa, the agreement matrix) had no
    tests at all before this class, which is why most of their mutants
    survived; the values asserted here were verified by hand against the
    documented formulas, not just copied from the implementation.
    """

    # -- _family_vote -----------------------------------------------------

    def test_family_vote_tie_abstains(self):
        # Mutants negating `ai > human` / `human > ai` (Gt_GtE) vote ai_like
        # on a tie; the original abstains.
        vote = _family_vote(
            "f",
            [prediction("a", "f", "ai_like"), prediction("b", "f", "human_like")],
        )
        self.assertEqual(vote.verdict, "abstain")

    def test_family_vote_majority_wins_both_directions(self):
        ai_majority = _family_vote(
            "f",
            [
                prediction("a", "f", "ai_like"),
                prediction("b", "f", "ai_like"),
                prediction("c", "f", "human_like"),
            ],
        )
        self.assertEqual(ai_majority.verdict, "ai_like")
        human_majority = _family_vote(
            "f",
            [
                prediction("a", "f", "ai_like"),
                prediction("b", "f", "human_like"),
                prediction("c", "f", "human_like"),
            ],
        )
        self.assertEqual(human_majority.verdict, "human_like")

    def test_family_vote_large_tie_abstains(self):
        # Mutant `human > ai` -> `human is not ai` (Gt_IsNot): with 257
        # votes each way the two counts are distinct int objects outside
        # CPython's small-int cache, so `is not` is True and the mutant
        # votes human_like where the original abstains.
        preds = [prediction(f"a{i}", "f", "ai_like") for i in range(257)]
        preds += [prediction(f"h{i}", "f", "human_like") for i in range(257)]
        self.assertEqual(_family_vote("f", preds).verdict, "abstain")

    def test_family_vote_first_probability_not_carried_for_multi_member_family(self):
        # Mutant `len(predictions) == 1` -> `>= 1` carries the first
        # member's probability for any family size; the original only
        # carries it for a single-member family.
        vote = _family_vote(
            "f",
            [
                prediction("a", "f", "ai_like", probability=0.9, calibration_id="a-cal"),
                prediction("b", "f", "human_like"),
            ],
        )
        self.assertIsNone(vote.calibrated_ai_probability)
        self.assertTrue(any("withheld" in w for w in vote.warnings))

    def test_family_vote_all_members_with_probability_warns(self):
        # Mutant `is not None` -> `is None` in the any() check flips the
        # warning onto families with no probabilities at all.
        vote = _family_vote(
            "f",
            [
                prediction("a", "f", "ai_like", probability=0.9, calibration_id="a-cal"),
                prediction("b", "f", "human_like", probability=0.8, calibration_id="b-cal"),
            ],
        )
        self.assertTrue(any("withheld" in w for w in vote.warnings))
        no_prob = _family_vote(
            "f",
            [prediction("a", "f", "ai_like"), prediction("b", "f", "human_like")],
        )
        self.assertEqual(no_prob.warnings, [])

    def test_family_vote_all_abstentions_abstain_without_warning(self):
        vote = _family_vote(
            "f",
            [prediction("a", "f", "abstain"), prediction("b", "f", "abstain")],
        )
        self.assertEqual(vote.verdict, "abstain")
        self.assertIsNone(vote.calibrated_ai_probability)
        self.assertEqual(vote.warnings, [])

    # -- family_balanced_consensus: signature and ensemble probability ---

    def test_positional_ensemble_arguments_rejected(self):
        # Mutant `*,` -> `/,` turns the keyword-only ensemble arguments
        # into positional-or-keyword ones; the original rejects positional
        # ensemble arguments.
        with self.assertRaises(TypeError):
            family_balanced_consensus(
                [prediction("a", "transformer", "ai_like")],
                0.75,
                "ensemble-v1",
            )

    def test_ensemble_probability_boundaries(self):
        # Mutant `0.0` -> `-1.0` accepts -0.5; the original rejects it.
        # Mutants `<=` -> `<` reject exactly 0.0 / 1.0; the original
        # accepts both endpoints.
        for ok_value in (0.0, 1.0):
            result = family_balanced_consensus(
                [prediction("a", "transformer", "ai_like")],
                ensemble_probability=ok_value,
                ensemble_calibration_id="e",
            )
            self.assertEqual(result.calibrated_ai_probability, ok_value)
        for bad_value in (-0.5, 1.5):
            with self.assertRaises(ValueError):
                family_balanced_consensus(
                    [prediction("a", "transformer", "ai_like")],
                    ensemble_probability=bad_value,
                    ensemble_calibration_id="e",
                )

    # -- family_balanced_consensus: family counting and agreement --------

    def test_two_families_have_no_single_family_warning(self):
        # Mutant `len(grouped) < 2` -> `< 3` warns with two families;
        # mutant `!= 2` warns with three.
        result = family_balanced_consensus(
            [
                prediction("a", "transformer", "ai_like"),
                prediction("b", "likelihood", "human_like"),
            ]
        )
        self.assertFalse(any("multiple" in w.lower() for w in result.warnings))
        three = family_balanced_consensus(
            [
                prediction("a", "transformer", "ai_like"),
                prediction("b", "likelihood", "human_like"),
                prediction("c", "statistical", "ai_like"),
            ]
        )
        self.assertFalse(any("multiple" in w.lower() for w in three.warnings))

    def test_two_voting_families_vote(self):
        # Mutant `len(voting) < 2` -> `<= 2` abstains with two voters.
        result = family_balanced_consensus(
            [
                prediction("a", "transformer", "ai_like"),
                prediction("b", "likelihood", "ai_like"),
            ]
        )
        self.assertEqual(result.verdict, "ai_like")
        self.assertEqual(result.family_agreement, 1.0)

    def test_one_ai_two_human_families_vote_human_like(self):
        # Mutants `ai > human` -> `!=` / `is not` vote ai_like whenever
        # the counts differ, even when human wins.
        result = family_balanced_consensus(
            [
                prediction("a", "transformer", "ai_like"),
                prediction("b", "likelihood", "human_like"),
                prediction("c", "statistical", "human_like"),
            ]
        )
        self.assertEqual(result.verdict, "human_like")

    def test_large_family_tie_abstains(self):
        # Mutant `ai == human` -> `ai is human` (Eq_Is): with 257 voting
        # families each way the two sums are distinct int objects outside
        # CPython's small-int cache, so `is` is False and the mutant
        # votes human_like where the original abstains.
        preds = [prediction(f"a{i}", f"fam-a{i}", "ai_like") for i in range(257)]
        preds += [prediction(f"h{i}", f"fam-h{i}", "human_like") for i in range(257)]
        self.assertEqual(family_balanced_consensus(preds).verdict, "abstain")

    def test_agreement_two_thirds_rounds_to_four_places(self):
        # Mutants `/` -> `//` (agreement 0 instead of 2/3), `1.0` -> `2.0`
        # / `0.0` (warning threshold), and `round(..., 4)` -> 3 / 5 places.
        result = family_balanced_consensus(
            [
                prediction("a", "transformer", "ai_like"),
                prediction("b", "likelihood", "ai_like"),
                prediction("c", "statistical", "human_like"),
            ]
        )
        self.assertEqual(result.verdict, "ai_like")
        self.assertEqual(result.family_agreement, 0.6667)
        self.assertTrue(any("disagree" in w.lower() for w in result.warnings))

    def test_unanimous_agreement_has_no_disagreement_warning(self):
        # Mutant `agreement < 1.0` -> `< 2.0` warns even on unanimity.
        result = family_balanced_consensus(
            [
                prediction("a", "transformer", "ai_like"),
                prediction("b", "likelihood", "ai_like"),
                prediction("c", "statistical", "ai_like"),
            ]
        )
        self.assertEqual(result.family_agreement, 1.0)
        self.assertFalse(any("disagree" in w.lower() for w in result.warnings))

    def test_ensemble_probability_rounds_to_four_places(self):
        result = family_balanced_consensus(
            [prediction("a", "transformer", "ai_like")],
            ensemble_probability=0.123456,
            ensemble_calibration_id="e",
        )
        self.assertEqual(result.calibrated_ai_probability, 0.1235)
        result2 = family_balanced_consensus(
            [prediction("a", "transformer", "ai_like")],
            ensemble_probability=0.123449,
            ensemble_calibration_id="e",
        )
        self.assertEqual(result2.calibrated_ai_probability, 0.1234)

    def test_no_fused_warning_without_component_probabilities(self):
        # Mutant `and` -> `or` warns whenever the ensemble probability
        # is missing, even when no component has one either.
        result = family_balanced_consensus(
            [
                prediction("a", "transformer", "ai_like"),
                prediction("b", "likelihood", "ai_like"),
            ]
        )
        self.assertFalse(any("separately" in w.lower() for w in result.warnings))

    def test_single_voting_family_agreement_is_none(self):
        result = family_balanced_consensus(
            [
                prediction("a1", "transformer", "abstain"),
                prediction("b1", "likelihood", "ai_like"),
            ]
        )
        self.assertIsNone(result.family_agreement)
        self.assertEqual(result.voting_families, 1)

    # -- _interpret_kappa -------------------------------------------------

    def test_interpret_kappa_full_landis_koch_scale(self):
        cases = [
            (-1.0, "poor (less than chance)"),
            (-0.5, "poor (less than chance)"),
            (0.0, "slight"),
            (0.19, "slight"),
            (0.20, "fair"),
            (0.39, "fair"),
            (0.40, "moderate"),
            (0.59, "moderate"),
            (0.60, "substantial"),
            (0.79, "substantial"),
            (0.80, "almost perfect"),
            (0.95, "almost perfect"),
            (1.0, "almost perfect"),
        ]
        for kappa, expected in cases:
            with self.subTest(kappa=kappa):
                self.assertEqual(_interpret_kappa(kappa), expected)

    # -- _is_abstain ------------------------------------------------------

    def test_is_abstain_forms(self):
        self.assertTrue(_is_abstain(None))
        self.assertTrue(_is_abstain("abstain"))
        self.assertTrue(_is_abstain("ABSTAIN "))
        self.assertTrue(_is_abstain("insufficient_evidence"))
        self.assertTrue(_is_abstain("  Insufficient_Evidence "))
        self.assertTrue(_is_abstain(""))
        self.assertTrue(_is_abstain("   "))
        self.assertFalse(_is_abstain("ai_like"))
        self.assertFalse(_is_abstain("human_like"))
        self.assertFalse(_is_abstain("  AI_LIKE  "))

    # -- percent_agreement ------------------------------------------------

    def test_percent_agreement_exact_two_thirds(self):
        fraction, paired = percent_agreement(
            ["ai_like", "human_like", "ai_like"],
            ["ai_like", "human_like", "human_like"],
        )
        self.assertEqual((fraction, paired), (2 / 3, 3))

    def test_percent_agreement_abstention_mid_sequence_skipped(self):
        # Mutant `continue` -> `break` stops at the first abstention and
        # drops the agreeing pair that follows it.
        fraction, paired = percent_agreement(
            ["ai_like", None, "human_like"],
            ["ai_like", "ai_like", "human_like"],
        )
        self.assertEqual((fraction, paired), (1.0, 2))
        # Mutant `or` -> `and` only skips pairs where BOTH abstain.
        fraction2, paired2 = percent_agreement(
            ["ai_like", None],
            ["human_like", "human_like"],
        )
        self.assertEqual((fraction2, paired2), (0.0, 1))

    def test_percent_agreement_normalizes_case_and_whitespace(self):
        fraction, paired = percent_agreement(
            ["AI_LIKE", " ai_like "],
            ["ai_like", "ai_like"],
        )
        self.assertEqual((fraction, paired), (1.0, 2))

    def test_percent_agreement_all_abstain_returns_zero_zero(self):
        self.assertEqual(
            percent_agreement([None, "abstain"], ["ai_like", "human_like"]),
            (0.0, 0),
        )

    def test_percent_agreement_single_disagreement(self):
        self.assertEqual(percent_agreement(["ai_like"], ["human_like"]), (0.0, 1))

    def test_percent_agreement_length_mismatch_raises(self):
        with self.assertRaises(ValueError):
            percent_agreement(["ai_like"], ["ai_like", "human_like"])
        with self.assertRaises(ValueError):
            percent_agreement(["ai_like", "human_like"], ["ai_like"])

    def test_percent_agreement_equal_long_sequences_do_not_raise(self):
        # Mutant `!=` -> `is not`: with 300-element sequences the two
        # lengths are distinct int objects outside CPython's small-int
        # cache, so `is not` is True and the mutant raises.
        a = ["ai_like"] * 300
        b = ["ai_like"] * 300
        self.assertEqual(percent_agreement(a, b), (1.0, 300))

    def test_percent_agreement_equality_is_value_not_identity(self):
        # Mutants `==` -> `is` / `is not`: the compared strings are
        # fresh objects produced by .strip().lower(), so identity and
        # equality differ.
        fraction, paired = percent_agreement(["AI_LIKE"], ["ai_like"])
        self.assertEqual((fraction, paired), (1.0, 1))
        fresh = "".join(["ai", "_like"])
        fraction2, paired2 = percent_agreement([fresh], ["ai_like"])
        self.assertEqual((fraction2, paired2), (1.0, 1))
        fraction3, paired3 = percent_agreement(["ai_like"], ["human_like"])
        self.assertEqual((fraction3, paired3), (0.0, 1))

    def test_percent_agreement_lexicographically_greater_is_not_agreement(self):
        # Mutant `==` -> `>=` on the normalized strings: "human_like"
        # is lexicographically greater than "ai_like", so the mutant
        # counts the first pair as agreement.
        fraction, paired = percent_agreement(
            ["human_like", "ai_like"],
            ["ai_like", "human_like"],
        )
        self.assertEqual((fraction, paired), (0.0, 2))

    # -- cohens_kappa -----------------------------------------------------

    def test_cohens_perfect_agreement(self):
        kappa, p_o, paired, confusion = cohens_kappa(
            ["ai_like", "human_like"], ["ai_like", "human_like"]
        )
        self.assertEqual(kappa, 1.0)
        self.assertEqual(p_o, 1.0)
        self.assertEqual(paired, 2)
        self.assertEqual(confusion, {"ai_like|ai_like": 1, "human_like|human_like": 1})

    def test_cohens_complete_disagreement(self):
        kappa, p_o, paired, _ = cohens_kappa(["ai_like", "human_like"], ["human_like", "ai_like"])
        self.assertEqual(kappa, -1.0)
        self.assertEqual(p_o, 0.0)
        self.assertEqual(paired, 2)

    def test_cohens_chance_level_agreement(self):
        # p_o = 0.5, p_e = 0.5 -> kappa exactly 0.
        kappa, p_o, paired, _ = cohens_kappa(
            ["ai_like", "ai_like", "human_like", "human_like"],
            ["ai_like", "human_like", "ai_like", "human_like"],
        )
        self.assertEqual(kappa, 0.0)
        self.assertEqual(p_o, 0.5)
        self.assertEqual(paired, 4)

    def test_cohens_asymmetric_marginals(self):
        # Categories present in only one rater's marginals: the set-union
        # mutant `|` -> `^` / `-` drops the shared categories and changes
        # p_e (and hence kappa); `|` -> `&` does not, and is baselined.
        kappa, p_o, paired, confusion = cohens_kappa(
            ["ai_like", "ai_like"], ["ai_like", "human_like"]
        )
        self.assertEqual(kappa, 0.0)
        self.assertEqual(p_o, 0.5)
        self.assertEqual(paired, 2)
        self.assertEqual(confusion, {"ai_like|ai_like": 1, "ai_like|human_like": 1})

    def test_cohens_degenerate_constant_raters(self):
        # p_e == 1.0: kappa is undefined, not 0/0.
        kappa, p_o, paired, confusion = cohens_kappa(["ai_like", "ai_like"], ["ai_like", "ai_like"])
        self.assertIsNone(kappa)
        self.assertEqual(p_o, 1.0)
        self.assertEqual(paired, 2)
        self.assertEqual(confusion, {"ai_like|ai_like": 2})

    def test_cohens_abstentions_excluded(self):
        kappa, p_o, paired, _ = cohens_kappa([None, "ai_like"], ["ai_like", "ai_like"])
        self.assertIsNone(kappa)
        self.assertEqual(p_o, 1.0)
        self.assertEqual(paired, 1)

    def test_cohens_three_items_exact(self):
        # p_o = 1/3, p_e = 5/9 -> kappa = -1/2.
        kappa, p_o, paired, _ = cohens_kappa(
            ["ai_like", "human_like", "ai_like"],
            ["ai_like", "ai_like", "human_like"],
        )
        self.assertAlmostEqual(kappa, -0.5, places=10)
        self.assertAlmostEqual(p_o, 1 / 3, places=10)
        self.assertEqual(paired, 3)

    def test_cohens_four_items_exact(self):
        # p_o = 3/4, p_e = 1/2 -> kappa = 1/2.
        kappa, p_o, paired, confusion = cohens_kappa(
            ["ai_like", "ai_like", "ai_like", "human_like"],
            ["ai_like", "ai_like", "human_like", "human_like"],
        )
        self.assertEqual(kappa, 0.5)
        self.assertEqual(p_o, 0.75)
        self.assertEqual(paired, 4)
        self.assertEqual(
            confusion,
            {
                "ai_like|ai_like": 2,
                "ai_like|human_like": 1,
                "human_like|human_like": 1,
            },
        )

    def test_cohens_all_abstain_returns_none(self):
        self.assertEqual(
            cohens_kappa([None, "abstain"], ["ai_like", "human_like"]),
            (None, 0.0, 0, {}),
        )

    def test_cohens_length_mismatch_raises(self):
        with self.assertRaises(ValueError):
            cohens_kappa(["ai_like"], ["ai_like", "human_like"])

    def test_cohens_length_mismatch_raises_when_first_is_longer(self):
        # Mutant `!=` -> `<` in the length check only raises when the
        # first sequence is shorter; a longer first sequence slips
        # through and the mutant computes kappa on truncated pairs.
        with self.assertRaises(ValueError):
            cohens_kappa(
                ["ai_like", "human_like", "ai_like"],
                ["ai_like", "human_like"],
            )

    def test_cohens_equal_long_sequences_do_not_raise(self):
        # Mutant `!=` -> `is not` (length check): 300-element sequences
        # have distinct length objects outside the small-int cache.
        a = ["ai_like"] * 300
        b = ["ai_like"] * 300
        kappa, p_o, paired, _ = cohens_kappa(a, b)
        self.assertIsNone(kappa)
        self.assertEqual(p_o, 1.0)
        self.assertEqual(paired, 300)

    def test_cohens_case_variants_are_equal_not_identical(self):
        # Mutants `==` -> `is` / `is not` on the normalized verdicts.
        kappa, _, paired, _ = cohens_kappa(["AI_LIKE", "human_like"], ["ai_like", "human_like"])
        self.assertEqual(kappa, 1.0)
        self.assertEqual(paired, 2)
        kappa2, _, paired2, _ = cohens_kappa(["ai_like", "human_like"], ["human_like", "ai_like"])
        self.assertEqual(kappa2, -1.0)
        self.assertEqual(paired2, 2)

    # -- fleiss_kappa -----------------------------------------------------

    def test_fleiss_empty_matrix(self):
        self.assertEqual(fleiss_kappa([]), (None, 0, 0, ["empty matrix"]))

    def test_fleiss_ragged_rows_raise_naming_expected_raters(self):
        # Mutants `[0]` -> `[1]` / `[-1]` change the expected count in
        # the message: row 0 has 2 raters, row 1 has 1.
        with self.assertRaisesRegex(ValueError, r"Row 1 has 1 raters, expected 2"):
            fleiss_kappa([["ai_like", "ai_like"], ["ai_like"]])

    def test_fleiss_ragged_longer_row_raises(self):
        # Mutant `!=` -> `<` in the row-length check only raises when a
        # row is shorter than expected; a longer row slips through and
        # the mutant computes kappa over the extra cells.
        with self.assertRaisesRegex(ValueError, r"Row 1 has 3 raters, expected 2"):
            fleiss_kappa([["ai_like", "ai_like"], ["ai_like", "ai_like", "human_like"]])

    def test_fleiss_single_usable_item_returns_none(self):
        # Mutant `len(usable) < 2` -> `< 1` proceeds with a single
        # usable item: disagreeing raters give kappa -1.0, agreeing
        # raters hit the degenerate-marginals branch; both differ from
        # the early return (None + "fewer than 2" warning).
        expected = (
            None,
            1,
            2,
            ["fewer than 2 usable items with >=2 non-abstaining raters"],
        )
        self.assertEqual(fleiss_kappa([["ai_like", "human_like"]]), expected)
        self.assertEqual(fleiss_kappa([["ai_like", "ai_like"]]), expected)

    def test_fleiss_perfect_agreement(self):
        kappa, n_items, n_raters, warnings = fleiss_kappa(
            [
                ["ai_like", "ai_like", "ai_like"],
                ["human_like", "human_like", "human_like"],
            ]
        )
        self.assertEqual(kappa, 1.0)
        self.assertEqual((n_items, n_raters), (2, 3))
        self.assertEqual(warnings, [])

    def test_fleiss_negative_third(self):
        # p_bar = 1/2, p_e = 5/8 -> kappa = -1/3.
        kappa, n_items, n_raters, _ = fleiss_kappa(
            [["ai_like", "ai_like"], ["ai_like", "human_like"]]
        )
        self.assertAlmostEqual(kappa, -1 / 3, places=10)
        self.assertEqual((n_items, n_raters), (2, 2))

    def test_fleiss_three_items_exact(self):
        # p_bar = 7/9, p_e = 41/81 -> kappa = 11/20.
        kappa, n_items, n_raters, _ = fleiss_kappa(
            [
                ["ai_like", "ai_like", "ai_like"],
                ["ai_like", "ai_like", "human_like"],
                ["human_like", "human_like", "human_like"],
            ]
        )
        self.assertAlmostEqual(kappa, 0.55, places=10)
        self.assertEqual((n_items, n_raters), (3, 3))

    def test_fleiss_abstain_cells_excluded(self):
        kappa, n_items, n_raters, _ = fleiss_kappa(
            [["ai_like", None, "ai_like"], ["human_like", "human_like", None]]
        )
        self.assertEqual(kappa, 1.0)
        self.assertEqual((n_items, n_raters), (2, 3))

    def test_fleiss_single_rater_items_excluded(self):
        kappa, n_items, n_raters, warnings = fleiss_kappa([["ai_like"], ["human_like"]])
        self.assertIsNone(kappa)
        self.assertEqual((n_items, n_raters), (0, 1))
        self.assertEqual(
            warnings,
            ["fewer than 2 usable items with >=2 non-abstaining raters"],
        )

    def test_fleiss_three_items_two_raters(self):
        # p_bar = 2/3, p_e = 1/2 -> kappa = 1/3. Mutant `n_i < 2` ->
        # `n_i < 3` skips every two-rater item and reports -5/3.
        kappa, n_items, n_raters, _ = fleiss_kappa(
            [
                ["ai_like", "ai_like"],
                ["human_like", "human_like"],
                ["ai_like", "human_like"],
            ]
        )
        self.assertAlmostEqual(kappa, 1 / 3, places=10)
        self.assertEqual((n_items, n_raters), (3, 2))

    def test_fleiss_degenerate_marginals(self):
        kappa, n_items, n_raters, warnings = fleiss_kappa(
            [
                ["ai_like", "ai_like", "ai_like"],
                ["ai_like", "ai_like", "ai_like"],
            ]
        )
        self.assertIsNone(kappa)
        self.assertEqual((n_items, n_raters), (2, 3))
        self.assertEqual(warnings, ["degenerate marginals: all raters constant"])

    def test_fleiss_four_raters(self):
        # p_bar = 1/3, p_e = 1/2 -> kappa = -1/3.
        kappa, n_items, n_raters, _ = fleiss_kappa(
            [
                ["ai_like", "human_like", "ai_like", "human_like"],
                ["ai_like", "ai_like", "human_like", "human_like"],
            ]
        )
        self.assertAlmostEqual(kappa, -1 / 3, places=10)
        self.assertEqual((n_items, n_raters), (2, 4))

    def test_fleiss_three_rater_items_counted(self):
        # All three items have exactly three raters; the middle item has
        # one abstaining rater, so exactly two raters vote on it. Mutants
        # that skip three-rater items (`n_i > 2`, `n_i >= 2`, `n_i != 2`)
        # change p_bar and the kappa.
        kappa, n_items, n_raters, _ = fleiss_kappa(
            [
                ["ai_like", "ai_like", "ai_like"],
                ["ai_like", "ai_like", None],
                ["human_like", "human_like", "human_like"],
            ]
        )
        self.assertEqual(kappa, 1.0)
        self.assertEqual((n_items, n_raters), (3, 3))

    def test_fleiss_long_rows_equal_lengths(self):
        # Mutant `len(row) != n_raters` -> `is not`: 300-column rows
        # have distinct length objects outside the small-int cache.
        kappa, n_items, n_raters, _ = fleiss_kappa([["ai_like"] * 300, ["ai_like"] * 300])
        self.assertIsNone(kappa)
        self.assertEqual((n_items, n_raters), (2, 300))

    # -- build_agreement_matrix -------------------------------------------

    def test_matrix_empty(self):
        matrix = build_agreement_matrix({})
        self.assertEqual(matrix.detectors, [])
        self.assertEqual(matrix.pairwise, [])
        self.assertIsNone(matrix.fleiss_kappa)
        self.assertEqual((matrix.fleiss_n_texts, matrix.fleiss_n_raters), (0, 0))
        self.assertEqual(matrix.warnings, ["no detectors provided"])

    def test_matrix_single_detector_warns_and_has_no_fleiss(self):
        matrix = build_agreement_matrix({"a": ["ai_like", "human_like"]})
        self.assertEqual(matrix.detectors, ["a"])
        self.assertEqual(matrix.pairwise, [])
        self.assertIsNone(matrix.fleiss_kappa)
        self.assertTrue(any("fewer than 2 detectors" in w for w in matrix.warnings))

    def test_matrix_two_detectors_exact(self):
        matrix = build_agreement_matrix(
            {"a": ["ai_like", "human_like"], "b": ["ai_like", "ai_like"]}
        )
        self.assertEqual(matrix.detectors, ["a", "b"])
        self.assertEqual(len(matrix.pairwise), 1)
        pair = matrix.pairwise[0]
        self.assertEqual((pair.detector_a, pair.detector_b), ("a", "b"))
        self.assertEqual(pair.paired_n, 2)
        self.assertEqual(pair.percent_agreement, 0.5)
        self.assertEqual(pair.cohens_kappa, 0.0)
        self.assertEqual(pair.kappa_interpretation, "slight")
        self.assertEqual(pair.confusion, {"ai_like|ai_like": 1, "human_like|ai_like": 1})
        self.assertAlmostEqual(matrix.fleiss_kappa, -1 / 3, places=10)
        self.assertEqual((matrix.fleiss_n_texts, matrix.fleiss_n_raters), (2, 2))
        self.assertEqual(matrix.warnings, [])

    def test_matrix_three_detectors_exact(self):
        # Pairwise kappas -1/2, 2/5, -4/5; Fleiss -7/20. The exact pair
        # list also kills the `detector_ids[i + 1:]` slice mutants, which
        # drop or duplicate pairs.
        matrix = build_agreement_matrix(
            {
                "a": ["ai_like", "human_like", "ai_like"],
                "b": ["ai_like", "ai_like", "human_like"],
                "c": ["human_like", "human_like", "ai_like"],
            }
        )
        self.assertEqual(matrix.detectors, ["a", "b", "c"])
        self.assertEqual(
            [(p.detector_a, p.detector_b) for p in matrix.pairwise],
            [("a", "b"), ("a", "c"), ("b", "c")],
        )
        self.assertAlmostEqual(matrix.pairwise[0].cohens_kappa, -0.5, places=10)
        self.assertAlmostEqual(matrix.pairwise[1].cohens_kappa, 0.4, places=10)
        self.assertAlmostEqual(matrix.pairwise[2].cohens_kappa, -0.8, places=10)
        self.assertEqual(matrix.pairwise[0].kappa_interpretation, "poor (less than chance)")
        self.assertEqual(matrix.pairwise[1].kappa_interpretation, "fair")
        self.assertEqual(matrix.pairwise[2].kappa_interpretation, "poor (less than chance)")
        self.assertAlmostEqual(matrix.fleiss_kappa, -0.35, places=10)
        self.assertEqual((matrix.fleiss_n_texts, matrix.fleiss_n_raters), (3, 3))

    def test_matrix_length_mismatch_raises(self):
        with self.assertRaisesRegex(ValueError, r"Detector 'b' has 1 verdicts, expected 2"):
            build_agreement_matrix({"a": ["ai_like", "human_like"], "b": ["ai_like"]})

    def test_matrix_length_mismatch_raises_when_later_detector_is_longer(self):
        # Mutant `!=` -> `<` in the length check only raises when the
        # detector is shorter; a longer later detector slips through
        # and the mutant raises cohens_kappa's generic message instead
        # of the per-detector one.
        with self.assertRaisesRegex(ValueError, r"Detector 'b' has 3 verdicts, expected 2"):
            build_agreement_matrix(
                {
                    "a": ["ai_like", "human_like"],
                    "b": ["ai_like", "human_like", "ai_like"],
                }
            )

    def test_matrix_equal_long_sequences_do_not_raise(self):
        matrix = build_agreement_matrix({"a": ["ai_like"] * 300, "b": ["ai_like"] * 300})
        self.assertEqual(matrix.detectors, ["a", "b"])
        self.assertEqual(len(matrix.pairwise), 1)

    def test_matrix_abstentions_excluded_from_pairwise(self):
        matrix = build_agreement_matrix(
            {
                "a": ["ai_like", None, "human_like"],
                "b": ["ai_like", "ai_like", "human_like"],
            }
        )
        pair = matrix.pairwise[0]
        self.assertEqual(pair.paired_n, 2)
        self.assertEqual(pair.percent_agreement, 1.0)
        self.assertEqual(pair.cohens_kappa, 1.0)

    def test_matrix_to_dict_round_trip(self):
        matrix = build_agreement_matrix(
            {"a": ["ai_like", "human_like"], "b": ["ai_like", "ai_like"]}
        )
        data = matrix.to_dict()
        self.assertEqual(data["detectors"], ["a", "b"])
        self.assertEqual(len(data["pairwise"]), 1)
        self.assertEqual(data["pairwise"][0]["detector_a"], "a")
        self.assertAlmostEqual(data["fleiss_kappa"], -1 / 3, places=10)
        self.assertEqual(data["fleiss_n_texts"], 2)
        self.assertEqual(data["fleiss_n_raters"], 2)

    # -- AgreementMatrix.summary ------------------------------------------

    def _summary_with_mean(self, kappas):
        pairwise = [
            PairwiseAgreement(
                detector_a="a",
                detector_b="b",
                paired_n=2,
                percent_agreement=1.0,
                cohens_kappa=k,
                kappa_interpretation="x",
                confusion={},
            )
            for k in kappas
        ]
        return AgreementMatrix(
            detectors=["a", "b"],
            pairwise=pairwise,
            fleiss_kappa=0.0,
            fleiss_n_texts=2,
            fleiss_n_raters=2,
        ).summary()

    def test_summary_independence_hint_boundaries(self):
        cases = [
            ([0.8, 0.8], "highly_correlated"),
            ([0.9, 0.9], "highly_correlated"),
            ([0.7999, 0.7999], "substantially_correlated"),
            ([0.6, 0.6], "substantially_correlated"),
            ([0.7, 0.7], "substantially_correlated"),
            ([0.5999, 0.5999], "moderate_agreement"),
            ([0.4, 0.4], "moderate_agreement"),
            ([0.5, 0.5], "moderate_agreement"),
            ([0.3999, 0.3999], "weakly_correlated"),
            ([0.0, 0.0], "weakly_correlated"),
            ([-0.5, -0.5], "weakly_correlated"),
        ]
        for kappas, expected in cases:
            with self.subTest(kappas=kappas):
                summary = self._summary_with_mean(kappas)
                self.assertEqual(summary["independence_hint"], expected)
                self.assertAlmostEqual(summary["mean_pairwise_kappa"], sum(kappas) / len(kappas))

    def test_summary_empty_pairwise_is_undetermined(self):
        summary = self._summary_with_mean([])
        self.assertIsNone(summary["mean_pairwise_kappa"])
        self.assertEqual(summary["independence_hint"], "undetermined")
        self.assertEqual(summary["n_pairwise_comparisons"], 0)

    def test_summary_ignores_none_kappas(self):
        # Mutant `is not None` -> `is None` keeps only the None kappa
        # and crashes summing it.
        summary = self._summary_with_mean([None, 0.8])
        self.assertAlmostEqual(summary["mean_pairwise_kappa"], 0.8)
        self.assertEqual(summary["independence_hint"], "highly_correlated")

    def test_summary_all_none_kappas_is_undetermined(self):
        summary = self._summary_with_mean([None, None])
        self.assertIsNone(summary["mean_pairwise_kappa"])
        self.assertEqual(summary["independence_hint"], "undetermined")

    # -- dataclasses: slots / frozen / decorators -------------------------

    def test_family_vote_slots_reject_arbitrary_attributes(self):
        # Mutant `@dataclass(slots=True)` -> `slots=False` lets arbitrary
        # attributes be set; slotted instances raise AttributeError.
        vote = FamilyVote(
            family="f",
            detector_count=1,
            verdict="ai_like",
            calibrated_ai_probability=None,
        )
        with self.assertRaises(AttributeError):
            vote.unexpected_attribute = 1

    def test_consensus_result_slots_reject_arbitrary_attributes(self):
        # Mutant `@dataclass(slots=True)` -> `slots=False` on
        # ConsensusResult lets arbitrary attributes be set; the
        # FamilyVote test above covers a different decorator.
        result = ConsensusResult(
            verdict="ai_like",
            family_agreement=1.0,
            independent_families=1,
            voting_families=1,
            calibrated_ai_probability=None,
            ensemble_calibration_id=None,
            family_votes=[],
        )
        with self.assertRaises(AttributeError):
            result.unexpected_attribute = 1

    def test_pairwise_agreement_is_frozen_and_slotted(self):
        pair = PairwiseAgreement(
            detector_a="a",
            detector_b="b",
            paired_n=2,
            percent_agreement=1.0,
            cohens_kappa=1.0,
            kappa_interpretation="almost perfect",
            confusion={},
        )
        with self.assertRaises(AttributeError):
            pair.cohens_kappa = 0.0
        # Slotted instances have no __dict__: setting an unknown attribute
        # raises (TypeError on this CPython, from the frozen __setattr__
        # delegation; AttributeError on others). With slots=False the
        # assignment would silently succeed.
        with self.assertRaises((AttributeError, TypeError)):
            pair.unexpected_attribute = 1
        self.assertEqual(pair.to_dict()["kappa_interpretation"], "almost perfect")

    def test_pairwise_agreement_has_no_instance_dict(self):
        # Mutant `@dataclass(slots=True)` -> `slots=False` on
        # PairwiseAgreement is invisible to the frozen/attribute tests
        # above: frozen blocks every assignment either way. The slots
        # contract is still observable — slotted instances have no
        # __dict__.
        pair = PairwiseAgreement(
            detector_a="a",
            detector_b="b",
            paired_n=2,
            percent_agreement=1.0,
            cohens_kappa=1.0,
            kappa_interpretation="almost perfect",
            confusion={},
        )
        self.assertFalse(hasattr(pair, "__dict__"))

    def test_agreement_matrix_instantiates_and_serializes(self):
        matrix = AgreementMatrix(
            detectors=["a"],
            pairwise=[],
            fleiss_kappa=None,
            fleiss_n_texts=0,
            fleiss_n_raters=1,
        )
        self.assertEqual(matrix.to_dict()["detectors"], ["a"])
        self.assertEqual(matrix.summary()["independence_hint"], "undetermined")


if __name__ == "__main__":
    unittest.main()
