from __future__ import annotations

import unittest

from textforensics.detectors import DetectorPrediction
from textforensics.trust import (
    TRUST_STATES,
    TrustDimension,
    TrustMap,
    build_trust_map,
)


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


class TrustMapContractTests(unittest.TestCase):
    def test_states_are_the_declared_qualitative_set(self):
        self.assertEqual(
            TRUST_STATES,
            {"supported", "partial", "unknown", "out_of_scope"},
        )

    def test_dimension_and_map_serialize(self):
        dim = TrustDimension(
            dimension="text_length",
            state="supported",
            reason="ok",
            observed={"word_count": 100},
        )
        self.assertEqual(dim.to_dict()["dimension"], "text_length")
        tm = TrustMap(
            schema="textforensics.trust-map/v1",
            overall="mixed",
            dimensions=[dim],
        )
        self.assertEqual(tm.to_dict()["overall"], "mixed")

    def test_length_supported_when_above_minimum(self):
        tm = build_trust_map(
            [prediction(min_words=80)],
            word_count=200,
            robustness=[],
        )
        dim = next(d for d in tm.dimensions if d.dimension == "text_length")
        self.assertEqual(dim.state, "supported")

    def test_length_partial_when_some_detectors_unsupported(self):
        tm = build_trust_map(
            [prediction("a", min_words=80), prediction("b", "fam2", min_words=400)],
            word_count=200,
            robustness=[],
        )
        dim = next(d for d in tm.dimensions if d.dimension == "text_length")
        self.assertEqual(dim.state, "partial")

    def test_length_out_of_scope_when_below_all_minima(self):
        tm = build_trust_map(
            [prediction("a", min_words=80), prediction("b", "fam2", min_words=400)],
            word_count=40,
            robustness=[],
        )
        dim = next(d for d in tm.dimensions if d.dimension == "text_length")
        self.assertEqual(dim.state, "out_of_scope")

    def test_length_unknown_when_no_minimum_declared(self):
        tm = build_trust_map(
            [prediction("a")],
            word_count=200,
            robustness=[],
        )
        dim = next(d for d in tm.dimensions if d.dimension == "text_length")
        self.assertEqual(dim.state, "unknown")

    def test_diversity_supported_with_two_families_and_no_failures(self):
        tm = build_trust_map(
            [prediction("a", "fam1"), prediction("b", "fam2")],
            word_count=200,
            robustness=[],
            failure_count=0,
        )
        dim = next(d for d in tm.dimensions if d.dimension == "detector_diversity")
        self.assertEqual(dim.state, "supported")

    def test_diversity_partial_with_one_family(self):
        tm = build_trust_map(
            [prediction("a", "fam1")],
            word_count=200,
            robustness=[],
        )
        dim = next(d for d in tm.dimensions if d.dimension == "detector_diversity")
        self.assertEqual(dim.state, "partial")

    def test_diversity_partial_when_detectors_failed(self):
        tm = build_trust_map(
            [prediction("a", "fam1"), prediction("b", "fam2")],
            word_count=200,
            robustness=[],
            failure_count=1,
        )
        dim = next(d for d in tm.dimensions if d.dimension == "detector_diversity")
        self.assertEqual(dim.state, "partial")

    def test_diversity_unknown_with_no_observations(self):
        tm = build_trust_map(
            [],
            word_count=200,
            robustness=[],
        )
        dim = next(d for d in tm.dimensions if d.dimension == "detector_diversity")
        self.assertEqual(dim.state, "unknown")

    def test_stability_supported_when_all_verdicts_hold(self):
        robustness = [
            {
                "detector_id": "a",
                "verdict_stability": 1.0,
                "native_score_range": 0.05,
            }
        ]
        tm = build_trust_map([prediction("a")], word_count=200, robustness=robustness)
        dim = next(d for d in tm.dimensions if d.dimension == "benign_stability")
        self.assertEqual(dim.state, "supported")

    def test_stability_partial_when_verdict_flips(self):
        robustness = [
            {
                "detector_id": "a",
                "verdict_stability": 0.75,
                "native_score_range": 0.2,
            }
        ]
        tm = build_trust_map([prediction("a")], word_count=200, robustness=robustness)
        dim = next(d for d in tm.dimensions if d.dimension == "benign_stability")
        self.assertEqual(dim.state, "partial")

    def test_stability_unknown_without_probes(self):
        tm = build_trust_map([prediction("a")], word_count=200, robustness=[])
        dim = next(d for d in tm.dimensions if d.dimension == "benign_stability")
        self.assertEqual(dim.state, "unknown")

    def test_overall_is_insufficient_when_many_dimensions_unknown(self):
        tm = build_trust_map(
            [prediction("a")],
            word_count=200,
            robustness=[],
        )
        self.assertEqual(tm.overall, "insufficient")

    def test_overall_is_mixed_with_some_unknown(self):
        # The current alpha has five static dimensions that are always
        # unknown (language, domain_genre, editing_revision,
        # human_false_positive_evidence, temporal_version_stability), so
        # "mixed" is unreachable today; this test documents that the
        # rule that drives overall is the unknown/out_of_scope count.
        robustness = [
            {
                "detector_id": "a",
                "verdict_stability": 1.0,
                "native_score_range": 0.0,
            }
        ]
        tm = build_trust_map(
            [prediction("a", "fam1"), prediction("b", "fam2")],
            word_count=200,
            robustness=robustness,
        )
        self.assertEqual(tm.overall, "insufficient")
        unknown = sum(d.state == "unknown" for d in tm.dimensions)
        self.assertGreaterEqual(unknown, 3)

    def test_overall_is_strong_only_when_no_unknown_and_no_partial(self):
        # Force every dimension to a supported state by supplying enough
        # evidence: two families, supported length, stable probes. The
        # static language/domain/human-FPR/temporal dimensions remain
        # unknown in the current alpha, so "strong" is unreachable today;
        # this test documents that invariant.
        robustness = [
            {
                "detector_id": "a",
                "verdict_stability": 1.0,
                "native_score_range": 0.0,
            },
            {
                "detector_id": "b",
                "verdict_stability": 1.0,
                "native_score_range": 0.0,
            },
        ]
        tm = build_trust_map(
            [prediction("a", "fam1", min_words=80), prediction("b", "fam2", min_words=80)],
            word_count=200,
            robustness=robustness,
        )
        self.assertEqual(tm.overall, "insufficient")

    def test_trust_map_is_not_an_authorship_probability(self):
        tm = build_trust_map([prediction("a")], word_count=200, robustness=[])
        self.assertTrue(
            any("not probability of authorship" in limitation.lower() for limitation in tm.limitations)
        )


if __name__ == "__main__":
    unittest.main()
