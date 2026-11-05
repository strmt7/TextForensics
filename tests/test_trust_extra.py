"""Additional tests for trust.py overall-state logic.

The v2 ``_overall_state`` contract is:

* ``out_of_scope`` on ``language`` or ``text_length`` -> ``insufficient``
* all dimensions ``supported`` -> ``strong``
* ``supported == 0`` and ``partial == 0`` -> ``insufficient``
* ``supported == 0`` and ``unknown >= 4`` -> ``insufficient``
* otherwise -> ``mixed``

These tests exercise that contract directly with hand-built dimension lists,
so they do not depend on the registry-backed ``build_trust_map`` path.
"""

from __future__ import annotations

import unittest

from textforensics.detectors import DetectorPrediction
from textforensics.trust import (
    TrustDimension,
    TrustMap,
    _overall_state,
    build_trust_map,
)


def prediction(
    detector_id: str = "detector",
    family: str = "family",
    verdict: str = "ai_like",
    score: float = 0.8,
    min_words: int | None = None,
) -> DetectorPrediction:
    """Create a DetectorPrediction for testing."""
    return DetectorPrediction(
        schema="textforensics.detector-result/v2",
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


def _dim(name: str, state: str) -> TrustDimension:
    return TrustDimension(dimension=name, state=state, reason=f"{name}:{state}")


class TrustMapOverallStateLogicTests(unittest.TestCase):
    """Tests for the overall state logic in trust._overall_state."""

    def test_out_of_scope_on_language_is_insufficient(self):
        dims = [
            _dim("language", "out_of_scope"),
            _dim("text_length", "supported"),
        ]
        self.assertEqual(_overall_state(dims), "insufficient")

    def test_out_of_scope_on_text_length_is_insufficient(self):
        dims = [
            _dim("language", "supported"),
            _dim("text_length", "out_of_scope"),
        ]
        self.assertEqual(_overall_state(dims), "insufficient")

    def test_out_of_scope_on_other_dimension_is_not_insufficient(self):
        # Under v2 only language/text_length out_of_scope forces insufficient.
        dims = [
            _dim("language", "supported"),
            _dim("text_length", "supported"),
            _dim("domain_genre", "out_of_scope"),
        ]
        self.assertEqual(_overall_state(dims), "mixed")

    def test_all_supported_is_strong(self):
        dims = [
            _dim("language", "supported"),
            _dim("text_length", "supported"),
            _dim("domain_genre", "supported"),
            _dim("editing_revision", "supported"),
            _dim("generator_scope", "supported"),
            _dim("human_population", "supported"),
            _dim("human_false_positive_evidence", "supported"),
            _dim("temporal_version_stability", "supported"),
            _dim("detector_diversity", "supported"),
            _dim("benign_stability", "supported"),
        ]
        self.assertEqual(_overall_state(dims), "strong")

    def test_no_supported_no_partial_is_insufficient(self):
        dims = [
            _dim("language", "unknown"),
            _dim("text_length", "unknown"),
            _dim("domain_genre", "unknown"),
        ]
        self.assertEqual(_overall_state(dims), "insufficient")

    def test_four_unknowns_with_no_supported_is_insufficient(self):
        # Rule: supported==0 and unknown>=4 -> insufficient
        dims = [
            _dim("language", "unknown"),
            _dim("text_length", "unknown"),
            _dim("domain_genre", "unknown"),
            _dim("editing_revision", "unknown"),
        ]
        self.assertEqual(_overall_state(dims), "insufficient")

    def test_partial_yields_mixed(self):
        dims = [
            _dim("language", "supported"),
            _dim("text_length", "supported"),
            _dim("domain_genre", "partial"),
        ]
        self.assertEqual(_overall_state(dims), "mixed")

    def test_single_unknown_yields_mixed(self):
        dims = [
            _dim("language", "supported"),
            _dim("text_length", "supported"),
            _dim("domain_genre", "unknown"),
        ]
        self.assertEqual(_overall_state(dims), "mixed")

    def test_three_unknowns_with_supported_yields_mixed(self):
        dims = [
            _dim("language", "supported"),
            _dim("text_length", "supported"),
            _dim("domain_genre", "unknown"),
            _dim("editing_revision", "unknown"),
            _dim("generator_scope", "unknown"),
        ]
        self.assertEqual(_overall_state(dims), "mixed")

    def test_trust_map_overall_matches_recomputed(self):
        dims = [
            _dim("language", "supported"),
            _dim("text_length", "supported"),
            _dim("domain_genre", "partial"),
        ]
        tm = TrustMap(
            schema="textforensics.trust-map/v2",
            overall=_overall_state(dims),
            dimensions=dims,
        )
        self.assertEqual(tm.overall, "mixed")


class TrustMapDimensionTests(unittest.TestCase):
    """Tests for individual trust dimensions."""

    def test_language_dimension_defaults_to_unknown(self):
        """Test that language dimension defaults to unknown in alpha."""
        tm = build_trust_map(
            [prediction("a")],
            word_count=200,
            robustness=[],
        )
        lang_dim = next(d for d in tm.dimensions if d.dimension == "language")
        self.assertEqual(lang_dim.state, "unknown")

    def test_diversity_dimension_supported_with_multiple_families(self):
        """Test diversity dimension with multiple detector families."""
        tm = build_trust_map(
            [prediction("a", "fam1"), prediction("b", "fam2")],
            word_count=200,
            robustness=[],
            failure_count=0,
        )
        div_dim = next(d for d in tm.dimensions if d.dimension == "detector_diversity")
        self.assertEqual(div_dim.state, "supported")

    def test_diversity_dimension_unknown_with_no_predictions(self):
        """Test diversity dimension with no predictions."""
        tm = build_trust_map([], word_count=200, robustness=[], failure_count=0)
        div_dim = next(d for d in tm.dimensions if d.dimension == "detector_diversity")
        self.assertEqual(div_dim.state, "unknown")

    def test_stability_dimension_unknown_without_robustness(self):
        """Test stability dimension without robustness evidence."""
        tm = build_trust_map([prediction("a")], word_count=200, robustness=[])
        stab_dim = next(d for d in tm.dimensions if d.dimension == "benign_stability")
        self.assertEqual(stab_dim.state, "unknown")

    def test_stability_dimension_supported_with_perfect_stability(self):
        """Test stability dimension with perfect verdict stability."""
        robustness = [
            {
                "detector_id": "a",
                "verdict_stability": 1.0,
                "native_score_range": 0.0,
            }
        ]
        tm = build_trust_map([prediction("a")], word_count=200, robustness=robustness)
        stab_dim = next(d for d in tm.dimensions if d.dimension == "benign_stability")
        self.assertEqual(stab_dim.state, "supported")

    def test_stability_dimension_partial_with_imperfect_stability(self):
        """Test stability dimension with imperfect verdict stability."""
        robustness = [
            {
                "detector_id": "a",
                "verdict_stability": 0.75,
                "native_score_range": 0.2,
            }
        ]
        tm = build_trust_map([prediction("a")], word_count=200, robustness=robustness)
        stab_dim = next(d for d in tm.dimensions if d.dimension == "benign_stability")
        self.assertEqual(stab_dim.state, "partial")


class TrustMapSerializationTests(unittest.TestCase):
    """Tests for TrustMap serialization."""

    def test_trust_map_to_dict(self):
        """Test TrustMap.to_dict() method."""
        tm = TrustMap(
            schema="textforensics.trust-map/v2",
            overall="mixed",
            dimensions=[TrustDimension(dimension="text_length", state="supported", reason="ok")],
        )
        data = tm.to_dict()

        self.assertEqual(data["schema"], "textforensics.trust-map/v2")
        self.assertEqual(data["overall"], "mixed")
        self.assertTrue(len(data["dimensions"]) > 0)

    def test_trust_dimension_to_dict(self):
        """Test TrustDimension.to_dict() method."""
        dim = TrustDimension(
            dimension="text_length",
            state="supported",
            reason="Text meets minimum word count",
            evidence_refs=["benchmark/v1"],
            observed={"word_count": 100},
            limitations=["Minimum is capability metadata"],
        )
        data = dim.to_dict()

        self.assertEqual(data["dimension"], "text_length")
        self.assertEqual(data["state"], "supported")
        self.assertEqual(data["reason"], "Text meets minimum word count")
        self.assertEqual(data["evidence_refs"], ["benchmark/v1"])
        self.assertEqual(data["observed"], {"word_count": 100})


if __name__ == "__main__":
    unittest.main()
