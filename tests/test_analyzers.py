from __future__ import annotations

import math
import unittest

from textforensics.analyzers import (
    _clamp,
    _high_when_high,
    _high_when_low,
    analyze_formulaic_language,
    analyze_lexical_profile,
    analyze_uniformity,
    run_builtin_analyzers,
)
from textforensics.models import AnalyzerResult, Evidence


def _features(**overrides):
    base = {
        "word_count": 200,
        "sentence_count": 10,
        "sentence_length_cv": 0.4,
        "paragraph_length_cv": 0.4,
        "repeated_sentence_start_ratio": 0.1,
        "transition_density": 0.5,
        "cliche_density": 0.1,
        "repeated_trigram_ratio": 0.02,
        "type_token_ratio": 0.5,
        "hapax_ratio": 0.6,
        "punctuation_variety": 4.0,
    }
    base.update(overrides)
    return base


class HelperTests(unittest.TestCase):
    def test_clamp_bounds(self):
        self.assertEqual(_clamp(1.5), 1.0)
        self.assertEqual(_clamp(-0.2), 0.0)
        self.assertEqual(_clamp(0.5), 0.5)

    def test_high_when_low_is_monotonic(self):
        self.assertEqual(_high_when_low(0.0, 0.2, 0.6), 1.0)
        self.assertEqual(_high_when_low(1.0, 0.2, 0.6), 0.0)
        self.assertAlmostEqual(_high_when_low(0.4, 0.2, 0.6), 0.5)

    def test_high_when_high_is_monotonic(self):
        self.assertEqual(_high_when_high(0.0, 0.2, 0.6), 0.0)
        self.assertEqual(_high_when_high(1.0, 0.2, 0.6), 1.0)
        self.assertAlmostEqual(_high_when_high(0.4, 0.2, 0.6), 0.5)

    def test_clamp_rejects_non_finite(self):
        with self.assertRaises(ValueError):
            _clamp(math.inf)


class AnalyzerContractTests(unittest.TestCase):
    def test_uniformity_score_is_bounded(self):
        result = analyze_uniformity(_features())
        self.assertIsInstance(result, AnalyzerResult)
        self.assertTrue(0.0 <= result.score <= 1.0)
        self.assertTrue(0.0 <= result.reliability <= 1.0)
        self.assertEqual(len(result.evidence), 3)
        self.assertTrue(all(isinstance(e, Evidence) for e in result.evidence))

    def test_formulaic_language_detects_stock_phrasing(self):
        result = analyze_formulaic_language(
            _features(transition_density=2.0, cliche_density=2.0, repeated_trigram_ratio=0.5)
        )
        self.assertGreater(result.score, 0.9)

    def test_lexical_profile_is_conservative(self):
        result = analyze_lexical_profile(_features())
        self.assertTrue(0.0 <= result.score <= 1.0)
        self.assertLessEqual(result.reliability, 0.75)

    def test_analyzers_share_feature_inputs(self):
        results = run_builtin_analyzers(_features())
        self.assertEqual(len(results), 3)
        names = {r.name for r in results}
        self.assertEqual(
            names,
            {"structural_uniformity", "formulaic_language", "lexical_profile"},
        )

    def test_uniformity_reliability_scales_with_sentence_count(self):
        low = analyze_uniformity(_features(sentence_count=2))
        high = analyze_uniformity(_features(sentence_count=60))
        self.assertLessEqual(low.reliability, high.reliability)

    def test_uniformity_uses_three_weighted_components(self):
        result = analyze_uniformity(_features())
        # Weights sum to 1.0; each contribution is bounded by its weight.
        total = sum(item.contribution for item in result.evidence)
        self.assertAlmostEqual(total, result.score, places=6)


if __name__ == "__main__":
    unittest.main()
