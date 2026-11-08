from __future__ import annotations

import math
import unittest

from textforensics.analyzers import (
    _clamp,
    _high_when_high,
    _high_when_low,
    _require_finite,
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

    def test_require_finite_rejects_boolean(self):
        # Line 20: _require_finite rejects bool (which is a subclass of int)
        from textforensics.analyzers import _NonFiniteValueError

        with self.assertRaises(_NonFiniteValueError):
            _require_finite(True)
        with self.assertRaises(_NonFiniteValueError):
            _require_finite(False)


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


class AnalyzersMutationKillTests(unittest.TestCase):
    """Kill tests for the Phase 5 full mutation session on textforensics.analyzers.

    Session (2026-11-08, ``scripts/run_mutation.py --mode full --modules
    textforensics.analyzers --budget 0``): 516 work items, 354 killed,
    162 survived, 0 timeout / 0 error / 0 incompetent / 0 pending.
    Of the 162 survivors, 158 are killed by the four tests below and 4 are
    genuinely equivalent (no existing baseline kind fits them; see the
    no-kind list in the wave report):

    - ``LtE_Lt`` occ 0 (L32) and occ 1 (L41), ``GtE_Gt`` occ 0 (L34) and
      occ 1 (L43): at ``value == low`` / ``value == high`` the fall-through
      interpolation gives exactly the branch value (``0.0 / (high - low)``
      is exactly ``0.0``; ``(high - low) / (high - low)`` is exactly
      ``1.0``) for every ``low < high``, which holds at all call sites,
      so the boundary branches are redundant. No test can distinguish
      them; the boundary values are pinned by the interpolator test
      only as documentation of the original behaviour.

    Each golden test pins exact scores, reliabilities and evidence
    contributions at a point where every component is strictly interior
    (0 < component < 1), so every weight, threshold, divisor and
    operator mutant in its analyzer changes at least one pinned value.
    Expected values are literals computed from the unmutated module, not
    recomputed from its helpers, so a mutant cannot move both sides.
    """

    def test_interpolator_values_off_midpoint(self):
        # [15] Sub_Mul and [16] Sub_Mod at L36 coincide with the original
        # at the midpoint (0.5) but not off it: _high_when_low(0.3, ...)
        # is 0.75 originally, 0.25 under either mutant.
        self.assertAlmostEqual(_high_when_low(0.3, 0.2, 0.6), 0.75)
        self.assertAlmostEqual(_high_when_high(0.3, 0.2, 0.6), 0.25)

    def test_uniformity_golden_values(self):
        # Kills [82]/[85]/[88]/[91]/[96] (Div_* on the /12.0 reliability),
        # [101]-[112] (all four NumberReplacer threshold mutants of each
        # of the three interpolator calls) and [113]/[114] (12.0 -> 13.0
        # / 11.0). Score/evidence mutants on L52/L57/L63/L69 were already
        # killed by test_uniformity_uses_three_weighted_components.
        result = analyze_uniformity(
            _features(sentence_count=6, repeated_sentence_start_ratio=0.175)
        )
        self.assertAlmostEqual(result.score, 0.5786159039759939)
        self.assertAlmostEqual(result.reliability, 0.5)
        self.assertAlmostEqual(result.evidence[0].contribution, 0.3023255813953488)
        self.assertAlmostEqual(result.evidence[1].contribution, 0.16129032258064518)
        self.assertAlmostEqual(result.evidence[2].contribution, 0.11499999999999999)

    def test_formulaic_language_golden_values(self):
        # Kills [4]/[5]/[8] (Add_Div/Add_FloorDiv on the score),
        # [17]-[19] (Mul_Add on the score), [20]-[22] (Mul_Add on the
        # evidence), [29]-[31] (Mul_Sub on the evidence), [39]/[40]
        # (Mul_Div on the score), [41]/[42] (Mul_Div on the evidence),
        # [49]/[50] (Mul_FloorDiv on the evidence), [58]/[59] (Mul_Mod
        # on the score), [60]/[61] (Mul_Mod on the evidence),
        # [69]-[74] (Mul_Pow on the score and evidence), [83]/[86]/
        # [89]/[92]/[94] (Div_* on the /180.0 reliability), [115]-[123]
        # (all NumberReplacer threshold mutants), [124]-[126] (score
        # weights), [127]/[128] (180.0 -> 181.0 / 179.0) and [129]-[134]
        # (evidence weights).
        result = analyze_formulaic_language(
            _features(
                transition_density=1.125,
                cliche_density=0.65,
                repeated_trigram_ratio=0.055,
                word_count=90,
            )
        )
        self.assertAlmostEqual(result.score, 0.5)
        self.assertAlmostEqual(result.reliability, 0.5)
        self.assertAlmostEqual(result.evidence[0].contribution, 0.175)
        self.assertAlmostEqual(result.evidence[1].contribution, 0.20000000000000007)
        self.assertAlmostEqual(result.evidence[2].contribution, 0.12499999999999999)

    def test_lexical_profile_golden_values(self):
        # Kills [0]-[3]/[6]/[7]/[9]-[14] (Add_* on the score),
        # [23]-[28] (Mul_Add on the score and evidence), [32]-[38]
        # (Mul_Sub on the score, evidence and the *0.75 reliability),
        # [43]-[48] (Mul_Div), [51]-[57] (Mul_FloorDiv), [62]-[68]
        # (Mul_Mod), [75]-[81] (Mul_Pow), [84]/[87]/[90]/[93]/[95]
        # (Div_* on the /300.0 reliability), [135]-[146] (all
        # NumberReplacer threshold mutants), [147]-[152] (score
        # weights), [153]/[154] (300.0 -> 301.0 / 299.0), [155]
        # (0.75 -> -0.25) and [156]-[161] (evidence weights).
        result = analyze_lexical_profile(
            _features(
                type_token_ratio=0.46,
                hapax_ratio=0.57,
                punctuation_variety=4.0,
                word_count=150,
            )
        )
        self.assertAlmostEqual(result.score, 0.5)
        self.assertAlmostEqual(result.reliability, 0.375)
        self.assertAlmostEqual(result.evidence[0].contribution, 0.19999999999999996)
        self.assertAlmostEqual(result.evidence[1].contribution, 0.15000000000000002)
        self.assertAlmostEqual(result.evidence[2].contribution, 0.15)


if __name__ == "__main__":
    unittest.main()
