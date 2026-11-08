from __future__ import annotations

import unittest
from contextlib import ExitStack
from unittest import mock

import textforensics.engine as engine
from textforensics.engine import (
    AnalysisResult,
    ComparisonResult,
    _analyze_text_internal,
    _disagreement,
    _verdict,
    _weighted_score,
    analyze_text,
    compare_texts,
)
from textforensics.features import benign_variants
from textforensics.models import AnalyzerResult


def _sample(score: float) -> AnalyzerResult:
    return AnalyzerResult(name="x", score=score, reliability=0.5)


class EngineContractTests(unittest.TestCase):
    def test_weighted_score_is_weighted_average(self):
        self.assertAlmostEqual(_weighted_score([_sample(0.2), _sample(0.8)]), 0.5)

    def test_weighted_score_respects_reliability(self):
        high = AnalyzerResult(name="a", score=1.0, reliability=0.9)
        low = AnalyzerResult(name="b", score=0.0, reliability=0.1)
        result = _weighted_score([high, low])
        self.assertGreater(result, 0.5)

    def test_disagreement_is_bounded(self):
        self.assertEqual(_disagreement([]), 0.0)
        self.assertEqual(_disagreement([_sample(0.5)]), 0.0)
        self.assertGreater(_disagreement([_sample(0.0), _sample(1.0)]), 0.0)
        self.assertLessEqual(_disagreement([_sample(0.0), _sample(1.0)]), 1.0)

    def test_verdict_abstains_on_low_reliability(self):
        self.assertEqual(_verdict(0.9, 0.1), "insufficient_evidence")
        self.assertEqual(_verdict(0.1, 0.1), "insufficient_evidence")

    def test_verdict_thresholds_are_explicit(self):
        self.assertEqual(_verdict(0.9, 0.9), "machine_like_patterns")
        self.assertEqual(_verdict(0.1, 0.9), "human_like_patterns")
        self.assertEqual(_verdict(0.5, 0.9), "indeterminate")

    def test_verdict_rejects_non_finite_score(self):
        with self.assertRaises((ValueError, OverflowError)):
            _verdict(float("nan"), 0.9)


class RobustnessTests(unittest.TestCase):
    def test_benign_variants_include_original(self):
        text = "Hello world.\n\nSecond sentence."
        variants = benign_variants(text)
        self.assertEqual(variants["original"], text)
        self.assertEqual(len(variants), 4)

    def test_benign_variants_collapse_whitespace(self):
        variants = benign_variants("a   b\n\n\n\nc")
        self.assertNotIn("a   b", variants["normalized_whitespace"])
        self.assertIn("a b", variants["normalized_whitespace"])

    def test_benign_variants_normalize_smart_punctuation(self):
        variants = benign_variants("He said \u201cyes\u201d and \u2014left.")
        self.assertNotIn("\u201c", variants["normalized_punctuation"])
        self.assertNotIn("\u2014", variants["normalized_punctuation"])

    def test_benign_variants_strip_markdown_lists(self):
        variants = benign_variants("- one\n- two\n* three")
        self.assertNotIn("- one", variants["plain_list_formatting"])


class CompareTests(unittest.TestCase):
    def test_similarity_is_between_zero_and_one(self):
        result = compare_texts("alpha beta", "alpha gamma")
        self.assertIsInstance(result, ComparisonResult)
        self.assertTrue(0.0 <= result.similarity <= 1.0)

    def test_identical_texts_have_high_similarity(self):
        text = "the quick brown fox jumps over the lazy dog"
        result = compare_texts(text, text)
        self.assertGreater(result.similarity, 0.99)
        self.assertEqual(result.score_delta, 0.0)

    def test_added_and_removed_estimates_are_consistent(self):
        result = compare_texts("one two three", "one two three four five")
        self.assertGreater(result.words_added_estimate, 0)
        self.assertEqual(result.words_removed_estimate, 0)


class AnalysisResultSerializationTests(unittest.TestCase):
    def test_to_dict_exposes_diagnostic_reliability_alias(self):
        result = AnalysisResult(
            score=0.5,
            verdict="indeterminate",
            confidence=0.3,
            disagreement=0.1,
            robustness_stability=0.9,
            word_count=100,
            analyzers=[],
            features={},
        )
        data = result.to_dict()
        self.assertIn("diagnostic_reliability", data)
        self.assertEqual(data["diagnostic_reliability"], 0.3)
        self.assertIn("confidence_semantics", data)

    def test_diagnostic_reliability_alias_matches_confidence(self):
        result = AnalysisResult(
            score=0.5,
            verdict="indeterminate",
            confidence=0.4,
            disagreement=0.1,
            robustness_stability=0.9,
            word_count=100,
            analyzers=[],
            features={},
        )
        self.assertEqual(result.diagnostic_reliability, 0.4)


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# Mutation kill tests (Phase 5 mutation-survivors wave).
#
# Full session on textforensics.engine (2026-11-08, branch
# fix/mutation-engine): 322 work items, 153 killed, 169 surviving.
# The tests below kill 164 of the 169. The 5 that no test can kill are
# genuinely equivalent and are NOT covered here (they belong in
# mutation-baseline.toml, Phase 2 — this branch must not touch it):
#   - [116] ReplaceFalseWithTrue, zip(..., strict=False) -> strict=True
#     (L17): weights is built one-per-result, so the two iterables
#     always have equal length and strict=True can never raise.
#     No existing kind fits (not NumberReplacer, not a branch
#     condition) — documented no-kind list.
#   - [120] NumberReplacer, `len(results) < 2` -> `< 1` (L22):
#     differs only for len == 1, where statistics.pstdev of a single
#     value is exactly 0.0 — the guard's return. Kind
#     "unobservable-value".
#   - [127] NumberReplacer, max(0.0, 1.0 - spread) -> max(-1.0, ...)
#     (L84): variant scores are weighted averages of analyzer scores
#     clamped to [0, 1] (analyzers.py _clamp), so spread <= 1 and
#     1.0 - spread >= 0 > -1.0. Kind "unobservable-value".
#   - [145] NumberReplacer, max(0.0, min(1.0, dr)) -> max(-1.0, ...)
#     (L93): diagnostic_reliability >= 0 for every input — word_count
#     is a token count (>= 0), disagreement is clamped to [0, 1] and
#     stability to [0, 1], so both factors are >= 0.65 / >= 0.7.
#     Kind "unobservable-value".
#   - [146] NumberReplacer, min(1.0, dr) -> min(2.0, dr) (L94):
#     diagnostic_reliability <= 1 for every input — each of its three
#     factors is <= 1 by construction (min(1.0, wc/250); 0.65 + 0.35 *
#     (1 - d) with d in [0, 1]; 0.7 + 0.3 * s with s in [0, 1]).
#     Kind "unobservable-value".
# Each equivalence was verified by differential probes (original vs
# hand-applied mutant, exhaustive over the relevant input grid), not
# by reasoning alone.
# ---------------------------------------------------------------------------


def _analysis(score: float) -> AnalysisResult:
    return AnalysisResult(
        score=score,
        verdict="indeterminate",
        confidence=0.5,
        disagreement=0.0,
        robustness_stability=1.0,
        word_count=100,
        analyzers=[],
        features={},
    )


class EngineMutationKillTests(unittest.TestCase):
    """Kill tests for the 164 killable engine.py survivors.

    `_analyze_text_internal` is driven through mocked `_base_score` /
    `benign_variants` so the diagnostic-reliability formula, the
    warning thresholds and the rounding are pinned exactly; the mocks
    stop at the boundary of the code under test (the formula and the
    comparisons live in `_analyze_text_internal` itself, not in
    `_base_score`). Default scenario: main results [0.4, 0.6]
    (disagreement 0.2), variant scores (0.4, 0.9) (spread 0.5,
    stability 0.5), word_count 100 (length_reliability 0.4) ->
    confidence round(0.4 * 0.93 * 0.85, 4) == 0.3162.
    """

    def _run_internal(
        self,
        *,
        main_score=0.5,
        results=None,
        word_count=100,
        variant_scores=(0.4, 0.9),
        include_robustness=True,
        disagreement=None,
    ):
        if results is None:
            results = [_sample(0.4), _sample(0.6)]
        calls = [(main_score, results, {"word_count": word_count})]
        if include_robustness:
            calls += [(s, [], {}) for s in variant_scores]
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.object(engine, "_base_score", side_effect=calls))
        stack.enter_context(
            mock.patch.object(
                engine,
                "benign_variants",
                return_value={"original": "x", "variant": "y"},
            )
        )
        if disagreement is not None:
            stack.enter_context(
                mock.patch.object(engine, "_disagreement", return_value=disagreement)
            )
        return _analyze_text_internal("x", include_robustness=include_robustness)

    @staticmethod
    def _has_warning(result, fragment):
        return any(fragment in w for w in result.warnings)

    # -- diagnostic-reliability formula (golden values) ------------------
    def test_internal_golden_confidence(self):
        result = self._run_internal()
        self.assertEqual(result.score, 0.5)
        self.assertEqual(result.confidence, 0.3162)
        self.assertEqual(result.disagreement, 0.2)
        self.assertEqual(result.robustness_stability, 0.5)
        self.assertEqual(result.verdict, "indeterminate")
        self.assertTrue(self._has_warning(result, "sensitive to harmless"))

    def test_internal_golden_confidence_narrow_spread(self):
        # Spread 0.2 -> stability 0.8 -> confidence
        # round(0.4 * 0.93 * 0.94, 4) == 0.3497. The 1.0 * spread
        # mutant ([17]) coincides with the original at spread 0.5
        # (1.0 * 0.5 == 1.0 - 0.5) but differs here (0.2 vs 0.8).
        result = self._run_internal(variant_scores=(0.4, 0.6))
        self.assertEqual(result.confidence, 0.3497)
        self.assertEqual(result.robustness_stability, 0.8)

    def test_internal_no_robustness_golden(self):
        # include_robustness=False leaves stability at its 1.0 default:
        # confidence round(0.4 * 0.93 * 1.0, 4) == 0.372, no
        # sensitivity warning.
        result = self._run_internal(include_robustness=False)
        self.assertEqual(result.confidence, 0.372)
        self.assertEqual(result.robustness_stability, 1.0)
        self.assertFalse(self._has_warning(result, "sensitive to harmless"))

    def test_internal_long_text_length_reliability(self):
        # word_count 300 -> min(1.0, 300/250) == 1.0 -> confidence
        # round(1.0 * 0.93 * 0.85, 4) == 0.7905.
        result = self._run_internal(word_count=300)
        self.assertEqual(result.confidence, 0.7905)

    # -- rounding ---------------------------------------------------------
    def test_internal_score_rounding(self):
        result = self._run_internal(main_score=0.12346)
        self.assertEqual(result.score, 0.1235)

    def test_internal_confidence_rounding(self):
        # word_count 101 -> length 0.404 -> confidence 0.319362 ->
        # round 4 == 0.3194, round 5 == 0.31936, round 3 == 0.319.
        result = self._run_internal(word_count=101)
        self.assertEqual(result.confidence, 0.3194)

    def test_internal_disagreement_rounding(self):
        result = self._run_internal(disagreement=0.12346)
        self.assertEqual(result.disagreement, 0.1235)

    def test_internal_stability_rounding(self):
        # Spread 0.12346 -> stability 0.87654 -> round 4 == 0.8765.
        result = self._run_internal(variant_scores=(0.5, 0.62346))
        self.assertEqual(result.robustness_stability, 0.8765)

    # -- verdict boundaries (exact) ---------------------------------------
    def test_verdict_reliability_boundary_exact(self):
        self.assertEqual(_verdict(0.9, 0.28), "machine_like_patterns")
        self.assertEqual(_verdict(0.5, 0.28), "indeterminate")

    def test_verdict_score_boundaries_exact(self):
        self.assertEqual(_verdict(0.32, 0.9), "human_like_patterns")
        self.assertEqual(_verdict(0.68, 0.9), "machine_like_patterns")

    # -- _disagreement / _weighted_score ----------------------------------
    def test_disagreement_exact_values(self):
        self.assertAlmostEqual(_disagreement([_sample(0.4), _sample(0.6)]), 0.2)

    def test_disagreement_bounded_by_one_for_extreme_scores(self):
        # pstdev([0.0, 5.0]) * 2 == 5.0; the min(1.0, ...) clamp caps it.
        self.assertEqual(_disagreement([_sample(0.0), _sample(5.0)]), 1.0)

    def test_disagreement_three_samples_uses_pstdev(self):
        # len == 3 must go through pstdev, not the len < 2 guard.
        self.assertAlmostEqual(
            _disagreement([_sample(0.0), _sample(0.5), _sample(1.0)]),
            0.816496580927726,
        )

    def test_disagreement_single_sample_is_zero(self):
        # pstdev of a single value is 0.0, so the len < 2 guard and the
        # pstdev path agree here (this is why [120] is equivalent).
        self.assertEqual(_disagreement([_sample(0.7)]), 0.0)

    def test_weighted_score_reliability_floor(self):
        # Reliability 0.0 still weighs 0.05: (1.0 * 0.05 + 0.0) / 1.05.
        result = _weighted_score(
            [
                AnalyzerResult(name="a", score=1.0, reliability=0.0),
                AnalyzerResult(name="b", score=0.0, reliability=1.0),
            ]
        )
        self.assertAlmostEqual(result, 0.05 / 1.05)

    def test_weighted_score_divides_by_weight_sum(self):
        # Weights sum to 1.8, not 1.0: (1.0 * 0.9) / 1.8 == 0.5.
        result = _weighted_score(
            [
                AnalyzerResult(name="a", score=1.0, reliability=0.9),
                AnalyzerResult(name="b", score=0.0, reliability=0.9),
            ]
        )
        self.assertAlmostEqual(result, 0.5)

    # -- warning thresholds -----------------------------------------------
    def test_short_text_warning_boundaries(self):
        self.assertTrue(self._has_warning(self._run_internal(word_count=79), "Short text"))
        self.assertFalse(self._has_warning(self._run_internal(word_count=80), "Short text"))
        self.assertFalse(self._has_warning(self._run_internal(word_count=100), "Short text"))

    def test_disagreement_warning_boundaries(self):
        self.assertTrue(
            self._has_warning(self._run_internal(disagreement=0.5), "High analyzer disagreement")
        )
        self.assertFalse(
            self._has_warning(self._run_internal(disagreement=0.2), "High analyzer disagreement")
        )
        self.assertFalse(
            self._has_warning(self._run_internal(disagreement=0.45), "High analyzer disagreement")
        )
        self.assertFalse(
            self._has_warning(self._run_internal(disagreement=0.3), "High analyzer disagreement")
        )

    def test_stability_warning_boundaries(self):
        # Variant scores (0.1, 0.25) give spread exactly 0.15, so
        # stability is exactly 0.85 (1.0 - (0.25 - 0.1) == 0.85).
        self.assertFalse(
            self._has_warning(
                self._run_internal(variant_scores=(0.1, 0.25)),
                "sensitive to harmless",
            )
        )
        self.assertTrue(self._has_warning(self._run_internal(), "sensitive to harmless"))
        self.assertFalse(
            self._has_warning(
                self._run_internal(include_robustness=False),
                "sensitive to harmless",
            )
        )

    # -- signatures / defaults / validation -------------------------------
    def test_analyze_text_accepts_text_as_keyword(self):
        result = analyze_text(text="hello world this is a simple test")
        self.assertIsInstance(result, AnalysisResult)

    def test_internal_accepts_text_as_keyword(self):
        # `text` is positional-or-keyword in _analyze_text_internal
        # (the `*` after it only makes include_robustness keyword-only).
        with mock.patch.object(
            engine,
            "_base_score",
            side_effect=[(0.5, [_sample(0.4), _sample(0.6)], {"word_count": 100})],
        ):
            result = _analyze_text_internal(text="x", include_robustness=False)
        self.assertEqual(result.confidence, 0.372)

    def test_default_include_robustness_is_true(self):
        # Default (no include_robustness argument): variants are scored,
        # so stability is 0.5, not the 1.0 default.
        with (
            mock.patch.object(
                engine,
                "_base_score",
                side_effect=[
                    (0.5, [_sample(0.4), _sample(0.6)], {"word_count": 100}),
                    (0.4, [], {}),
                    (0.9, [], {}),
                ],
            ),
            mock.patch.object(
                engine,
                "benign_variants",
                return_value={"original": "x", "variant": "y"},
            ),
        ):
            result = analyze_text("x")
        self.assertEqual(result.robustness_stability, 0.5)
        with (
            mock.patch.object(
                engine,
                "_base_score",
                side_effect=[
                    (0.5, [_sample(0.4), _sample(0.6)], {"word_count": 100}),
                    (0.4, [], {}),
                    (0.9, [], {}),
                ],
            ),
            mock.patch.object(
                engine,
                "benign_variants",
                return_value={"original": "x", "variant": "y"},
            ),
        ):
            result = _analyze_text_internal("x")
        self.assertEqual(result.robustness_stability, 0.5)

    def test_comparison_result_has_no_instance_dict(self):
        # @dataclass(slots=True): instances carry no __dict__.
        result = ComparisonResult(
            similarity=1.0,
            before_score=0.5,
            after_score=0.5,
            score_delta=0.0,
            before_verdict="indeterminate",
            after_verdict="indeterminate",
            words_added_estimate=0,
            words_removed_estimate=0,
        )
        self.assertFalse(hasattr(result, "__dict__"))

    def test_analyze_text_rejects_empty_and_non_string(self):
        with self.assertRaises(ValueError):
            analyze_text("")
        with self.assertRaises(ValueError):
            analyze_text(123)

    # -- compare_texts -----------------------------------------------------
    def test_insert_counts_exact_added(self):
        # Insert opcode (i1=i2=1, j1=1, j2=4): added == 3, removed == 0.
        result = compare_texts("one two three", "one extra words here two three")
        self.assertEqual(result.words_added_estimate, 3)
        self.assertEqual(result.words_removed_estimate, 0)

    def test_delete_counts_exact_removed(self):
        # Delete opcode (i1=1, i2=4, j1=j2=1): removed == 3, added == 0.
        result = compare_texts("one extra words here two three", "one two three")
        self.assertEqual(result.words_added_estimate, 0)
        self.assertEqual(result.words_removed_estimate, 3)

    def test_identical_texts_have_zero_added_and_removed(self):
        result = compare_texts("one two three", "one two three")
        self.assertEqual(result.words_added_estimate, 0)
        self.assertEqual(result.words_removed_estimate, 0)

    def test_similarity_rounding(self):
        # ratio == 2 * 2 / 6 == 0.6666... -> round 4 == 0.6667.
        result = compare_texts("one two three", "one two four")
        self.assertEqual(result.similarity, 0.6667)
        self.assertEqual(result.words_added_estimate, 1)
        self.assertEqual(result.words_removed_estimate, 1)

    def test_score_delta_uses_subtraction(self):
        with mock.patch.object(
            engine, "analyze_text", side_effect=[_analysis(0.3), _analysis(0.8)]
        ):
            result = compare_texts("a b", "c d")
        self.assertEqual(result.score_delta, 0.5)

    def test_score_delta_rounding(self):
        with mock.patch.object(
            engine,
            "analyze_text",
            side_effect=[_analysis(0.0), _analysis(0.12346)],
        ):
            result = compare_texts("a b", "c d")
        self.assertEqual(result.score_delta, 0.1235)

    def test_long_repeated_word_similarity_uses_autojunk_false(self):
        # 250x "the" is a >1% popular element in a >= 200-word
        # sequence: with autojunk=True the run stops matching and the
        # ratio collapses to 0.0; with autojunk=False it is 0.9434.
        before = ("w " * 10) + ("the " * 250) + ("x " * 10)
        after = ("the " * 250) + ("y " * 10)
        result = compare_texts(before, after)
        self.assertEqual(result.similarity, 0.9434)
