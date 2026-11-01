from __future__ import annotations

import unittest

from textforensics.compare import ComparisonResult, compare_texts
from textforensics.engine import AnalysisResult, _disagreement, _verdict, _weighted_score
from textforensics.models import AnalyzerResult
from textforensics.robustness import benign_variants


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
        variants = benign_variants('He said \u201cyes\u201d and \u2014left.')
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
