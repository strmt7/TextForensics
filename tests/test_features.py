from __future__ import annotations

import unittest

from textforensics.features import (
    AI_CLICHES,
    CONTRACTION_RE,
    SENTENCE_RE,
    TRANSITIONS,
    WORD_RE,
    _cv,
    _entropy,
    _sentence_starts,
    extract_features,
)


class RegexTests(unittest.TestCase):
    def test_word_regex_matches_apostrophes(self):
        self.assertEqual(WORD_RE.findall("don't can't"), ["don't", "can't"])

    def test_word_regex_is_unicode_aware(self):
        words = WORD_RE.findall("café naïve résumé")
        self.assertEqual(words, ["café", "naïve", "résumé"])

    def test_sentence_regex_splits_on_punctuation(self):
        sentences = SENTENCE_RE.split("First. Second! Third?")
        self.assertEqual(len(sentences), 3)

    def test_transition_list_is_non_empty(self):
        self.assertIn("furthermore", TRANSITIONS)
        self.assertIn("in conclusion", TRANSITIONS)

    def test_cliche_list_is_non_empty(self):
        self.assertIn("delve into", AI_CLICHES)
        self.assertIn("landscape", AI_CLICHES)

    def test_contraction_regex_matches_common_contractions(self):
        self.assertEqual(len(CONTRACTION_RE.findall("I don't think it's can't")), 3)


class HelperTests(unittest.TestCase):
    def test_cv_returns_zero_for_single_value(self):
        self.assertEqual(_cv([5]), 0.0)

    def test_cv_returns_zero_for_constant_values(self):
        self.assertAlmostEqual(_cv([3, 3, 3]), 0.0)

    def test_cv_returns_zero_for_zero_mean(self):
        # Line 38: return 0.0 when mean is zero
        # Values [-1, 1] have mean 0
        self.assertEqual(_cv([-1, 1]), 0.0)

    def test_cv_is_positive_for_varying_values(self):
        self.assertGreater(_cv([1, 2, 3]), 0.0)

    def test_entropy_is_zero_for_empty(self):
        self.assertEqual(_entropy([]), 0.0)

    def test_entropy_is_zero_for_single_repeated_token(self):
        self.assertAlmostEqual(_entropy(["a", "a"]), 0.0)

    def test_entropy_is_positive_for_mixed_tokens(self):
        self.assertGreater(_entropy(["a", "b"]), 0.0)


class SentenceStartsTests(unittest.TestCase):
    def test_returns_first_two_words_lowercased(self):
        self.assertEqual(_sentence_starts(["The Quick Brown Fox."]), ["the quick"])

    def test_skips_sentences_without_words(self):
        self.assertEqual(_sentence_starts(["...", "The cat."]), ["the cat"])


class FeatureExtractionTests(unittest.TestCase):
    def test_empty_text_yields_zero_counts(self):
        f = extract_features("")
        self.assertEqual(f["word_count"], 0)
        self.assertEqual(f["sentence_count"], 0)
        self.assertEqual(f["type_token_ratio"], 0.0)

    def test_whitespace_only_yields_zero_counts(self):
        f = extract_features("   \n\t  ")
        self.assertEqual(f["word_count"], 0)

    def test_word_count_matches_regex(self):
        f = extract_features("one two three four")
        self.assertEqual(f["word_count"], 4)

    def test_type_token_ratio_is_between_zero_and_one(self):
        f = extract_features("the cat the cat the dog")
        self.assertTrue(0.0 <= f["type_token_ratio"] <= 1.0)

    def test_repeated_trigram_ratio_is_between_zero_and_one(self):
        f = extract_features("alpha beta gamma alpha beta gamma")
        self.assertTrue(0.0 <= f["repeated_trigram_ratio"] <= 1.0)

    def test_repeated_sentence_start_ratio_is_between_zero_and_one(self):
        f = extract_features("The cat sat. The dog ran. The bird flew.")
        self.assertTrue(0.0 <= f["repeated_sentence_start_ratio"] <= 1.0)

    def test_transition_density_counts_phrases(self):
        f = extract_features("Furthermore, it is important to note. Moreover, however.")
        self.assertGreater(f["transition_density"], 0.0)

    def test_cliche_density_counts_phrases(self):
        f = extract_features("This robust solution will seamlessly unlock the potential.")
        self.assertGreater(f["cliche_density"], 0.0)

    def test_contraction_density_counts_contractions(self):
        f = extract_features("I don't think it's can't won't.")
        self.assertGreater(f["contraction_density"], 0.0)

    def test_punctuation_variety_counts_distinct_symbols(self):
        f = extract_features("Hello; world: test—done?")
        self.assertGreater(f["punctuation_variety"], 0)

    def test_paragraph_count_splits_on_blank_lines(self):
        f = extract_features("para one.\n\npara two.\n\n\npara three.")
        self.assertEqual(f["paragraph_count"], 3)

    def test_question_rate_and_semicolon_rate_are_non_negative(self):
        f = extract_features("Why? What? Now; then.")
        self.assertGreaterEqual(f["question_rate"], 0.0)
        self.assertGreaterEqual(f["semicolon_rate"], 0.0)

    def test_features_are_json_serializable(self):
        import json

        f = extract_features("A simple test sentence with several words.")
        serialized = json.dumps(f, default=str)
        self.assertIsInstance(json.loads(serialized), dict)

    def test_unicode_text_is_accepted(self):
        f = extract_features("Café naïve résumé. Héllo wörld!")
        self.assertGreater(f["word_count"], 0)

    def test_text_without_sentence_punctuation_treated_as_single_sentence(self):
        # Line 65: sentences = [clean] when no sentences but clean text exists
        f = extract_features("just words without punctuation")
        self.assertEqual(f["sentence_count"], 1)
        self.assertEqual(f["word_count"], 4)


if __name__ == "__main__":
    unittest.main()
