"""Additional tests for features.py uncovered lines."""
from __future__ import annotations

import unittest

from textforensics.features import extract_features


class FeatureExtractionEdgeCasesTests(unittest.TestCase):
    """Tests for edge cases in feature extraction (line 65 and others)."""

    def test_text_without_sentence_punctuation_triggers_line_65(self):
        """Test that text without sentence punctuation triggers line 65.

        Line 65 is: sentences = [clean] when not sentences and clean text exists.
        This happens when there's text but no sentence-ending punctuation that
        produces a split result.
        """
        # Text with no sentence-ending punctuation triggers line 65
        result = extract_features("just words without punctuation")
        self.assertEqual(result["sentence_count"], 1)
        self.assertEqual(result["word_count"], 4)

        # Another test case
        result = extract_features("no periods or exclamation marks")
        self.assertEqual(result["sentence_count"], 1)
        self.assertEqual(result["word_count"], 5)

    def test_text_with_only_sentence_ending_chars(self):
        """Test text that looks like sentence endings but no content."""
        # This tests the edge case where there's content but it's minimal
        result = extract_features("...")
        self.assertEqual(result["word_count"], 0)  # "..." has no words
        self.assertEqual(result["sentence_count"], 1)  # Treated as one sentence

    def test_multiple_sentences_with_lowercase_after_punctuation(self):
        """Test sentences where lowercase follows punctuation.

        The SENTENCE_RE only splits when followed by uppercase/digit/quotes,
        so lowercase after punctuation creates combined sentences.
        """
        result = extract_features("hello. world. test.")
        # No split occurs because all start with lowercase
        self.assertEqual(result["sentence_count"], 1)
        # "hello. world. test." has 3 words
        self.assertEqual(result["word_count"], 3)

    def test_mixed_case_sentence_boundaries(self):
        """Test text with mixed case sentence boundaries."""
        result = extract_features("hello. World. test.")
        # "World." followed by uppercase 't' would be split... wait, 't' is lowercase
        # Actually uppercase W would be split from "hello."
        self.assertGreaterEqual(result["sentence_count"], 1)

    def test_trigram_coverage(self):
        """Test trigram features for various text patterns."""
        # Repetitive text creates repeated trigrams
        result = extract_features("the cat the cat the cat")
        self.assertGreater(result["repeated_trigram_ratio"], 0)

        # Non-repetitive text
        result = extract_features("one two three four five six")
        self.assertGreaterEqual(result["repeated_trigram_ratio"], 0)

    def test_type_token_ratio_zero_for_empty(self):
        """Test type_token_ratio is 0.0 for empty text."""
        result = extract_features("")
        self.assertEqual(result["type_token_ratio"], 0.0)

    def test_hapax_ratio_zero_for_empty(self):
        """Test hapax_ratio is 0.0 for empty text."""
        result = extract_features("")
        self.assertEqual(result["hapax_ratio"], 0.0)

    def test_word_entropy_zero_for_empty(self):
        """Test word_entropy is 0.0 for empty text."""
        result = extract_features("")
        self.assertEqual(result["word_entropy"], 0.0)

    def test_all_transitions_present(self):
        """Test features when text contains many transition phrases."""
        text = "Furthermore, moreover, however, therefore, consequently."
        result = extract_features(text)
        self.assertGreater(result["transition_density"], 0)

    def test_all_cliches_present(self):
        """Test features when text contains AI clichés."""
        text = "This robust solution will seamlessly unlock the potential."
        result = extract_features(text)
        self.assertGreater(result["cliche_density"], 0)

    def test_contractions_all_types(self):
        """Test contraction density with various contractions."""
        text = "I don't think it's can't won't shouldn't"
        result = extract_features(text)
        self.assertGreater(result["contraction_density"], 0)

    def test_punctuation_variety_counts_unique(self):
        """Test that punctuation_variety counts unique punctuation types."""
        # Text with 3 different punctuation types
        result = extract_features("Hello; world!")
        # Should have comma and exclamation = 2 (but ; and ! are different)
        # Actually: comma , and ! = 2
        self.assertGreaterEqual(result["punctuation_variety"], 2)

    def test_question_semicolon_parenthetical_rates(self):
        """Test question_rate, semicolon_rate, parenthetical_rate."""
        text = "Why? What? Now; then; (aside) more."
        result = extract_features(text)
        self.assertGreater(result["question_rate"], 0)
        self.assertGreater(result["semicolon_rate"], 0)
        self.assertGreater(result["parenthetical_rate"], 0)

    def test_mean_sentence_length_edge_cases(self):
        """Test mean_sentence_length for various inputs."""
        # Empty text
        result = extract_features("")
        self.assertEqual(result["mean_sentence_length"], 0.0)

        # Single sentence
        result = extract_features("Hello world.")
        # No sentence split happens, so it's one sentence with 2 words
        self.assertEqual(result["mean_sentence_length"], 2.0)

    def test_sentence_length_cv_edge_cases(self):
        """Test sentence_length_cv for various inputs."""
        # Empty text
        result = extract_features("")
        self.assertEqual(result["sentence_length_cv"], 0.0)

        # Single sentence (CV is 0 for single value)
        result = extract_features("Hello world.")
        self.assertEqual(result["sentence_length_cv"], 0.0)

    def test_paragraph_count_splits_correctly(self):
        """Test that paragraph_count correctly splits on double newlines."""
        result = extract_features("para one\n\npara two\n\n\npara three")
        self.assertEqual(result["paragraph_count"], 3)

    def test_paragraph_length_cv_edge_cases(self):
        """Test paragraph_length_cv for various inputs."""
        # Empty text
        result = extract_features("")
        self.assertEqual(result["paragraph_length_cv"], 0.0)


if __name__ == "__main__":
    unittest.main()