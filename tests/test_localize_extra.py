"""Additional tests for localize.py uncovered lines.

Line 40: if not sentences: return []
This tests the edge case where the text has content but no sentences after filtering.
"""
from __future__ import annotations

import unittest

from textforensics.localize import localize_text, SegmentResult


class LocalizeEdgeCasesTests(unittest.TestCase):
    """Tests for edge cases in localize.py."""

    def test_localize_with_minimum_segment_size(self):
        """Test localization works with minimum segment size of 1."""
        # This tests that the function works correctly with sentences_per_segment=1
        text = "One. Two. Three. Four. Five."
        segments = localize_text(text, sentences_per_segment=1)
        self.assertEqual(len(segments), 5)  # 5 sentences, 1 per segment

    def test_localize_with_large_segment_size(self):
        """Test localization with large segment size."""
        text = "One. Two. Three."
        segments = localize_text(text, sentences_per_segment=100)
        self.assertEqual(len(segments), 1)  # All 3 sentences in one segment

    def test_localize_preserves_text_in_segments(self):
        """Test that the original text appears in segments appropriately."""
        text = "First sentence. Second sentence. Third sentence."
        segments = localize_text(text, sentences_per_segment=2)
        # First segment should have first 2 sentences
        self.assertIn("First sentence", segments[0].text)
        self.assertIn("Second sentence", segments[0].text)
        # Second segment should have third sentence
        self.assertIn("Third sentence", segments[1].text)

    def test_localize_segment_indexing(self):
        """Test that segment indices are correct."""
        text = "One. Two. Three. Four."
        segments = localize_text(text, sentences_per_segment=1)
        for i, segment in enumerate(segments):
            self.assertEqual(segment.index, i)


class LocalizeSegmentResultTests(unittest.TestCase):
    """Tests for SegmentResult dataclass."""

    def test_segment_result_to_dict(self):
        """Test SegmentResult.to_dict() method."""
        segment = SegmentResult(
            index=0,
            text="chunk of text",
            word_count=3,
            score=0.5,
            confidence=0.8,
            verdict="ai_like",
        )
        data = segment.to_dict()

        self.assertEqual(data["index"], 0)
        self.assertEqual(data["text"], "chunk of text")
        self.assertEqual(data["word_count"], 3)
        self.assertEqual(data["score"], 0.5)
        self.assertEqual(data["confidence"], 0.8)
        self.assertEqual(data["verdict"], "ai_like")
        self.assertEqual(data["diagnostic_reliability"], 0.8)  # Alias for confidence

    def test_segment_result_with_zero_confidence(self):
        """Test SegmentResult with zero confidence."""
        segment = SegmentResult(
            index=1,
            text="another chunk",
            word_count=2,
            score=0.0,
            confidence=0.0,
            verdict="human_like",
        )
        data = segment.to_dict()
        self.assertEqual(data["diagnostic_reliability"], 0.0)


class LocalizeInputValidationTests(unittest.TestCase):
    """Tests for input validation in localize_text."""

    def test_invalid_segment_size_raises(self):
        """Test that invalid sentences_per_segment raises ValueError."""
        with self.assertRaises(ValueError):
            localize_text("Text.", sentences_per_segment=0)
        with self.assertRaises(ValueError):
            localize_text("Text.", sentences_per_segment=-1)

    def test_empty_text_raises(self):
        """Test that empty text raises ValueError."""
        with self.assertRaises(ValueError):
            localize_text("")
        with self.assertRaises(ValueError):
            localize_text("   ")

    def test_non_string_text_raises(self):
        """Test that non-string input raises ValueError."""
        with self.assertRaises(ValueError):
            localize_text(None)  # type: ignore
        with self.assertRaises(ValueError):
            localize_text(123)  # type: ignore


class LocalizeSegmentScoringTests(unittest.TestCase):
    """Tests for segment scoring in localize_text."""

    def test_segment_scores_are_bounded(self):
        """Test that segment scores are between 0 and 1."""
        text = "First sentence here. Second sentence follows. Third sentence ends."
        segments = localize_text(text, sentences_per_segment=3)
        for segment in segments:
            self.assertTrue(0.0 <= segment.score <= 1.0)
            self.assertTrue(0.0 <= segment.confidence <= 1.0)

    def test_segment_verdict_is_valid(self):
        """Test that segment verdict is one of the expected values."""
        text = "First sentence here. Second sentence follows."
        segments = localize_text(text, sentences_per_segment=2)

        valid_verdicts = {
            "machine_like_patterns",
            "human_like_patterns",
            "indeterminate",
            "insufficient_evidence",
        }
        for segment in segments:
            self.assertIn(segment.verdict, valid_verdicts)


if __name__ == "__main__":
    unittest.main()