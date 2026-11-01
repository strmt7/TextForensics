from __future__ import annotations

import unittest

from textforensics.localize import SegmentResult, localize_text

TEXT = (
    "First sentence here. Second sentence follows. Third sentence ends. "
    "Fourth sentence closes the paragraph. Fifth sentence adds detail. "
    "Sixth sentence finishes the thought."
)


class SegmentResultTests(unittest.TestCase):
    def test_to_dict_exposes_diagnostic_reliability_alias(self):
        segment = SegmentResult(
            index=0,
            text="chunk",
            word_count=2,
            score=0.5,
            confidence=0.3,
            verdict="indeterminate",
        )
        data = segment.to_dict()
        self.assertEqual(data["diagnostic_reliability"], 0.3)
        self.assertEqual(data["index"], 0)


class LocalizeTests(unittest.TestCase):
    def test_segments_cover_full_text(self):
        segments = localize_text(TEXT, sentences_per_segment=2)
        self.assertGreaterEqual(len(segments), 3)
        # 6 sentences split into 3 segments of 2 sentences each.
        self.assertEqual(len(segments), 3)

    def test_default_segment_size_is_four(self):
        segments = localize_text(TEXT)
        self.assertEqual(len(segments), 2)

    def test_invalid_segment_size_raises(self):
        with self.assertRaises(ValueError):
            localize_text(TEXT, sentences_per_segment=0)
        with self.assertRaises(ValueError):
            localize_text(TEXT, sentences_per_segment=-1)

    def test_empty_text_raises_explicitly(self):
        with self.assertRaises(ValueError):
            localize_text("")
        with self.assertRaises(ValueError):
            localize_text("   ")

    def test_text_without_sentence_boundary_yields_one_segment(self):
        # Without sentence punctuation the whole text is treated as one segment.
        segments = localize_text("just words without punctuation")
        self.assertEqual(len(segments), 1)
        self.assertEqual(segments[0].word_count, 4)

    def test_single_sentence_yields_one_segment(self):
        segments = localize_text("Only one sentence.", sentences_per_segment=4)
        self.assertEqual(len(segments), 1)
        self.assertEqual(segments[0].word_count, 3)

    def test_segment_scores_are_bounded(self):
        segments = localize_text(TEXT, sentences_per_segment=3)
        for segment in segments:
            self.assertTrue(0.0 <= segment.score <= 1.0)
            self.assertTrue(0.0 <= segment.confidence <= 1.0)
            self.assertIn(
                segment.verdict,
                {
                    "machine_like_patterns",
                    "human_like_patterns",
                    "indeterminate",
                    "insufficient_evidence",
                },
            )

    def test_segments_are_indexed_sequentially(self):
        segments = localize_text(TEXT, sentences_per_segment=1)
        self.assertEqual([s.index for s in segments], list(range(len(segments))))


if __name__ == "__main__":
    unittest.main()
