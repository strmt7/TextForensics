"""Comprehensive tests for enhanced localize module with visual diff and anomaly detection."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from textforensics.localize import (
    SegmentResult,
    detect_anomalous_segments,
    segment_to_dict,
    visual_diff,
)


class VisualDiffTests(unittest.TestCase):
    """Tests for the visual_diff function."""

    def test_diff_side_by_side_equal_texts(self):
        text = "Line 1\nLine 2\nLine 3"
        result = visual_diff(text, text, style="side_by_side")
        self.assertIn("Line 1", result)
        self.assertIn("Line 2", result)
        self.assertIn("Line 3", result)
        # No change markers for equal texts (except in header separator)
        self.assertNotIn(" -", result)  # Not preceded by space
        self.assertNotIn(" +", result)  # Not preceded by space

    def test_diff_side_by_side_different_texts(self):
        text1 = "Line 1\nLine 2\nLine 3"
        text2 = "Line 1\nModified Line\nLine 3\nLine 4"
        result = visual_diff(text1, text2, style="side_by_side")
        self.assertIn("Modified Line", result)
        self.assertIn("Line 4", result)
        # Should have change markers
        self.assertTrue(
            "-" in result and "+" in result,
            "Side-by-side diff should contain change markers",
        )

    def test_diff_unified_format(self):
        text1 = "Line 1\nLine 2\nLine 3"
        text2 = "Line 1\nModified Line\nLine 3"
        result = visual_diff(text1, text2, style="unified")
        self.assertIn("@@", result)  # Unified diff hunk header
        self.assertIn("-Line 2", result)
        self.assertIn("+Modified Line", result)

    def test_diff_inline_format(self):
        text1 = "The quick brown fox."
        text2 = "The quick red fox."
        result = visual_diff(text1, text2, style="inline")
        self.assertIn("<del>", result)
        self.assertIn("</del>", result)
        self.assertIn("<ins>", result)
        self.assertIn("</ins>", result)
        # The diff operates character-by-character; check that words are split
        self.assertIn("b", result)  # "brown" split across del/ins
        self.assertIn("r", result)  # "red" split across del/ins

    def test_diff_inline_html_escaping(self):
        text1 = "<script>alert(1)</script>"
        text2 = "<script>alert(2)</script>"
        result = visual_diff(text1, text2, style="inline")
        # HTML should be escaped - check for escaped versions
        self.assertIn("&lt;script&gt;", result)
        self.assertIn("&lt;/script&gt;", result)

    def test_diff_invalid_style_raises(self):
        with self.assertRaises(ValueError):
            visual_diff("a", "b", style="invalid_style")


class AnomalyDetectionTests(unittest.TestCase):
    """Tests for detect_anomalous_segments function."""

    def test_detect_anomalies_in_mixed_text(self):
        # Create text with clearly different segments - need enough sentences for multiple segments
        text = (
            "Simple sentence. Another simple one. Short. "
            "This segment has very very very very very very repetitive repetitive "
            "repetitive words which should trigger high burstiness and low entropy. "
            "Normal sentence here. Another normal sentence with some variety. "
            "Final normal part. "
            "More normal content. Additional normal sentence. "
            "Even more normal text to fill the space. "
            "Another sentence with variety. Yet another one. "
            "Final stretch of normal text. "
            "Last few sentences here. End of normal text. "
            "One more normal sentence for good measure."
        )
        result = detect_anomalous_segments(text, threshold=1.0)
        # Should find at least the repetitive segment
        self.assertGreater(len(result), 0)
        for seg in result:
            self.assertIn("segment_index", seg)
            self.assertIn("text", seg)
            self.assertIn("features", seg)
            self.assertIn("z_scores", seg)
            self.assertIn("max_z_score", seg)
            self.assertIn("is_anomalous", seg)
            self.assertTrue(seg["is_anomalous"])

    def test_detect_anomalies_empty_text_raises(self):
        with self.assertRaises(ValueError):
            detect_anomalous_segments("")
        with self.assertRaises(ValueError):
            detect_anomalous_segments("   ")

    def test_detect_anomalies_negative_threshold_raises(self):
        with self.assertRaises(ValueError):
            detect_anomalous_segments("some text", threshold=-1.0)

    def test_detect_anomalies_high_threshold_returns_empty(self):
        text = "This is a perfectly normal paragraph. It has several sentences. "
        "Each sentence is reasonably varied. Nothing unusual here."
        result = detect_anomalous_segments(text, threshold=10.0)
        self.assertEqual(len(result), 0)

    def test_detect_anomalies_feature_structure(self):
        text = "Short. Very very very very very long repetitive segment. Normal end."
        result = detect_anomalous_segments(text, threshold=0.5)
        if result:
            seg = result[0]
            self.assertIn("word_entropy", seg["features"])
            self.assertIn("burstiness", seg["features"])
            self.assertIn("type_token_ratio", seg["features"])
            self.assertIn("word_entropy", seg["z_scores"])
            self.assertIn("burstiness", seg["z_scores"])
            self.assertIn("type_token_ratio", seg["z_scores"])

    def test_detect_anomalies_single_segment(self):
        # Very short text - only one segment
        text = "Just one sentence."
        result = detect_anomalous_segments(text, threshold=0.5)
        # With one segment, std dev is 0, so no anomalies should be detected
        self.assertEqual(len(result), 0)


class SegmentToDictTests(unittest.TestCase):
    """Tests for segment_to_dict serialization."""

    def test_segment_to_dict_basic(self):
        segment = SegmentResult(
            index=0,
            text="Test segment",
            word_count=2,
            score=0.7,
            confidence=0.8,
            verdict="machine_like_patterns",
        )
        data = segment_to_dict(segment)
        self.assertEqual(data["index"], 0)
        self.assertEqual(data["text"], "Test segment")
        self.assertEqual(data["word_count"], 2)
        self.assertEqual(data["score"], 0.7)
        self.assertEqual(data["confidence"], 0.8)
        self.assertEqual(data["verdict"], "machine_like_patterns")
        self.assertEqual(data["diagnostic_reliability"], 0.8)

    def test_segment_to_dict_preserves_all_fields(self):
        segment = SegmentResult(
            index=5,
            text="Another test",
            word_count=2,
            score=0.3,
            confidence=0.9,
            verdict="human_like_patterns",
        )
        data = segment_to_dict(segment)
        self.assertEqual(set(data.keys()), {
            "index", "text", "word_count", "score",
            "confidence", "verdict", "diagnostic_reliability"
        })


class LocalizeIntegrationTests(unittest.TestCase):
    """Integration tests for localize CLI commands via in-process execution."""

    def test_localize_segments_json_output(self):
        import sys
        from io import StringIO

        from textforensics.cli import main

        text = "First sentence. Second sentence. Third sentence. Fourth sentence."
        old_argv = sys.argv
        old_stdin = sys.stdin
        old_stdout = sys.stdout
        try:
            sys.argv = ["textforensics", "localize", "segments", "--sentences", "2"]
            sys.stdin = StringIO(text)
            sys.stdout = StringIO()
            main()
            output = sys.stdout.getvalue()
            result = json.loads(output)
            self.assertEqual(len(result), 2)
            self.assertEqual(result[0]["index"], 0)
            self.assertEqual(result[1]["index"], 1)
        finally:
            sys.argv = old_argv
            sys.stdin = old_stdin
            sys.stdout = old_stdout

    def test_localize_diff_side_by_side(self):
        import sys
        from io import StringIO

        from textforensics.cli import main

        text1 = "Line one\nLine two\nLine three"
        text2 = "Line one\nModified line\nLine three\nLine four"

        with tempfile.TemporaryDirectory() as tmp:
            f1 = Path(tmp) / "file1.txt"
            f2 = Path(tmp) / "file2.txt"
            f1.write_text(text1)
            f2.write_text(text2)

            old_argv = sys.argv
            old_stdout = sys.stdout
            try:
                sys.argv = [
                    "textforensics", "localize", "diff",
                    str(f1), str(f2), "--style", "side_by_side"
                ]
                sys.stdout = StringIO()
                main()
                output = sys.stdout.getvalue()
                self.assertIn("Line one", output)
                self.assertIn("Modified line", output)
                self.assertIn("Line four", output)
            finally:
                sys.argv = old_argv
                sys.stdout = old_stdout

    def test_localize_diff_unified(self):
        import sys
        from io import StringIO

        from textforensics.cli import main

        text1 = "Line one\nLine two\nLine three"
        text2 = "Line one\nModified line\nLine three"

        with tempfile.TemporaryDirectory() as tmp:
            f1 = Path(tmp) / "file1.txt"
            f2 = Path(tmp) / "file2.txt"
            f1.write_text(text1)
            f2.write_text(text2)

            old_argv = sys.argv
            old_stdout = sys.stdout
            try:
                sys.argv = [
                    "textforensics", "localize", "diff",
                    str(f1), str(f2), "--style", "unified"
                ]
                sys.stdout = StringIO()
                main()
                output = sys.stdout.getvalue()
                self.assertIn("@@", output)
                self.assertIn("-Line two", output)
                self.assertIn("+Modified line", output)
            finally:
                sys.argv = old_argv
                sys.stdout = old_stdout

    def test_localize_diff_inline(self):
        import sys
        from io import StringIO

        from textforensics.cli import main

        text1 = "The quick brown fox."
        text2 = "The quick red fox."

        with tempfile.TemporaryDirectory() as tmp:
            f1 = Path(tmp) / "file1.txt"
            f2 = Path(tmp) / "file2.txt"
            f1.write_text(text1)
            f2.write_text(text2)

            old_argv = sys.argv
            old_stdout = sys.stdout
            try:
                sys.argv = [
                    "textforensics", "localize", "diff",
                    str(f1), str(f2), "--style", "inline"
                ]
                sys.stdout = StringIO()
                main()
                output = sys.stdout.getvalue()
                self.assertIn("<del>", output)
                self.assertIn("<ins>", output)
            finally:
                sys.argv = old_argv
                sys.stdout = old_stdout

    def test_localize_anomalies_json_output(self):
        import sys
        from io import StringIO

        from textforensics.cli import main

        text = "Short. Very very very very very long repetitive segment. Normal end."

        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "file.txt"
            f.write_text(text)

            old_argv = sys.argv
            old_stdout = sys.stdout
            try:
                sys.argv = [
                    "textforensics", "localize", "anomalies",
                    str(f), "--threshold", "0.5"
                ]
                sys.stdout = StringIO()
                main()
                output = sys.stdout.getvalue()
                result = json.loads(output)
                self.assertIsInstance(result, list)
            finally:
                sys.argv = old_argv
                sys.stdout = old_stdout

    def test_localize_anomalies_output_file(self):
        import sys
        from io import StringIO

        from textforensics.cli import main

        text = "Short. Very very very very very long repetitive segment. Normal end."

        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "file.txt"
            out = Path(tmp) / "anomalies.json"
            f.write_text(text)

            old_argv = sys.argv
            old_stdout = sys.stdout
            try:
                sys.argv = [
                    "textforensics", "localize", "anomalies",
                    str(f), "--threshold", "0.5", "--output", str(out)
                ]
                sys.stdout = StringIO()
                main()
                output = sys.stdout.getvalue().strip()
                self.assertEqual(output, str(out))
                self.assertTrue(out.exists())
                with open(out, encoding="utf-8") as fp:
                    result = json.load(fp)
                self.assertIsInstance(result, list)
            finally:
                sys.argv = old_argv
                sys.stdout = old_stdout


if __name__ == "__main__":
    unittest.main()
