from __future__ import annotations

import unittest

from textforensics.naturalness import audit_naturalness

FORMULAIC = (
    "Furthermore, it is important to note that the modern technology landscape "
    "is ever-evolving. Additionally, a robust solution can seamlessly unlock the "
    "potential of organizations. Moreover, this multifaceted approach can help "
    "navigate the complexities of today's world. In conclusion, the solution "
    "is a testament to innovation."
)

HUMANISH = (
    "I tried the new setup on Tuesday and hit two problems. The first was "
    "mundane: the cable was too short. The second took longer to understand."
)

PLAIN = "This is a plain sentence. It says one thing and then another. Done."


class NaturalnessTests(unittest.TestCase):
    def test_formulaic_text_flags_stock_phrasing(self):
        issues = audit_naturalness(FORMULAIC)
        self.assertTrue(
            any(item["issue"] == "stock_phrasing" for item in issues)
        )

    def test_formulaic_text_flags_transitions(self):
        issues = audit_naturalness(FORMULAIC)
        self.assertTrue(
            any(item["issue"] == "heavy_explicit_transitions" for item in issues)
        )

    def test_plain_text_reports_no_obvious_pattern(self):
        issues = audit_naturalness(PLAIN)
        self.assertTrue(
            any(item["issue"] == "no_obvious_formulaic_pattern" for item in issues)
        )

    def test_short_text_does_not_flag_dense_paragraphing(self):
        issues = audit_naturalness("Short text only.")
        self.assertFalse(
            any(item["issue"] == "dense_paragraphing" for item in issues)
        )

    def test_long_single_paragraph_flags_dense_paragraphing(self):
        # A single unbroken paragraph of well over 250 words.
        long_text = " ".join(
            f"sentence number {i} has several ordinary words in it."
            for i in range(60)
        )
        self.assertGreater(len(long_text.split()), 250)
        issues = audit_naturalness(long_text)
        self.assertTrue(
            any(item["issue"] == "dense_paragraphing" for item in issues)
        )

    def test_uniform_sentence_rhythm_is_flagged(self):
        uniform = " ".join("Short sentence here." for _ in range(6))
        issues = audit_naturalness(uniform)
        self.assertTrue(
            any(item["issue"] == "uniform_sentence_rhythm" for item in issues)
        )

    def test_repeated_sentence_openings_are_flagged(self):
        repeated = " ".join("The cat sat. The dog ran. The bird flew. The fish swam. The boy cried. The girl laughed.")
        issues = audit_naturalness(repeated)
        self.assertTrue(
            any(item["issue"] == "repeated_sentence_openings" for item in issues)
        )

    def test_suggestions_are_strings(self):
        for item in audit_naturalness(FORMULAIC):
            self.assertIsInstance(item["issue"], str)
            self.assertIsInstance(item["suggestion"], str)

    def test_does_not_rewrite_input(self):
        text = "Original text that should not be modified by the audit."
        audit_naturalness(text)
        self.assertEqual(text, "Original text that should not be modified by the audit.")


if __name__ == "__main__":
    unittest.main()
