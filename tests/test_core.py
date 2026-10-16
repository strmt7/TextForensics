import tempfile
import unittest
from pathlib import Path

from textforensics import analyze_text, compare_texts
from textforensics.naturalness import audit_naturalness
from textforensics.provenance import snapshot_file, verify_ledger
from textforensics.localize import localize_text
from textforensics.benchmark import calibrate_threshold_jsonl


HUMANISH = """
I tried the new setup on Tuesday and hit two problems. The first was mundane: the cable was too short.
The second took longer to understand. After three runs, I noticed the sensor drifted only when the enclosure
was warm. I don't yet know why, but tomorrow I'll repeat the test with the fan locked at one speed.
"""

FORMULAIC = """
Furthermore, it is important to note that the modern technology landscape is ever-evolving. Additionally,
a robust solution can seamlessly unlock the potential of organizations. Moreover, this multifaceted approach
can help navigate the complexities of today's world. In conclusion, the solution is a testament to innovation.
"""


class CoreTests(unittest.TestCase):
    def test_scan_has_bounded_scores(self):
        result = analyze_text(HUMANISH)
        self.assertGreaterEqual(result.score, 0)
        self.assertLessEqual(result.score, 1)
        self.assertGreaterEqual(result.confidence, 0)
        self.assertLessEqual(result.confidence, 1)

    def test_formulaic_text_scores_higher_than_humanish_sample(self):
        self.assertGreater(analyze_text(FORMULAIC).score, analyze_text(HUMANISH).score)

    def test_compare(self):
        result = compare_texts(HUMANISH, HUMANISH + " One more sentence.")
        self.assertGreater(result.similarity, 0.8)
        self.assertGreater(result.words_added_estimate, 0)

    def test_naturalness_audit(self):
        issues = audit_naturalness(FORMULAIC)
        self.assertTrue(any(i["issue"] in {"stock_phrasing", "heavy_explicit_transitions"} for i in issues))

    def test_ledger_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "draft.txt"
            ledger = Path(tmp) / "ledger.jsonl"
            file.write_text("first", encoding="utf-8")
            snapshot_file(file, ledger)
            file.write_text("second", encoding="utf-8")
            snapshot_file(file, ledger)
            verified = verify_ledger(ledger)
            self.assertTrue(verified["valid"])
            self.assertEqual(verified["records"], 2)

    def test_localize(self):
        segments = localize_text((HUMANISH + " " + FORMULAIC) * 2, sentences_per_segment=3)
        self.assertGreaterEqual(len(segments), 2)

    def test_calibration(self):
        with tempfile.TemporaryDirectory() as tmp:
            dataset = Path(tmp) / "data.jsonl"
            dataset.write_text(
                '{"label":"human","text":' + __import__('json').dumps(HUMANISH) + '}\n' +
                '{"label":"ai","text":' + __import__('json').dumps(FORMULAIC) + '}\n',
                encoding="utf-8",
            )
            result = calibrate_threshold_jsonl(dataset, target_fpr=0.0)
            self.assertIn("recommended_threshold", result)


if __name__ == "__main__":
    unittest.main()
