import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from textforensics import analyze_text, compare_texts
from textforensics.localize import localize_text
from textforensics.naturalness import audit_naturalness
from textforensics.provenance import snapshot_file, verify_ledger
from textforensics.report import build_forensic_bundle
from textforensics.webapp import HTML, analyze_payload


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
    def test_scan_has_bounded_diagnostics(self):
        result = analyze_text(HUMANISH)
        self.assertGreaterEqual(result.score, 0)
        self.assertLessEqual(result.score, 1)
        self.assertGreaterEqual(result.diagnostic_reliability, 0)
        self.assertLessEqual(result.diagnostic_reliability, 1)
        self.assertIn("Uncalibrated", result.confidence_semantics)

    def test_formulaic_sample_scores_higher_than_humanish_sample(self):
        self.assertGreater(
            analyze_text(FORMULAIC).score,
            analyze_text(HUMANISH).score,
        )

    def test_compare(self):
        result = compare_texts(
            HUMANISH,
            HUMANISH + " One more sentence.",
        )
        self.assertGreater(result.similarity, 0.8)
        self.assertGreater(result.words_added_estimate, 0)

    def test_naturalness_audit(self):
        issues = audit_naturalness(FORMULAIC)
        self.assertTrue(
            any(
                item["issue"]
                in {"stock_phrasing", "heavy_explicit_transitions"}
                for item in issues
            )
        )

    def test_ledger_chain_and_tamper_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "draft.txt"
            ledger = Path(tmp) / "ledger.jsonl"
            file.write_text("first", encoding="utf-8")
            snapshot_file(file, ledger)
            file.write_text("second", encoding="utf-8")
            snapshot_file(file, ledger)
            self.assertTrue(verify_ledger(ledger)["valid"])

            lines = ledger.read_text(encoding="utf-8").splitlines()
            ledger.write_text(
                lines[0].replace('"file_size": 5', '"file_size": 6')
                + "\n"
                + lines[1]
                + "\n",
                encoding="utf-8",
            )
            self.assertFalse(verify_ledger(ledger)["valid"])
            with self.assertRaises(ValueError):
                snapshot_file(file, ledger)

    def test_ledger_concurrent_writers_keep_one_valid_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "draft.txt"
            ledger = Path(tmp) / "ledger.jsonl"
            file.write_text("concurrent snapshot source", encoding="utf-8")

            with ThreadPoolExecutor(max_workers=4) as pool:
                records = list(
                    pool.map(
                        lambda _: snapshot_file(file, ledger),
                        range(8),
                    )
                )

            verified = verify_ledger(ledger)
            self.assertTrue(verified["valid"], verified["errors"])
            self.assertEqual(verified["records"], 8)
            self.assertEqual(len(records), 8)
            self.assertTrue(Path(str(ledger) + ".lock").exists())

    def test_localize_validates_segment_size(self):
        segments = localize_text(
            (HUMANISH + " " + FORMULAIC) * 2,
            sentences_per_segment=3,
        )
        self.assertGreaterEqual(len(segments), 2)
        with self.assertRaises(ValueError):
            localize_text(HUMANISH, sentences_per_segment=0)

    def test_forensic_bundle_exposes_trust_map_and_legacy_status(self):
        data = build_forensic_bundle(HUMANISH).to_dict()
        self.assertEqual(
            data["schema"],
            "textforensics.forensic-bundle/v1",
        )
        self.assertEqual(len(data["content_sha256"]), 64)
        self.assertFalse(data["input"]["raw_text_included"])
        self.assertEqual(
            data["verdict_integrity"]["status"],
            "alpha_unvalidated_heuristic",
        )
        self.assertEqual(data["trust_map"]["overall"], "insufficient")
        self.assertTrue(data["trust_map"]["dimensions"])

    def test_local_web_ui_forwards_detector_selection(self):
        from unittest.mock import patch

        with patch("textforensics.webapp.build_forensic_bundle") as build:
            build.return_value.to_dict.return_value = {"ok": True}
            result = analyze_payload(
                {"text": HUMANISH},
                detector_ids=("textforensics/builtin-heuristic",),
            )
        self.assertEqual(result, {"ok": True})
        build.assert_called_once_with(
            HUMANISH,
            detector_ids=("textforensics/builtin-heuristic",),
        )

    def test_local_web_ui_uses_evidence_coverage(self):
        self.assertIn("TextForensics", HTML)
        self.assertIn("Evidence coverage", HTML)
        result = analyze_payload({"text": HUMANISH})
        self.assertEqual(
            result["schema"],
            "textforensics.forensic-bundle/v1",
        )
        with self.assertRaises(ValueError):
            analyze_payload({"text": ""})
        with self.assertRaises(ValueError):
            analyze_payload(
                {"text": "é" * 20},
                max_input_bytes=10,
            )


if __name__ == "__main__":
    unittest.main()
