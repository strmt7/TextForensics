import tempfile
import unittest
from pathlib import Path

from textforensics import analyze_text, compare_texts
from textforensics.naturalness import audit_naturalness
from textforensics.provenance import snapshot_file, verify_ledger
from textforensics.localize import localize_text
from textforensics.benchmark import calibrate_threshold_jsonl
from textforensics.detectors import BuiltinHeuristicDetector, DetectorPrediction, list_detector_metadata
from textforensics.consensus import family_balanced_consensus
from textforensics.report import build_forensic_bundle


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

    def test_detector_protocol_result(self):
        result = BuiltinHeuristicDetector().detect(HUMANISH)
        self.assertEqual(result.schema, "textforensics.detector-result/v1")
        self.assertEqual(result.detector_family, "stylometric-heuristic")
        self.assertIsNone(result.calibrated_ai_probability)
        self.assertIn(result.verdict, {"ai_like", "human_like", "abstain"})

    def test_detector_discovery_lists_builtin(self):
        ids = {row["detector_id"] for row in list_detector_metadata()}
        self.assertIn("textforensics/builtin-heuristic", ids)

    def test_forensic_bundle_is_evidence_grade_not_probability(self):
        bundle = build_forensic_bundle(HUMANISH)
        data = bundle.to_dict()
        self.assertEqual(data["schema"], "textforensics.forensic-bundle/v1")
        self.assertEqual(len(data["content_sha256"]), 64)
        self.assertEqual(data["verdict_integrity"]["detector_count"], 1)
        self.assertIn(data["verdict_integrity"]["grade"], {"D", "INSUFFICIENT"})
        self.assertIn("single_detector_family", data["verdict_integrity"]["factors"])

    def test_family_balanced_consensus_prevents_duplicate_family_votes(self):
        def pred(detector_id, family, verdict, probability=None):
            return DetectorPrediction(
                schema="textforensics.detector-result/v1",
                detector_id=detector_id,
                detector_version="1",
                detector_family=family,
                execution="local",
                score=0.8 if verdict == "ai_like" else 0.2,
                score_semantics="test",
                verdict=verdict,
                threshold=0.5,
                calibrated_ai_probability=probability,
            )

        result = family_balanced_consensus([
            pred("a1", "transformer", "ai_like"),
            pred("a2", "transformer", "ai_like"),
            pred("b1", "likelihood", "human_like"),
        ])
        self.assertEqual(result.independent_families, 2)
        self.assertEqual(result.verdict, "abstain")
        self.assertEqual(len(result.family_votes), 2)


if __name__ == "__main__":
    unittest.main()
