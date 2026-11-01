from __future__ import annotations

import unittest

from textforensics.detectors import BuiltinHeuristicDetector
from textforensics.report import (
    ForensicBundle,
    VerdictIntegrity,
    _integrity,
    _robustness_for_detector,
    build_forensic_bundle,
)

TEXT = (
    "I tested the device twice yesterday and wrote down what changed. "
    "The second run was warmer, so I plan to repeat it before drawing conclusions."
)


class BundleContractTests(unittest.TestCase):
    def test_bundle_schema_and_sha(self):
        bundle = build_forensic_bundle(TEXT)
        self.assertIsInstance(bundle, ForensicBundle)
        self.assertEqual(bundle.schema, "textforensics.forensic-bundle/v1")
        self.assertEqual(len(bundle.content_sha256), 64)
        self.assertFalse(bundle.input["raw_text_included"])
        self.assertEqual(bundle.input["word_count"], len(TEXT.split()))

    def test_bundle_serializes_without_raw_text(self):
        data = build_forensic_bundle(TEXT).to_dict()
        serialized = str(data)
        self.assertNotIn(TEXT, serialized)
        self.assertIn("trust_map", serialized)
        self.assertIn("consensus", serialized)
        self.assertIn("verdict_integrity", serialized)
        self.assertIn("robustness", serialized)
        self.assertIn("provenance", serialized)
        self.assertIn("limitations", serialized)

    def test_bundle_includes_plugin_health(self):
        data = build_forensic_bundle(TEXT).to_dict()
        self.assertTrue(data["plugin_health"])
        self.assertTrue(data["detector_results"])

    def test_bundle_records_failures_separately(self):
        class Failing:
            detector_id = "fake/failing"
            detector_version = "1"
            detector_family = "failure-family"

            def detect(self, text):
                raise RuntimeError("boom")

        data = build_forensic_bundle(TEXT, detectors=[Failing()]).to_dict()
        self.assertEqual(data["detector_results"], [])
        self.assertEqual(len(data["detector_failures"]), 1)
        self.assertEqual(data["consensus"]["verdict"], "abstain")
        self.assertTrue(
            any("failed" in limitation.lower() for limitation in data["limitations"])
        )

    def test_bundle_rejects_empty_text(self):
        with self.assertRaises(ValueError):
            build_forensic_bundle("")
        with self.assertRaises(ValueError):
            build_forensic_bundle("   ")

    def test_bundle_rejects_no_detectors(self):
        with self.assertRaises(ValueError):
            build_forensic_bundle(TEXT, detectors=[])

    def test_bundle_with_explicit_detectors_skips_health(self):
        data = build_forensic_bundle(
            TEXT, detectors=[BuiltinHeuristicDetector()]
        ).to_dict()
        self.assertEqual(data["plugin_health"], [])
        self.assertEqual(len(data["detector_results"]), 1)


class RobustnessProbeTests(unittest.TestCase):
    def test_robustness_records_native_score_range(self):
        detector = BuiltinHeuristicDetector()
        prediction = detector.detect(TEXT)
        row = _robustness_for_detector(detector, TEXT, prediction)
        self.assertEqual(row["detector_id"], detector.detector_id)
        self.assertIn("native_score_range", row)
        self.assertIn("score_range_semantics", row)
        self.assertIn("verdict_stability", row)
        self.assertIn("probes", row)
        self.assertIn("failures", row)
        self.assertGreaterEqual(len(row["probes"]), 1)

    def test_robustness_records_probe_failures(self):
        class Flaky:
            detector_id = "fake/flaky"
            detector_version = "1"
            detector_family = "flaky-family"

            def __init__(self):
                self.calls = 0

            def detect(self, text):
                from textforensics.detectors import DetectorPrediction

                self.calls += 1
                if self.calls > 1:
                    raise RuntimeError("probe failure")
                return DetectorPrediction(
                    schema="textforensics.detector-result/v1",
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    detector_family=self.detector_family,
                    execution="local",
                    score=0.5,
                    score_semantics="test",
                    verdict="ai_like",
                    threshold=0.5,
                    calibrated_ai_probability=None,
                    calibration_id=None,
                )

        detector = Flaky()
        original = detector.detect(TEXT)
        row = _robustness_for_detector(detector, TEXT, original)
        self.assertGreaterEqual(len(row["failures"]), 1)


class IntegrityTests(unittest.TestCase):
    def test_integrity_status_is_alpha_unvalidated(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        self.assertEqual(
            bundle["verdict_integrity"]["status"],
            "alpha_unvalidated_heuristic",
        )

    def test_integrity_serializes(self):
        predictions = [BuiltinHeuristicDetector().detect(TEXT)]
        robustness = [
            _robustness_for_detector(BuiltinHeuristicDetector(), TEXT, predictions[0])
        ]
        integrity = _integrity(predictions, len(TEXT.split()), robustness)
        self.assertIsInstance(integrity, VerdictIntegrity)
        self.assertTrue(0.0 <= integrity.score <= 1.0)
        self.assertIn(integrity.grade, {"A", "B", "C", "D", "INSUFFICIENT"})


class LimitationsTests(unittest.TestCase):
    def test_bundle_always_states_text_only_is_not_proof(self):
        data = build_forensic_bundle(TEXT).to_dict()
        self.assertTrue(
            any("not proof of authorship" in limitation.lower() for limitation in data["limitations"])
        )

    def test_bundle_always_states_scores_are_not_probabilities(self):
        data = build_forensic_bundle(TEXT).to_dict()
        self.assertTrue(
            any("not treated as comparable probabilities" in limitation.lower() for limitation in data["limitations"])
        )

    def test_bundle_states_trust_map_is_not_probability(self):
        data = build_forensic_bundle(TEXT).to_dict()
        self.assertTrue(
            any("not an authorship probability" in limitation.lower() for limitation in data["limitations"])
        )


if __name__ == "__main__":
    unittest.main()
