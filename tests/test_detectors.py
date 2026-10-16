import unittest
from unittest.mock import patch

from textforensics.consensus import family_balanced_consensus
from textforensics.detectors import (
    DetectorContractError,
    DetectorPrediction,
    discover_detector_registry,
    execute_detector,
    validate_prediction,
)
from textforensics.report import build_forensic_bundle


def prediction(
    detector_id="detector",
    family="family",
    verdict="ai_like",
    score=0.8,
    probability=None,
    calibration_id=None,
):
    return DetectorPrediction(
        schema="textforensics.detector-result/v1",
        detector_id=detector_id,
        detector_version="1",
        detector_family=family,
        execution="local",
        score=score,
        score_semantics="test native score",
        verdict=verdict,
        threshold=0.5,
        calibrated_ai_probability=probability,
        calibration_id=calibration_id,
    )


class FakeDetector:
    detector_id = "fake/detector"
    detector_version = "1"
    detector_family = "fake-family"

    def detect(self, text):
        return prediction(
            detector_id=self.detector_id,
            family=self.detector_family,
        )


class LargeScaleDetector:
    detector_id = "fake/large-scale"
    detector_version = "1"
    detector_family = "large-native-scale"

    def detect(self, text):
        return prediction(
            detector_id=self.detector_id,
            family=self.detector_family,
            verdict="human_like",
            score=float(len(text) * 10),
        )


class EchoWarningDetector:
    detector_id = "fake/echo-warning"
    detector_version = "1"
    detector_family = "echo-family"

    def detect(self, text):
        result = prediction(
            detector_id=self.detector_id,
            family=self.detector_family,
        )
        result.warnings = [f"Provider response: {text}"]
        return result


class FailingDetector:
    detector_id = "fake/failing"
    detector_version = "1"
    detector_family = "failure-family"

    def detect(self, text):
        raise RuntimeError("secret submitted text must never appear")


class BadEntryPoint:
    name = "bad-plugin"

    def load(self):
        raise RuntimeError("provider echoed secret source text")


class DetectorContractTests(unittest.TestCase):
    def test_native_score_is_not_forced_into_probability_range(self):
        result = prediction(score=12.5)
        validate_prediction(result)

    def test_probability_requires_calibration_id(self):
        result = prediction(probability=0.7)
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_probability_with_calibration_id_is_valid(self):
        result = prediction(
            probability=0.7,
            calibration_id="calibration-1",
        )
        validate_prediction(result)

    def test_raw_text_evidence_fields_are_rejected(self):
        result = prediction()
        result.evidence = [{"snippet": "private source text"}]
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_nested_raw_text_evidence_fields_are_rejected(self):
        result = prediction()
        result.evidence = [{"details": {"snippet": "private source text"}}]
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_source_echo_in_warning_fails_closed(self):
        submitted = (
            "This is private submitted source text with enough length "
            "to trigger source-echo protection."
        )
        _, failure = execute_detector(EchoWarningDetector(), submitted)
        self.assertIsNotNone(failure)
        self.assertEqual(failure.error_type, "DetectorContractError")
        self.assertNotIn(submitted, failure.message)

    def test_detector_identity_must_match_adapter(self):
        result = prediction(detector_id="wrong")
        with self.assertRaises(DetectorContractError):
            validate_prediction(result, detector=FakeDetector())

    def test_execution_failure_redacts_exception_message(self):
        _, failure = execute_detector(
            FailingDetector(),
            "private source text",
        )
        self.assertIsNotNone(failure)
        self.assertNotIn("secret submitted", failure.message)

    def test_native_score_stability_is_not_normalized_implicitly(self):
        data = build_forensic_bundle(
            "A stable test sentence with enough variation for representation probes.",
            detectors=[LargeScaleDetector()],
        ).to_dict()
        robustness = data["robustness"]["detectors"][0]
        self.assertIn("native_score_range", robustness)
        self.assertNotIn("score_stability", robustness)
        self.assertGreaterEqual(robustness["native_score_range"], 0)
        stability = next(
            row
            for row in data["trust_map"]["dimensions"]
            if row["dimension"] == "benign_stability"
        )
        self.assertEqual(stability["state"], "supported")

    def test_report_survives_detector_failure(self):
        data = build_forensic_bundle(
            "A sufficiently ordinary test sentence for failure handling.",
            detectors=[FailingDetector()],
        ).to_dict()
        self.assertEqual(data["detector_results"], [])
        self.assertEqual(len(data["detector_failures"]), 1)
        self.assertEqual(data["consensus"]["verdict"], "abstain")
        self.assertEqual(data["trust_map"]["overall"], "insufficient")

    def test_plugin_health_surfaces_load_failure_without_secret(self):
        with patch(
            "textforensics.detectors._entry_points",
            return_value=[BadEntryPoint()],
        ):
            registry = discover_detector_registry()
        bad = [
            item
            for item in registry.plugin_health
            if item.entry_point == "bad-plugin"
        ][0]
        self.assertEqual(bad.status, "error")
        self.assertNotIn("secret", bad.message)

    def test_family_balancing_prevents_duplicate_family_vote_inflation(self):
        result = family_balanced_consensus(
            [
                prediction("a1", "transformer", "ai_like"),
                prediction("a2", "transformer", "ai_like"),
                prediction("b1", "likelihood", "human_like"),
            ]
        )
        self.assertEqual(result.independent_families, 2)
        self.assertEqual(result.verdict, "abstain")
        self.assertEqual(len(result.family_votes), 2)

    def test_component_probabilities_are_not_averaged_into_ensemble(self):
        result = family_balanced_consensus(
            [
                prediction(
                    "a",
                    "transformer",
                    "ai_like",
                    probability=0.9,
                    calibration_id="a-cal",
                ),
                prediction(
                    "b",
                    "likelihood",
                    "ai_like",
                    probability=0.8,
                    calibration_id="b-cal",
                ),
            ]
        )
        self.assertIsNone(result.calibrated_ai_probability)
        self.assertTrue(
            any(
                "separately" in warning.lower()
                for warning in result.warnings
            )
        )

    def test_top_level_probability_requires_ensemble_calibration(self):
        rows = [prediction("a", "transformer", "ai_like")]
        with self.assertRaises(ValueError):
            family_balanced_consensus(
                rows,
                ensemble_probability=0.75,
            )
        result = family_balanced_consensus(
            rows,
            ensemble_probability=0.75,
            ensemble_calibration_id="ensemble-v1",
        )
        self.assertEqual(result.calibrated_ai_probability, 0.75)


if __name__ == "__main__":
    unittest.main()
