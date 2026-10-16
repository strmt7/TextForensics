import unittest
from unittest.mock import patch

from textforensics.detector_rai import (
    ALIGNED_MODEL_REVISION,
    ALIGNED_WEIGHTS_SHA256,
    BASE_MODEL_REVISION,
    BASE_WEIGHTS_SHA256,
    DETECTOR_ID,
    DETECTOR_VERSION,
    QwenRAIDetector,
)


LONG_TEXT = " ".join(f"word{index}" for index in range(120))


class QwenRAIAdapterTests(unittest.TestCase):
    @patch(
        "textforensics.detector_rai._missing_dependencies",
        return_value=[],
    )
    def test_continuous_score_abstains_until_calibrated(self, _):
        detector = QwenRAIDetector()
        with patch.object(
            detector,
            "_score",
            return_value=(0.1234567, -2.1, -1.9765433, "cpu", 110),
        ):
            result = detector.detect(LONG_TEXT)

        self.assertEqual(result.detector_id, DETECTOR_ID)
        self.assertEqual(result.detector_version, DETECTOR_VERSION)
        self.assertEqual(result.detector_family, "alignment-likelihood")
        self.assertEqual(result.score, 0.123457)
        self.assertEqual(result.verdict, "abstain")
        self.assertIsNone(result.threshold)
        self.assertIsNone(result.calibrated_ai_probability)
        self.assertTrue(
            result.score_semantics.startswith(
                "higher_means_more_machine_like"
            )
        )
        self.assertTrue(
            any(
                "separately validated threshold" in warning
                for warning in result.warnings
            )
        )

    @patch(
        "textforensics.detector_rai._missing_dependencies",
        return_value=[],
    )
    def test_short_text_abstains_without_loading_models(self, _):
        detector = QwenRAIDetector(min_words=80)
        with patch.object(
            detector,
            "_score",
            side_effect=AssertionError("models should not load"),
        ):
            result = detector.detect("short input")
        self.assertEqual(result.verdict, "abstain")
        self.assertIsNone(result.score)

    def test_revisions_and_weight_hashes_are_immutable_identifiers(self):
        self.assertEqual(len(BASE_MODEL_REVISION), 40)
        self.assertEqual(len(ALIGNED_MODEL_REVISION), 40)
        self.assertEqual(len(BASE_WEIGHTS_SHA256), 64)
        self.assertEqual(len(ALIGNED_WEIGHTS_SHA256), 64)
        self.assertNotEqual(BASE_MODEL_REVISION, ALIGNED_MODEL_REVISION)

    @patch(
        "textforensics.detector_rai._missing_dependencies",
        return_value=[],
    )
    def test_configuration_validation(self, _):
        with self.assertRaises(ValueError):
            QwenRAIDetector(max_length=32)
        with self.assertRaises(ValueError):
            QwenRAIDetector(min_words=0)


if __name__ == "__main__":
    unittest.main()
