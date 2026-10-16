import unittest
from unittest.mock import patch

from textforensics.detector_desklib import (
    DETECTOR_VERSION,
    MODEL_ID,
    MODEL_REVISION,
    MODEL_WEIGHTS_SHA256,
    DesklibDetector,
)
from textforensics.detectors import (
    list_optional_detector_metadata,
)


LONG_TEXT = " ".join(
    f"word{index}" for index in range(120)
)


class DesklibAdapterTests(unittest.TestCase):
    @patch(
        "textforensics.detector_desklib._missing_dependencies",
        return_value=[],
    )
    def test_native_score_is_not_exposed_as_calibrated_probability(self, _):
        detector = DesklibDetector()
        with patch.object(
            detector,
            "_predict_score",
            return_value=(0.91, "cpu"),
        ):
            result = detector.detect(LONG_TEXT)

        self.assertEqual(result.detector_id, MODEL_ID)
        self.assertEqual(result.detector_version, DETECTOR_VERSION)
        self.assertEqual(result.detector_family, "supervised-transformer")
        self.assertEqual(result.verdict, "ai_like")
        self.assertEqual(result.score, 0.91)
        self.assertIsNone(result.calibrated_ai_probability)
        self.assertIsNone(result.calibration_id)
        self.assertTrue(
            result.score_semantics.startswith(
                "higher_means_more_machine_like"
            )
        )
        self.assertTrue(
            any("not treat it as a calibrated" in item for item in result.warnings)
        )

    @patch(
        "textforensics.detector_desklib._missing_dependencies",
        return_value=[],
    )
    def test_short_text_abstains_without_loading_model(self, _):
        detector = DesklibDetector(min_words=80)
        with patch.object(
            detector,
            "_predict_score",
            side_effect=AssertionError("model should not load"),
        ):
            result = detector.detect("short input")
        self.assertEqual(result.verdict, "abstain")
        self.assertIsNone(result.score)

    @patch(
        "textforensics.detector_desklib._missing_dependencies",
        return_value=[],
    )
    def test_threshold_validation(self, _):
        with self.assertRaises(ValueError):
            DesklibDetector(threshold=1.1)

    def test_optional_detector_metadata_is_pinned(self):
        rows = {
            row["detector_id"]: row
            for row in list_optional_detector_metadata()
        }
        row = rows[MODEL_ID]
        self.assertEqual(row["detector_version"], DETECTOR_VERSION)
        self.assertFalse(row["enabled_by_default"])
        self.assertEqual(len(MODEL_REVISION), 40)
        self.assertEqual(len(MODEL_WEIGHTS_SHA256), 64)


if __name__ == "__main__":
    unittest.main()
