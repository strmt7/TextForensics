import json
import tempfile
import unittest
from pathlib import Path

from textforensics.benchmark import (
    DatasetFormatError,
    benchmark_jsonl,
    benchmark_with_calibration_jsonl,
    calibrate_threshold_jsonl,
    dataset_sha256,
    validate_calibration_artifact,
)


HUMAN = (
    "I ran the test twice this morning. The first result looked wrong, "
    "so I changed the cable and wrote the new values in my notebook."
)
AI = (
    "Furthermore, it is important to note that this robust solution "
    "seamlessly unlocks the potential of an ever-evolving landscape."
)


def write_dataset(path: Path, human_suffix: str = "", ai_suffix: str = "") -> None:
    rows = [
        {"label": "human", "text": HUMAN + human_suffix},
        {"label": "human", "text": HUMAN + " Another observation." + human_suffix},
        {"label": "ai", "text": AI + ai_suffix},
        {"label": "ai", "text": AI + " Moreover, this approach is multifaceted." + ai_suffix},
    ]
    path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )


class BenchmarkTests(unittest.TestCase):
    def test_dataset_fingerprint_is_stable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            first = dataset_sha256(path)
            second = dataset_sha256(path)
            self.assertEqual(first, second)
            self.assertEqual(len(first), 64)

    def test_invalid_jsonl_fails_in_strict_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.jsonl"
            path.write_text('{"label":"human"}\n', encoding="utf-8")
            with self.assertRaises(DatasetFormatError):
                benchmark_jsonl(path)

    def test_calibration_artifact_is_explicitly_calibration_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "calibration.jsonl"
            write_dataset(path)
            artifact = calibrate_threshold_jsonl(path, target_fpr=0.0)
            self.assertEqual(
                artifact["mode"],
                "calibration_only_not_final_evaluation",
            )
            self.assertEqual(
                artifact["calibration_dataset_sha256"],
                dataset_sha256(path),
            )
            validate_calibration_artifact(artifact)

    def test_same_dataset_is_rejected_for_held_out_evaluation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            artifact = calibrate_threshold_jsonl(path, target_fpr=0.0)
            with self.assertRaises(ValueError):
                benchmark_with_calibration_jsonl(path, artifact)

    def test_separate_evaluation_dataset_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            calibration = Path(tmp) / "calibration.jsonl"
            evaluation = Path(tmp) / "evaluation.jsonl"
            write_dataset(calibration)
            write_dataset(
                evaluation,
                human_suffix=" This is the evaluation split.",
                ai_suffix=" This is a separate evaluation sample.",
            )
            artifact = calibrate_threshold_jsonl(calibration, target_fpr=0.0)
            result = benchmark_with_calibration_jsonl(
                evaluation,
                artifact,
            )
            self.assertEqual(result["mode"], "held_out_evaluation")
            self.assertNotEqual(
                result["dataset_sha256"],
                result["calibration_dataset_sha256"],
            )
            self.assertIn("false_positive_rate", result)
            self.assertIn("true_positive_rate", result)

    def test_mismatched_detector_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "calibration.jsonl"
            write_dataset(path)
            artifact = calibrate_threshold_jsonl(path)
            artifact["detector_version"] = "wrong"
            with self.assertRaises(ValueError):
                validate_calibration_artifact(artifact)

    def test_fixed_threshold_benchmark_is_labeled_diagnostic(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            result = benchmark_jsonl(path, threshold=0.5)
            self.assertEqual(result["mode"], "diagnostic_fixed_threshold")
            self.assertEqual(result["evaluated"], 4)


if __name__ == "__main__":
    unittest.main()
