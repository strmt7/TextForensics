"""Tests for threshold selection module."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from textforensics.threshold_selection import (
    create_calibration_artifact,
    evaluate_threshold,
    load_threshold_artifact,
    run_calibration_evaluation,
    select_threshold,
    validate_no_contamination,
)

# Standard test samples
HUMAN_SAMPLE = "I ran this test yesterday. The first result looked odd, " \
               "so I changed one cable and wrote down the second result."
AI_SAMPLE = "Furthermore, it is important to note that this robust solution " \
            "seamlessly unlocks the potential of an ever-evolving landscape."


def write_calibration_dataset(path: Path, n_human: int = 5, n_ai: int = 5) -> float:
    """Write a calibration dataset with human-like and AI-like scores."""
    rows = []
    # Human samples with high pattern scores (false positive risk)
    for i in range(n_human):
        rows.append({"label": "human", "text": HUMAN_SAMPLE + f" observation {i}"})
    # AI samples with low pattern scores (higher detection)
    for i in range(n_ai):
        rows.append({"label": "ai", "text": AI_SAMPLE + f" sample {i}"})
    path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )
    return n_human, n_ai


def write_evaluation_dataset(
    path: Path,
    n_human: int = 3,
    n_ai: int = 3,
) -> None:
    """Write an evaluation dataset with different content."""
    rows = []
    for i in range(n_human):
        rows.append({"label": "human", "text": HUMAN_SAMPLE + f" eval {i}"})
    for i in range(n_ai):
        rows.append({"label": "ai", "text": AI_SAMPLE + f" eval {i}"})
    path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )


class SelectThresholdTests(unittest.TestCase):
    """Tests for select_threshold function."""

    def test_select_threshold_basic(self):
        """Test basic threshold selection."""
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "calibration.jsonl"
            write_calibration_dataset(cal_path)

            result = select_threshold(cal_path, target_fpr=0.05)

            self.assertIsNotNone(result.threshold)
            self.assertTrue(0 < result.threshold <= 1.0)
            self.assertTrue(0 <= result.observed_fpr <= 1.0)
            self.assertTrue(0 <= result.observed_tpr <= 1.0)
            self.assertGreater(result.human_samples, 0)
            self.assertGreater(result.ai_samples, 0)

    def test_select_threshold_tracks_dataset_hash(self):
        """Test that threshold selection records dataset hash."""
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "calibration.jsonl"
            write_calibration_dataset(cal_path)

            result = select_threshold(cal_path, target_fpr=0.05)
            artifact = result.to_dict()

            # The recorded hash should match the file hash
            from textforensics.benchmark import dataset_sha256
            expected_hash = dataset_sha256(cal_path)
            self.assertEqual(artifact["calibration_dataset_hash"], expected_hash)

    def test_select_threshold_invalid_target_fpr(self):
        """Test that invalid target FPR is rejected."""
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "calibration.jsonl"
            write_calibration_dataset(cal_path)

            with self.assertRaises(ValueError):
                select_threshold(cal_path, target_fpr=1.5)

            with self.assertRaises(ValueError):
                select_threshold(cal_path, target_fpr=-0.1)

    def test_select_threshold_missing_label(self):
        """Test that calibration fails with single-class data."""
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "only_ai.jsonl"
            rows = [{"label": "ai", "text": AI_SAMPLE}] * 3
            cal_path.write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="utf-8",
            )

            with self.assertRaises(ValueError) as ctx:
                select_threshold(cal_path)

            self.assertIn("human", str(ctx.exception).lower())

    def test_select_threshold_respects_target_fpr(self):
        """Test that selected threshold meets target FPR constraint."""
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "calibration.jsonl"
            # Create dataset where we can control FPR
            n_human, n_ai = write_calibration_dataset(cal_path, n_human=10, n_ai=10)

            target_fpr = 0.1
            result = select_threshold(cal_path, target_fpr=target_fpr)

            # Observed FPR should be <= target FPR
            self.assertLessEqual(result.observed_fpr, target_fpr)


class EvaluateThresholdTests(unittest.TestCase):
    """Tests for evaluate_threshold function."""

    def test_evaluate_on_held_out_data(self):
        """Test evaluation on separate data."""
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "calibration.jsonl"
            eval_path = Path(tmp) / "evaluation.jsonl"

            write_calibration_dataset(cal_path)
            write_evaluation_dataset(eval_path)

            # First select threshold
            cal_result = select_threshold(cal_path, target_fpr=0.05)

            # Then evaluate
            eval_result = evaluate_threshold(
                eval_path,
                cal_result.threshold,
                calibration_dataset_hash="dummy_for_testing",
            )

            self.assertEqual(eval_result.tp + eval_result.fp + eval_result.tn + eval_result.fn,
                           eval_result.evaluated)
            self.assertTrue(0 <= eval_result.accuracy <= 1)

    def test_evaluate_rejects_same_dataset(self):
        """Test that evaluation rejects same dataset as calibration."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_calibration_dataset(path)

            cal_result = select_threshold(path, target_fpr=0.05)
            # Use the actual dataset hash, not Python's hash()
            from textforensics.benchmark import dataset_sha256
            same_hash = dataset_sha256(path)

            with self.assertRaises(ValueError) as ctx:
                evaluate_threshold(
                    path,
                    cal_result.threshold,
                    calibration_dataset_hash=same_hash,
                )

            self.assertIn("matches the calibration", str(ctx.exception).lower())

    def test_evaluate_with_allow_same_dataset(self):
        """Test diagnostic evaluation with allow_same_dataset=True."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_calibration_dataset(path, n_human=3, n_ai=3)  # Match expected 6

            cal_result = select_threshold(path, target_fpr=0.05)

            # This should work with allow_same_dataset
            result = evaluate_threshold(
                path,
                cal_result.threshold,
                calibration_dataset_hash="dummy",
                allow_same_dataset=True,
            )

            self.assertEqual(result.evaluated, 6)  # 3 human + 3 ai


class ValidateNoContaminationTests(unittest.TestCase):
    """Tests for validate_no_contamination function."""

    def test_validate_disjoint_datasets(self):
        """Test validation passes for disjoint datasets."""
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "calibration.jsonl"
            eval_path = Path(tmp) / "evaluation.jsonl"

            write_calibration_dataset(cal_path)
            write_evaluation_dataset(eval_path)

            result = validate_no_contamination(cal_path, eval_path)

            self.assertTrue(result["valid"])
            self.assertFalse(result["contamination_detected"])

    def test_validate_contaminated_datasets(self):
        """Test detection of contaminated datasets."""
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "calibration.jsonl"
            eval_path = Path(tmp) / "evaluation.jsonl"

            # Common sample
            shared = "This is a shared sample text"
            cal_path.write_text(
                json.dumps({"label": "human", "text": shared}) + "\n" +
                json.dumps({"label": "ai", "text": AI_SAMPLE}) + "\n",
                encoding="utf-8",
            )
            eval_path.write_text(
                json.dumps({"label": "human", "text": shared}) + "\n" +
                json.dumps({"label": "ai", "text": AI_SAMPLE}) + "\n",
                encoding="utf-8",
            )

            result = validate_no_contamination(cal_path, eval_path)

            self.assertFalse(result["valid"])
            self.assertTrue(result["contamination_detected"])

    def test_validate_identical_files(self):
        """Test that identical files are flagged as contaminated."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "same.jsonl"
            write_calibration_dataset(path)

            result = validate_no_contamination(path, path)

            self.assertFalse(result["valid"])
            self.assertTrue(result["contamination_detected"])


class RunCalibrationEvaluationTests(unittest.TestCase):
    """Tests for run_calibration_evaluation pipeline."""

    def test_full_pipeline_success(self):
        """Test full calibration and evaluation pipeline."""
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "calibration.jsonl"
            eval_path = Path(tmp) / "evaluation.jsonl"

            write_calibration_dataset(cal_path)
            write_evaluation_dataset(eval_path)

            result = run_calibration_evaluation(
                cal_path,
                eval_path,
                target_fpr=0.05,
            )

            self.assertIn("calibration_result", result)
            self.assertIn("evaluation_result", result)
            self.assertIn("validation", result)

            cal_result = result["calibration_result"]
            self.assertIn("threshold", cal_result)
            self.assertIn("calibration_dataset_hash", cal_result)

            eval_result = result["evaluation_result"]
            self.assertIn("test_dataset_hash", eval_result)
            self.assertEqual(eval_result["evaluation_mode"], "held_out")

    def test_full_pipeline_rejects_contamination(self):
        """Test pipeline rejects contaminated data."""
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "calibration.jsonl"
            eval_path = Path(tmp) / "evaluation.jsonl"

            # Same content in both
            shared = "Same content in both datasets"
            cal_path.write_text(
                json.dumps({"label": "human", "text": shared}) + "\n",
                encoding="utf-8",
            )
            eval_path.write_text(
                json.dumps({"label": "human", "text": shared}) + "\n",
                encoding="utf-8",
            )

            with self.assertRaises(ValueError) as ctx:
                run_calibration_evaluation(cal_path, eval_path)

            self.assertIn("contamination", str(ctx.exception).lower())


class ArtifactSerializationTests(unittest.TestCase):
    """Tests for threshold artifact serialization."""

    def test_load_invalid_artifact_type(self):
        """Test that non-object artifacts are rejected."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "artifact.json"
            path.write_text("[]", encoding="utf-8")

            with self.assertRaises(ValueError):
                load_threshold_artifact(path)

    def test_load_artifact_missing_fields(self):
        """Test that artifacts missing required fields are rejected."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "artifact.json"
            path.write_text(json.dumps({"name": "test"}), encoding="utf-8")

            with self.assertRaises(ValueError):
                load_threshold_artifact(path)

    def test_load_valid_artifact(self):
        """Test loading a valid threshold artifact."""
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "cal.jsonl"
            write_calibration_dataset(cal_path)

            # Create artifact
            result = select_threshold(cal_path, target_fpr=0.05)
            artifact_path = Path(tmp) / "artifact.json"
            create_calibration_artifact(result, artifact_path)

            # Load and verify
            loaded = load_threshold_artifact(artifact_path)
            self.assertEqual(loaded["threshold"], result.threshold)
            self.assertEqual(
                loaded["calibration_dataset_hash"],
                result.calibration_dataset_hash,
            )

    def test_create_artifact_file(self):
        """Test creating artifact file."""
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "cal.jsonl"
            write_calibration_dataset(cal_path)

            result = select_threshold(cal_path, target_fpr=0.05)
            artifact_path = Path(tmp) / "artifact.json"

            created = create_calibration_artifact(result, artifact_path)
            self.assertEqual(created, artifact_path)
            self.assertTrue(artifact_path.exists())


class ThresholdTrackingTests(unittest.TestCase):
    """Tests for data usage tracking."""

    def test_calibration_vs_evaluation_data_tracking(self):
        """Test that calibration and evaluation data are tracked separately."""
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "calibration.jsonl"
            eval_path = Path(tmp) / "evaluation.jsonl"

            write_calibration_dataset(cal_path, n_human=10, n_ai=10)
            write_evaluation_dataset(eval_path, n_human=5, n_ai=5)

            # Select threshold (uses calibration data)
            cal_result = select_threshold(cal_path, target_fpr=0.05)
            artifact = cal_result.to_dict()

            # Verify it records calibration dataset hash
            self.assertEqual(len(artifact["calibration_dataset_hash"]), 64)

            # Evaluate (uses test data)
            eval_result = evaluate_threshold(
                eval_path,
                cal_result.threshold,
                calibration_dataset_hash=cal_result.calibration_dataset_hash,
            )

            # Verify it records test dataset hash
            self.assertEqual(len(eval_result.test_dataset_hash), 64)
            # And that they're different
            self.assertNotEqual(eval_result.test_dataset_hash, eval_result.calibration_dataset_hash)


class ThresholdSelectionResultTests(unittest.TestCase):
    """Tests for ThresholdSelectionResult edge cases."""

    def test_to_dict_with_warning(self):
        """Test to_dict includes warning when present."""
        from textforensics.threshold_selection import ThresholdSelectionResult
        
        result = ThresholdSelectionResult(
            threshold=0.5,
            observed_fpr=0.01,
            observed_tpr=0.8,
            target_fpr=0.01,
            human_samples=10,
            ai_samples=10,
            detector_id="test",
            detector_version="1.0",
            calibration_dataset_hash="a" * 64,
            warning="Custom warning message",
        )
        artifact = result.to_dict()
        self.assertEqual(artifact["warning"], "Custom warning message")


class ValidateNoContaminationTests(unittest.TestCase):
    """Tests for validate_no_contamination edge cases."""

    def test_validate_identical_files(self):
        """Test that identical files are flagged as contaminated."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "same.jsonl"
            write_calibration_dataset(path)

            result = validate_no_contamination(path, path)

            self.assertFalse(result["valid"])
            self.assertTrue(result["contamination_detected"])
            self.assertEqual(result["shared_samples"], -1)


class GetTestSamplesTests(unittest.TestCase):
    """Tests for _get_test_samples function."""

    def test_get_test_samples_with_empty_lines(self):
        """Test _get_test_samples skips empty lines."""
        from textforensics.threshold_selection import _get_test_samples
        
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.jsonl"
            path.write_text(
                '{"label": "human", "text": "sample 1"}\n\n{"label": "ai", "text": "sample 2"}\n',
                encoding="utf-8",
            )
            
            samples = _get_test_samples(path)
            self.assertEqual(len(samples), 2)

    def test_get_test_samples_skips_invalid_json(self):
        """Test _get_test_samples skips invalid JSON lines."""
        from textforensics.threshold_selection import _get_test_samples
        
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.jsonl"
            path.write_text(
                '{"label": "human", "text": "sample 1"}\ninvalid json\n{"label": "ai", "text": "sample 2"}\n',
                encoding="utf-8",
            )
            
            samples = _get_test_samples(path)
            self.assertEqual(len(samples), 2)

    def test_get_test_samples_skips_non_dict(self):
        """Test _get_test_samples skips non-dict JSON."""
        from textforensics.threshold_selection import _get_test_samples
        
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.jsonl"
            path.write_text(
                '"just a string"\n{"label": "human", "text": "sample 1"}\n',
                encoding="utf-8",
            )
            
            samples = _get_test_samples(path)
            self.assertEqual(len(samples), 1)

    def test_get_test_samples_skips_no_text_field(self):
        """Test _get_test_samples skips rows without text field."""
        from textforensics.threshold_selection import _get_test_samples
        
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.jsonl"
            path.write_text(
                '{"label": "human"}\n{"label": "human", "text": "sample 1"}\n',
                encoding="utf-8",
            )
            
            samples = _get_test_samples(path)
            self.assertEqual(len(samples), 1)


class LoadThresholdArtifactTests(unittest.TestCase):
    """Tests for load_threshold_artifact edge cases."""

    def test_load_artifact_non_finite_threshold(self):
        """Test artifact with non-finite threshold is rejected."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "artifact.json"
            path.write_text(
                json.dumps({
                    "schema": "textforensics.threshold-selection/v1",
                    "threshold": float("inf"),
                    "calibration_dataset_hash": "a" * 64,
                }),
                encoding="utf-8",
            )
            
            with self.assertRaises(ValueError) as ctx:
                load_threshold_artifact(path)
            
            self.assertIn("finite", str(ctx.exception).lower())


class RunCalibrationEvaluationEdgeCases(unittest.TestCase):
    """Tests for run_calibration_evaluation edge cases."""

    def test_run_calibration_evaluation_with_strict_false(self):
        """Test run_calibration_evaluation with strict=False."""
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "calibration.jsonl"
            eval_path = Path(tmp) / "evaluation.jsonl"
            
            # Create datasets with some invalid lines
            cal_path.write_text(
                '{"label": "human", "text": "sample 1"}\ninvalid\n{"label": "ai", "text": "sample 2"}\n',
                encoding="utf-8",
            )
            eval_path.write_text(
                '{"label": "human", "text": "eval 1"}\n{"label": "ai", "text": "eval 2"}\n',
                encoding="utf-8",
            )
            
            # Should work with strict=False
            result = run_calibration_evaluation(
                cal_path,
                eval_path,
                target_fpr=0.5,  # High target to ensure threshold found
                strict=False,
            )
            
            self.assertIn("calibration_result", result)
            self.assertIn("evaluation_result", result)


if __name__ == "__main__":
    unittest.main()
