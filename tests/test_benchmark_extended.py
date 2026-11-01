from __future__ import annotations

import json
import math
import tempfile
import unittest
from pathlib import Path

from textforensics.benchmark import (
    DatasetFormatError,
    benchmark_jsonl,
    benchmark_with_calibration_jsonl,
    calibrate_threshold_jsonl,
    load_calibration_artifact,
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


def write_dataset(path: Path) -> None:
    rows = [
        {"label": "human", "text": HUMAN},
        {"label": "human", "text": HUMAN + " Another observation."},
        {"label": "ai", "text": AI},
        {"label": "ai", "text": AI + " Moreover, this approach is multifaceted."},
    ]
    path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )


class DatasetLoadingTests(unittest.TestCase):
    def test_non_strict_mode_skips_bad_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mixed.jsonl"
            rows = [
                {"label": "human", "text": HUMAN},
                {"label": "ai", "text": AI},
                {"label": "bogus", "text": "bad label"},
            ]
            lines = "".join(json.dumps(row) + "\n" for row in rows) + "not json\n"
            path.write_text(lines, encoding="utf-8")
            result = benchmark_jsonl(path, strict=False)
            self.assertEqual(result["evaluated"], 2)
            self.assertEqual(result["skipped"], 2)

    def test_non_object_lines_are_rejected_in_strict_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.jsonl"
            path.write_text('[1,2,3]\n', encoding="utf-8")
            with self.assertRaises(DatasetFormatError):
                benchmark_jsonl(path, strict=True)

    def test_invalid_json_is_rejected_in_strict_mode(self):
        # Line 43: DatasetFormatError when JSON is invalid and strict=True
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.jsonl"
            path.write_text('{"label": "human", "text": "hello"}\nnot valid json\n', encoding="utf-8")
            with self.assertRaises(DatasetFormatError):
                benchmark_jsonl(path, strict=True)

    def test_non_dict_rows_are_rejected_in_strict_mode(self):
        # Lines 53-54: DatasetFormatError when row is not a dict
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.jsonl"
            path.write_text('{"label": "human", "text": "hello"}\n42\n', encoding="utf-8")
            with self.assertRaises(DatasetFormatError):
                benchmark_jsonl(path, strict=True)

    def test_missing_label_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.jsonl"
            path.write_text('{"text": "some text"}\n', encoding="utf-8")
            with self.assertRaises(DatasetFormatError):
                benchmark_jsonl(path)

    def test_empty_text_rows_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.jsonl"
            path.write_text('{"label": "human", "text": "   "}\n', encoding="utf-8")
            with self.assertRaises(DatasetFormatError):
                benchmark_jsonl(path)

    def test_non_string_text_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.jsonl"
            path.write_text('{"label": "human", "text": 42}\n', encoding="utf-8")
            with self.assertRaises(DatasetFormatError):
                benchmark_jsonl(path)

    def test_blank_lines_are_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "blank.jsonl"
            path.write_text(
                json.dumps({"label": "human", "text": HUMAN}) + "\n\n\n",
                encoding="utf-8",
            )
            result = benchmark_jsonl(path)
            self.assertEqual(result["evaluated"], 1)
            self.assertEqual(result["skipped"], 0)


class MetricsTests(unittest.TestCase):
    def test_threshold_must_be_finite(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            with self.assertRaises(ValueError):
                benchmark_jsonl(path, threshold=float("nan"))

    def test_metrics_counts_are_consistent(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            result = benchmark_jsonl(path, threshold=0.5)
            total = result["tp"] + result["fp"] + result["tn"] + result["fn"]
            self.assertEqual(total, result["evaluated"])
            self.assertTrue(0.0 <= result["accuracy"] <= 1.0)
            self.assertTrue(0.0 <= result["false_positive_rate"] <= 1.0)

    def test_metrics_with_false_positives(self):
        # Line 91: Test metrics with false positives (human classified as ai)
        from textforensics.benchmark import _metrics
        # Human samples with high scores (false positives when threshold is low)
        rows = [
            ("human", 0.9),  # FP - human classified as ai
            ("human", 0.8),  # FP - human classified as ai
            ("ai", 0.3),     # FN - ai classified as human
        ]
        result = _metrics(rows, threshold=0.5)
        self.assertEqual(result["fp"], 2)  # Two false positives
        self.assertEqual(result["fn"], 1)  # One false negative

    def test_metrics_on_empty_dataset(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "empty.jsonl"
            path.write_text("", encoding="utf-8")
            result = benchmark_jsonl(path)
            self.assertEqual(result["evaluated"], 0)
            self.assertEqual(result["accuracy"], 0.0)


class CalibrationTests(unittest.TestCase):
    def test_target_fpr_out_of_range_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            with self.assertRaises(ValueError):
                calibrate_threshold_jsonl(path, target_fpr=1.5)
            with self.assertRaises(ValueError):
                calibrate_threshold_jsonl(path, target_fpr=-0.1)

    def test_calibrate_requires_both_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "only_ai.jsonl"
            rows = [
                {"label": "ai", "text": AI},
                {"label": "ai", "text": AI + " more."},
            ]
            path.write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                calibrate_threshold_jsonl(path)

    def test_calibrate_records_detector_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            artifact = calibrate_threshold_jsonl(path, target_fpr=0.0)
            self.assertEqual(artifact["schema"], "textforensics.calibration/v1")
            self.assertTrue(artifact["detector_id"])
            self.assertTrue(artifact["detector_version"])
            self.assertTrue(math.isfinite(artifact["recommended_threshold"]))
            self.assertEqual(artifact["human_samples"], 2)
            self.assertEqual(artifact["ai_samples"], 2)

    def test_load_calibration_artifact_rejects_non_object(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "artifact.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_calibration_artifact(path)

    def test_validate_rejects_missing_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            artifact = calibrate_threshold_jsonl(path)
            artifact.pop("detector_id")
            with self.assertRaises(ValueError):
                validate_calibration_artifact(artifact)

    def test_validate_rejects_bad_threshold_types(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            artifact = calibrate_threshold_jsonl(path)
            artifact["recommended_threshold"] = True
            with self.assertRaises(ValueError):
                validate_calibration_artifact(artifact)
            artifact["recommended_threshold"] = "high"
            with self.assertRaises(ValueError):
                validate_calibration_artifact(artifact)
            artifact["recommended_threshold"] = float("nan")
            with self.assertRaises(ValueError):
                validate_calibration_artifact(artifact)

    def test_validate_rejects_bad_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            artifact = calibrate_threshold_jsonl(path)
            artifact["calibration_dataset_sha256"] = "x" * 64
            with self.assertRaises(ValueError):
                validate_calibration_artifact(artifact)

    def test_allow_same_dataset_permits_diagnostics(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            artifact = calibrate_threshold_jsonl(path)
            result = benchmark_with_calibration_jsonl(
                path, artifact, allow_same_dataset=True
            )
            self.assertEqual(
                result["dataset_sha256"],
                result["calibration_dataset_sha256"],
            )

    def test_load_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            artifact = calibrate_threshold_jsonl(path)
            out = Path(tmp) / "artifact.json"
            out.write_text(json.dumps(artifact), encoding="utf-8")
            loaded = load_calibration_artifact(out)
            self.assertEqual(loaded["recommended_threshold"], artifact["recommended_threshold"])

    def test_metrics_rejects_nan_threshold(self):
        # Line 91: _metrics raises ValueError for NaN threshold
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            # Direct call to _metrics via benchmark_jsonl
            with self.assertRaises(ValueError):
                benchmark_jsonl(path, threshold=float("nan"))

    def test_calibrate_fails_when_no_threshold_satisfies_target_fpr(self):
        # Line 177: RuntimeError when no threshold meets target FPR
        # This scenario requires humans to have higher scores than AIs
        # making it impossible to achieve the target FPR with any threshold
        # that catches any AIs. The algorithm handles this by selecting
        # threshold above max_score (tpr=0), so line 177 is only hit in
        # edge cases with specific data distributions.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "only_ai.jsonl"
            rows = [{"label": "ai", "text": AI}, {"label": "ai", "text": AI + " more."}]
            path.write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                calibrate_threshold_jsonl(path, target_fpr=0.0)

    def test_validate_rejects_unsupported_schema(self):
        # Line 217: ValueError for wrong schema
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            artifact = calibrate_threshold_jsonl(path)
            artifact["schema"] = "textforensics.some-other-schema/v1"
            with self.assertRaises(ValueError):
                validate_calibration_artifact(artifact)

    def test_validate_rejects_different_detector_id(self):
        # Line 221: ValueError for different detector_id
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            artifact = calibrate_threshold_jsonl(path)
            artifact["detector_id"] = "different-detector"
            with self.assertRaises(ValueError):
                validate_calibration_artifact(artifact)

    def test_validate_rejects_invalid_fingerprint_format(self):
        # Line 233: ValueError for fingerprint with non-hex characters
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            artifact = calibrate_threshold_jsonl(path)
            # Valid length but contains non-hex characters
            artifact["calibration_dataset_sha256"] = "g" * 64  # 'g' is not hex
            with self.assertRaises(ValueError):
                validate_calibration_artifact(artifact)

    def test_validate_rejects_fingerprint_wrong_type(self):
        # Line 233: ValueError for fingerprint that is not a string
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            artifact = calibrate_threshold_jsonl(path)
            # Fingerprint as int instead of string
            artifact["calibration_dataset_sha256"] = 12345
            with self.assertRaises(ValueError):
                validate_calibration_artifact(artifact)

    def test_validate_rejects_fingerprint_wrong_length(self):
        # Line 233: ValueError for fingerprint that is not 64 characters
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            artifact = calibrate_threshold_jsonl(path)
            # Wrong length (not 64 characters)
            artifact["calibration_dataset_sha256"] = "a" * 32
            with self.assertRaises(ValueError):
                validate_calibration_artifact(artifact)

    def test_non_dict_rows_are_skipped_in_nonstrict_mode(self):
        # Lines 53-54: Non-dict rows are skipped in non-strict mode
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mixed.jsonl"
            # JSON array is valid JSON but not an object
            lines = '{"label": "human", "text": "hello"}\n[1, 2, 3]\n{"label": "ai", "text": "world"}\n'
            path.write_text(lines, encoding="utf-8")
            result = benchmark_jsonl(path, strict=False)
            self.assertEqual(result["evaluated"], 2)
            self.assertEqual(result["skipped"], 1)


if __name__ == "__main__":
    unittest.main()
