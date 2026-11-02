"""Tests for N-version integrity replay."""

import json
import tempfile
import unittest
from pathlib import Path

from textforensics.benchmark import (
    benchmark_jsonl,
    calibrate_threshold_jsonl,
)
from textforensics.casefile import seal_case_file
from textforensics.report import build_forensic_bundle
from textforensics.verify import (
    VerificationReport,
    verify_all,
    verify_benchmark,
    verify_calibration,
    verify_case_file,
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


class VerifyCaseFileTests(unittest.TestCase):
    """Tests for verify_case_file (N-version replay)."""

    TEXT = (
        "I tested the device twice yesterday and wrote down what changed. "
        "The second run was warmer, so I plan to repeat it before drawing conclusions."
    )

    def test_valid_case_file_passes(self):
        """A properly sealed case file should verify successfully."""
        bundle = build_forensic_bundle(self.TEXT).to_dict()
        case = seal_case_file(bundle)
        result = verify_case_file(case)
        self.assertTrue(result["valid"], f"Expected valid, got errors: {result.get('errors')}")
        self.assertTrue(result.get("seal_verified"))
        self.assertTrue(result.get("trust_map_verified"))

    def test_corrupted_case_hash_fails(self):
        """A case file with a tampered hash should fail verification."""
        bundle = build_forensic_bundle(self.TEXT).to_dict()
        case = seal_case_file(bundle)
        # Tamper with the hash
        case["case_sha256"] = "0" * 64
        result = verify_case_file(case)
        self.assertFalse(result["valid"])
        self.assertTrue(
            any("seal" in str(e) for e in result.get("errors", [])),
            f"Expected seal mismatch error, got: {result.get('errors')}",
        )

    def test_wrong_schema_fails(self):
        """A case file with wrong schema should fail."""
        case = {"schema": "wrong-schema", "case_sha256": "a" * 64}
        result = verify_case_file(case)
        self.assertFalse(result["valid"])
        self.assertIn("unexpected case schema", result.get("errors", [""])[0])

    def test_raw_text_included_fails(self):
        """A case file that includes raw text should fail."""
        bundle = build_forensic_bundle(self.TEXT).to_dict()
        case = seal_case_file(bundle)
        case["raw_text_included"] = True
        result = verify_case_file(case)
        self.assertFalse(result["valid"])
        self.assertIn("raw_text_included", result.get("errors", [""])[0])

    def test_missing_forensic_bundle_fails(self):
        """A case file without a forensic bundle should fail."""
        case = {"schema": "textforensics.case-file/v1", "raw_text_included": False}
        result = verify_case_file(case)
        self.assertFalse(result["valid"])

    def test_trust_map_manipulation_detected(self):
        """Tampering with Trust Map overall state should be detected."""
        bundle = build_forensic_bundle(self.TEXT).to_dict()
        case = seal_case_file(bundle)
        # Tamper with trust_map overall
        case["forensic_bundle"]["trust_map"]["overall"] = "strong"
        result = verify_case_file(case)
        self.assertFalse(result["valid"])
        errors = result.get("errors", [])
        self.assertTrue(
            any("trust_map" in str(e) for e in errors),
            f"Expected trust_map error, got: {errors}",
        )


class VerifyCalibrationTests(unittest.TestCase):
    """Tests for verify_calibration (N-version replay)."""

    def test_valid_calibration_passes(self):
        """A valid calibration artifact should verify successfully."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "calib.jsonl"
            write_dataset(path)
            artifact = calibrate_threshold_jsonl(path, target_fpr=0.01)
            result = verify_calibration(artifact)
            self.assertTrue(result["valid"], f"Errors: {result.get('errors')}")

    def test_wrong_schema_fails(self):
        """A calibration artifact with wrong schema should fail."""
        artifact = {"schema": "wrong", "detector_id": "d1"}
        result = verify_calibration(artifact)
        self.assertFalse(result["valid"])

    def test_missing_detector_id_fails(self):
        """A calibration artifact without detector_id should fail."""
        artifact = {
            "schema": "textforensics.calibration/v1",
            "detector_version": "1.0.0",
        }
        result = verify_calibration(artifact)
        self.assertFalse(result["valid"])

    def test_invalid_threshold_fails(self):
        """A calibration artifact with non-finite threshold should fail."""
        artifact = {
            "schema": "textforensics.calibration/v1",
            "detector_id": "textforensics/builtin-heuristic",
            "detector_version": "0.1.0",
            "recommended_threshold": float("nan"),
            "calibration_dataset_sha256": "a" * 64,
        }
        result = verify_calibration(artifact)
        self.assertFalse(result["valid"])

    def test_invalid_dataset_fingerprint_fails(self):
        """A calibration artifact with invalid dataset fingerprint should fail."""
        artifact = {
            "schema": "textforensics.calibration/v1",
            "detector_id": "textforensics/builtin-heuristic",
            "detector_version": "0.1.0",
            "recommended_threshold": 0.5,
            "calibration_dataset_sha256": "not-a-valid-hash",
        }
        result = verify_calibration(artifact)
        self.assertFalse(result["valid"])


class VerifyBenchmarkTests(unittest.TestCase):
    """Tests for verify_benchmark (N-version replay)."""

    def test_valid_benchmark_passes(self) -> None:
        """A valid benchmark result should verify successfully."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bench.jsonl"
            write_dataset(path)
            result = benchmark_jsonl(path, threshold=0.5)
            verification = verify_benchmark(result)
            self.assertTrue(verification["valid"], f"Errors: {verification.get('errors')}")

    def test_metric_mismatch_detected(self) -> None:
        """Metric mismatches between counts and rates should be detected."""
        result = {
            "schema": "textforensics.benchmark-result/v1",
            "dataset_sha256": "a" * 64,
            "threshold": 0.5,
            "tp": 10,
            "fp": 5,
            "tn": 85,
            "fn": 10,
            "evaluated": 100,
            "accuracy": 0.75,  # Actually (10+85)/100 = 0.95
            "true_positive_rate": 0.5,  # Actually 10/20 = 0.5, correct
            "false_positive_rate": 0.05,  # Actually 5/90 = 0.056
        }
        verification = verify_benchmark(result)
        self.assertFalse(verification["valid"])

    def test_count_mismatch_detected(self) -> None:
        """Mismatched counts between total and evaluated should be detected."""
        result = {
            "schema": "textforensics.benchmark-result/v1",
            "dataset_sha256": "a" * 64,
            "threshold": 0.5,
            "tp": 10,
            "fp": 5,
            "tn": 85,
            "fn": 10,
            "evaluated": 120,  # Actually 110
        }
        verification = verify_benchmark(result)
        self.assertFalse(verification["valid"])
        self.assertTrue(
            any("evaluated" in str(e) for e in verification.get("errors", [])),
            f"Expected evaluated error, got: {verification.get('errors')}",
        )

    def test_all_metrics_recomputed(self) -> None:
        """verify_benchmark should return recomputed metrics."""
        result = {
            "schema": "textforensics.benchmark-result/v1",
            "dataset_sha256": "a" * 64,
            "threshold": 0.5,
            "tp": 10,
            "fp": 5,
            "tn": 85,
            "fn": 10,
            "evaluated": 110,
            "accuracy": 0.6818,  # Will be recomputed
            "true_positive_rate": 0.5,
            "false_positive_rate": 0.0556,  # Will be recomputed
            "specificity": 0.9444,
            "false_negative_rate": 0.0909,
            "precision": 0.6667,
        }
        verification = verify_benchmark(result)
        self.assertIn("recomputed_metrics", verification)
        # The recomputed accuracy should be (10+85)/110 = 0.8636
        self.assertIn("accuracy", verification["recomputed_metrics"])


class VerifyAllTests(unittest.TestCase):
    """Tests for verify_all unified entry point."""

    TEXT = "This is a test document for forensic analysis."

    def test_verify_all_with_valid_case_file(self):
        """verify_all should pass for a valid case file."""
        bundle = build_forensic_bundle(self.TEXT).to_dict()
        case = seal_case_file(bundle)
        report = verify_all(case_payload=case)
        self.assertTrue(report.overall_valid)
        self.assertIsNotNone(report.case_file)
        self.assertTrue(report.case_file["valid"])

    def test_verify_all_with_multiple_valid_artifacts(self):
        """verify_all should pass when all artifacts are valid."""
        bundle = build_forensic_bundle(self.TEXT).to_dict()
        case = seal_case_file(bundle)

        with tempfile.TemporaryDirectory() as tmp:
            calib_path = Path(tmp) / "calib.jsonl"
            write_dataset(calib_path)
            artifact = calibrate_threshold_jsonl(calib_path)

            bench_path = Path(tmp) / "bench.jsonl"
            write_dataset(bench_path)
            result = benchmark_jsonl(bench_path)

            report = verify_all(
                case_payload=case,
                calibration_artifact=artifact,
                benchmark_result=result,
            )
            self.assertTrue(report.overall_valid)

    def test_verify_all_returns_report_type(self):
        """verify_all should return a VerificationReport instance."""
        report = verify_all()
        self.assertIsInstance(report, VerificationReport)

    def test_verify_all_partial_failure(self):
        """verify_all should fail if any artifact fails."""
        bundle = build_forensic_bundle(self.TEXT).to_dict()
        case = seal_case_file(bundle)
        # Tamper the case
        case["case_sha256"] = "0" * 64

        with tempfile.TemporaryDirectory() as tmp:
            calib_path = Path(tmp) / "calib.jsonl"
            write_dataset(calib_path)
            artifact = calibrate_threshold_jsonl(calib_path)

            report = verify_all(
                case_payload=case,
                calibration_artifact=artifact,
            )
            self.assertFalse(report.overall_valid)
            self.assertFalse(report.case_file["valid"])


class VerificationReportTests(unittest.TestCase):
    """Tests for VerificationReport dataclass."""

    def test_to_dict_includes_all_fields(self):
        report = VerificationReport(
            case_file={"valid": True, "errors": []},
            calibration={"valid": True, "errors": []},
            benchmark={"valid": True, "errors": []},
            overall_valid=True,
        )
        d = report.to_dict()
        self.assertEqual(d["schema"], "textforensics.verification-report/v1")
        self.assertTrue(d["overall_valid"])
        self.assertIn("case_file", d)
        self.assertIn("calibration", d)
        self.assertIn("benchmark", d)


if __name__ == "__main__":
    unittest.main()
