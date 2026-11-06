"""Tests for N-version integrity replay."""

import hashlib
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
    _recompute_overall,
    _verify_trust_dimension,
    verify_all,
    verify_benchmark,
    verify_calibration,
    verify_case_file,
    verify_case_file_path,
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
        # Use a v1 case so the raw-text policy check is the first error
        # encountered (the schema check runs first on v2 payloads).
        case = {
            "schema": "textforensics.case-file/v1",
            "raw_text_included": True,
            "case_sha256": "a" * 64,
        }
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


class VerifyTrustDimensionTests(unittest.TestCase):
    """Tests for _verify_trust_dimension function."""

    def test_valid_dimension(self):
        """Test valid dimension passes."""
        dim = {
            "dimension": "language_coverage",
            "state": "supported",
            "reason": "Language is supported",
        }
        self.assertEqual(_verify_trust_dimension(dim), "ok")

    def test_invalid_dimension_not_dict(self):
        """Test non-dict dimension fails."""
        self.assertEqual(_verify_trust_dimension("not a dict"), "error: dimension is not a dict")

    def test_invalid_state(self):
        """Test invalid state fails."""
        dim = {
            "dimension": "language_coverage",
            "state": "invalid_state",
            "reason": "Reason",
        }
        self.assertIn("invalid state", _verify_trust_dimension(dim))

    def test_missing_dimension_name(self):
        """Test missing dimension name fails."""
        dim = {
            "state": "supported",
            "reason": "Reason",
        }
        self.assertIn("missing or empty dimension name", _verify_trust_dimension(dim))

    def test_empty_dimension_name(self):
        """Test empty dimension name fails."""
        dim = {
            "dimension": "",
            "state": "supported",
            "reason": "Reason",
        }
        self.assertIn("missing or empty dimension name", _verify_trust_dimension(dim))

    def test_missing_reason(self):
        """Test missing reason fails."""
        dim = {
            "dimension": "language_coverage",
            "state": "supported",
        }
        self.assertIn("missing or empty reason", _verify_trust_dimension(dim))

    def test_empty_reason(self):
        """Test empty reason fails."""
        dim = {
            "dimension": "language_coverage",
            "state": "supported",
            "reason": "",
        }
        self.assertIn("missing or empty reason", _verify_trust_dimension(dim))

    def test_all_valid_states(self):
        """Test all valid trust states pass."""
        for state in ["supported", "partial", "unknown", "out_of_scope"]:
            dim = {
                "dimension": "test",
                "state": state,
                "reason": "Reason",
            }
            self.assertEqual(_verify_trust_dimension(dim), "ok")


class RecomputeOverallTests(unittest.TestCase):
    """Tests for _recompute_overall function."""

    def test_all_supported(self):
        """Test all supported returns strong.

        "All" means the full declared dimension set: the re-derivation
        must agree with trust._overall_state, which requires every
        declared dimension present and supported for "strong" (a
        partial set of supported dimensions is "mixed", not "strong").
        """
        from textforensics.trust import TRUST_DIMENSIONS

        dims = [
            {"dimension": name, "state": "supported", "reason": "r"} for name in TRUST_DIMENSIONS
        ]
        self.assertEqual(_recompute_overall(dims), "strong")

    def test_unknown_count_3_returns_insufficient(self):
        """Under v2, three unknown dimensions with no supported/partial
        state yields insufficient (supported==0 and partial==0)."""
        dims = [
            {"dimension": "d1", "state": "unknown", "reason": "r1"},
            {"dimension": "d2", "state": "unknown", "reason": "r2"},
            {"dimension": "d3", "state": "unknown", "reason": "r3"},
        ]
        self.assertEqual(_recompute_overall(dims), "insufficient")

    def test_unknown_4_returns_insufficient(self):
        """Test 4 unknown returns insufficient under v2."""
        dims = [
            {"dimension": "d1", "state": "unknown", "reason": "r1"},
            {"dimension": "d2", "state": "unknown", "reason": "r2"},
            {"dimension": "d3", "state": "unknown", "reason": "r3"},
            {"dimension": "d4", "state": "unknown", "reason": "r4"},
        ]
        self.assertEqual(_recompute_overall(dims), "insufficient")

    def test_out_of_scope_on_language_returns_insufficient(self):
        """Under v2, out_of_scope on the language dimension yields insufficient."""
        dims = [
            {"dimension": "language", "state": "out_of_scope", "reason": "r1"},
            {"dimension": "d2", "state": "supported", "reason": "r2"},
        ]
        self.assertEqual(_recompute_overall(dims), "insufficient")

    def test_out_of_scope_on_text_length_returns_insufficient(self):
        """Under v2, out_of_scope on text_length yields insufficient."""
        dims = [
            {"dimension": "text_length", "state": "out_of_scope", "reason": "r1"},
            {"dimension": "d2", "state": "supported", "reason": "r2"},
        ]
        self.assertEqual(_recompute_overall(dims), "insufficient")

    def test_out_of_scope_on_other_dimension_is_not_insufficient(self):
        """Under v2, out_of_scope on a non-language/length dimension alone
        does not force insufficient."""
        dims = [
            {"dimension": "domain_genre", "state": "out_of_scope", "reason": "r1"},
            {"dimension": "d2", "state": "supported", "reason": "r2"},
        ]
        self.assertEqual(_recompute_overall(dims), "mixed")

    def test_partial_returns_mixed(self):
        """Test partial returns mixed."""
        dims = [
            {"dimension": "d1", "state": "partial", "reason": "r1"},
            {"dimension": "d2", "state": "supported", "reason": "r2"},
        ]
        self.assertEqual(_recompute_overall(dims), "mixed")

    def test_unknown_returns_mixed(self):
        """Test single unknown returns mixed."""
        dims = [
            {"dimension": "d1", "state": "unknown", "reason": "r1"},
            {"dimension": "d2", "state": "supported", "reason": "r2"},
        ]
        self.assertEqual(_recompute_overall(dims), "mixed")

    def test_unknown_2_returns_mixed(self):
        """Test 2 unknown returns mixed (not insufficient)."""
        dims = [
            {"dimension": "d1", "state": "unknown", "reason": "r1"},
            {"dimension": "d2", "state": "unknown", "reason": "r2"},
            {"dimension": "d3", "state": "supported", "reason": "r3"},
        ]
        self.assertEqual(_recompute_overall(dims), "mixed")


class VerifyCaseFileEdgeCases(unittest.TestCase):
    """Tests for verify_case_file edge cases."""

    def test_bundle_not_dict(self):
        """Test case file with non-dict forensic_bundle."""
        case = {
            "schema": "textforensics.case-file/v1",
            "raw_text_included": False,
            "forensic_bundle": "not a dict",
            "case_sha256": "a" * 64,
        }
        result = verify_case_file(case)
        self.assertFalse(result["valid"])
        self.assertIn("forensic_bundle is not a dict", result["errors"])
        self.assertFalse(result["seal_verified"])

    def test_trust_map_not_dict(self):
        """Test case file with non-dict trust_map."""
        case = {
            "schema": "textforensics.case-file/v1",
            "raw_text_included": False,
            "forensic_bundle": {
                "schema": "textforensics.forensic-bundle/v1",
                "trust_map": "not a dict",
            },
            "case_sha256": "a" * 64,
        }
        result = verify_case_file(case)
        self.assertFalse(result["trust_map_verified"])

    def test_trust_map_dimensions_not_list(self):
        """Test trust_map with non-list dimensions."""
        case = {
            "schema": "textforensics.case-file/v1",
            "raw_text_included": False,
            "forensic_bundle": {
                "schema": "textforensics.forensic-bundle/v1",
                "trust_map": {
                    "dimensions": "not a list",
                    "overall": "strong",
                },
            },
            "case_sha256": "a" * 64,
        }
        result = verify_case_file(case)
        self.assertFalse(result["valid"])
        self.assertIn("trust_map.dimensions is not a list", result["errors"])

    def test_bundle_wrong_schema(self):
        """Test forensic_bundle with wrong schema."""
        case = {
            "schema": "textforensics.case-file/v1",
            "raw_text_included": False,
            "forensic_bundle": {
                "schema": "wrong-schema",
                "trust_map": {"dimensions": [], "overall": "strong"},
            },
            "case_sha256": "a" * 64,
        }
        result = verify_case_file(case)
        self.assertFalse(result["valid"])
        self.assertIn("forensic_bundle has unexpected schema", result["errors"])

    def test_invalid_content_sha256(self):
        """Test invalid content_sha256."""
        case = {
            "schema": "textforensics.case-file/v1",
            "raw_text_included": False,
            "forensic_bundle": {
                "schema": "textforensics.forensic-bundle/v1",
                "content_sha256": "invalid-hash",
                "trust_map": {"dimensions": [], "overall": "strong"},
            },
            "case_sha256": "a" * 64,
        }
        result = verify_case_file(case)
        self.assertFalse(result["valid"])
        self.assertIn("invalid content_sha256", result["errors"])

    def test_input_raw_text_included_true(self):
        """Test input with raw_text_included True."""
        case = {
            "schema": "textforensics.case-file/v1",
            "raw_text_included": False,
            "forensic_bundle": {
                "schema": "textforensics.forensic-bundle/v1",
                "content_sha256": "a" * 64,
                "trust_map": {"dimensions": [], "overall": "strong"},
                "input": {"raw_text_included": True},
            },
            "case_sha256": "a" * 64,
        }
        result = verify_case_file(case)
        self.assertFalse(result["valid"])
        self.assertIn("input.raw_text_included must be False", result["errors"])

    def test_detector_wrong_schema(self):
        """Test detector result with wrong schema."""
        case = {
            "schema": "textforensics.case-file/v1",
            "raw_text_included": False,
            "forensic_bundle": {
                "schema": "textforensics.forensic-bundle/v1",
                "content_sha256": "a" * 64,
                "trust_map": {"dimensions": [], "overall": "strong"},
                "detector_results": [
                    {"schema": "wrong", "detector_id": "det1", "score": 0.5, "verdict": "ai_like"},
                ],
            },
            "case_sha256": "a" * 64,
        }
        # Seal the case to get correct hash
        case["case_sha256"] = hashlib.sha256(
            json.dumps(
                {k: v for k, v in case.items() if k != "case_sha256"},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        result = verify_case_file(case)
        self.assertFalse(result["valid"])
        self.assertTrue(any("has wrong schema" in e for e in result["errors"]))

    def test_detector_score_not_numeric(self):
        """Test detector result with non-numeric score."""
        case = {
            "schema": "textforensics.case-file/v1",
            "raw_text_included": False,
            "forensic_bundle": {
                "schema": "textforensics.forensic-bundle/v1",
                "content_sha256": "a" * 64,
                "trust_map": {"dimensions": [], "overall": "strong"},
                "detector_results": [
                    {
                        "schema": "textforensics.detector-result/v1",
                        "detector_id": "det1",
                        "score": "not numeric",
                        "verdict": "ai_like",
                    },
                ],
            },
            "case_sha256": "a" * 64,
        }
        # Seal the case to get correct hash
        case["case_sha256"] = hashlib.sha256(
            json.dumps(
                {k: v for k, v in case.items() if k != "case_sha256"},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        result = verify_case_file(case)
        self.assertFalse(result["valid"])
        self.assertTrue(any("score is not numeric" in e for e in result["errors"]))

    def test_detector_score_not_finite(self):
        """Test detector result with non-finite score."""
        # Create a case with non-finite score for verification
        # Use a very large number to simulate inf (JSON doesn't support inf)
        case = {
            "schema": "textforensics.case-file/v1",
            "raw_text_included": False,
            "forensic_bundle": {
                "schema": "textforensics.forensic-bundle/v1",
                "content_sha256": "a" * 64,
                "trust_map": {"dimensions": [], "overall": "strong"},
                "detector_results": [
                    {
                        "schema": "textforensics.detector-result/v1",
                        "detector_id": "det1",
                        "score": 1e100,
                        "verdict": "ai_like",
                    },
                ],
            },
            "case_sha256": "a" * 64,
        }
        # The verify function checks for math.isfinite, so use math.inf in the actual test
        # We test the verification logic directly by patching the score after hash computation
        import math

        case_for_hash = {
            "schema": "textforensics.case-file/v1",
            "raw_text_included": False,
            "forensic_bundle": {
                "schema": "textforensics.forensic-bundle/v1",
                "content_sha256": "a" * 64,
                "trust_map": {"dimensions": [], "overall": "strong"},
                "detector_results": [
                    {
                        "schema": "textforensics.detector-result/v1",
                        "detector_id": "det1",
                        "score": 1e100,
                        "verdict": "ai_like",
                    },
                ],
            },
            "case_sha256": "a" * 64,
        }
        # Compute hash with finite score
        case_for_hash["case_sha256"] = hashlib.sha256(
            json.dumps(
                {k: v for k, v in case_for_hash.items() if k != "case_sha256"},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()

        # Now create case with inf score for verification
        case = {**case_for_hash}
        case["forensic_bundle"]["detector_results"][0]["score"] = math.inf
        result = verify_case_file(case)
        self.assertFalse(result["valid"])
        self.assertTrue(any("score is not finite" in e for e in result["errors"]))

    def test_detector_invalid_verdict(self):
        """Test detector result with invalid verdict."""
        case = {
            "schema": "textforensics.case-file/v1",
            "raw_text_included": False,
            "forensic_bundle": {
                "schema": "textforensics.forensic-bundle/v1",
                "content_sha256": "a" * 64,
                "trust_map": {"dimensions": [], "overall": "strong"},
                "detector_results": [
                    {
                        "schema": "textforensics.detector-result/v1",
                        "detector_id": "det1",
                        "score": 0.5,
                        "verdict": "invalid",
                    },
                ],
            },
            "case_sha256": "a" * 64,
        }
        # Seal the case to get correct hash
        case["case_sha256"] = hashlib.sha256(
            json.dumps(
                {k: v for k, v in case.items() if k != "case_sha256"},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        result = verify_case_file(case)
        self.assertFalse(result["valid"])
        self.assertTrue(any("has invalid verdict" in e for e in result["errors"]))


class VerifyCalibrationEdgeCases(unittest.TestCase):
    """Tests for verify_calibration edge cases."""

    def test_threshold_false_not_numeric(self):
        """Test boolean threshold fails."""
        artifact = {
            "schema": "textforensics.calibration/v1",
            "detector_id": "det1",
            "detector_version": "1.0",
            "recommended_threshold": True,
            "calibration_dataset_sha256": "a" * 64,
        }
        result = verify_calibration(artifact)
        self.assertFalse(result["valid"])
        self.assertIn("not a finite number", result["errors"][0])

    def test_observed_fpr_outside_range(self):
        """Test observed_fpr outside [0,1] fails."""
        artifact = {
            "schema": "textforensics.calibration/v1",
            "detector_id": "det1",
            "detector_version": "1.0",
            "recommended_threshold": 0.5,
            "calibration_dataset_sha256": "a" * 64,
            "observed_false_positive_rate": 1.5,
        }
        result = verify_calibration(artifact)
        self.assertFalse(result["valid"])
        self.assertIn("outside [0, 1]", result["errors"][0])

    def test_observed_tpr_outside_range(self):
        """Test observed_tpr outside [0,1] fails."""
        artifact = {
            "schema": "textforensics.calibration/v1",
            "detector_id": "det1",
            "detector_version": "1.0",
            "recommended_threshold": 0.5,
            "calibration_dataset_sha256": "a" * 64,
            "observed_true_positive_rate": -0.1,
        }
        result = verify_calibration(artifact)
        self.assertFalse(result["valid"])
        self.assertIn("outside [0, 1]", result["errors"][0])

    def test_observed_fpr_not_numeric(self):
        """Test non-numeric observed_fpr fails."""
        artifact = {
            "schema": "textforensics.calibration/v1",
            "detector_id": "det1",
            "detector_version": "1.0",
            "recommended_threshold": 0.5,
            "calibration_dataset_sha256": "a" * 64,
            "observed_false_positive_rate": "not numeric",
        }
        result = verify_calibration(artifact)
        self.assertFalse(result["valid"])
        self.assertIn("not numeric", result["errors"][0])

    def test_human_samples_not_positive_int(self):
        """Test non-positive human_samples fails."""
        artifact = {
            "schema": "textforensics.calibration/v1",
            "detector_id": "det1",
            "detector_version": "1.0",
            "recommended_threshold": 0.5,
            "calibration_dataset_sha256": "a" * 64,
            "human_samples": 0,
        }
        result = verify_calibration(artifact)
        self.assertFalse(result["valid"])
        self.assertIn("must be a positive integer", result["errors"][0])

    def test_ai_samples_not_positive_int(self):
        """Test non-positive ai_samples fails."""
        artifact = {
            "schema": "textforensics.calibration/v1",
            "detector_id": "det1",
            "detector_version": "1.0",
            "recommended_threshold": 0.5,
            "calibration_dataset_sha256": "a" * 64,
            "ai_samples": -1,
        }
        result = verify_calibration(artifact)
        self.assertFalse(result["valid"])
        self.assertIn("must be a positive integer", result["errors"][0])


class VerifyBenchmarkEdgeCases(unittest.TestCase):
    """Tests for verify_benchmark edge cases."""

    def test_zero_total(self):
        """Test with zero total samples."""
        result = {
            "schema": "textforensics.benchmark-result/v1",
            "dataset_sha256": "a" * 64,
            "threshold": 0.5,
            "tp": 0,
            "fp": 0,
            "tn": 0,
            "fn": 0,
            "evaluated": 0,
            "accuracy": 0.0,
            "true_positive_rate": 0.0,
            "false_positive_rate": 0.0,
            "specificity": 0.0,
            "false_negative_rate": 0.0,
            "precision": 0.0,
        }
        verification = verify_benchmark(result)
        self.assertTrue(verification["valid"])
        self.assertEqual(verification["recomputed_metrics"]["accuracy"], 0.0)
        self.assertEqual(verification["recomputed_metrics"]["true_positive_rate"], 0.0)

    def test_metric_stored_none(self):
        """Test when stored metric is None but derived exists."""
        result = {
            "schema": "textforensics.benchmark-result/v1",
            "dataset_sha256": "a" * 64,
            "threshold": 0.5,
            "tp": 10,
            "fp": 5,
            "tn": 85,
            "fn": 10,
            "evaluated": 110,
            "accuracy": 0.8636,
            "true_positive_rate": 0.5,
            "false_positive_rate": 0.0556,
            "specificity": 0.9444,
            "false_negative_rate": 0.5,
            "precision": 0.6667,
        }
        verification = verify_benchmark(result)
        self.assertTrue(verification["valid"])

    def test_threshold_not_finite(self):
        """Test non-finite threshold."""
        result = {
            "schema": "textforensics.benchmark-result/v1",
            "dataset_sha256": "a" * 64,
            "threshold": 0.5,  # Use valid threshold
            "tp": 10,
            "fp": 5,
            "tn": 85,
            "fn": 10,
            "evaluated": 110,
            "accuracy": 0.8636,
            "true_positive_rate": 0.5,
            "false_positive_rate": 0.0556,
            "specificity": 0.9444,
            "false_negative_rate": 0.0909,
            "precision": 0.6667,
        }
        # Manually add an error for threshold check
        result["threshold"] = float("inf")
        verification = verify_benchmark(result)
        self.assertFalse(verification["valid"])
        self.assertTrue(any("not a finite number" in e for e in verification["errors"]))

    def test_threshold_boolean(self):
        """Test boolean threshold."""
        result = {
            "schema": "textforensics.benchmark-result/v1",
            "dataset_sha256": "a" * 64,
            "threshold": 0.5,  # Use valid threshold
            "tp": 10,
            "fp": 5,
            "tn": 85,
            "fn": 10,
            "evaluated": 110,
            "accuracy": 0.8636,
            "true_positive_rate": 0.5,
            "false_positive_rate": 0.0556,
            "specificity": 0.9444,
            "false_negative_rate": 0.0909,
            "precision": 0.6667,
        }
        # Manually add an error for threshold check
        result["threshold"] = True
        verification = verify_benchmark(result)
        self.assertFalse(verification["valid"])
        self.assertTrue(any("not a finite number" in e for e in verification["errors"]))

    def test_invalid_dataset_sha256(self):
        """Test invalid dataset_sha256."""
        result = {
            "schema": "textforensics.benchmark-result/v1",
            "dataset_sha256": "invalid",
            "threshold": 0.5,
            "tp": 10,
            "fp": 5,
            "tn": 85,
            "fn": 10,
            "evaluated": 110,
            "accuracy": 0.8636,
            "true_positive_rate": 0.5,
            "false_positive_rate": 0.0556,
            "specificity": 0.9444,
            "false_negative_rate": 0.0909,
            "precision": 0.6667,
        }
        verification = verify_benchmark(result)
        self.assertFalse(verification["valid"])
        self.assertTrue(
            any("missing or invalid dataset_sha256" in e for e in verification["errors"])
        )


class VerifyAllEdgeCases(unittest.TestCase):
    """Tests for verify_all edge cases."""

    def test_verify_all_no_args(self):
        """Test verify_all with no arguments."""
        report = verify_all()
        self.assertIsInstance(report, VerificationReport)
        self.assertTrue(report.overall_valid)
        self.assertIsNone(report.case_file)
        self.assertIsNone(report.calibration)
        self.assertIsNone(report.benchmark)

    def test_verify_all_case_file_only(self):
        """Test verify_all with only case file."""
        from textforensics.casefile import seal_case_file
        from textforensics.report import build_forensic_bundle

        TEXT = "Test document."
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle)

        report = verify_all(case_payload=case)
        self.assertTrue(report.overall_valid)
        self.assertIsNotNone(report.case_file)
        self.assertIsNone(report.calibration)
        self.assertIsNone(report.benchmark)

    def test_verify_all_calibration_only(self):
        """Test verify_all with only calibration artifact."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "calib.jsonl"
            write_dataset(path)
            artifact = calibrate_threshold_jsonl(path)

            report = verify_all(calibration_artifact=artifact)
            self.assertTrue(report.overall_valid)
            self.assertIsNotNone(report.calibration)
            self.assertIsNone(report.case_file)
            self.assertIsNone(report.benchmark)

    def test_verify_all_benchmark_only(self):
        """Test verify_all with only benchmark result."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bench.jsonl"
            write_dataset(path)
            result = benchmark_jsonl(path, threshold=0.5)

            report = verify_all(benchmark_result=result)
            self.assertTrue(report.overall_valid)
            self.assertIsNotNone(report.benchmark)
            self.assertIsNone(report.case_file)
            self.assertIsNone(report.calibration)


class VerifyCaseFilePathTests(unittest.TestCase):
    """Tests for verify_case_file_path function."""

    def test_verify_case_file_path_invalid_json(self):
        """Test verify_case_file_path with invalid JSON file."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "case.json"
            path.write_text("not valid json", encoding="utf-8")

            # The function catches JSONDecodeError and returns a report
            report = verify_case_file_path(path)
            self.assertFalse(report.overall_valid)
            self.assertFalse(report.case_file["valid"])
            self.assertTrue(any("JSON" in e for e in report.case_file["errors"]))

    def test_verify_case_file_path_valid(self):
        """Test verify_case_file_path with valid case file."""
        from textforensics.casefile import seal_case_file
        from textforensics.report import build_forensic_bundle

        TEXT = "Test document."
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "case.json"
            path.write_text(json.dumps(case), encoding="utf-8")

            report = verify_case_file_path(path)
            self.assertTrue(report.overall_valid)
            self.assertTrue(report.case_file["valid"])


if __name__ == "__main__":
    unittest.main()
