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
    _recompute_overall_v3,
    _verify_trust_dimension,
    verify_all,
    verify_benchmark,
    verify_calibration,
    verify_case_file,
    verify_case_file_combined,
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

    def test_empty_dimension_list_v3_is_insufficient(self):
        """Under v3, an empty dimension list yields insufficient, never
        strong — the replay agrees with validation._overall_state_v3."""
        from textforensics.validation import _overall_state_v3

        self.assertEqual(_recompute_overall_v3([]), "insufficient")
        self.assertEqual(_overall_state_v3([]), "insufficient")
        self.assertEqual(_recompute_overall_v3([]), _overall_state_v3([]))


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

    def test_verify_case_file_path_deeply_nested_array(self):
        """A deeply nested top-level array returns structured invalid.

        Same bug class as verify_case_file_path_combined: on Python 3.11
        the json C scanner shares the ~1000 Python recursion limit, so
        parsing this raises RecursionError; the loader must return the
        "case file must be a JSON object" report instead of raising.
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "case.json"
            path.write_text("[" * 1100 + "]" * 1100, encoding="utf-8")
            report = verify_case_file_path(path)
            self.assertFalse(report.overall_valid)
            self.assertFalse(report.case_file["valid"])
            self.assertIn("case file must be a JSON object", report.case_file["errors"])

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


# ---------------------------------------------------------------------------
# W2 Worker C (C10 / C19): Trust Map completeness and benchmark domains.
# ---------------------------------------------------------------------------

_V3_TEXT = (
    "The committee met on Tuesday to review the quarterly figures and "
    "discuss the outlook for the coming year. The chair opened the meeting "
    "with a summary of the previous session, and the members agreed to "
    "focus on three items: revenue, staffing, and the maintenance budget. "
    "Revenue grew modestly in the first quarter, driven by new contracts "
    "in the northern region. Staffing remains tight, and the hiring plan "
    "was approved with minor changes. The maintenance budget was reduced "
    "after a review of the supplier quotes. The meeting ended with a plan "
    "to reconvene in four weeks to review progress on each item."
)


def _dim(name: str, state: str = "supported") -> dict:
    return {"dimension": name, "state": state, "reason": "synthetic"}


def _coverage_for(dimensions: list[dict], *, stale_key: bool = True) -> dict:
    counts = {"supported": 0, "partial": 0, "unknown": 0, "out_of_scope": 0, "stale": 0}
    for item in dimensions:
        counts[item["state"]] += 1
    if not stale_key:
        counts.pop("stale")
    return counts


def _reseal_case(case: dict) -> dict:
    """Recompute the case seal after tampering (mirrors _hash_without_seal)."""
    import copy

    resealed = copy.deepcopy(case)
    stripped = copy.deepcopy(resealed)
    stripped.pop("case_sha256", None)
    stripped.pop("created_at_utc", None)
    canonical = json.dumps(
        stripped, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    resealed["case_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return resealed


def _genuine_v3_case() -> dict:
    """A genuine v3 case: empty-registry v3 Trust Map sealed as case-file/v3."""
    from textforensics.conditions import conditions_from_dict
    from textforensics.validation import ValidationRegistry, derive_trust_map

    bundle = build_forensic_bundle(_V3_TEXT).to_dict()
    conditions = conditions_from_dict(bundle["input_conditions"])
    trust_map = derive_trust_map(
        conditions,
        ValidationRegistry(),
        detector_id="textforensics/builtin-heuristic",
        detector_version="0.1.0",
        now="2026-11-07T00:00:00Z",
    ).to_dict()
    bundle["trust_map"] = trust_map
    case = seal_case_file(bundle, version="v3")
    assert verify_case_file_combined(case)["valid"], "genuine v3 fixture must verify"
    return case


def _mutated_case(case: dict, *, dimensions, overall, coverage=None) -> dict:
    import copy

    mutated = copy.deepcopy(case)
    trust_map = mutated["forensic_bundle"]["trust_map"]
    trust_map["dimensions"] = dimensions
    trust_map["overall"] = overall
    if coverage is not None:
        trust_map["coverage"] = coverage
    return _reseal_case(mutated)


class TrustMapCompletenessTests(unittest.TestCase):
    """C10: exactly the declared dimension set is required before `strong`."""

    def test_genuine_v3_case_verifies(self):
        case = _genuine_v3_case()
        result = verify_case_file(case)
        self.assertTrue(result["valid"], result.get("errors"))
        self.assertTrue(result["trust_map_verified"])

    def test_one_undeclared_dimension_cannot_be_strong(self):
        """The audit's precise C10 case: one undeclared supported dimension
        with overall `strong` and a consistent manifest must fail."""
        case = _genuine_v3_case()
        self.assertEqual(
            case["manifest"]["schema_versions"]["trust_map"], "textforensics.trust-map/v3"
        )
        dims = [_dim("not-a-declared-dimension")]
        mutated = _mutated_case(
            case, dimensions=dims, overall="strong", coverage=_coverage_for(dims)
        )
        result = verify_case_file(mutated)
        self.assertFalse(result["valid"])
        self.assertFalse(result["trust_map_verified"])
        self.assertTrue(any("dimension" in e for e in result["errors"]), result["errors"])
        combined = verify_case_file_combined(mutated)
        self.assertFalse(combined["valid"])
        self.assertFalse(combined["trust_map_verified"])

    def test_nonempty_subset_cannot_be_strong(self):
        from textforensics.trust import TRUST_DIMENSIONS

        case = _genuine_v3_case()
        dims = [_dim(name) for name in TRUST_DIMENSIONS[:9]]
        mutated = _mutated_case(
            case, dimensions=dims, overall="strong", coverage=_coverage_for(dims)
        )
        result = verify_case_file(mutated)
        self.assertFalse(result["valid"])
        self.assertFalse(result["trust_map_verified"])

    def test_duplicated_dimension_cannot_complete_the_set(self):
        from textforensics.trust import TRUST_DIMENSIONS

        case = _genuine_v3_case()
        dims = [_dim(name) for name in TRUST_DIMENSIONS[:9]]
        dims.append(_dim(TRUST_DIMENSIONS[0]))
        mutated = _mutated_case(
            case, dimensions=dims, overall="strong", coverage=_coverage_for(dims)
        )
        result = verify_case_file(mutated)
        self.assertFalse(result["valid"])
        self.assertFalse(result["trust_map_verified"])

    def test_ten_wrong_names_cannot_be_strong(self):
        case = _genuine_v3_case()
        dims = [_dim(f"wrong-{i}") for i in range(10)]
        mutated = _mutated_case(
            case, dimensions=dims, overall="strong", coverage=_coverage_for(dims)
        )
        result = verify_case_file(mutated)
        self.assertFalse(result["valid"])
        self.assertFalse(result["trust_map_verified"])

    def test_complete_supported_v3_map_still_verifies(self):
        from textforensics.trust import TRUST_DIMENSIONS

        case = _genuine_v3_case()
        dims = [_dim(name) for name in TRUST_DIMENSIONS]
        mutated = _mutated_case(
            case, dimensions=dims, overall="strong", coverage=_coverage_for(dims)
        )
        result = verify_case_file(mutated)
        self.assertTrue(result["valid"], result.get("errors"))
        self.assertTrue(result["trust_map_verified"])

    def test_stale_v3_dimension_still_verifies(self):
        from textforensics.trust import TRUST_DIMENSIONS

        case = _genuine_v3_case()
        dims = [_dim(name, "unknown") for name in TRUST_DIMENSIONS]
        dims[TRUST_DIMENSIONS.index("temporal_version_stability")] = _dim(
            "temporal_version_stability", "stale"
        )
        mutated = _mutated_case(
            case, dimensions=dims, overall="insufficient", coverage=_coverage_for(dims)
        )
        result = verify_case_file(mutated)
        self.assertTrue(result["valid"], result.get("errors"))
        self.assertTrue(result["trust_map_verified"])

    def test_out_of_scope_language_v3_map_still_verifies(self):
        from textforensics.trust import TRUST_DIMENSIONS

        case = _genuine_v3_case()
        dims = [_dim(name, "unknown") for name in TRUST_DIMENSIONS]
        dims[0] = _dim("language", "out_of_scope")
        mutated = _mutated_case(
            case, dimensions=dims, overall="insufficient", coverage=_coverage_for(dims)
        )
        result = verify_case_file(mutated)
        self.assertTrue(result["valid"], result.get("errors"))
        self.assertTrue(result["trust_map_verified"])

    def test_v3_coverage_mismatch_is_rejected(self):
        from textforensics.trust import TRUST_DIMENSIONS

        case = _genuine_v3_case()
        dims = [_dim(name) for name in TRUST_DIMENSIONS]
        coverage = _coverage_for(dims)
        coverage["supported"] = 5  # inconsistent with ten supported dimensions
        mutated = _mutated_case(case, dimensions=dims, overall="strong", coverage=coverage)
        result = verify_case_file(mutated)
        self.assertFalse(result["valid"])
        self.assertTrue(any("coverage" in e for e in result["errors"]), result["errors"])

    def test_v3_missing_generated_at_utc_is_rejected(self):
        from textforensics.trust import TRUST_DIMENSIONS

        case = _genuine_v3_case()
        dims = [_dim(name) for name in TRUST_DIMENSIONS]
        mutated = _mutated_case(
            case, dimensions=dims, overall="strong", coverage=_coverage_for(dims)
        )
        mutated["forensic_bundle"]["trust_map"]["generated_at_utc"] = None
        mutated = _reseal_case(mutated)
        result = verify_case_file(mutated)
        self.assertFalse(result["valid"])
        self.assertTrue(any("generated_at_utc" in e for e in result["errors"]), result["errors"])

    def test_v2_subset_cannot_be_strong(self):
        from textforensics.trust import TRUST_DIMENSIONS

        bundle = build_forensic_bundle(VerifyCaseFileTests.TEXT).to_dict()
        case = seal_case_file(bundle)
        dims = [_dim(name) for name in TRUST_DIMENSIONS[:9]]
        mutated = _mutated_case(
            case, dimensions=dims, overall="strong", coverage=_coverage_for(dims, stale_key=False)
        )
        result = verify_case_file(mutated)
        self.assertFalse(result["valid"])
        self.assertFalse(result["trust_map_verified"])

    def test_v2_complete_supported_map_still_verifies(self):
        from textforensics.trust import TRUST_DIMENSIONS

        bundle = build_forensic_bundle(VerifyCaseFileTests.TEXT).to_dict()
        case = seal_case_file(bundle)
        dims = [_dim(name) for name in TRUST_DIMENSIONS]
        mutated = _mutated_case(
            case, dimensions=dims, overall="strong", coverage=_coverage_for(dims, stale_key=False)
        )
        result = verify_case_file(mutated)
        self.assertTrue(result["valid"], result.get("errors"))
        self.assertTrue(result["trust_map_verified"])

    def test_recompute_overall_v3_requires_exact_declared_set(self):
        from textforensics.trust import TRUST_DIMENSIONS

        full = [_dim(name) for name in TRUST_DIMENSIONS]
        self.assertEqual(_recompute_overall_v3(full), "strong")
        self.assertEqual(_recompute_overall_v3(full[:9]), "mixed")
        dup = full[:9] + [_dim(TRUST_DIMENSIONS[0])]
        self.assertEqual(_recompute_overall_v3(dup), "mixed")
        wrong = [_dim(f"wrong-{i}") for i in range(10)]
        self.assertEqual(_recompute_overall_v3(wrong), "mixed")
        self.assertEqual(_recompute_overall_v3([_dim("not-a-declared-dimension")]), "mixed")

    def test_recompute_overall_requires_exact_declared_set(self):
        from textforensics.trust import TRUST_DIMENSIONS

        full = [_dim(name) for name in TRUST_DIMENSIONS]
        self.assertEqual(_recompute_overall(full), "strong")
        self.assertEqual(_recompute_overall(full[:9]), "mixed")
        wrong = [_dim(f"wrong-{i}") for i in range(10)]
        self.assertEqual(_recompute_overall(wrong), "mixed")
        self.assertEqual(_recompute_overall([_dim("not-a-declared-dimension")]), "mixed")


class VerifyBenchmarkInvalidInputsTests(unittest.TestCase):
    """C19: benchmark verification must validate domains before recomputation."""

    def _base_result(self) -> dict:
        return {
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

    def test_nan_rates_rejected(self):
        import math

        result = self._base_result()
        for metric in (
            "accuracy",
            "true_positive_rate",
            "false_positive_rate",
            "specificity",
            "false_negative_rate",
            "precision",
        ):
            result[metric] = math.nan
        verification = verify_benchmark(result)
        self.assertFalse(verification["valid"])
        single = self._base_result()
        single["accuracy"] = math.nan
        self.assertFalse(verify_benchmark(single)["valid"])

    def test_infinite_rates_rejected(self):
        import math

        for bad in (math.inf, -math.inf):
            result = self._base_result()
            result["accuracy"] = bad
            with self.subTest(bad=bad):
                self.assertFalse(verify_benchmark(result)["valid"])

    def test_null_string_bool_rates_rejected(self):
        for metric in (
            "accuracy",
            "true_positive_rate",
            "false_positive_rate",
            "specificity",
            "false_negative_rate",
            "precision",
        ):
            for bad in (None, "0.5", True):
                result = self._base_result()
                result[metric] = bad
                with self.subTest(metric=metric, bad=bad):
                    self.assertFalse(verify_benchmark(result)["valid"])

    def test_out_of_range_rates_rejected(self):
        for bad in (1.5, -0.1, 2.0):
            result = self._base_result()
            result["accuracy"] = bad
            with self.subTest(bad=bad):
                self.assertFalse(verify_benchmark(result)["valid"])

    def test_negative_counts_rejected(self):
        """The audit's algebraic case: tp=tn=-1, evaluated=-2 with
        algebraically consistent rates must still reject."""
        result = self._base_result()
        result.update(
            tp=-1,
            tn=-1,
            fp=0,
            fn=0,
            evaluated=-2,
            accuracy=1.0,
            true_positive_rate=1.0,
            false_positive_rate=0.0,
            specificity=1.0,
            false_negative_rate=0.0,
            precision=1.0,
        )
        verification = verify_benchmark(result)
        self.assertFalse(verification["valid"])

    def test_bool_fractional_string_null_counts_rejected(self):
        for field in ("tp", "fp", "tn", "fn", "evaluated"):
            for bad in (True, 10.5, "10", None, -1):
                result = self._base_result()
                result[field] = bad
                with self.subTest(field=field, bad=bad):
                    self.assertFalse(verify_benchmark(result)["valid"])

    def test_missing_count_rejected(self):
        for field in ("tp", "fp", "tn", "fn", "evaluated"):
            result = self._base_result()
            del result[field]
            with self.subTest(field=field):
                self.assertFalse(verify_benchmark(result)["valid"])

    def test_nonhex_dataset_digest_rejected(self):
        for bad in ("z" * 64, "A" * 64, "a" * 63, "a" * 65, 1234, None):
            result = self._base_result()
            result["dataset_sha256"] = bad
            with self.subTest(bad=bad):
                self.assertFalse(verify_benchmark(result)["valid"])

    def test_boundary_rates_accepted(self):
        result = self._base_result()
        result.update(
            tp=10,
            fp=0,
            tn=10,
            fn=0,
            evaluated=20,
            accuracy=1.0,
            true_positive_rate=1.0,
            false_positive_rate=0.0,
            specificity=1.0,
            false_negative_rate=0.0,
            precision=1.0,
        )
        verification = verify_benchmark(result)
        self.assertTrue(verification["valid"], verification.get("errors"))

    def test_valid_benchmark_still_passes(self):
        verification = verify_benchmark(self._base_result())
        self.assertTrue(verification["valid"], verification.get("errors"))


if __name__ == "__main__":
    unittest.main()
