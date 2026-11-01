from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from textforensics.casefile import (
    CASE_SCHEMA,
    _forbidden_paths,
    _hash_without_seal,
    _strip_runtime_ms_from_bundle,
    canonical_json_bytes,
    seal_case_file,
    verify_case_file,
    verify_case_file_path,
    write_case_file,
)
from textforensics.report import build_forensic_bundle

TEXT = (
    "I tested the device twice yesterday and wrote down what changed. "
    "The second run was warmer, so I plan to repeat it before drawing conclusions."
)


class CanonicalizationTests(unittest.TestCase):
    def test_canonical_json_bytes_is_stable(self):
        a = canonical_json_bytes({"b": 1, "a": 2})
        b = canonical_json_bytes({"a": 2, "b": 1})
        self.assertEqual(a, b)
        self.assertTrue(a.startswith(b'{"a":'))

    def test_canonical_json_bytes_rejects_nan(self):
        with self.assertRaises(ValueError):
            canonical_json_bytes({"x": float("nan")})


class CaseFileSealTests(unittest.TestCase):
    def test_seal_omits_raw_text_by_default(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle)
        self.assertEqual(case["schema"], CASE_SCHEMA)
        self.assertFalse(case["raw_text_included"])
        self.assertEqual(case["tool"]["name"], "TextForensics")
        self.assertEqual(len(case["case_sha256"]), 64)
        self.assertNotIn(TEXT, json.dumps(case))

    def test_seal_is_deterministic(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        self.assertEqual(
            seal_case_file(bundle)["case_sha256"],
            seal_case_file(bundle)["case_sha256"],
        )

    def test_seal_rejects_obvious_raw_text_fields(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        bundle["raw_text"] = TEXT
        with self.assertRaises(ValueError):
            seal_case_file(bundle)

    def test_seal_rejects_nested_raw_text_in_detector_evidence(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        bundle["detector_results"][0]["evidence"].append({"snippet": TEXT})
        with self.assertRaises(ValueError):
            seal_case_file(bundle)

    def test_seal_rejects_non_portable_bundle_schema(self):
        with self.assertRaises(ValueError):
            seal_case_file({"schema": "wrong"})

    def test_seal_rejects_invalid_content_sha256(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        bundle["content_sha256"] = "deadbeef"
        with self.assertRaises(ValueError):
            seal_case_file(bundle)

    def test_seal_rejects_bundle_that_includes_raw_text(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        bundle["document_text"] = TEXT
        with self.assertRaises(ValueError):
            seal_case_file(bundle)


class CaseFileVerifyTests(unittest.TestCase):
    def test_verify_detects_tampering(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle)
        self.assertTrue(verify_case_file(case)["valid"])

        case["forensic_bundle"]["content_sha256"] = "0" * 64
        result = verify_case_file(case)
        self.assertFalse(result["valid"])
        self.assertIn("case_hash_mismatch", result["errors"])

    def test_verify_rejects_wrong_schema(self):
        result = verify_case_file({"schema": "wrong"})
        self.assertFalse(result["valid"])
        self.assertIn("unsupported_schema", result["errors"])

    def test_verify_rejects_raw_text_inclusion(self):
        result = verify_case_file({"schema": CASE_SCHEMA, "raw_text_included": True})
        self.assertFalse(result["valid"])
        self.assertIn("raw_text_policy_violation", result["errors"])

    def test_verify_reports_note_about_integrity_not_authorship(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle)
        self.assertIn("does not prove", verify_case_file(case)["note"].lower())

    def test_verify_detects_tampered_bundle_schema(self):
        # Lines 130-131: verify_case_file catches invalid forensic bundle
        bundle = build_forensic_bundle(TEXT).to_dict()
        # Create case with tampered bundle schema
        case = seal_case_file(bundle)
        case["forensic_bundle"]["schema"] = "wrong-schema"
        result = verify_case_file(case)
        self.assertFalse(result["valid"])
        self.assertIn("invalid_or_nonportable_forensic_bundle", result["errors"])


class CaseFileIOTests(unittest.TestCase):
    def test_write_and_verify_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "case.json"
            bundle = build_forensic_bundle(TEXT).to_dict()
            case = write_case_file(path, bundle)
            self.assertTrue(path.exists())
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["case_sha256"], case["case_sha256"])
            self.assertNotIn(TEXT, path.read_text(encoding="utf-8"))

    def test_verify_case_file_path_detects_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "case.json"
            bundle = build_forensic_bundle(TEXT).to_dict()
            write_case_file(path, bundle)
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["forensic_bundle"]["content_sha256"] = "0" * 64
            path.write_text(json.dumps(payload), encoding="utf-8")
            result = verify_case_file_path(path)
            self.assertFalse(result["valid"])

    def test_verify_case_file_path_rejects_non_object(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "case.json"
            path.write_text("[]", encoding="utf-8")
            result = verify_case_file_path(path)
            self.assertFalse(result["valid"])


class ForbiddenPathTests(unittest.TestCase):
    def test_forbidden_paths_detect_top_level_keys(self):
        self.assertEqual(
            _forbidden_paths({"text": "x"}),
            ["$.text"],
        )

    def test_forbidden_paths_detect_nested_keys(self):
        self.assertEqual(
            _forbidden_paths({"evidence": [{"snippet": "x"}]}),
            ["$.evidence[0].snippet"],
        )

    def test_forbidden_paths_ignore_safe_keys(self):
        self.assertEqual(_forbidden_paths({"evidence": [{"feature": "x"}]}), [])


class BundleValidationTests(unittest.TestCase):
    def test_validate_portable_bundle_rejects_missing_input_metadata(self):
        # Line 78: raise ValueError when input metadata has raw_text_included != False
        from textforensics.casefile import _validate_portable_bundle

        bundle = {"schema": "textforensics.forensic-bundle/v1", "content_sha256": "a" * 64}
        # No 'input' field at all
        with self.assertRaises(ValueError) as ctx:
            _validate_portable_bundle(bundle)
        self.assertIn("raw_text_included", str(ctx.exception))

    def test_validate_portable_bundle_rejects_raw_text_included_true(self):
        # Line 78: raise ValueError when raw_text_included is True (not False)
        from textforensics.casefile import _validate_portable_bundle

        bundle = {
            "schema": "textforensics.forensic-bundle/v1",
            "content_sha256": "a" * 64,
            "input": {"raw_text_included": True},
        }
        with self.assertRaises(ValueError) as ctx:
            _validate_portable_bundle(bundle)
        self.assertIn("raw_text_included", str(ctx.exception))

    def test_seal_case_file_propagates_validation_error(self):
        # Test that seal_case_file raises ValueError when input validation fails
        bundle = build_forensic_bundle(TEXT).to_dict()
        bundle["input"]["raw_text_included"] = True
        with self.assertRaises(ValueError):
            seal_case_file(bundle)


class StripRuntimeMsTests(unittest.TestCase):
    """Tests for _strip_runtime_ms_from_bundle."""

    def test_strip_runtime_ms_from_detector_results(self):
        bundle = {
            "schema": "textforensics.forensic-bundle/v1",
            "content_sha256": "a" * 64,
            "detector_results": [
                {"detector_id": "d1", "runtime_ms": 12.3, "score": 0.8},
                {"detector_id": "d2", "runtime_ms": 45.6, "score": 0.5},
            ],
            "detector_failures": [],
        }
        result = _strip_runtime_ms_from_bundle(bundle)
        for r in result["detector_results"]:
            self.assertNotIn("runtime_ms", r)
        self.assertEqual(result["detector_results"][0]["score"], 0.8)
        # Original untouched
        self.assertEqual(bundle["detector_results"][0]["runtime_ms"], 12.3)

    def test_strip_runtime_ms_from_detector_failures(self):
        bundle = {
            "schema": "textforensics.forensic-bundle/v1",
            "content_sha256": "a" * 64,
            "detector_results": [],
            "detector_failures": [
                {"detector_id": "d1", "runtime_ms": 1.0, "error_type": "RuntimeError"},
            ],
        }
        result = _strip_runtime_ms_from_bundle(bundle)
        self.assertNotIn("runtime_ms", result["detector_failures"][0])
        self.assertEqual(result["detector_failures"][0]["error_type"], "RuntimeError")

    def test_strip_runtime_ms_handles_missing_fields(self):
        bundle = {
            "schema": "textforensics.forensic-bundle/v1",
            "content_sha256": "a" * 64,
        }
        result = _strip_runtime_ms_from_bundle(bundle)
        self.assertNotIn("detector_results", result)
        self.assertNotIn("detector_failures", result)

    def test_strip_runtime_ms_handles_non_dict_entries(self):
        bundle = {
            "schema": "textforensics.forensic-bundle/v1",
            "content_sha256": "a" * 64,
            "detector_results": ["not-a-dict", {"detector_id": "d1", "runtime_ms": 1.0}],
            "detector_failures": [],
        }
        result = _strip_runtime_ms_from_bundle(bundle)
        self.assertNotIn("runtime_ms", result["detector_results"][1])


class DeterministicSealTests(unittest.TestCase):
    """Tests for seal_case_file and write_case_file in deterministic mode."""

    def test_seal_deterministic_strips_runtime_ms(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        # Ensure runtime_ms is present in detector_results
        for r in bundle["detector_results"]:
            r["runtime_ms"] = 1.0
        for f in bundle["detector_failures"]:
            f["runtime_ms"] = 1.0
        case = seal_case_file(bundle, deterministic=True)
        for r in case["forensic_bundle"]["detector_results"]:
            self.assertNotIn("runtime_ms", r)
        for f in case["forensic_bundle"]["detector_failures"]:
            self.assertNotIn("runtime_ms", f)

    def test_seal_deterministic_with_fixed_timestamp(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(
            bundle, deterministic=True, fixed_timestamp="2025-01-01T00:00:00+00:00"
        )
        self.assertEqual(
            case["forensic_bundle"]["generated_at_utc"], "2025-01-01T00:00:00+00:00"
        )

    def test_seal_deterministic_without_fixed_timestamp_keeps_generated(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle, deterministic=True)
        self.assertIn("generated_at_utc", case["forensic_bundle"])

    def test_seal_non_deterministic_preserves_runtime_ms(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        for r in bundle["detector_results"]:
            r["runtime_ms"] = 1.0
        case = seal_case_file(bundle, deterministic=False)
        for r in case["forensic_bundle"]["detector_results"]:
            self.assertIn("runtime_ms", r)

    def test_write_case_file_deterministic_with_fixed_timestamp(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "case.json"
            bundle = build_forensic_bundle(TEXT).to_dict()
            for r in bundle["detector_results"]:
                r["runtime_ms"] = 1.0
            case = write_case_file(
                path,
                bundle,
                deterministic=True,
                fixed_timestamp="2025-06-01T12:00:00+00:00",
            )
            self.assertTrue(path.exists())
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(
                payload["forensic_bundle"]["generated_at_utc"],
                "2025-06-01T12:00:00+00:00",
            )
            for r in payload["forensic_bundle"]["detector_results"]:
                self.assertNotIn("runtime_ms", r)
            self.assertEqual(payload["case_sha256"], case["case_sha256"])

    def test_write_case_file_deterministic_reproducible(self):
        with tempfile.TemporaryDirectory() as tmp:
            path1 = Path(tmp) / "case1.json"
            path2 = Path(tmp) / "case2.json"
            bundle = build_forensic_bundle(TEXT).to_dict()
            c1 = write_case_file(path1, bundle, deterministic=True, fixed_timestamp="2025-01-01T00:00:00+00:00")
            c2 = write_case_file(path2, bundle, deterministic=True, fixed_timestamp="2025-01-01T00:00:00+00:00")
            self.assertEqual(c1["case_sha256"], c2["case_sha256"])

    def test_write_case_file_cleans_up_temp_file_on_failure(self):
        # Lines 204-207: finally block unlinks the temp file if os.replace fails.
        import unittest.mock as mock

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "case.json"
            bundle = build_forensic_bundle(TEXT).to_dict()
            real_replace = os.replace

            def failing_replace(src, dst):
                real_replace(src, dst)
                raise OSError("simulated replace failure")

            with mock.patch("textforensics.casefile.os.replace", side_effect=failing_replace), \
                 self.assertRaises(OSError):
                write_case_file(path, bundle)

            # No stray temp files remain in the directory
            leftovers = [p for p in Path(tmp).iterdir() if p.name != path.name]
            self.assertEqual(leftovers, [])
            # The original path was replaced before the failure, so the case file exists
            self.assertTrue(path.exists())


class HashWithoutSealTests(unittest.TestCase):
    def test_hash_ignores_case_sha256_field(self):
        case = {"schema": CASE_SCHEMA, "case_sha256": "a" * 64}
        without = {"schema": CASE_SCHEMA}
        self.assertEqual(_hash_without_seal(case), _hash_without_seal(without))


if __name__ == "__main__":
    unittest.main()
