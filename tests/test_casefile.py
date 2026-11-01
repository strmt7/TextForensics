from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from textforensics.casefile import (
    CASE_SCHEMA,
    _forbidden_paths,
    _hash_without_seal,
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


class HashWithoutSealTests(unittest.TestCase):
    def test_hash_ignores_case_sha256_field(self):
        case = {"schema": CASE_SCHEMA, "case_sha256": "a" * 64}
        without = {"schema": CASE_SCHEMA}
        self.assertEqual(_hash_without_seal(case), _hash_without_seal(without))


if __name__ == "__main__":
    unittest.main()
