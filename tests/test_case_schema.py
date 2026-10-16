import importlib.util
import unittest

from textforensics.casefile import seal_case_file, verify_case_file
from textforensics.report import build_forensic_bundle
from textforensics.schema import load_schema


TEXT = (
    "I tested the device twice yesterday and wrote down what changed. "
    "The second run was warmer, so I plan to repeat it before drawing conclusions."
)


class CaseAndSchemaTests(unittest.TestCase):
    def test_case_file_seal_detects_tampering(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle)
        self.assertFalse(case["raw_text_included"])
        self.assertTrue(verify_case_file(case)["valid"])

        case["forensic_bundle"]["content_sha256"] = "0" * 64
        result = verify_case_file(case)
        self.assertFalse(result["valid"])
        self.assertIn("case_hash_mismatch", result["errors"])

    def test_case_file_rejects_obvious_raw_text_fields(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        bundle["raw_text"] = TEXT
        with self.assertRaises(ValueError):
            seal_case_file(bundle)

    def test_case_file_rejects_raw_text_inside_detector_evidence(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        bundle["detector_results"][0]["evidence"].append(
            {"snippet": TEXT}
        )
        with self.assertRaises(ValueError):
            seal_case_file(bundle)

    def test_packaged_schemas_are_available(self):
        detector = load_schema("detector-result")
        forensic = load_schema("forensic-bundle")
        case = load_schema("case-file")
        self.assertEqual(
            detector["title"],
            "TextForensics Detector Result v1",
        )
        self.assertEqual(
            forensic["title"],
            "TextForensics Forensic Bundle v1",
        )
        self.assertEqual(
            case["title"],
            "TextForensics Case File v1",
        )

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_runtime_outputs_validate_against_packaged_schemas(self):
        import jsonschema

        bundle = build_forensic_bundle(TEXT).to_dict()
        jsonschema.validate(
            bundle,
            load_schema("forensic-bundle"),
        )
        case = seal_case_file(bundle)
        jsonschema.validate(
            case,
            load_schema("case-file"),
        )
        for detector in bundle["detector_results"]:
            jsonschema.validate(
                detector,
                load_schema("detector-result"),
            )


if __name__ == "__main__":
    unittest.main()
