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
        bundle["detector_results"][0]["evidence"].append({"snippet": TEXT})
        with self.assertRaises(ValueError):
            seal_case_file(bundle)

    def test_packaged_schemas_are_available(self):
        detector = load_schema("detector-result")
        forensic = load_schema("forensic-bundle")
        case = load_schema("case-file")
        self.assertEqual(
            detector["title"],
            "TextForensics Detector Result",
        )
        self.assertEqual(
            forensic["title"],
            "TextForensics Forensic Bundle",
        )
        self.assertEqual(
            case["title"],
            "TextForensics Case File",
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

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_generated_bundle_with_v3_trust_map_validates_against_all_schemas(self):
        """C23: a genuine current v3 Trust Map inside a v2 bundle (and the
        case sealing it) must validate against every applicable public
        schema — forensic-bundle, trust-map and case-file alike."""
        import jsonschema

        from textforensics.conditions import conditions_from_dict
        from textforensics.validation import ValidationRegistry, derive_trust_map

        bundle = build_forensic_bundle(TEXT).to_dict()
        conditions = conditions_from_dict(bundle["input_conditions"])
        bundle["trust_map"] = derive_trust_map(
            conditions,
            ValidationRegistry(),
            detector_id="textforensics/builtin-heuristic",
            detector_version="0.1.0",
            now="2026-11-07T00:00:00Z",
        ).to_dict()
        case = seal_case_file(bundle, version="v3")
        jsonschema.validate(bundle, load_schema("forensic-bundle"))
        jsonschema.validate(bundle["trust_map"], load_schema("trust-map"))
        jsonschema.validate(case, load_schema("case-file"))
        jsonschema.validate(case["forensic_bundle"], load_schema("forensic-bundle"))


class BundleTrustMapPairTableTests(unittest.TestCase):
    """W3 (C23 + CORE-10): the full bundle/map version pair table —
    every accepted pair validates through every applicable public
    schema and the generic surface; every rejected pair is refused
    by the schema, the pair validator and the sealer.  The table is
    the W2 decision and is NOT loosened here: v1 bundle + v1/v2 map;
    v2 bundle + v2/v3 map; never v3-in-v1, never v1-in-v2."""

    ACCEPTED_PAIRS = [
        ("textforensics.forensic-bundle/v1", "textforensics.trust-map/v1"),
        ("textforensics.forensic-bundle/v1", "textforensics.trust-map/v2"),
        ("textforensics.forensic-bundle/v2", "textforensics.trust-map/v2"),
        ("textforensics.forensic-bundle/v2", "textforensics.trust-map/v3"),
    ]
    REJECTED_PAIRS = [
        ("textforensics.forensic-bundle/v1", "textforensics.trust-map/v3"),
        ("textforensics.forensic-bundle/v2", "textforensics.trust-map/v1"),
    ]

    def _v1_trust_map(self):
        from textforensics.schema import DECLARED_TRUST_MAP_DIMENSIONS

        return {
            "schema": "textforensics.trust-map/v1",
            "overall": "mixed",
            "dimensions": [
                {"dimension": dim, "state": "unknown", "reason": "legacy view"}
                for dim in sorted(DECLARED_TRUST_MAP_DIMENSIONS)
            ],
            "limitations": ["legacy capability view"],
        }

    def _v3_trust_map(self, bundle):
        from textforensics.conditions import conditions_from_dict
        from textforensics.validation import ValidationRegistry, derive_trust_map

        conditions = conditions_from_dict(bundle["input_conditions"])
        return derive_trust_map(
            conditions,
            ValidationRegistry(),
            detector_id="textforensics/builtin-heuristic",
            detector_version="0.1.0",
            now="2026-11-07T00:00:00Z",
        ).to_dict()

    def _bundle_with(self, bundle_schema, trust_map_schema):
        bundle = build_forensic_bundle(TEXT).to_dict()
        bundle["schema"] = bundle_schema
        if bundle_schema == "textforensics.forensic-bundle/v1":
            bundle["verdict_integrity"] = {"verdict": "unknown"}
        if trust_map_schema == "textforensics.trust-map/v1":
            bundle["trust_map"] = self._v1_trust_map()
        elif trust_map_schema == "textforensics.trust-map/v3":
            bundle["trust_map"] = self._v3_trust_map(bundle)
        else:
            self.assertEqual(bundle["trust_map"]["schema"], "textforensics.trust-map/v2")
        return bundle

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_every_accepted_pair_validates_against_all_schemas(self):
        import jsonschema

        from textforensics.schema import validate, validate_bundle_trust_map_pair

        for bundle_schema, map_schema in self.ACCEPTED_PAIRS:
            with self.subTest(bundle=bundle_schema, trust_map=map_schema):
                bundle = self._bundle_with(bundle_schema, map_schema)
                jsonschema.validate(bundle, load_schema("forensic-bundle"))
                jsonschema.validate(bundle["trust_map"], load_schema("trust-map"))
                self.assertEqual(validate_bundle_trust_map_pair(bundle_schema, map_schema), [])
                self.assertEqual(validate(bundle, "forensic-bundle"), [])
                self.assertEqual(validate(bundle["trust_map"], "trust-map"), [])

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_every_rejected_pair_fails_schema_and_pair_validator(self):
        import jsonschema

        from textforensics.schema import validate, validate_bundle_trust_map_pair

        for bundle_schema, map_schema in self.REJECTED_PAIRS:
            with self.subTest(bundle=bundle_schema, trust_map=map_schema):
                bundle = self._bundle_with(bundle_schema, map_schema)
                with self.assertRaises(jsonschema.ValidationError):
                    jsonschema.validate(bundle, load_schema("forensic-bundle"))
                self.assertNotEqual(validate_bundle_trust_map_pair(bundle_schema, map_schema), [])
                self.assertNotEqual(validate(bundle, "forensic-bundle"), [])
                with self.assertRaises(ValueError):
                    seal_case_file(bundle)

    def test_accepted_v2_pairs_seal_and_verify(self):
        from textforensics.verify import verify_case_file_combined

        for bundle_schema, map_schema in self.ACCEPTED_PAIRS:
            if not bundle_schema.endswith("/v2"):
                continue
            with self.subTest(bundle=bundle_schema, trust_map=map_schema):
                bundle = self._bundle_with(bundle_schema, map_schema)
                case = seal_case_file(bundle, version="v3")
                self.assertTrue(verify_case_file(case)["valid"])
                self.assertTrue(verify_case_file_combined(case)["valid"])

    def test_accepted_v1_pairs_seal_as_legacy_v1(self):
        for bundle_schema, map_schema in self.ACCEPTED_PAIRS:
            if not bundle_schema.endswith("/v1"):
                continue
            with self.subTest(bundle=bundle_schema, trust_map=map_schema):
                bundle = self._bundle_with(bundle_schema, map_schema)
                case = seal_case_file(bundle, version="v1")
                self.assertEqual(case["schema"], "textforensics.case-file/v1")
                self.assertTrue(verify_case_file(case)["valid"])

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_stale_v3_dimensions_validate_in_v2_bundle(self):
        import jsonschema

        from textforensics.verify import verify_case_file_combined

        bundle = self._bundle_with("textforensics.forensic-bundle/v2", "textforensics.trust-map/v3")
        trust_map = bundle["trust_map"]
        # Flip one dimension to stale and keep the coverage counts exact.
        stale_dim = trust_map["dimensions"][0]
        old_state = stale_dim["state"]
        stale_dim["state"] = "stale"
        trust_map["coverage"][old_state] -= 1
        trust_map["coverage"]["stale"] = trust_map["coverage"].get("stale", 0) + 1
        jsonschema.validate(bundle, load_schema("forensic-bundle"))
        jsonschema.validate(trust_map, load_schema("trust-map"))
        case = seal_case_file(bundle, version="v3")
        jsonschema.validate(case, load_schema("case-file"))
        self.assertTrue(verify_case_file_combined(case)["valid"])


if __name__ == "__main__":
    unittest.main()
