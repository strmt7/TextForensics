"""Tests for schema validation module."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from textforensics.casefile import seal_case_file
from textforensics.report import build_forensic_bundle
from textforensics.schema import (
    _SCHEMA_NAMES,
    list_schemas,
    load_schema,
    validate,
    validate_case_file,
    validate_detector_result,
    validate_evidence_record,
    validate_forensic_bundle,
    validate_trust_map,
)

TEXT = (
    "I tested the device twice yesterday and wrote down what changed. "
    "The second run was warmer, so I plan to repeat it before drawing conclusions."
)


def minimal_evidence_record() -> dict:
    """A minimal well-formed synthetic U1 evidence record (no real data)."""
    metric = {
        "value": 0.8,
        "n": 240,
        "ci_lower": 0.7,
        "ci_upper": 0.9,
        "method": "bootstrap, 1000 resamples, seed 20261106",
    }
    fpr_native = {
        "value": 0.02,
        "n": 120,
        "ci_lower": 0.0,
        "ci_upper": 0.05,
        "method": "bootstrap, 1000 resamples, seed 20261106",
        "operating_point": "builtin-heuristic native verdict (analyze_text); no score threshold",
    }
    return {
        "schema": "textforensics.evidence-record/v1",
        "record_id": "evr-20261106-synthetic-test-builtin-heuristic",
        "detector_id": "textforensics/builtin-heuristic",
        "detector_version": "0.1.0",
        "detector_family": "stylometric-heuristic",
        "calibration_id": None,
        "status": "partial",
        "supersedes": None,
        "regime": {
            "language": "en",
            "script": "Latn",
            "language_variety": None,
            "length_bucket": {
                "min_words": 80,
                "max_words": None,
                "floor_words": 80,
                "measured_min_words": 85,
                "measured_median_words": 120,
                "measured_max_words": 400,
            },
            "domain": ["synthetic"],
            "genre": "synthetic-test",
            "generator": {
                "families": ["synthetic"],
                "vintage": "synthetic",
                "current_as_of": "2026-11-06",
            },
            "editing_regime": "raw",
            "human_population": {
                "populations": ["synthetic"],
                "determined_how": "synthetic test fixture",
            },
            "attack_slice": None,
        },
        "data": {
            "dataset_name": "synthetic-test",
            "dataset_version": "1.0",
            "file_sha256": "a" * 64,
            "row_hash_method": "sha256 of normalised text (benchmark fingerprint)",
            "split": "test",
            "split_role": "test",
            "n_human": 120,
            "n_ai": 120,
            "licence": "MIT",
            "licence_reference": "https://example.invalid/synthetic-test-licence",
            "contamination_flag": "no",
            "near_duplicate_rate": None,
            "near_duplicate_method": None,
        },
        "run": {
            "run_id": "EV-20261106-synthetic-test",
            "run_artifact": "docs/evidence/runs/EV-20261106-synthetic-test.json",
            "run_artifact_sha256": "b" * 64,
            "run_date": "2026-11-06",
            "runner": "synthetic-test",
            "code_version": "a" * 40,
            "dependency_lock_sha": None,
            "hardware": "synthetic-test",
            "runtime": "CPython 3.12.3 on Linux",
            "seeds": {"bootstrap_seed": 20261106},
            "command": "python -m pytest tests/test_schema.py",
            "drops_manifest": [],
            "reporting_rules": "synthetic test fixture",
        },
        "metrics": [
            {
                "slice_id": "synthetic-test",
                "n_human": 120,
                "n_ai": 120,
                "auroc": dict(metric),
                "tpr_at_fpr_0_01": dict(metric, value=0.5, n=120, ci_lower=0.4, ci_upper=0.6),
                "tpr_at_fpr_0_05": dict(metric, value=0.7, n=120, ci_lower=0.6, ci_upper=0.8),
                "fpr_native": fpr_native,
                "coverage": 1.0,
                "abstention_rate": 0.0,
                "worst_slice": True,
            }
        ],
        "limits": {
            "known_failure_modes": ["synthetic test fixture"],
            "limitations": ["not validated for anything real"],
            "next_revalidation_due": "2027-02-04",
            "appeal_note": "synthetic test fixture",
            "reviewer": None,
            "review_date": None,
            "demoted_by": None,
        },
        "signature": "c" * 64,
    }


class SchemaLoaderTests(unittest.TestCase):
    def test_all_packaged_schemas_load(self):
        for name in ("detector-result", "forensic-bundle", "case-file", "trust-map"):
            schema = load_schema(name)
            self.assertIsInstance(schema, dict)
            self.assertTrue(schema.get("title"))

    def test_unknown_schema_raises_with_available_list(self):
        with self.assertRaises(ValueError) as ctx:
            load_schema("does-not-exist")
        self.assertIn("Available:", str(ctx.exception))
        self.assertIn("trust-map", str(ctx.exception))

    def test_list_schemas_returns_all(self):
        schemas = list_schemas()
        self.assertEqual(schemas, sorted(_SCHEMA_NAMES.keys()))
        self.assertIn("trust-map", schemas)
        self.assertIn("evidence-record", schemas)
        self.assertIn("validation-registry", schemas)

    def test_evidence_record_schema_loads(self):
        schema = load_schema("evidence-record")
        self.assertEqual(schema["title"], "TextForensics validation evidence record (U1)")
        self.assertEqual(
            schema["properties"]["schema"]["const"], "textforensics.evidence-record/v1"
        )
        self.assertIn("supported", schema["properties"]["status"]["enum"])
        self.assertIn("contested", schema["properties"]["status"]["enum"])

    def test_validation_registry_schema_loads(self):
        schema = load_schema("validation-registry")
        self.assertEqual(schema["title"], "TextForensics validation registry (U1)")
        self.assertEqual(
            schema["properties"]["schema"]["const"], "textforensics.validation-registry/v1"
        )
        self.assertIn("records", schema["required"])

    def test_load_schema_caching(self):
        # Call twice - should use cache on second call
        schema1 = load_schema("forensic-bundle")
        schema2 = load_schema("forensic-bundle")
        self.assertIs(schema1, schema2)


class SchemaValidationTests(unittest.TestCase):
    def setUp(self):
        self.bundle = build_forensic_bundle(TEXT).to_dict()
        self.case = seal_case_file(self.bundle)

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_valid_forensic_bundle_passes(self):
        errors = validate_forensic_bundle(self.bundle)
        self.assertEqual(errors, [])

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_valid_case_file_passes(self):
        errors = validate_case_file(self.case)
        self.assertEqual(errors, [])

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_detector_results_validate(self):
        for detector in self.bundle["detector_results"]:
            errors = validate_detector_result(detector)
            self.assertEqual(errors, [], f"Detector {detector.get('detector_id')} failed: {errors}")

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_trust_map_validates(self):
        trust_map = self.bundle["trust_map"]
        errors = validate_trust_map(trust_map)
        self.assertEqual(errors, [])

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_invalid_forensic_bundle_fails(self):
        invalid_bundle = self.bundle.copy()
        # Remove required field
        del invalid_bundle["schema"]
        errors = validate_forensic_bundle(invalid_bundle)
        self.assertGreater(len(errors), 0)
        self.assertTrue(any("schema" in e for e in errors))

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_invalid_case_file_fails(self):
        invalid_case = self.case.copy()
        del invalid_case["schema"]
        errors = validate_case_file(invalid_case)
        self.assertGreater(len(errors), 0)

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_invalid_detector_result_fails(self):
        detector = self.bundle["detector_results"][0].copy()
        del detector["schema"]
        errors = validate_detector_result(detector)
        self.assertGreater(len(errors), 0)

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_invalid_trust_map_fails(self):
        trust_map = self.bundle["trust_map"].copy()
        del trust_map["schema"]
        errors = validate_trust_map(trust_map)
        self.assertGreater(len(errors), 0)

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_validate_function_dispatches_correctly(self):
        errors = validate(self.bundle, "forensic-bundle")
        self.assertEqual(errors, [])

        errors = validate(self.case, "case-file")
        self.assertEqual(errors, [])

        errors = validate(self.bundle["trust_map"], "trust-map")
        self.assertEqual(errors, [])

        for det in self.bundle["detector_results"]:
            errors = validate(det, "detector-result")
            self.assertEqual(errors, [])

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_valid_evidence_record_passes(self):
        errors = validate_evidence_record(minimal_evidence_record())
        self.assertEqual(errors, [])

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_invalid_evidence_record_fails(self):
        record = minimal_evidence_record()
        record["status"] = "definitely-supported"
        del record["signature"]
        errors = validate_evidence_record(record)
        self.assertGreater(len(errors), 0)
        self.assertTrue(any("status" in e for e in errors))
        self.assertTrue(any("signature" in e for e in errors))

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_invalid_contamination_flag_fails(self):
        record = minimal_evidence_record()
        record["data"]["contamination_flag"] = "maybe"
        errors = validate_evidence_record(record)
        self.assertGreater(len(errors), 0)
        self.assertTrue(any("contamination_flag" in e for e in errors))

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_validate_dispatches_evidence_record(self):
        errors = validate(minimal_evidence_record(), "evidence-record")
        self.assertEqual(errors, [])

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_valid_validation_registry_passes(self):
        import jsonschema

        schema = load_schema("validation-registry")
        registry = {
            "schema": "textforensics.validation-registry/v1",
            "registry_id": "d" * 64,
            "created_at_utc": "2026-11-06T00:00:00+00:00",
            "records": [minimal_evidence_record()],
        }
        validator = jsonschema.Draft202012Validator(schema)
        self.assertEqual(list(validator.iter_errors(registry)), [])

    def test_validate_unknown_schema_raises(self):
        with self.assertRaises(ValueError) as ctx:
            validate(self.bundle, "unknown-schema")
        self.assertIn("Unknown schema", str(ctx.exception))


class SchemaCLITests(unittest.TestCase):
    """Tests for CLI schema commands."""

    def setUp(self):
        self.bundle = build_forensic_bundle(TEXT).to_dict()
        self.case = seal_case_file(self.bundle)

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_cli_schema_validate_forensic_bundle(self):
        """Test CLI schema validate command for forensic bundle."""
        import subprocess

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(self.bundle, f)
            temp_path = f.name

        try:
            result = subprocess.run(
                ["textforensics", "schema", "validate", temp_path, "--type", "forensic-bundle"],
                capture_output=True,
                text=True,
                cwd=Path(__file__).parent.parent,
            )
            self.assertEqual(result.returncode, 0, f"stderr: {result.stderr}")
            output = json.loads(result.stdout)
            self.assertTrue(output["valid"])
            self.assertEqual(output["errors"], [])
        finally:
            Path(temp_path).unlink()

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_cli_schema_validate_invalid(self):
        """Test CLI schema validate command fails for invalid data."""
        import subprocess

        invalid_bundle = self.bundle.copy()
        del invalid_bundle["schema"]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(invalid_bundle, f)
            temp_path = f.name

        try:
            result = subprocess.run(
                ["textforensics", "schema", "validate", temp_path, "--type", "forensic-bundle"],
                capture_output=True,
                text=True,
                cwd=Path(__file__).parent.parent,
            )
            self.assertEqual(result.returncode, 2)  # EXIT_INCOMPLETE
            output = json.loads(result.stdout)
            self.assertFalse(output["valid"])
            self.assertGreater(len(output["errors"]), 0)
        finally:
            Path(temp_path).unlink()

    def test_cli_schema_list(self):
        """Test CLI schema list command."""
        import subprocess

        result = subprocess.run(
            ["textforensics", "schema", "list"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("schemas", output)
        schemas = output["schemas"]
        self.assertIn("forensic-bundle", schemas)
        self.assertIn("detector-result", schemas)
        self.assertIn("case-file", schemas)
        self.assertIn("trust-map", schemas)

    def test_cli_schema_show(self):
        """Test CLI schema show command."""
        import subprocess

        result = subprocess.run(
            ["textforensics", "schema", "show", "forensic-bundle"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        self.assertEqual(result.returncode, 0)
        schema = json.loads(result.stdout)
        self.assertEqual(schema["title"], "TextForensics Forensic Bundle")

    def test_cli_schema_show_unknown(self):
        """Test CLI schema show command for unknown schema."""
        import subprocess

        result = subprocess.run(
            ["textforensics", "schema", "show", "unknown"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
