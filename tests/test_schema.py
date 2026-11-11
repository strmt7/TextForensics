"""Tests for schema validation module."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from textforensics import schema as schema_module
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


# ---------------------------------------------------------------------------
# W2 Worker C (CORE-10 / C23): one explicit, complete, version-aware
# schema registry.  New API is reached through the module so these tests
# fail (AttributeError) on the pre-fix registry instead of failing at
# collection time.
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMAS_DIR = REPO_ROOT / "src" / "textforensics" / "schemas"


def _valid_payloads() -> dict[str, dict]:
    """One minimal valid synthetic payload per shipped schema."""
    return {
        "evidence-registry": {
            "schema": "textforensics.evidence-registry/v1",
            "records": [],
        },
        "validation-registry": {
            "schema": "textforensics.validation-registry/v1",
            "registry_id": "d" * 64,
            "created_at_utc": "2026-11-06T00:00:00+00:00",
            "records": [],
        },
        "run-artifact": {
            "schema": "textforensics.run-artifact/v1",
            "evidence_record_id": "EV-20261106-synthetic-test",
            "kind": "test",
            "command": "pytest",
            "environment": {"python": "3.12.3"},
            "code_version": "a" * 40,
            "run_date": "2026-11-06",
            "results": {},
            "drops": [],
            "badge": "available",
        },
        "sealed-bundle-manifest": {
            "schema": "textforensics.sealed-bundle-manifest/v1",
            "context": {
                "tool_version": "0.1.0",
                "case_id": "a" * 64,
                "input_sha256": "b" * 64,
                "registry_sha256": None,
                "signature": None,
                "signer": None,
                "timestamp_token_sha256": None,
                "timestamp_imprint": None,
                "appeal_checklist_digest": None,
            },
            "files": [],
        },
        "evidence-manifest": {
            "schema": "textforensics.evidence-manifest/v1",
            "manifest_version": "1",
            "candidate_source_sha": "a" * 40,
            "source_tree_digest": {"method": "git-tree", "value": "a" * 40},
            "package_inputs": [
                {
                    "name": "textforensics",
                    "version": "0.2.0",
                    "digest": {"algorithm": "sha256", "value": "a" * 64},
                }
            ],
            "schema_versions": {"forensic-bundle": "textforensics.forensic-bundle/v2"},
            "test_suites": [{"suite": "core", "run_id": "local-synthetic"}],
            "scientific_run_ids": [],
            "artifacts": [
                {"path": "docs/evidence/report-card.md", "sha256": "a" * 64, "role": "report"}
            ],
            "gate_results": {
                "verify_release_output": {"path": "verify-release.json", "sha256": "a" * 64},
                "gates": {"core": {"status": "pass"}},
                "required_gates": ["core"],
            },
            "recorded_at_utc": "2026-11-06T00:00:00+00:00",
        },
        "probe-run": {
            "schema": "textforensics.probe-run/v1",
            "run_id": "run-1",
            "run_at_utc": "2026-11-06T00:00:00+00:00",
            "scope": "full",
            "corpus_version": "1.0.0",
            "corpus_fingerprint": "a" * 64,
            "detector_id": "synthetic-detector",
            "detector_version": "0.1.0",
            "code_sha": "a" * 40,
            "baseline_run_id": None,
            "is_baseline": True,
            "previous_run_id": None,
            "alpha_per_run": 0.01,
            "thresholds": {
                "psi_action": 0.1,
                "ks_effect_size": 0.1,
                "ks_p_threshold": 0.01,
                "flip_rate_tier2": 0.1,
                "flip_rate_tier1": 0.2,
                "ece_increase_tier2": 0.05,
                "coverage_shortfall_tier2_pp": 5.0,
                "coverage_shortfall_tier1_pp": 10.0,
                "version_change_stale_days": 30,
                "min_clean_full_runs_for_temporal_support": 3,
                "min_slice_n": 100,
                "min_slice_n_for_fpr_claim": 100,
                "fpr_cap": 0.05,
            },
            "metrics": {},
            "alerts": [],
            "breaches": [],
            "demotions_applied": {},
            "demotions_cleared": {},
            "watches": [],
            "gaps": [],
            "scope_statement": "synthetic",
            "limitations": [],
        },
        "mixed-origin-report": {
            "schema": "textforensics.mixed-origin-report/v1",
            "input": {
                "char_count": 10,
                "word_count": 3,
                "segment_count": 1,
                "content_hash": "sha256:" + "a" * 64,
            },
            "detector": {"id": "synthetic-detector", "version": "0.1.0"},
            "verdict": "withheld",
            "withheld_reasons": ["synthetic"],
            "collaboration_type": "unknown",
            "collaboration_confidence": "low",
            "degree_of_change": {
                "estimate": 0.5,
                "tiers": "human",
                "method": "synthetic",
                "calibration": "none",
            },
            "operation_hypothesis": {
                "operation": "unknown",
                "direction": "unknown",
                "confidence": "low",
                "evidence": [],
            },
            "segments": [],
            "non_monotonicity_warning": (
                "Intermediate mixtures are the hardest regime to detect "
                "(OpAI-Bench 2026); a low AI score here does not mean human."
            ),
            "idea_provenance_note": (
                "Prose evidence cannot determine who originated the ideas (IdeaLens 2026)."
            ),
            "regime": {"language": "en", "domain": "synthetic", "validation_slice_covered": False},
            "limitations": ["synthetic"],
        },
    }


class SchemaRegistryCompletenessTests(unittest.TestCase):
    """CORE-10: discovery, dispatch and versioning must agree with the tree."""

    def test_registry_lists_every_shipped_schema(self):
        shipped = sorted(p.name.removesuffix(".schema.json") for p in SCHEMAS_DIR.glob("*.json"))
        self.assertEqual(shipped, sorted(list_schemas()))
        self.assertIn("evidence-manifest", list_schemas())
        self.assertIn("mixed-origin-report", list_schemas())
        self.assertIn("probe-run", list_schemas())

    def test_every_listed_schema_loads(self):
        for name in list_schemas():
            schema = load_schema(name)
            self.assertIsInstance(schema, dict)
            self.assertIn("$schema", schema)

    def test_validate_dispatches_every_listed_name(self):
        # An invalid payload must produce schema errors, never an
        # "Unknown schema" ValueError: dispatch must exist for every
        # listed name, including the four CORE-10 names.
        for name in list_schemas():
            with self.subTest(name=name):
                errors = validate({}, name)
                self.assertIsInstance(errors, list)
                self.assertGreater(len(errors), 0)

    def test_validate_accepts_valid_payload_for_every_listed_name(self):
        payloads = _valid_payloads()
        payloads["evidence-record"] = minimal_evidence_record()
        bundle = build_forensic_bundle(TEXT).to_dict()
        payloads["forensic-bundle"] = bundle
        payloads["case-file"] = seal_case_file(bundle)
        payloads["trust-map"] = bundle["trust_map"]
        payloads["detector-result"] = bundle["detector_results"][0]
        payloads["enterprise-policy"] = {
            "revision": 1,
            "settings": {},
            "rules": [
                {
                    "id": "synthetic-rule",
                    "description": "synthetic",
                    "action": "warn",
                    "scope": "global",
                }
            ],
        }
        self.assertEqual(set(payloads), set(list_schemas()))
        for name, payload in payloads.items():
            with self.subTest(name=name):
                self.assertEqual(validate(payload, name), [], f"{name} failed to validate")

    def test_supported_versions_come_from_the_schema_files(self):
        supported_versions = schema_module.supported_versions
        self.assertEqual(
            supported_versions("trust-map"),
            frozenset(
                {
                    "textforensics.trust-map/v1",
                    "textforensics.trust-map/v2",
                    "textforensics.trust-map/v3",
                }
            ),
        )
        self.assertEqual(
            supported_versions("forensic-bundle"),
            frozenset({"textforensics.forensic-bundle/v1", "textforensics.forensic-bundle/v2"}),
        )
        self.assertEqual(
            supported_versions("case-file"),
            frozenset(
                {
                    "textforensics.case-file/v1",
                    "textforensics.case-file/v2",
                    "textforensics.case-file/v3",
                    "textforensics.case-file/v4",
                }
            ),
        )
        self.assertEqual(
            supported_versions("evidence-record"),
            frozenset({"textforensics.evidence-record/v1"}),
        )
        # enterprise-policy carries no top-level version: unversioned.
        self.assertEqual(supported_versions("enterprise-policy"), frozenset())
        with self.assertRaises(ValueError):
            supported_versions("does-not-exist")

    def test_unsupported_version_is_refused_deliberately(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        bundle["schema"] = "textforensics.forensic-bundle/v99"
        errors = validate(bundle, "forensic-bundle")
        self.assertTrue(any("v99" in e and "unsupported" in e.lower() for e in errors), errors)
        trust_map = bundle["trust_map"]
        trust_map["schema"] = "textforensics.trust-map/v9"
        errors = validate(trust_map, "trust-map")
        self.assertTrue(any("unsupported" in e.lower() for e in errors), errors)
        with self.assertRaises(ValueError):
            load_schema("trust-map", version="textforensics.trust-map/v9")
        # A supported version loads.
        self.assertIsInstance(load_schema("trust-map", version="textforensics.trust-map/v3"), dict)

    def test_declared_trust_map_dimensions_are_the_single_set(self):
        from textforensics.trust import TRUST_DIMENSIONS

        declared = schema_module.DECLARED_TRUST_MAP_DIMENSIONS
        self.assertEqual(declared, frozenset(TRUST_DIMENSIONS))
        self.assertEqual(
            declared,
            {
                "language",
                "text_length",
                "domain_genre",
                "editing_revision",
                "generator_scope",
                "human_population",
                "human_false_positive_evidence",
                "detector_diversity",
                "benign_stability",
                "temporal_version_stability",
            },
        )
        trust_schema = load_schema("trust-map")
        for version in ("v2", "v3"):
            branch = next(
                item["then"]["properties"]["dimensions"]["items"]["properties"]["dimension"][
                    "enum"
                ]
                for item in trust_schema["allOf"]
                if item["if"]["properties"]["schema"]["const"]
                == f"textforensics.trust-map/{version}"
            )
            self.assertEqual(set(branch), set(declared))

    def test_bundle_trust_map_version_pairs(self):
        # C23 compatibility decision: a bundle accepts its own map
        # version and the next one; nothing else.
        check_pair = schema_module.validate_bundle_trust_map_pair
        for bundle_version, map_version in (
            ("textforensics.forensic-bundle/v1", "textforensics.trust-map/v1"),
            ("textforensics.forensic-bundle/v1", "textforensics.trust-map/v2"),
            ("textforensics.forensic-bundle/v2", "textforensics.trust-map/v2"),
            ("textforensics.forensic-bundle/v2", "textforensics.trust-map/v3"),
        ):
            with self.subTest(bundle=bundle_version, trust_map=map_version):
                self.assertEqual(check_pair(bundle_version, map_version), [])
        for bundle_version, map_version in (
            ("textforensics.forensic-bundle/v1", "textforensics.trust-map/v3"),
            ("textforensics.forensic-bundle/v2", "textforensics.trust-map/v1"),
            ("textforensics.forensic-bundle/v2", "textforensics.trust-map/v9"),
            ("textforensics.forensic-bundle/v9", "textforensics.trust-map/v2"),
        ):
            with self.subTest(bundle=bundle_version, trust_map=map_version):
                self.assertGreater(len(check_pair(bundle_version, map_version)), 0)


if __name__ == "__main__":
    unittest.main()
