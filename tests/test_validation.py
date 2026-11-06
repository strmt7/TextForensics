"""Tests for the U1 validation-evidence registry (validation.py).

All records here are synthetic fixtures (dataset_name "synthetic-test",
clearly invented values). No dataset data, no raw text, and no measured
numbers appear in these tests.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from textforensics.benchmark import DatasetFingerprint, check_disjointness, fingerprint_dataset
from textforensics.validation import (
    CONTAMINATED_LABEL,
    ValidationError,
    ValidationRecord,
    ValidationRegistry,
    compute_signature,
    contamination_label,
    default_next_revalidation_due,
    effective_status,
    empty_validation_registry,
    load_validation_registry,
    missing_mandatory_fields,
    validate_record,
    verify_signature,
)

NOW_FRESH = "2026-11-06T00:00:00+00:00"


def make_record_dict(*, status: str = "supported", record_id: str | None = None) -> dict:
    """Build a complete synthetic record dict, signed with compute_signature."""
    metric = {
        "value": 0.8,
        "n": 240,
        "ci_lower": 0.7,
        "ci_upper": 0.9,
        "method": "bootstrap, 1000 resamples, seed 20261106",
    }
    record = {
        "schema": "textforensics.evidence-record/v1",
        "record_id": record_id or "evr-20261106-synthetic-test-builtin-heuristic",
        "detector_id": "textforensics/builtin-heuristic",
        "detector_version": "0.1.0",
        "detector_family": "stylometric-heuristic",
        "calibration_id": None,
        "status": status,
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
            "command": "python scripts/seed_validation.py --synthetic-test",
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
                "fpr_native": dict(
                    metric,
                    value=0.02,
                    n=120,
                    ci_lower=0.0,
                    ci_upper=0.05,
                    operating_point=(
                        "builtin-heuristic native verdict (analyze_text); no score threshold"
                    ),
                ),
                "tpr_native": dict(metric, value=0.1, n=120, ci_lower=0.05, ci_upper=0.2),
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
        "signature": "0" * 64,
    }
    record["signature"] = compute_signature(record)
    return record


def resign(record: dict) -> dict:
    """Recompute the signature of a mutated record dict (in place)."""
    record["signature"] = compute_signature(record)
    return record


class ValidRecordTests(unittest.TestCase):
    def test_valid_record_has_no_issues(self):
        self.assertEqual(validate_record(make_record_dict()), [])

    def test_from_dict_round_trip(self):
        original = make_record_dict()
        record = ValidationRecord.from_dict(original)
        self.assertEqual(record.to_dict(), original)
        self.assertEqual(record.validation_notes, ())

    def test_tpr_native_round_trip(self):
        record = ValidationRecord.from_dict(make_record_dict())
        tpr_native = record.metrics[0].tpr_native
        self.assertIsNotNone(tpr_native)
        assert tpr_native is not None
        self.assertEqual(tpr_native.value, 0.1)
        self.assertEqual(tpr_native.n, 120)
        self.assertEqual((tpr_native.ci_lower, tpr_native.ci_upper), (0.05, 0.2))
        self.assertEqual(record.to_dict()["metrics"][0]["tpr_native"]["value"], 0.1)

    def test_record_without_tpr_native_still_valid(self):
        payload = make_record_dict()
        del payload["metrics"][0]["tpr_native"]
        resign(payload)
        self.assertEqual(validate_record(payload), [])
        record = ValidationRecord.from_dict(payload)
        self.assertIsNone(record.metrics[0].tpr_native)
        self.assertNotIn("tpr_native", record.to_dict()["metrics"][0])

    def test_tpr_native_n_cannot_exceed_n_ai(self):
        payload = make_record_dict()
        payload["metrics"][0]["tpr_native"]["n"] = 121
        resign(payload)
        issues = validate_record(payload)
        self.assertTrue(
            any("tpr_native n cannot exceed n_ai" in issue for issue in issues),
            issues,
        )

    def test_effective_status_supported_when_fresh(self):
        record = make_record_dict()
        self.assertEqual(
            effective_status(record, detector_version="0.1.0", now=NOW_FRESH),
            "supported",
        )

    def test_effective_status_accepts_datetime_now(self):
        record = ValidationRecord.from_dict(make_record_dict())
        self.assertEqual(
            effective_status(
                record,
                detector_version="0.1.0",
                now=datetime(2026, 11, 6, 12, 0, 0),
            ),
            "supported",
        )

    def test_partial_stored_status_stays_partial(self):
        record = make_record_dict(status="partial")
        self.assertEqual(
            effective_status(record, detector_version="0.1.0", now=NOW_FRESH),
            "partial",
        )

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_complete_record_passes_json_schema(self):
        from textforensics.schema import validate_evidence_record

        record = ValidationRecord.from_dict(make_record_dict())
        self.assertEqual(validate_evidence_record(record.to_dict()), [])


class PartialCapTests(unittest.TestCase):
    def test_missing_genre_caps_at_partial(self):
        record = copy.deepcopy(make_record_dict())
        del record["regime"]["genre"]
        issues = validate_record(record)
        self.assertTrue(any("regime.genre" in issue for issue in issues))
        self.assertEqual(
            effective_status(record, detector_version="0.1.0", now=NOW_FRESH),
            "partial",
        )

    def test_missing_hardware_caps_at_partial(self):
        record = copy.deepcopy(make_record_dict())
        record["run"]["hardware"] = None
        resign(record)
        self.assertIn("run.hardware", missing_mandatory_fields(record))
        self.assertEqual(
            effective_status(record, detector_version="0.1.0", now=NOW_FRESH),
            "partial",
        )
        # A capped record still loads: the cap is a status, not a refusal.
        loaded = ValidationRecord.from_dict(record)
        self.assertEqual(loaded.validation_notes, ("run.hardware",))

    def test_missing_mandatory_fields_lists_exact_paths(self):
        record = copy.deepcopy(make_record_dict())
        del record["regime"]["genre"]
        record["limits"]["appeal_note"] = None
        self.assertEqual(
            missing_mandatory_fields(record),
            ["regime.genre", "limits.appeal_note"],
        )

    def test_nullable_fields_do_not_cap(self):
        record = copy.deepcopy(make_record_dict())
        # Explicitly nullable fields carry a null and must not cap.
        record["calibration_id"] = None
        record["regime"]["language_variety"] = None
        record["regime"]["attack_slice"] = None
        record["limits"]["reviewer"] = None
        self.assertEqual(missing_mandatory_fields(record), [])
        self.assertEqual(
            effective_status(record, detector_version="0.1.0", now=NOW_FRESH),
            "supported",
        )

    def test_zero_sample_count_is_a_value_not_a_missing_field(self):
        record = copy.deepcopy(make_record_dict())
        record["data"]["n_human"] = 0
        self.assertEqual(missing_mandatory_fields(record), [])


class HardRejectionTests(unittest.TestCase):
    def test_missing_licence_is_rejected(self):
        record = copy.deepcopy(make_record_dict())
        record["data"]["licence"] = ""
        issues = validate_record(record)
        self.assertTrue(any("licence" in issue for issue in issues))
        with self.assertRaises(ValidationError):
            ValidationRecord.from_dict(record)

    def test_absent_licence_key_is_rejected(self):
        record = copy.deepcopy(make_record_dict())
        del record["data"]["licence"]
        with self.assertRaises(ValidationError):
            ValidationRecord.from_dict(record)

    def test_missing_contamination_flag_is_rejected(self):
        record = copy.deepcopy(make_record_dict())
        del record["data"]["contamination_flag"]
        issues = validate_record(record)
        self.assertTrue(any("contamination_flag" in issue for issue in issues))
        with self.assertRaises(ValidationError):
            ValidationRecord.from_dict(record)

    def test_bad_status_is_rejected(self):
        record = copy.deepcopy(make_record_dict())
        record["status"] = "great"
        self.assertTrue(validate_record(record))
        with self.assertRaises(ValidationError):
            ValidationRecord.from_dict(record)

    def test_bad_signature_format_is_rejected(self):
        record = copy.deepcopy(make_record_dict())
        record["signature"] = "not-a-hash"
        self.assertTrue(validate_record(record))
        with self.assertRaises(ValidationError):
            ValidationRecord.from_dict(record)

    def test_bad_metric_ci_is_rejected(self):
        record = copy.deepcopy(make_record_dict())
        record["metrics"][0]["auroc"]["value"] = 0.95  # outside its CI
        self.assertTrue(validate_record(record))
        with self.assertRaises(ValidationError):
            ValidationRecord.from_dict(record)

    def test_validation_error_is_a_value_error(self):
        self.assertTrue(issubclass(ValidationError, ValueError))


class SignatureTests(unittest.TestCase):
    def test_compute_verify_round_trip(self):
        record = make_record_dict()
        self.assertTrue(verify_signature(record))
        self.assertEqual(compute_signature(record), record["signature"])

    def test_signature_excludes_itself(self):
        record = make_record_dict()
        unsigned = {key: value for key, value in record.items() if key != "signature"}
        self.assertEqual(compute_signature(unsigned), record["signature"])

    def test_tamper_detected(self):
        record = copy.deepcopy(make_record_dict())
        record["data"]["n_human"] = 121
        self.assertFalse(verify_signature(record))

    def test_missing_signature_fails_verify(self):
        record = copy.deepcopy(make_record_dict())
        del record["signature"]
        self.assertFalse(verify_signature(record))

    def test_verify_accepts_record_object(self):
        record = ValidationRecord.from_dict(make_record_dict())
        self.assertTrue(verify_signature(record))
        self.assertEqual(compute_signature(record), record.signature)


class StalenessTests(unittest.TestCase):
    def test_version_mismatch_is_stale(self):
        record = make_record_dict()
        self.assertEqual(
            effective_status(record, detector_version="0.2.0", now=NOW_FRESH),
            "stale",
        )

    def test_due_date_expiry_is_stale(self):
        record = make_record_dict()
        self.assertEqual(
            effective_status(record, detector_version="0.1.0", now="2027-02-05T00:00:00+00:00"),
            "stale",
        )

    def test_due_date_itself_is_not_stale(self):
        record = make_record_dict()
        self.assertEqual(
            effective_status(record, detector_version="0.1.0", now="2027-02-04T12:00:00+00:00"),
            "supported",
        )

    def test_demotion_is_stale(self):
        record = copy.deepcopy(make_record_dict())
        record["limits"]["demoted_by"] = "u3-drift-observatory"
        resign(record)
        self.assertEqual(
            effective_status(record, detector_version="0.1.0", now=NOW_FRESH),
            "stale",
        )

    def test_staleness_triggers_are_independent(self):
        # Each trigger alone produces stale while the other two stay fresh.
        fresh = make_record_dict()
        self.assertEqual(effective_status(fresh, detector_version="0.2.0", now=NOW_FRESH), "stale")
        self.assertEqual(
            effective_status(fresh, detector_version="0.1.0", now="2027-02-05T00:00:00+00:00"),
            "stale",
        )
        demoted = copy.deepcopy(make_record_dict())
        demoted["limits"]["demoted_by"] = "u3-drift-observatory"
        resign(demoted)
        self.assertEqual(
            effective_status(demoted, detector_version="0.1.0", now=NOW_FRESH),
            "stale",
        )
        # And with no trigger, the same record is supported.
        self.assertEqual(
            effective_status(fresh, detector_version="0.1.0", now=NOW_FRESH),
            "supported",
        )

    def test_staleness_does_not_change_the_stored_record(self):
        record = ValidationRecord.from_dict(make_record_dict())
        self.assertEqual(
            effective_status(record, detector_version="0.2.0", now=NOW_FRESH),
            "stale",
        )
        self.assertEqual(record.status, "supported")
        self.assertTrue(verify_signature(record))


class ContaminationTests(unittest.TestCase):
    def test_yes_label(self):
        record = copy.deepcopy(make_record_dict())
        record["data"]["contamination_flag"] = "yes"
        resign(record)
        self.assertEqual(contamination_label(record), CONTAMINATED_LABEL)

    def test_unknown_label_is_a_caution(self):
        record = copy.deepcopy(make_record_dict())
        record["data"]["contamination_flag"] = "unknown"
        resign(record)
        label = contamination_label(record)
        self.assertIsNotNone(label)
        self.assertIn("unknown", label)

    def test_no_label_is_none(self):
        self.assertIsNone(contamination_label(make_record_dict()))

    def test_missing_flag_is_treated_as_unknown(self):
        record = copy.deepcopy(make_record_dict())
        del record["data"]["contamination_flag"]
        label = contamination_label(record)
        self.assertIsNotNone(label)
        self.assertIn("unknown", label)


class RegistryTests(unittest.TestCase):
    def _two_record_registry(self):
        first = ValidationRecord.from_dict(make_record_dict())
        second_dict = copy.deepcopy(make_record_dict())
        second_dict["record_id"] = "evr-20261106-synthetic-test-2-builtin-heuristic"
        second_dict["regime"]["language"] = "de"
        second_dict["regime"]["length_bucket"]["floor_words"] = 50
        second_dict["regime"]["length_bucket"]["min_words"] = 50
        resign(second_dict)
        second = ValidationRecord.from_dict(second_dict)
        return ValidationRegistry([first, second], created_at_utc="2026-11-06T00:00:00+00:00")

    def test_save_load_round_trip(self):
        registry = self._two_record_registry()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "registry.json"
            registry.save(path)
            loaded = ValidationRegistry.load(path)
        self.assertEqual(loaded.registry_id, registry.registry_id)
        self.assertEqual(loaded.created_at_utc, registry.created_at_utc)
        self.assertEqual(loaded.records, registry.records)
        self.assertEqual(loaded.to_dict(), registry.to_dict())

    def test_load_validation_registry_convenience(self):
        registry = self._two_record_registry()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "registry.json"
            registry.save(path)
            self.assertEqual(load_validation_registry(path).registry_id, registry.registry_id)

    def test_tampered_record_is_rejected(self):
        registry = self._two_record_registry()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "registry.json"
            registry.save(path)
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["records"][0]["metrics"][0]["auroc"]["value"] = 0.81
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(ValidationError):
                ValidationRegistry.load(path)

    def test_tampered_registry_id_is_rejected(self):
        registry = self._two_record_registry()
        payload = registry.to_dict()
        payload["registry_id"] = "0" * 64
        with self.assertRaises(ValidationError):
            ValidationRegistry.from_dict(payload)

    def test_from_dict_rejects_bad_signature(self):
        registry = self._two_record_registry()
        payload = registry.to_dict()
        payload["records"][0]["signature"] = "0" * 64
        with self.assertRaises(ValidationError):
            ValidationRegistry.from_dict(payload)

    def test_from_dict_rejects_licence_missing_record(self):
        registry = self._two_record_registry()
        payload = registry.to_dict()
        del payload["records"][0]["data"]["licence"]
        with self.assertRaises(ValidationError):
            ValidationRegistry.from_dict(payload)

    def test_from_dict_rejects_wrong_schema(self):
        payload = self._two_record_registry().to_dict()
        payload["schema"] = "textforensics.validation-registry/v99"
        with self.assertRaises(ValidationError):
            ValidationRegistry.from_dict(payload)

    def test_duplicate_record_ids_rejected(self):
        first = ValidationRecord.from_dict(make_record_dict())
        with self.assertRaises(ValidationError):
            ValidationRegistry([first, first])

    def test_records_for_filters_by_detector_and_version(self):
        registry = self._two_record_registry()
        self.assertEqual(len(registry.records_for("textforensics/builtin-heuristic")), 2)
        self.assertEqual(len(registry.records_for("textforensics/builtin-heuristic", "0.1.0")), 2)
        self.assertEqual(registry.records_for("textforensics/builtin-heuristic", "0.2.0"), ())
        self.assertEqual(registry.records_for("textforensics/other"), ())

    def test_summary(self):
        registry = self._two_record_registry()
        summary = registry.summary()
        self.assertEqual(summary["record_count"], 2)
        self.assertEqual(summary["detector_ids"], ["textforensics/builtin-heuristic"])
        self.assertEqual(summary["statuses"], {"supported": 2})
        self.assertEqual(
            summary["record_ids"],
            [
                "evr-20261106-synthetic-test-2-builtin-heuristic",
                "evr-20261106-synthetic-test-builtin-heuristic",
            ],
        )

    def test_empty_registry(self):
        registry = empty_validation_registry()
        self.assertEqual(registry.records, ())
        self.assertEqual(registry.summary()["record_count"], 0)

    def test_records_are_ordered_by_record_id(self):
        registry = self._two_record_registry()
        ids = [record.record_id for record in registry.records]
        self.assertEqual(ids, sorted(ids))


class RegimeMatchingTests(unittest.TestCase):
    def _registry(self):
        english = ValidationRecord.from_dict(make_record_dict())
        german_dict = copy.deepcopy(make_record_dict())
        german_dict["record_id"] = "evr-20261106-synthetic-test-2-builtin-heuristic"
        german_dict["regime"]["language"] = "de"
        german_dict["regime"]["length_bucket"]["floor_words"] = 50
        german_dict["regime"]["length_bucket"]["min_words"] = 50
        resign(german_dict)
        german = ValidationRecord.from_dict(german_dict)
        news_dict = copy.deepcopy(make_record_dict())
        news_dict["record_id"] = "evr-20261106-synthetic-test-3-builtin-heuristic"
        news_dict["regime"]["domain"] = ["news"]
        news_dict["regime"]["editing_regime"] = "paraphrased"
        resign(news_dict)
        news = ValidationRecord.from_dict(news_dict)
        return ValidationRegistry([english, german, news])

    def test_matching_language_exact(self):
        registry = self._registry()
        matched = registry.matching(language="de")
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0].regime.language, "de")

    def test_matching_word_count_below_floor_excluded(self):
        registry = self._registry()
        # English floor is 80 words; 79 words matches only the German record.
        matched = registry.matching(word_count=79)
        self.assertEqual(
            [record.record_id for record in matched],
            ["evr-20261106-synthetic-test-2-builtin-heuristic"],
        )

    def test_matching_word_count_within_bucket(self):
        registry = self._registry()
        matched = registry.matching(language="en", word_count=100)
        self.assertEqual(len(matched), 2)  # english + news records

    def test_matching_domain_must_be_in_list(self):
        registry = self._registry()
        matched = registry.matching(domain="news")
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0].regime.domain, ("news",))

    def test_matching_editing_regime_exact(self):
        registry = self._registry()
        matched = registry.matching(editing_regime="paraphrased")
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0].regime.editing_regime, "paraphrased")

    def test_matching_generator_family(self):
        registry = self._registry()
        self.assertEqual(len(registry.matching(generator_family="synthetic")), 3)
        self.assertEqual(registry.matching(generator_family="other"), ())

    def test_matching_no_filters_returns_all(self):
        registry = self._registry()
        self.assertEqual(len(registry.matching()), 3)


class HelperTests(unittest.TestCase):
    def test_default_next_revalidation_due(self):
        self.assertEqual(default_next_revalidation_due("2026-11-06"), "2027-02-04")
        self.assertEqual(default_next_revalidation_due(datetime(2026, 11, 6)), "2027-02-04")

    def test_public_exports(self):
        import textforensics

        for name in (
            "ValidationRecord",
            "ValidationRegistry",
            "ValidationError",
            "validate_record",
            "effective_status",
            "compute_signature",
            "verify_signature",
            "contamination_label",
            "missing_mandatory_fields",
            "default_next_revalidation_due",
        ):
            self.assertTrue(hasattr(textforensics, name), name)

    def test_disjointness_fail_closed_reverification(self):
        """Brief (e): re-verify check_disjointness is fail-closed.

        A missing dataset must never be reported disjoint: the registry
        must call check_disjointness (or consume its results) and never
        treat an unverified check as disjoint.
        """
        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp) / "good.jsonl"
            missing = Path(tmp) / "missing.jsonl"
            good.write_text(
                json.dumps({"label": "human", "text": "synthetic test sentence one."})
                + "\n"
                + json.dumps({"label": "ai", "text": "synthetic test sentence two."})
                + "\n",
                encoding="utf-8",
            )
            fp_good = fingerprint_dataset(good, name="Test", version="1.0", split="test")
            fp_missing = DatasetFingerprint(
                name="Test",
                version="1.0",
                split="calibration",
                dataset_hash="a" * 64,
            )
            result = check_disjointness(missing, fp_missing, good, fp_good)
            self.assertFalse(result["disjoint"])
            self.assertFalse(result["verified"])
            self.assertTrue(len(result["errors"]) > 0)


if __name__ == "__main__":
    unittest.main()
