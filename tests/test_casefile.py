from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path

from textforensics.casefile import (
    CASE_SCHEMA,
    CASE_SCHEMA_V3,
    CASE_SCHEMA_V4,
    CUSTODY_GENESIS_PREV_HASH,
    TRUST_SCHEMA,
    TRUST_SCHEMA_V3,
    _calibration_ids,
    _checklist_consistency,
    _checklist_item,
    _compare_scores,
    _custody_entry_hash,
    _forbidden_paths,
    _hash_without_seal,
    _manifest_for,
    _observations_match,
    _prediction_from_dict,
    _replay_detectors,
    _replay_trust_map,
    _replay_trust_map_v3,
    _resolve_determinism,
    _schema_versions,
    _strip_runtime_ms_from_bundle,
    _validate_digest,
    _validate_portable_bundle,
    _verify_case_sections,
    _verify_manifest,
    append_custody_entry,
    build_case_input,
    build_checklist,
    build_detector_observations,
    build_limitations,
    build_validation_refs,
    canonical_json_bytes,
    chain_custody_entry,
    replay_case_file,
    replay_case_file_path,
    seal_case_file,
    validate_checklist,
    verify_case_file,
    verify_case_file_path,
    verify_custody,
    write_case_file,
)
from textforensics.conditions import conditions_from_dict, length_band
from textforensics.detectors import DETECTOR_SCHEMA_V2, DetectorPrediction
from textforensics.evidence import EvidenceRegistry
from textforensics.report import build_forensic_bundle
from textforensics.trust import assess_trust_map
from textforensics.validation import ValidationRegistry, derive_trust_map

TEXT = (
    "I tested the device twice yesterday and wrote down what changed. "
    "The second run was warmer, so I plan to repeat it before drawing conclusions."
)

# Longer (144-word) text whose conditions match real U1 registry records
# (English, floor 80 words, domain "news", editing regime "raw").
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
_REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_real_registry() -> ValidationRegistry:
    payload = json.loads((_REPO_ROOT / "docs" / "validation" / "registry.json").read_text())
    return ValidationRegistry.from_dict(payload, verify_id=True)


def _matching_bundle() -> dict:
    bundle = build_forensic_bundle(_V3_TEXT).to_dict()
    conditions = dict(bundle["input_conditions"])
    conditions["domain_genre"] = "news"
    conditions["domain_confidence"] = "high"
    conditions["editing_regime"] = "machine_only"
    conditions["word_count"] = 144
    conditions["char_count"] = len(_V3_TEXT)
    conditions["length_band"] = length_band(144)
    bundle["input_conditions"] = conditions
    return bundle


def _v3_trust_map(bundle: dict, registry: ValidationRegistry) -> dict:
    conditions = conditions_from_dict(bundle["input_conditions"])
    predictions = [
        _prediction_from_dict(item) for item in bundle["detector_results"] if isinstance(item, dict)
    ]
    return derive_trust_map(
        conditions,
        registry,
        detector_id="textforensics/builtin-heuristic",
        detector_version="0.1.0",
        now="2026-11-07T00:00:00Z",
        predictions=predictions,
        robustness=(bundle.get("robustness") or {}).get("detectors", []),
        failure_count=len(bundle.get("detector_failures", [])),
    ).to_dict()


class _FakeReplayDetector:
    """A detector returning caller-chosen values for replay tests."""

    detector_family = "test"

    def __init__(
        self,
        detector_id,
        version="1.0.0",
        score=0.3996,
        verdict="abstain",
        calibration_id=None,
        fail=False,
        calibrated_ai_probability=None,
    ):
        self.detector_id = detector_id
        self.detector_version = version
        self.score = score
        self.verdict = verdict
        self.calibration_id = calibration_id
        self.fail = fail
        self.calibrated_ai_probability = calibrated_ai_probability

    def detect(self, text):
        if self.fail:
            raise RuntimeError("boom")
        return DetectorPrediction(
            schema=DETECTOR_SCHEMA_V2,
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            detector_family="test",
            execution="local",
            score=self.score,
            score_semantics="higher_means_ai; test prediction",
            verdict=self.verdict,
            threshold=None,
            calibration_id=self.calibration_id,
            calibrated_ai_probability=self.calibrated_ai_probability,
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
        # The default seal is case-file/v4 (determinism declarations);
        # v3 is still available explicitly via version="v3".
        self.assertEqual(case["schema"], CASE_SCHEMA_V4)
        self.assertFalse(case["raw_text_included"])
        self.assertEqual(case["tool"]["name"], "TextForensics")
        self.assertEqual(len(case["case_sha256"]), 64)
        self.assertNotIn(TEXT, json.dumps(case))

    def test_seal_v2_explicitly(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle, version="v2")
        self.assertEqual(case["schema"], CASE_SCHEMA)
        self.assertTrue(verify_case_file(case)["valid"])

    def test_seal_is_deterministic(self):
        # A v3 seal carries the seal time in its custody genesis entry, so
        # two ordinary seals of one bundle differ; deterministic mode
        # pins the timestamp and the seal is reproducible.
        bundle = build_forensic_bundle(TEXT).to_dict()
        self.assertEqual(
            seal_case_file(bundle, deterministic=True)["case_sha256"],
            seal_case_file(bundle, deterministic=True)["case_sha256"],
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
            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8"))["case_sha256"], case["case_sha256"]
            )
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
        self.assertEqual(case["forensic_bundle"]["generated_at_utc"], "2025-01-01T00:00:00+00:00")

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
            c1 = write_case_file(
                path1, bundle, deterministic=True, fixed_timestamp="2025-01-01T00:00:00+00:00"
            )
            c2 = write_case_file(
                path2, bundle, deterministic=True, fixed_timestamp="2025-01-01T00:00:00+00:00"
            )
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

            with (
                mock.patch("textforensics.casefile.os.replace", side_effect=failing_replace),
                self.assertRaises(OSError),
            ):
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


class CaseFileReplayTests(unittest.TestCase):
    def test_replay_valid_seal_with_matching_text(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle)
        result = replay_case_file(case, text=TEXT)
        self.assertTrue(result["valid"])
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["checks"]["seal"]["status"], "valid")
        self.assertEqual(result["checks"]["text"]["status"], "matched")

    def test_replay_without_text_reports_not_supplied(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle)
        result = replay_case_file(case)
        self.assertTrue(result["valid"])
        self.assertEqual(result["checks"]["text"]["status"], "not_supplied")

    def test_replay_text_hash_mismatch(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle)
        result = replay_case_file(case, text="A completely different text.")
        self.assertFalse(result["valid"])
        self.assertIn("text_hash_mismatch", result["errors"])
        self.assertEqual(result["checks"]["text"]["status"], "mismatch")

    def test_replay_tampered_seal_is_invalid(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle)
        case["forensic_bundle"]["content_sha256"] = "0" * 64
        result = replay_case_file(case, text=TEXT)
        self.assertFalse(result["valid"])
        self.assertEqual(result["checks"]["seal"]["status"], "invalid")


class CasefileMutationKillTests(unittest.TestCase):
    """Mutation-kill tests for textforensics.casefile (Phase 5 wave 2).

    Each test pins exact behaviour at a mutated position: the
    distinguishing inputs are chosen so the replacement operator
    changes the observable result (or raises).  Cluster references
    like ``L1731`` are source lines in src/textforensics/casefile.py
    at branch fix/mutation-casefile.
    """

    def _bundle(self):
        return build_forensic_bundle(TEXT).to_dict()

    def _sealed(self, **kwargs):
        kwargs.setdefault("deterministic", True)
        kwargs.setdefault("fixed_timestamp", "2025-01-01T00:00:00+00:00")
        return seal_case_file(self._bundle(), **kwargs)

    def _cs(self, expected, actual, atol=1e-9):
        return _compare_scores(expected, actual, atol=atol)

    # -- _compare_scores (L1724-1731) ------------------------------------

    def test_compare_scores_none_cases(self):
        self.assertTrue(self._cs(None, None))
        self.assertFalse(self._cs(None, 1.0))
        self.assertFalse(self._cs(1.0, None))
        self.assertFalse(self._cs(None, True))
        self.assertFalse(self._cs(False, None))

    def test_compare_scores_equal_numbers(self):
        self.assertTrue(self._cs(1.0, 1.0))
        self.assertTrue(self._cs(1, 1.0))
        self.assertTrue(self._cs(0.5, 0.5))
        self.assertFalse(self._cs(0.5, 0.6))
        self.assertFalse(self._cs(2.0, 1.0))

    def test_compare_scores_bool_branch(self):
        self.assertTrue(self._cs(True, True))
        self.assertFalse(self._cs(True, False))
        self.assertTrue(self._cs(1, True))
        self.assertTrue(self._cs(0, False))
        self.assertFalse(self._cs(1, False))
        self.assertFalse(self._cs(0, True))

    def test_compare_scores_non_numeric(self):
        self.assertFalse(self._cs("a", 1.0))
        self.assertFalse(self._cs(1.0, "a"))
        self.assertFalse(self._cs("a", "b"))
        self.assertFalse(self._cs([1], 1.0))

    def test_compare_scores_atol_boundary(self):
        # Exact-boundary comparisons with an explicit atol pin <=.
        self.assertTrue(self._cs(1.0, 1.5, atol=0.5))
        self.assertFalse(self._cs(1.0, 1.6, atol=0.5))
        self.assertTrue(self._cs(1.0, 1.5, atol=0.6))
        self.assertFalse(self._cs(0.5, 0.5 + 5e-9))
        self.assertTrue(self._cs(0.5, 0.5 + 5e-10))

    def test_compare_scores_arithmetic_replacements(self):
        # Each replacement of `-` changes one of these outcomes.
        self.assertFalse(self._cs(-0.5, 0.5))
        self.assertFalse(self._cs(0.0, 5.0))
        self.assertTrue(self._cs(0.001, 0.001))

    # -- canonical_json_bytes / _hash_without_seal / _validate_digest ---

    def test_canonical_json_bytes_keeps_non_ascii_raw(self):
        # ensure_ascii=False: non-ASCII stays raw in the output bytes.
        self.assertEqual(canonical_json_bytes({"x": "ü"}), '{"x":"ü"}'.encode())

    def test_hash_without_seal_ignores_created_at_utc(self):
        self.assertEqual(
            _hash_without_seal({"a": 1, "created_at_utc": "t1"}),
            _hash_without_seal({"a": 1, "created_at_utc": "t2"}),
        )
        self.assertNotEqual(
            _hash_without_seal({"a": 1}),
            _hash_without_seal({"a": 2}),
        )

    def test_validate_digest_rejects_wrong_length(self):
        _validate_digest("a" * 64, "x")
        with self.assertRaises(ValueError):
            _validate_digest("a" * 65, "x")
        with self.assertRaises(ValueError):
            _validate_digest("a" * 63, "x")
        with self.assertRaises(ValueError):
            _validate_digest("A" * 64, "x")
        with self.assertRaises(ValueError):
            _validate_digest(123, "x")

    # -- _validate_portable_bundle / _manifest_for / _schema_versions ---

    def test_validate_portable_bundle_rejects_zero_raw_text_flag(self):
        # 0 `is not False` (raises) but 0 != False is False (would pass).
        bundle = {
            "schema": "textforensics.forensic-bundle/v1",
            "content_sha256": "a" * 64,
            "input": {"raw_text_included": 0},
        }
        with self.assertRaises(ValueError):
            _validate_portable_bundle(bundle)

    def test_validate_portable_bundle_lists_first_five_forbidden(self):
        bundle = {
            "schema": "textforensics.forensic-bundle/v1",
            "content_sha256": "a" * 64,
            "input": {"raw_text_included": False},
            "text": "a",
            "raw_text": "b",
            "source_text": "c",
            "document_text": "d",
            "content": "e",
            "snippet": "f",
            "quote": "g",
        }
        with self.assertRaises(ValueError) as ctx:
            _validate_portable_bundle(bundle)
        message = str(ctx.exception)
        for key in ("text", "raw_text", "source_text", "document_text", "content"):
            self.assertIn(key, message)
        self.assertNotIn("snippet", message)
        self.assertNotIn("quote", message)

    def test_manifest_for_without_registry(self):
        bundle = {"content_sha256": "a" * 64}
        manifest = _manifest_for(bundle, {"git_sha": "abc"})
        self.assertIsNone(manifest["registry_id"])
        self.assertIsNone(manifest["registry_sha256"])
        self.assertEqual(manifest["git_sha"], "abc")

    def test_manifest_for_with_non_string_registry_id(self):
        bundle = self._bundle()
        bundle["evidence_registry"] = {"registry_id": 123}
        manifest = _manifest_for(bundle, {})
        self.assertIsNone(manifest["registry_id"])
        self.assertIsNotNone(manifest["registry_sha256"])

    def test_schema_versions_prefers_first_result(self):
        bundle = {
            "detector_results": [
                {"schema": "first-schema"},
                {"schema": "second-schema"},
            ],
            "trust_map": {"schema": "trust-schema"},
        }
        versions = _schema_versions(bundle)
        self.assertEqual(versions["detector_result"], "first-schema")
        self.assertEqual(versions["trust_map"], "trust-schema")

    def test_schema_versions_second_result_ignored_when_first_is_mapping(self):
        bundle = {
            "detector_results": [{"schema": "first-schema"}, "not-a-dict"],
        }
        self.assertEqual(_schema_versions(bundle)["detector_result"], "first-schema")

    def test_schema_versions_falls_back_when_first_schema_empty(self):
        from textforensics.casefile import DETECTOR_SCHEMA

        bundle = {"detector_results": [{"schema": ""}]}
        self.assertEqual(_schema_versions(bundle)["detector_result"], DETECTOR_SCHEMA)

    def test_schema_versions_trust_map_non_mapping(self):
        bundle = {"detector_results": [], "trust_map": "not-a-dict"}
        versions = _schema_versions(bundle)
        self.assertIsNone(versions["trust_map"])

    # -- _calibration_ids -------------------------------------------------

    def test_calibration_ids_collects_nested_and_top_level(self):
        bundle = {
            "detector_results": [
                {"calibration_id": "cal-a"},
                {"calibration": {"calibration_id": "cal-b"}},
                {"calibration_id": "cal-a", "calibration": {"calibration_id": "cal-c"}},
                {"calibration_id": ""},
                {"calibration": {"calibration_id": ""}},
                "not-a-dict",
                {"calibration": "not-a-dict"},
            ]
        }
        self.assertEqual(_calibration_ids(bundle), ["cal-a", "cal-b", "cal-c"])

    # -- _checklist_item / build_checklist / validate_checklist ----------

    def test_checklist_item_rejects_invalid_status(self):
        with self.assertRaises(ValueError):
            _checklist_item("bogus")
        item = _checklist_item("satisfied", evidence=["e1"], actor="a", at_utc="t", note="n")
        self.assertEqual(item["status"], "satisfied")
        self.assertEqual(item["evidence"], ["e1"])

    def test_build_checklist_rejects_unknown_item(self):
        with self.assertRaises(ValueError) as ctx:
            build_checklist({"D1": {}, "BOGUS": {}})
        self.assertIn("BOGUS", str(ctx.exception))

    def test_build_checklist_rejects_non_mapping_record(self):
        with self.assertRaises(ValueError):
            build_checklist({"D1": "not-a-mapping"})

    def test_build_checklist_rejects_bad_disposition(self):
        with self.assertRaises(ValueError):
            build_checklist(evidence_dispositions={"d1": {"disposition": "bogus"}})
        with self.assertRaises(ValueError):
            build_checklist(evidence_dispositions={"d1": "not-a-mapping"})

    def test_build_checklist_rejects_unknown_explanation(self):
        with self.assertRaises(ValueError):
            build_checklist(alternative_explanations={"bogus": {"tested": "tested"}})
        with self.assertRaises(ValueError):
            build_checklist(alternative_explanations={"short_text_limits": {"tested": "bogus"}})
        with self.assertRaises(ValueError):
            build_checklist(alternative_explanations={"short_text_limits": "not-a-mapping"})

    def test_build_checklist_records_dispositions_and_explanations(self):
        checklist = build_checklist(
            {"D1": {"status": "satisfied", "evidence": ["e1"]}},
            evidence_dispositions={"d1": {"disposition": "relied_on", "reason": "r"}},
            alternative_explanations={
                "short_text_limits": {"tested": "tested", "outcome": "ruled out"}
            },
        )
        self.assertEqual(checklist["items"]["D1"]["status"], "satisfied")
        self.assertEqual(checklist["evidence_dispositions"]["d1"]["disposition"], "relied_on")
        self.assertEqual(
            checklist["alternative_explanations"]["short_text_limits"]["tested"],
            "tested",
        )
        self.assertEqual(checklist["items"]["D2"]["status"], "unknown")

    def test_validate_checklist_missing_items(self):
        errors = validate_checklist({})
        self.assertIn("checklist_template_notice_missing_or_altered", errors)
        self.assertIn("checklist_items_missing", errors)
        self.assertEqual(len(errors), 2)

    def test_validate_checklist_bad_status_and_evidence(self):
        process = build_checklist({"D1": {"status": "satisfied"}})
        process["items"]["D1"]["status"] = "bogus"
        process["items"]["D2"]["evidence"] = "not-a-list"
        process["items"]["D3"]["evidence"] = ["ok", 123]
        errors = validate_checklist(process)
        self.assertIn("checklist_d1_invalid_status", errors)
        self.assertIn("checklist_d2_invalid_evidence", errors)
        self.assertIn("checklist_d3_invalid_evidence", errors)

    def test_validate_checklist_missing_item_record(self):
        process = build_checklist()
        del process["items"]["D4"]
        errors = validate_checklist(process)
        self.assertIn("checklist_d4_missing", errors)

    def test_validate_checklist_bad_disposition_and_explanation(self):
        process = build_checklist()
        process["evidence_dispositions"] = {"d1": {"disposition": "bogus"}}
        process["alternative_explanations"] = {
            "bogus_name": {"tested": "tested"},
            "short_text_limits": {"tested": "bogus"},
        }
        errors = validate_checklist(process)
        self.assertIn("checklist_disposition_invalid:d1", errors)
        self.assertIn("checklist_alternative_explanation_unknown:bogus_name", errors)
        self.assertIn("checklist_alternative_explanation_invalid:short_text_limits", errors)

    def test_validate_checklist_not_a_mapping(self):
        self.assertEqual(validate_checklist("nope"), ["process_not_a_mapping"])
        self.assertEqual(validate_checklist(None), ["process_not_a_mapping"])

    # -- _checklist_consistency (L985-1109) ------------------------------

    def _cons_process(self, **overrides):
        items = {f"D{i}": {"status": "satisfied"} for i in range(1, 11)}
        items.update(overrides.pop("items", {}))
        return build_checklist(
            items,
            policy_version=overrides.pop("policy_version", "pol-1"),
            procedure_version=overrides.pop("procedure_version", "proc-1"),
            reviewer=overrides.pop(
                "reviewer",
                {
                    "identity": "rev",
                    "role": "reviewer",
                    "reasoning": "r",
                    "agreed_with_tool": True,
                },
            ),
            appeal=overrides.pop(
                "appeal",
                {
                    "decider": "alice",
                    "appeal_decider": "bob",
                    "route": "r",
                    "deadline": "d",
                },
            ),
            retention=overrides.pop(
                "retention",
                {
                    "period": "p",
                    "legal_basis": "l",
                    "access": "a",
                    "disposal": "d",
                    "expungement": "e",
                },
            ),
            contrary_evidence=overrides.pop("contrary_evidence", [{"detector_id": "d1"}]),
            evidence_dispositions=overrides.pop("evidence_dispositions", {}),
            alternative_explanations=overrides.pop(
                "alternative_explanations",
                {"short_text_limits": {"tested": "tested", "outcome": "o"}},
            ),
            subject_response=overrides.pop(
                "subject_response",
                {"opportunity_given": True, "response_attached": True},
            ),
        )

    def _cons_case(self, process, observations=None, limitations=None):
        return {
            "process": process,
            "detector_observations": (
                observations
                if observations is not None
                else [
                    {
                        "kind": "observed",
                        "detector_id": "d1",
                        "verdict": "ai_like",
                        "disposition": "relied_on",
                    }
                ]
            ),
            "limitations": limitations
            if limitations is not None
            else {
                "plain_language": {
                    "score_not_probability": "s",
                    "authorship_warning": "a",
                    "human_fpr": "h",
                },
                "counterfactuals": ["c1"],
            },
        }

    def test_checklist_consistency_fully_satisfied_is_clean(self):
        case = self._cons_case(self._cons_process())
        self.assertEqual(_checklist_consistency(case, {}), [])

    def test_checklist_consistency_items_missing(self):
        case = self._cons_case({"template_notice": "x"})
        errors = _checklist_consistency(case, {})
        self.assertIn("checklist_items_missing", errors)

    def test_checklist_consistency_d1_missing_disposition(self):
        process = self._cons_process()
        case = self._cons_case(
            process,
            observations=[
                {"kind": "observed", "detector_id": "d1", "verdict": "ai_like"},
                {
                    "kind": "observed",
                    "detector_id": "d2",
                    "verdict": "human_like",
                    "disposition": "considered",
                },
                {"kind": "failed", "detector_id": "d3", "verdict": "ai_like"},
            ],
        )
        errors = _checklist_consistency(case, {})
        self.assertIn("checklist_d1_unsupported:missing_disposition:d1", errors)
        self.assertNotIn("d2", errors[0])
        self.assertNotIn("d3", errors[0])

    def test_checklist_consistency_d1_dispositioned_is_clean(self):
        process = self._cons_process()
        case = self._cons_case(
            process,
            observations=[
                {
                    "kind": "observed",
                    "detector_id": "d1",
                    "verdict": "ai_like",
                    "disposition": "relied_on",
                },
                {"kind": "plugin_health", "detector_id": "d2", "verdict": "human_like"},
            ],
        )
        self.assertEqual(_checklist_consistency(case, {}), [])

    def test_checklist_consistency_not_satisfied_items_do_not_fire(self):
        # Statuses below "satisfied" must not trigger any D-rule: this
        # kills the Eq_LtE mutants (e.g. "not_satisfied" <= "satisfied")
        # and the Eq_GtE mutants (e.g. "unknown" >= "satisfied").
        items = {
            "D1": {"status": "not_satisfied"},
            "D2": {"status": "unknown"},
            "D3": {"status": "not_satisfied"},
            "D4": {"status": "unknown"},
            "D5": {"status": "not_satisfied"},
            "D6": {"status": "unknown"},
            "D7": {"status": "not_satisfied"},
            "D8": {"status": "unknown"},
            "D9": {"status": "not_satisfied"},
            "D10": {"status": "unknown"},
        }
        process = self._cons_process(
            items=items,
            reviewer=None,
            appeal=None,
            retention=None,
            contrary_evidence=[],
            alternative_explanations={},
            subject_response=None,
            policy_version=None,
            procedure_version=None,
        )
        case = self._cons_case(
            process,
            observations=[
                {"kind": "observed", "detector_id": "d1", "verdict": "ai_like"},
                {"kind": "observed", "detector_id": "d2", "verdict": "human_like"},
            ],
            limitations={"plain_language": {}, "counterfactuals": []},
        )
        self.assertEqual(_checklist_consistency(case, {}), [])

    def test_checklist_consistency_d2_disagreement_needs_contrary(self):
        process = self._cons_process(contrary_evidence=[])
        case = self._cons_case(
            process,
            observations=[
                {"kind": "observed", "detector_id": "d1", "verdict": "ai_like"},
                {"kind": "observed", "detector_id": "d2", "verdict": "human_like"},
                {"kind": "failed", "detector_id": "d3", "verdict": "human_like"},
            ],
        )
        errors = _checklist_consistency(case, {})
        self.assertIn("checklist_d2_unsupported:detector_disagreement_unaddressed", errors)

    def test_checklist_consistency_d2_failed_verdict_does_not_count(self):
        # Only "observed" verdicts count toward disagreement: a failed
        # human_like row next to an observed ai_like row is agreement.
        process = self._cons_process(contrary_evidence=[])
        case = self._cons_case(
            process,
            observations=[
                {
                    "kind": "observed",
                    "detector_id": "d1",
                    "verdict": "ai_like",
                    "disposition": "relied_on",
                },
                {"kind": "failed", "detector_id": "d3", "verdict": "human_like"},
            ],
        )
        self.assertEqual(_checklist_consistency(case, {}), [])

    def test_checklist_consistency_d2_plugin_health_verdict_does_not_count(self):
        process = self._cons_process(contrary_evidence=[])
        case = self._cons_case(
            process,
            observations=[
                {
                    "kind": "observed",
                    "detector_id": "d1",
                    "verdict": "ai_like",
                    "disposition": "relied_on",
                },
                {
                    "kind": "plugin_health",
                    "detector_id": "d3",
                    "verdict": "human_like",
                },
            ],
        )
        self.assertEqual(_checklist_consistency(case, {}), [])

    def test_checklist_consistency_d2_contrary_needs_detector_id(self):
        process = self._cons_process(contrary_evidence=[{"note": "no id"}])
        case = self._cons_case(
            process,
            observations=[
                {"kind": "observed", "detector_id": "d1", "verdict": "ai_like"},
                {"kind": "observed", "detector_id": "d2", "verdict": "human_like"},
            ],
        )
        errors = _checklist_consistency(case, {})
        self.assertIn("checklist_d2_unsupported:contrary_evidence_incomplete", errors)

    def test_checklist_consistency_d2_contrary_non_list(self):
        process = self._cons_process()
        process["contrary_evidence"] = "not-a-list"
        case = self._cons_case(
            process,
            observations=[
                {"kind": "observed", "detector_id": "d1", "verdict": "ai_like"},
                {"kind": "observed", "detector_id": "d2", "verdict": "human_like"},
            ],
        )
        errors = _checklist_consistency(case, {})
        self.assertIn("checklist_d2_unsupported:detector_disagreement_unaddressed", errors)

    def test_checklist_consistency_d3_needs_explanations(self):
        process = self._cons_process(alternative_explanations={})
        errors = _checklist_consistency(self._cons_case(process), {})
        self.assertIn("checklist_d3_unsupported:no_alternative_explanations_recorded", errors)

    def test_checklist_consistency_d4_reviewer_rules(self):
        base = self._cons_process()
        no_reviewer = copy.deepcopy(base)
        no_reviewer["reviewer"] = None
        self.assertIn(
            "checklist_d4_unsupported:reviewer_missing",
            _checklist_consistency(self._cons_case(no_reviewer), {}),
        )
        no_identity = copy.deepcopy(base)
        no_identity["reviewer"] = {"role": "r", "reasoning": "x", "agreed_with_tool": True}
        self.assertIn(
            "checklist_d4_unsupported:reviewer_unidentified",
            _checklist_consistency(self._cons_case(no_identity), {}),
        )
        no_reasoning = copy.deepcopy(base)
        no_reasoning["reviewer"] = {
            "identity": "i",
            "role": "r",
            "agreed_with_tool": True,
        }
        self.assertIn(
            "checklist_d4_unsupported:reasoning_missing",
            _checklist_consistency(self._cons_case(no_reasoning), {}),
        )
        for agreed in (True, False):
            ok = copy.deepcopy(base)
            ok["reviewer"]["agreed_with_tool"] = agreed
            self.assertEqual(_checklist_consistency(self._cons_case(ok), {}), [])
        for agreed in (None, "yes"):
            bad = copy.deepcopy(base)
            bad["reviewer"]["agreed_with_tool"] = agreed
            self.assertIn(
                "checklist_d4_unsupported:position_missing",
                _checklist_consistency(self._cons_case(bad), {}),
            )

    def test_checklist_consistency_d5_decider_rules(self):
        base = self._cons_process()
        no_appeal = copy.deepcopy(base)
        no_appeal["appeal"] = None
        self.assertIn(
            "checklist_d5_unsupported:appeal_missing",
            _checklist_consistency(self._cons_case(no_appeal), {}),
        )
        missing = copy.deepcopy(base)
        missing["appeal"] = {"decider": "alice"}
        self.assertIn(
            "checklist_d5_unsupported:deciders_missing",
            _checklist_consistency(self._cons_case(missing), {}),
        )
        same = copy.deepcopy(base)
        same["appeal"] = {
            "decider": "alice",
            "appeal_decider": "alice",
            "route": "r",
            "deadline": "d",
        }
        self.assertIn(
            "checklist_d5_unsupported:same_decider_for_appeal",
            _checklist_consistency(self._cons_case(same), {}),
        )
        # Decider ordering matters: == must not fire for unequal pairs.
        for decider, appeal_decider in (("bob", "alice"), ("alice", "bob")):
            ok = copy.deepcopy(base)
            ok["appeal"] = {
                "decider": decider,
                "appeal_decider": appeal_decider,
                "route": "r",
                "deadline": "d",
            }
            self.assertEqual(_checklist_consistency(self._cons_case(ok), {}), [])
        no_route = copy.deepcopy(base)
        no_route["appeal"] = {"decider": "alice", "appeal_decider": "bob"}
        self.assertIn(
            "checklist_d5_unsupported:route_or_deadline_missing",
            _checklist_consistency(self._cons_case(no_route), {}),
        )

    def test_checklist_consistency_d6_needs_complete_disclosure(self):
        process = self._cons_process()
        bad = self._cons_case(
            process,
            limitations={
                "plain_language": {
                    "score_not_probability": "s",
                    "authorship_warning": " ",
                    "human_fpr": "h",
                },
                "counterfactuals": ["c1"],
            },
        )
        self.assertIn(
            "checklist_d6_unsupported:limitations_disclosure_incomplete",
            _checklist_consistency(bad, {}),
        )
        missing = self._cons_case(process, limitations=None)
        # limitations=None -> _cons_case defaults to a complete section,
        # so build the missing case explicitly instead.
        missing["limitations"] = None
        self.assertIn(
            "checklist_d6_unsupported:limitations_disclosure_incomplete",
            _checklist_consistency(missing, {}),
        )

    def test_checklist_consistency_d7_subject_response_rules(self):
        base = self._cons_process()
        missing = copy.deepcopy(base)
        missing["subject_response"] = None
        self.assertIn(
            "checklist_d7_unsupported:subject_response_missing",
            _checklist_consistency(self._cons_case(missing), {}),
        )
        no_opportunity = copy.deepcopy(base)
        no_opportunity["subject_response"] = {"opportunity_given": False}
        self.assertIn(
            "checklist_d7_unsupported:opportunity_not_given",
            _checklist_consistency(self._cons_case(no_opportunity), {}),
        )
        absent = copy.deepcopy(base)
        absent["subject_response"] = {"opportunity_given": True}
        self.assertIn(
            "checklist_d7_unsupported:absence_not_recorded",
            _checklist_consistency(self._cons_case(absent), {}),
        )
        noted = copy.deepcopy(base)
        noted["subject_response"] = {
            "opportunity_given": True,
            "response_attached": False,
            "note": "declined to respond",
        }
        self.assertEqual(_checklist_consistency(self._cons_case(noted), {}), [])

    def test_checklist_consistency_d8_needs_counterfactuals(self):
        process = self._cons_process()
        case = self._cons_case(
            process,
            limitations={
                "plain_language": {
                    "score_not_probability": "s",
                    "authorship_warning": "a",
                    "human_fpr": "h",
                },
                "counterfactuals": [],
            },
        )
        self.assertIn(
            "checklist_d8_unsupported:no_counterfactuals",
            _checklist_consistency(case, {}),
        )

    def test_checklist_consistency_d9_needs_retention_terms(self):
        base = self._cons_process()
        missing = copy.deepcopy(base)
        missing["retention"] = None
        self.assertIn(
            "checklist_d9_unsupported:retention_terms_incomplete",
            _checklist_consistency(self._cons_case(missing), {}),
        )
        blank = copy.deepcopy(base)
        blank["retention"] = {
            "period": "p",
            "legal_basis": "l",
            "access": "a",
            "disposal": " ",
            "expungement": "e",
        }
        self.assertIn(
            "checklist_d9_unsupported:retention_terms_incomplete",
            _checklist_consistency(self._cons_case(blank), {}),
        )

    def test_checklist_consistency_d10_needs_versions(self):
        base = self._cons_process()
        missing = copy.deepcopy(base)
        missing["policy_version"] = None
        self.assertIn(
            "checklist_d10_unsupported:policy_or_procedure_version_missing",
            _checklist_consistency(self._cons_case(missing), {}),
        )
        missing_both = copy.deepcopy(base)
        missing_both["policy_version"] = "pol-1"
        missing_both["procedure_version"] = ""
        self.assertIn(
            "checklist_d10_unsupported:policy_or_procedure_version_missing",
            _checklist_consistency(self._cons_case(missing_both), {}),
        )

    def test_checklist_consistency_non_mapping_item_status_is_none(self):
        # _status returns None for a non-mapping record: D1 must not fire.
        process = self._cons_process()
        process["items"]["D1"] = "not-a-mapping"
        case = self._cons_case(
            process,
            observations=[{"kind": "observed", "detector_id": "d1"}],
        )
        errors = _checklist_consistency(case, {})
        self.assertNotIn("checklist_d1_unsupported", str(errors))

    # -- _observations_match (L1109-1133) -------------------------------

    def test_observations_match_v3_ignores_determinism(self):
        sealed = [{"kind": "observed", "detector_id": "d1", "determinism": "unknown"}]
        expected = [{"kind": "observed", "detector_id": "d1", "determinism": "deterministic"}]
        self.assertTrue(_observations_match(sealed, expected, version="v3"))
        self.assertFalse(_observations_match(sealed, expected, version="v4"))

    def test_observations_match_v4_exact(self):
        sealed = [{"kind": "observed", "detector_id": "d1", "determinism": "unknown"}]
        self.assertTrue(_observations_match(sealed, list(sealed), version="v4"))
        self.assertFalse(_observations_match(sealed, [], version="v4"))
        self.assertTrue(_observations_match(sealed, list(sealed), version="v3"))

    def test_observations_match_strip_keeps_non_mappings(self):
        sealed = ["raw-item", {"kind": "observed", "determinism": "unknown"}]
        expected = ["raw-item", {"kind": "observed", "determinism": "deterministic"}]
        self.assertTrue(_observations_match(sealed, expected, version="v3"))
        self.assertFalse(_observations_match(sealed, expected, version="v4"))

    # -- _verify_case_sections / verify_case_file (v3/v4 sections) -------

    def _tampered(self, **changes):
        case = self._sealed()
        for key, value in changes.items():
            case[key] = value
        return case

    def test_verify_sections_input_hash_mismatch(self):
        case = self._sealed()
        case["input"]["content_sha256"] = "0" * 64
        errors = verify_case_file(case)["errors"]
        self.assertIn("v3_input_content_sha256_mismatch", errors)

    def test_verify_sections_observations_determinism_required_in_v4(self):
        case = self._sealed()
        del case["detector_observations"][0]["determinism"]
        errors = verify_case_file(case)["errors"]
        self.assertIn(
            "v4_detector_observations_determinism_missing:"
            + str(case["detector_observations"][0]["detector_id"]),
            errors,
        )

    def test_verify_sections_observations_determinism_optional_in_v3(self):
        case = self._sealed(version="v3")
        del case["detector_observations"][0]["determinism"]
        errors = verify_case_file(case)["errors"]
        self.assertNotIn(
            "v4_detector_observations_determinism_missing:"
            + str(case["detector_observations"][0]["detector_id"]),
            errors,
        )
        self.assertNotIn("v3_detector_observations_mismatch", errors)

    def test_verify_sections_invalid_determinism_prefix_v4_vs_v3(self):
        case = self._sealed()
        case["detector_observations"][0]["determinism"] = "bogus"
        errors = verify_case_file(case)["errors"]
        self.assertIn(
            "v4_detector_observations_determinism_invalid:"
            + str(case["detector_observations"][0]["detector_id"]),
            errors,
        )
        case3 = self._sealed(version="v3")
        case3["detector_observations"][0]["determinism"] = "bogus"
        errors3 = verify_case_file(case3)["errors"]
        self.assertIn(
            "v3_detector_observations_determinism_invalid:"
            + str(case3["detector_observations"][0]["detector_id"]),
            errors3,
        )

    def test_verify_sections_non_string_determinism_reason(self):
        case = self._sealed()
        case["detector_observations"][0]["determinism_reason"] = 123
        errors = verify_case_file(case)["errors"]
        self.assertIn(
            "v4_detector_observations_determinism_reason_invalid:"
            + str(case["detector_observations"][0]["detector_id"]),
            errors,
        )
        # A valid string reason, recorded at seal time, verifies clean.
        clean = self._sealed(
            determinism={"textforensics/builtin-heuristic": "deterministic"},
            determinism_reasons={"textforensics/builtin-heuristic": "a reason"},
        )
        self.assertTrue(verify_case_file(clean)["valid"])

    def test_verify_sections_observations_mismatch(self):
        case = self._sealed()
        case["detector_observations"][0]["score"] = 0.999
        errors = verify_case_file(case)["errors"]
        self.assertIn("v3_detector_observations_mismatch", errors)

    def test_verify_sections_non_mapping_observation_skipped(self):
        case = self._sealed()
        case["detector_observations"].append("not-a-mapping")
        errors = verify_case_file(case)["errors"]
        self.assertIn("v3_detector_observations_mismatch", errors)

    def test_verify_sections_failed_observation_skipped(self):
        case = self._sealed()
        case["detector_observations"].append({"kind": "failed", "detector_id": "x"})
        errors = verify_case_file(case)["errors"]
        self.assertIn("v3_detector_observations_mismatch", errors)

    def test_verify_sections_ref_not_a_mapping(self):
        case = self._sealed()
        case["validation_refs"] = ["not-a-mapping"]
        errors = verify_case_file(case)["errors"]
        self.assertIn("v3_validation_ref_invalid", errors)

    def test_verify_sections_registry_id_length(self):
        for bad_id in ("a" * 63, "a" * 65, "a" * 64):
            case = self._sealed()
            case["validation_refs"] = [{"registry_id": bad_id, "registry_sha256": bad_id}]
            errors = verify_case_file(case)["errors"]
            if len(bad_id) == 64:
                self.assertNotIn("v3_validation_ref_registry_id_invalid", errors)
            else:
                self.assertIn("v3_validation_ref_registry_id_invalid", errors)

    def test_verify_sections_registry_id_non_string(self):
        case = self._sealed()
        case["validation_refs"] = [{"registry_id": 123, "registry_sha256": 123}]
        errors = verify_case_file(case)["errors"]
        self.assertIn("v3_validation_ref_registry_id_invalid", errors)

    def test_verify_sections_registry_id_non_hex(self):
        case = self._sealed()
        case["validation_refs"] = [{"registry_id": "G" * 64, "registry_sha256": "G" * 64}]
        errors = verify_case_file(case)["errors"]
        self.assertIn("v3_validation_ref_registry_id_invalid", errors)

    def test_verify_sections_registry_sha256_mismatch(self):
        registry_id = "a" * 64
        case = self._sealed()
        case["validation_refs"] = [{"registry_id": registry_id, "registry_sha256": "b" * 64}]
        errors = verify_case_file(case)["errors"]
        self.assertIn("v3_validation_ref_registry_sha256_mismatch", errors)
        equal_value = "".join("a" for _ in range(64))
        self.assertEqual(equal_value, registry_id)
        self.assertIsNot(equal_value, registry_id)
        case2 = self._sealed()
        case2["validation_refs"] = [{"registry_id": registry_id, "registry_sha256": equal_value}]
        self.assertNotIn(
            "v3_validation_ref_registry_sha256_mismatch",
            verify_case_file(case2)["errors"],
        )

    def test_verify_sections_limitations_incomplete(self):
        case = self._sealed()
        case["limitations"]["plain_language"]["human_fpr"] = " "
        errors = verify_case_file(case)["errors"]
        self.assertIn("v3_limitations_incomplete", errors)
        case2 = self._sealed()
        case2["limitations"]["plain_language"]["human_fpr"] = 123
        self.assertIn("v3_limitations_incomplete", verify_case_file(case2)["errors"])
        case3 = self._sealed()
        case3["limitations"]["counterfactuals"] = "not-a-list"
        self.assertIn(
            "v3_limitations_counterfactuals_missing",
            verify_case_file(case3)["errors"],
        )

    def test_verify_sections_seal_algorithm(self):
        for algorithm in ("md5", "zzz"):
            case = self._sealed()
            case["seal"]["algorithm"] = algorithm
            self.assertIn("v3_seal_algorithm_invalid", verify_case_file(case)["errors"])

    def test_verify_sections_custody_head_mismatch(self):
        case = self._sealed(
            custody=[{"actor": "a2", "action": "reviewed", "at_utc": "2025-01-02T00:00:00+00:00"}]
        )
        self.assertTrue(verify_case_file(case)["valid"])
        case["seal"]["custody_head"] = "f" * 64
        self.assertIn("v3_seal_custody_head_mismatch", verify_case_file(case)["errors"])
        case2 = self._sealed(
            custody=[{"actor": "a2", "action": "reviewed", "at_utc": "2025-01-02T00:00:00+00:00"}]
        )
        head = case2["seal"]["custody_head"]
        equal_value = "".join(head[i] for i in range(len(head)))
        self.assertEqual(equal_value, head)
        self.assertIsNot(equal_value, head)
        case2["seal"]["custody_head"] = equal_value
        self.assertNotIn("v3_seal_custody_head_mismatch", verify_case_file(case2)["errors"])

    def test_verify_sections_signature_checks(self):
        seed = bytes(range(32))
        signer = {"identity": "strmt7", "role": "sealer"}
        base = self._sealed(signing_seed=seed, signer=signer)
        self.assertTrue(verify_case_file(base)["valid"])
        non_mapping = copy.deepcopy(base)
        non_mapping["seal"]["signature"] = "not-a-mapping"
        self.assertIn("v3_seal_signature_invalid", verify_case_file(non_mapping)["errors"])
        bad_algorithm = copy.deepcopy(base)
        bad_algorithm["seal"]["signature"]["algorithm"] = "rsa"
        self.assertIn(
            "v3_seal_signature_algorithm_invalid",
            verify_case_file(bad_algorithm)["errors"],
        )
        bad_fingerprint = copy.deepcopy(base)
        bad_fingerprint["seal"]["signature"]["key_fingerprint"] = "a" * 63
        self.assertIn(
            "v3_seal_signature_fingerprint_invalid",
            verify_case_file(bad_fingerprint)["errors"],
        )
        bad_hex = copy.deepcopy(base)
        bad_hex["seal"]["signature"]["key_fingerprint"] = "G" * 64
        self.assertIn(
            "v3_seal_signature_fingerprint_invalid",
            verify_case_file(bad_hex)["errors"],
        )
        no_dsse = copy.deepcopy(base)
        del no_dsse["seal"]["signature"]["dsse"]
        self.assertIn("v3_seal_signature_dsse_missing", verify_case_file(no_dsse)["errors"])
        no_signer = copy.deepcopy(base)
        del no_signer["seal"]["signature"]["signer"]
        self.assertIn(
            "v3_seal_signature_signer_missing",
            verify_case_file(no_signer)["errors"],
        )

    def test_verify_sections_timestamp_and_publication_types(self):
        case = self._sealed()
        case["seal"]["timestamp"] = "not-a-mapping"
        self.assertIn("v3_seal_timestamp_invalid", verify_case_file(case)["errors"])
        case2 = self._sealed()
        case2["seal"]["digest_publication"] = "not-a-mapping"
        self.assertIn(
            "v3_seal_digest_publication_invalid",
            verify_case_file(case2)["errors"],
        )

    def test_verify_sections_gaps_invalid(self):
        case = self._sealed()
        case["gaps"] = [{"field": "", "reason": "r"}]
        self.assertIn("v3_gaps_invalid", verify_case_file(case)["errors"])
        case2 = self._sealed()
        case2["gaps"] = [{"field": "f", "reason": ""}]
        self.assertIn("v3_gaps_invalid", verify_case_file(case2)["errors"])
        case3 = self._sealed()
        case3["gaps"] = ["not-a-mapping"]
        self.assertIn("v3_gaps_invalid", verify_case_file(case3)["errors"])

    def test_verify_case_file_signature_warning_without_key(self):
        seed = bytes(range(32))
        signer = {"identity": "strmt7", "role": "sealer"}
        case = self._sealed(signing_seed=seed, signer=signer)
        result = verify_case_file(case)
        self.assertTrue(result["valid"])
        self.assertTrue(any("public_key_not_supplied" in w for w in result["warnings"]))

    def test_verify_case_file_bad_signature_with_key(self):
        from textforensics.sealing import public_key_from_seed

        seed = bytes(range(32))
        signer = {"identity": "strmt7", "role": "sealer"}
        case = self._sealed(signing_seed=seed, signer=signer)
        tampered = copy.deepcopy(case)
        tampered["seal"]["signature"]["dsse"] = {"payload": "tampered"}
        result = verify_case_file(tampered, public_key=public_key_from_seed(bytes(range(32))))
        self.assertFalse(result["valid"])
        self.assertTrue(any(e.startswith("signature_invalid:") for e in result["errors"]))

    def test_verify_case_file_wrong_tool_name(self):
        case = self._sealed()
        case["tool"]["name"] = "OtherTool"
        self.assertIn("invalid_tool_identity", verify_case_file(case)["errors"])

    def test_verify_case_file_hash_length_checks(self):
        case = self._sealed()
        case["case_sha256"] = "a" * 63
        self.assertIn("missing_or_invalid_case_sha256", verify_case_file(case)["errors"])
        case2 = self._sealed()
        case2["case_sha256"] = "A" * 64
        self.assertIn("missing_or_invalid_case_sha256", verify_case_file(case2)["errors"])

    # -- custody -----------------------------------------------------------

    def test_custody_genesis_prev_hash_is_64_zeros(self):
        self.assertEqual(CUSTODY_GENESIS_PREV_HASH, "0" * 64)

    def test_custody_chain_links_three_entries(self):
        chain = []
        first = chain_custody_entry(
            chain, actor="a", action="sealed", at_utc="2025-01-01T00:00:00+00:00"
        )
        chain.append(first)
        self.assertEqual(first["prev_hash"], CUSTODY_GENESIS_PREV_HASH)
        second = chain_custody_entry(
            chain, actor="b", action="reviewed", at_utc="2025-01-02T00:00:00+00:00"
        )
        chain.append(second)
        self.assertEqual(second["prev_hash"], first["entry_hash"])
        third = chain_custody_entry(
            chain, actor="c", action="released", at_utc="2025-01-03T00:00:00+00:00"
        )
        chain.append(third)
        self.assertEqual(third["prev_hash"], second["entry_hash"])
        self.assertEqual(verify_custody(chain), [])

    def test_custody_entry_hash_is_deterministic(self):
        kwargs = {
            "actor": "a",
            "action": "sealed",
            "at_utc": "2025-01-01T00:00:00+00:00",
            "note": None,
            "prev_hash": CUSTODY_GENESIS_PREV_HASH,
        }
        self.assertEqual(_custody_entry_hash(**kwargs), _custody_entry_hash(**kwargs))
        changed = dict(kwargs, note="different")
        self.assertNotEqual(_custody_entry_hash(**kwargs), _custody_entry_hash(**changed))

    def test_chain_custody_entry_rejects_empty_fields(self):
        for kwargs in (
            {"actor": "", "action": "x", "at_utc": "t"},
            {"actor": 123, "action": "x", "at_utc": "t"},
            {"actor": "a", "action": "", "at_utc": "t"},
            {"actor": "a", "action": "x", "at_utc": ""},
            {"actor": "a", "action": "x", "at_utc": "   "},
        ):
            with self.assertRaises(ValueError):
                chain_custody_entry([], **kwargs)

    def test_verify_custody_rejects_bad_shapes(self):
        self.assertEqual(verify_custody([]), ["custody_missing_or_empty"])
        self.assertEqual(verify_custody("nope"), ["custody_missing_or_empty"])
        self.assertEqual(verify_custody(["not-a-mapping"]), ["custody_entry_not_a_mapping:0"])

    def test_verify_custody_detects_broken_link_and_hash(self):
        chain = []
        first = chain_custody_entry(
            chain, actor="a", action="sealed", at_utc="2025-01-01T00:00:00+00:00"
        )
        chain.append(first)
        second = chain_custody_entry(
            chain, actor="b", action="reviewed", at_utc="2025-01-02T00:00:00+00:00"
        )
        chain.append(second)
        broken = copy.deepcopy(chain)
        broken[1]["prev_hash"] = "0" * 64
        self.assertIn("custody_chain_broken:1", verify_custody(broken))
        tampered = copy.deepcopy(chain)
        tampered[0]["entry_hash"] = "f" * 64
        self.assertIn("custody_entry_hash_mismatch:0", verify_custody(tampered))

    def test_append_custody_entry_updates_head_and_hash(self):
        case = self._sealed()
        updated = append_custody_entry(
            case, actor="b", action="reviewed", at_utc="2025-01-02T00:00:00+00:00"
        )
        self.assertEqual(len(updated["custody"]), len(case["custody"]) + 1)
        self.assertEqual(updated["seal"]["custody_head"], updated["custody"][-1]["entry_hash"])
        self.assertNotEqual(updated["case_sha256"], case["case_sha256"])
        self.assertEqual(updated["custody"][-1]["actor"], "b")
        self.assertEqual(updated["custody"][-1]["at_utc"], "2025-01-02T00:00:00+00:00")
        # The input case is not mutated.
        self.assertEqual(len(case["custody"]), 1)
        self.assertTrue(verify_case_file(updated)["valid"])

    def test_append_custody_entry_rejects_non_v3_v4(self):
        case = self._sealed(version="v2")
        with self.assertRaises(ValueError):
            append_custody_entry(case, actor="b", action="reviewed")

    # -- seal_case_file branches (L1274-1499) ---------------------------

    def test_seal_default_is_non_deterministic(self):
        bundle = self._bundle()
        for result in bundle["detector_results"]:
            result["runtime_ms"] = 1.0
        case = seal_case_file(bundle)
        self.assertIn("runtime_ms", case["forensic_bundle"]["detector_results"][0])

    def test_seal_deterministic_pins_trust_map_timestamp(self):
        bundle = self._bundle()
        case = seal_case_file(
            bundle, deterministic=True, fixed_timestamp="2025-01-01T00:00:00+00:00"
        )
        self.assertEqual(
            case["forensic_bundle"]["trust_map"]["generated_at_utc"],
            "2025-01-01T00:00:00+00:00",
        )

    def test_seal_deterministic_without_trust_map_dict(self):
        bundle = self._bundle()
        bundle["trust_map"] = None
        case = seal_case_file(
            bundle, deterministic=True, fixed_timestamp="2025-01-01T00:00:00+00:00"
        )
        self.assertIsNone(case["forensic_bundle"]["trust_map"])

    def test_seal_tool_git_sha_rules(self):
        for git_sha, expected in (("abc", "abc"), ("", None), (123, None)):
            bundle = self._bundle()
            bundle["provenance"] = {"git_sha": git_sha}
            case = seal_case_file(bundle)
            self.assertEqual(case["tool"]["git_sha"], expected)
        bundle = self._bundle()
        bundle["provenance"] = {}
        self.assertIsNone(seal_case_file(bundle)["tool"]["git_sha"])

    def _legacy_bundle(self):
        return {
            "schema": "textforensics.forensic-bundle/v1",
            "content_sha256": "a" * 64,
            "input": {"raw_text_included": False},
        }

    def test_seal_legacy_bundle_v1_only(self):
        case = seal_case_file(self._legacy_bundle(), version="v1")
        self.assertEqual(case["schema"], "textforensics.case-file/v1")
        self.assertIs(case["raw_text_included"], False)
        with self.assertRaises(ValueError):
            seal_case_file(self._legacy_bundle(), version="v2")
        with self.assertRaises(ValueError):
            seal_case_file(self._bundle(), version="v1")

    def test_seal_version_schema_selection(self):
        self.assertEqual(seal_case_file(self._bundle(), version="v3")["schema"], CASE_SCHEMA_V3)
        self.assertEqual(seal_case_file(self._bundle(), version="v4")["schema"], CASE_SCHEMA_V4)
        self.assertEqual(seal_case_file(self._bundle(), version="v2")["schema"], CASE_SCHEMA)
        with self.assertRaises(ValueError):
            seal_case_file(self._bundle(), version="v9")

    def test_seal_rejects_non_mapping_input_meta(self):
        with self.assertRaises(ValueError):
            seal_case_file(self._bundle(), input_meta="not-a-mapping")

    def test_seal_process_non_mapping_uses_defaults(self):
        case = seal_case_file(self._bundle(), process="not-a-mapping")
        self.assertEqual(case["process"]["items"]["D1"]["status"], "unknown")
        self.assertIsNone(case["process"]["policy_version"])

    def test_seal_process_fields_recorded(self):
        case = seal_case_file(
            self._bundle(),
            process={"policy_version": "pol-9", "procedure_version": "proc-9"},
        )
        self.assertEqual(case["process"]["policy_version"], "pol-9")
        self.assertEqual(case["process"]["procedure_version"], "proc-9")

    def test_seal_limitations_override(self):
        override = {
            "plain_language": {"score_not_probability": "custom"},
            "counterfactuals": ["c1"],
            "bundle_limitations": ["b1"],
        }
        case = seal_case_file(self._bundle(), limitations=override)
        self.assertEqual(case["limitations"]["plain_language"], {"score_not_probability": "custom"})
        self.assertEqual(case["limitations"]["counterfactuals"], ["c1"])
        self.assertEqual(case["limitations"]["bundle_limitations"], ["b1"])
        with self.assertRaises(ValueError):
            seal_case_file(self._bundle(), limitations="not-a-mapping")

    def test_seal_custody_entries(self):
        case = seal_case_file(
            self._bundle(),
            custody=[
                {"actor": "a2", "action": "reviewed", "at_utc": "2025-01-02T00:00:00+00:00"},
                {"actor": "a3", "action": "released"},
            ],
        )
        self.assertEqual(len(case["custody"]), 3)
        self.assertEqual(case["custody"][1]["actor"], "a2")
        self.assertEqual(case["custody"][2]["at_utc"], case["created_at_utc"])
        self.assertEqual(case["seal"]["custody_head"], case["custody"][-1]["entry_hash"])
        with self.assertRaises(ValueError):
            seal_case_file(self._bundle(), custody=["not-a-mapping"])
        with self.assertRaises(ValueError):
            seal_case_file(
                self._bundle(),
                custody=[{"actor": "a", "action": "x", "prev_hash": "p"}],
            )

    def test_seal_signing_argument_validation(self):
        seed = bytes(range(32))
        signer = {"identity": "i", "role": "r"}
        with self.assertRaises(ValueError):
            seal_case_file(self._bundle(), signer=signer)
        with self.assertRaises(ValueError):
            seal_case_file(self._bundle(), signing_seed=seed)
        with self.assertRaises(ValueError):
            seal_case_file(self._bundle(), signing_seed="not-bytes", signer=signer)
        with self.assertRaises(ValueError):
            seal_case_file(self._bundle(), signing_seed=bytes(31), signer=signer)
        with self.assertRaises(ValueError):
            seal_case_file(self._bundle(), signing_seed=seed, signer={"identity": "i"})
        with self.assertRaises(ValueError):
            seal_case_file(self._bundle(), signing_seed=seed, signer={"role": "r"})
        case = seal_case_file(self._bundle(), signing_seed=bytearray(range(32)), signer=signer)
        self.assertEqual(case["seal"]["signature"]["algorithm"], "ed25519")

    def test_seal_digest_publication_validation(self):
        with self.assertRaises(ValueError):
            seal_case_file(self._bundle(), digest_publication="not-a-mapping")
        with self.assertRaises(ValueError):
            seal_case_file(
                self._bundle(),
                digest_publication={"channel": "c", "reference": "r"},
            )
        case = seal_case_file(
            self._bundle(),
            digest_publication={
                "channel": "c",
                "reference": "r",
                "published_at_utc": "2025-01-01T00:00:00+00:00",
            },
        )
        self.assertEqual(case["seal"]["digest_publication"]["channel"], "c")

    # -- build_case_input (L533-630) --------------------------------------

    def test_build_case_input_counts_and_gaps(self):
        bundle = self._bundle()
        section, gaps = build_case_input(bundle)
        self.assertEqual(section["word_count"], bundle["input_conditions"]["word_count"])
        self.assertEqual(section["char_count"], bundle["input_conditions"]["char_count"])
        fields = [g["field"] for g in gaps]
        self.assertIn("input.sentence_count", fields)
        self.assertIn("input.paragraph_count", fields)
        self.assertIn("input.source", fields)
        self.assertIn("input.acquired_by", fields)
        self.assertNotIn("input.word_count", fields)

    def test_build_case_input_missing_counts(self):
        bundle = {"content_sha256": "a" * 64}
        section, gaps = build_case_input(bundle)
        self.assertIsNone(section["word_count"])
        self.assertIsNone(section["char_count"])
        fields = [g["field"] for g in gaps]
        self.assertIn("input.word_count", fields)
        self.assertIn("input.char_count", fields)
        bundle2 = {"content_sha256": "a" * 64, "input_conditions": {"word_count": "5"}}
        section2, gaps2 = build_case_input(bundle2)
        self.assertIsNone(section2["word_count"])
        self.assertIn("input.word_count", [g["field"] for g in gaps2])

    def test_build_case_input_source_rules(self):
        bundle = self._bundle()
        with self.assertRaises(ValueError):
            build_case_input(bundle, source="not-a-mapping")
        section, gaps = build_case_input(
            bundle,
            source={"system": "sys", "receipt_id": "r1", "other": "ignored"},
        )
        self.assertEqual(section["source"], {"system": "sys", "receipt_id": "r1"})
        self.assertNotIn("input.source", [g["field"] for g in gaps])
        section2, _ = build_case_input(bundle, source={"system": ""})
        self.assertEqual(section2["source"], {})
        with self.assertRaises(ValueError):
            build_case_input(bundle, source={"filename_sha256": "bad"})
        section3, _ = build_case_input(bundle, source={"filename_sha256": "b" * 64})
        self.assertEqual(section3["source"]["filename_sha256"], "b" * 64)

    def test_build_case_input_acquisition_gaps(self):
        bundle = self._bundle()
        _, gaps = build_case_input(bundle, acquired_by="a", acquisition_method="m")
        fields = [g["field"] for g in gaps]
        self.assertNotIn("input.acquired_by", fields)
        self.assertNotIn("input.acquisition_method", fields)
        self.assertIn("input.authorisation_ref", fields)
        self.assertIn("input.acquired_at_utc", fields)
        reasons = {g["field"]: g["reason"] for g in gaps}
        self.assertIn("authorisation_ref", reasons["input.authorisation_ref"])

    def test_build_case_input_normalisation(self):
        bundle = self._bundle()
        section, _ = build_case_input(bundle)
        from textforensics.casefile import INPUT_NORMALISATION

        self.assertEqual(section["normalisation"], INPUT_NORMALISATION)
        section2, _ = build_case_input(bundle, normalisation="custom-norm")
        self.assertEqual(section2["normalisation"], "custom-norm")

    # -- build_detector_observations (L659-760) ---------------------------

    def test_build_detector_observations_rows(self):
        bundle = {
            "detector_results": [
                {
                    "detector_id": "d1",
                    "detector_version": "1.0",
                    "checkpoint_version": "ckpt",
                    "provider_version": "prov",
                    "model_version": "model",
                    "score": 0.5,
                },
                {
                    "detector_id": "d2",
                    "provider_version": "prov2",
                    "score": 0.6,
                },
                {"detector_id": "d3", "model_version": "model3"},
                "not-a-dict",
            ],
            "detector_failures": [
                {"detector_id": "f1", "reason": "boom"},
                {"detector_id": "f2", "error": "oops"},
                {"detector_id": "f3"},
                "not-a-dict",
            ],
            "plugin_health": [
                {"detector_id": "p1"},
                {"plugin": "p2"},
                "not-a-dict",
            ],
        }
        observations = build_detector_observations(
            bundle, dispositions={"d1": {"disposition": "relied_on", "reason": "r"}}
        )
        self.assertEqual(len(observations), 3 + 3 + 2)
        self.assertEqual(observations[0]["checkpoint_or_provider_version"], "ckpt")
        self.assertEqual(observations[0]["disposition"], "relied_on")
        self.assertEqual(observations[0]["disposition_reason"], "r")
        self.assertEqual(observations[1]["checkpoint_or_provider_version"], "prov2")
        self.assertEqual(observations[2]["checkpoint_or_provider_version"], "model3")
        self.assertIsNone(observations[1]["disposition"])
        failed = [o for o in observations if o["kind"] == "failed"]
        self.assertEqual(failed[0]["reason"], "boom")
        self.assertEqual(failed[1]["reason"], "oops")
        self.assertEqual(failed[2]["reason"], "detector failed")
        health = [o for o in observations if o["kind"] == "plugin_health"]
        self.assertEqual(health[0]["detector_id"], "p1")
        self.assertEqual(health[1]["detector_id"], "p2")
        self.assertEqual(health[0]["determinism"], "unknown")

    # -- build_limitations (L929-984) --------------------------------------

    def test_build_limitations_fpr_text_variants(self):
        bundle = {}
        refs_with_ci = [
            {
                "records": [
                    {
                        "record_id": "r1",
                        "fpr_native": {
                            "value": 0.05,
                            "n": 100,
                            "ci_lower": 0.01,
                            "ci_upper": 0.12,
                        },
                    }
                ]
            }
        ]
        section = build_limitations(bundle, refs_with_ci)
        self.assertIn("0.0500", section["plain_language"]["human_fpr"])
        self.assertIn("[0.0100, 0.1200]", section["plain_language"]["human_fpr"])
        self.assertIn("r1", section["plain_language"]["human_fpr"])
        refs_no_ci = [{"records": [{"record_id": "r2", "fpr_native": {"value": 0.02, "n": 50}}]}]
        section2 = build_limitations(bundle, refs_no_ci)
        self.assertIn("0.0200", section2["plain_language"]["human_fpr"])
        self.assertIn("(n=50)", section2["plain_language"]["human_fpr"])
        self.assertNotIn("CI", section2["plain_language"]["human_fpr"])
        refs_none = [{"records": [{"record_id": "r3", "fpr_native": {"value": None}}]}]
        section3 = build_limitations(bundle, refs_none)
        self.assertIn("unknown", section3["plain_language"]["human_fpr"])

    def test_build_limitations_first_record_with_fpr_wins(self):
        bundle = {}
        refs = [
            {"records": [{"record_id": "empty", "fpr_native": {}}]},
            {
                "records": [
                    {
                        "record_id": "winner",
                        "fpr_native": {"value": 0.03, "n": 10},
                    }
                ]
            },
        ]
        section = build_limitations(bundle, refs)
        self.assertIn("winner", section["plain_language"]["human_fpr"])

    def test_build_limitations_counterfactuals_and_bundle_limits(self):
        bundle = {"limitations": ["b1", "b2"]}
        section = build_limitations(bundle, counterfactuals=["x"])
        self.assertEqual(section["counterfactuals"], ["x"])
        self.assertEqual(section["bundle_limitations"], ["b1", "b2"])
        from textforensics.casefile import DEFAULT_COUNTERFACTUALS

        section2 = build_limitations({})
        self.assertEqual(section2["counterfactuals"], list(DEFAULT_COUNTERFACTUALS))
        self.assertEqual(section2["bundle_limitations"], [])
        section3 = build_limitations({"limitations": "not-a-list"})
        self.assertEqual(section3["bundle_limitations"], [])

    # -- _resolve_determinism / _apply_determinism_overrides --------------

    def test_resolve_determinism_rules(self):
        self.assertEqual(_resolve_determinism({}), ("unknown", None))
        self.assertEqual(
            _resolve_determinism({"determinism": "deterministic"}),
            ("deterministic", None),
        )
        self.assertEqual(
            _resolve_determinism({"determinism": "non_deterministic", "determinism_reason": "r"}),
            ("non_deterministic", "r"),
        )
        with self.assertRaises(ValueError):
            _resolve_determinism({"determinism": "bogus"})
        with self.assertRaises(ValueError):
            _resolve_determinism({"determinism": "deterministic", "determinism_reason": 123})

    def test_determinism_overrides_validation(self):
        bundle = self._bundle()
        with self.assertRaises(ValueError):
            seal_case_file(
                bundle,
                determinism={"textforensics/builtin-heuristic": "bogus"},
            )
        with self.assertRaises(ValueError):
            seal_case_file(
                bundle,
                determinism_reasons={"textforensics/builtin-heuristic": 123},
            )
        with self.assertRaises(ValueError):
            seal_case_file(bundle, determinism={"unknown-detector": "deterministic"})
        with self.assertRaises(ValueError):
            seal_case_file(
                bundle,
                determinism_reasons={"unknown-detector": "a reason"},
            )

    def test_determinism_override_reasons_only_unknown_detector(self):
        # The union check must see reasons-only ids: with `&` instead of
        # `|` the unknown detector in reasons alone would slip through.
        bundle = self._bundle()
        with self.assertRaises(ValueError):
            seal_case_file(
                bundle,
                determinism={},
                determinism_reasons={"unknown-detector": "a reason"},
            )
        with self.assertRaises(ValueError):
            seal_case_file(
                bundle,
                determinism={"unknown-detector": "deterministic"},
                determinism_reasons={},
            )

    def test_determinism_override_written_into_bundle_and_observations(self):
        bundle = self._bundle()
        case = seal_case_file(
            bundle,
            determinism={"textforensics/builtin-heuristic": "non_deterministic"},
            determinism_reasons={"textforensics/builtin-heuristic": "sampled output"},
        )
        self.assertEqual(
            case["forensic_bundle"]["detector_results"][0]["determinism"],
            "non_deterministic",
        )
        self.assertEqual(
            case["forensic_bundle"]["detector_results"][0]["determinism_reason"],
            "sampled output",
        )
        self.assertEqual(case["detector_observations"][0]["determinism"], "non_deterministic")

    # -- build_validation_refs (L824-927) ----------------------------------

    def _fake_registry(self, records_by_detector=None):
        class FakeRecord:
            def __init__(self, record_id, status, metrics=None, regime=None):
                self.record_id = record_id
                self.status = status
                self._metrics = metrics
                self._regime = regime or {}

            def to_dict(self):
                return {"metrics": self._metrics, "regime": self._regime}

        class FakeRegistry:
            registry_id = "c" * 64

            def __init__(self, calls):
                self._calls = calls
                self._records = records_by_detector or {}

            def matching(self, **kwargs):
                self._calls.append(kwargs)
                return list(self._records.get(kwargs.get("detector_id"), []))

        calls = []
        return FakeRegistry(calls), calls, FakeRecord

    def test_build_validation_refs_no_registry(self):
        refs, gaps = build_validation_refs(self._bundle(), None)
        self.assertEqual(refs, [])
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0]["field"], "validation_refs")

    def test_build_validation_refs_invalid_conditions(self):
        registry, _, _ = self._fake_registry()
        refs, gaps = build_validation_refs({"input_conditions": {"bad": True}}, registry)
        self.assertEqual(refs, [])
        self.assertEqual(gaps[0]["field"], "validation_refs")

    def test_build_validation_refs_matching_kwargs(self):
        registry, calls, _ = self._fake_registry()
        bundle = self._bundle()
        refs, gaps = build_validation_refs(bundle, registry)
        self.assertEqual(gaps, [])
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["detector_id"], "textforensics/builtin-heuristic")
        self.assertFalse(refs[0]["covers_input_regime"])
        self.assertEqual(refs[0]["registry_id"], "c" * 64)
        self.assertEqual(refs[0]["registry_sha256"], "c" * 64)
        self.assertEqual(len(calls), 1)
        # The real bundle's conditions are English / unknown domain.
        self.assertEqual(calls[0]["language"], "en")
        self.assertIsNone(calls[0]["domain"])

    def test_build_validation_refs_und_language_and_unknown_domain(self):
        registry, calls, _ = self._fake_registry()
        bundle = self._bundle()
        conditions = dict(bundle["input_conditions"])
        conditions["language_confidence"] = "low"
        conditions["domain_confidence"] = "low"
        conditions["editing_regime"] = "unknown"
        bundle["input_conditions"] = conditions
        build_validation_refs(bundle, registry)
        self.assertIsNone(calls[0]["language"])
        self.assertIsNone(calls[0]["domain"])
        self.assertIsNone(calls[0]["editing_regime"])

    def test_build_validation_refs_fpr_extraction(self):
        _, _, FakeRecord = self._fake_registry()
        record = FakeRecord(
            "rec-1",
            "supported",
            metrics=[
                {
                    "fpr_native": {
                        "value": 0.04,
                        "n": 80,
                        "ci_lower": 0.01,
                        "ci_upper": 0.09,
                        "method": "wilson",
                    }
                }
            ],
            regime={"domain": "news"},
        )
        registry, _, _ = self._fake_registry({"textforensics/builtin-heuristic": [record]})
        refs, _ = build_validation_refs(self._bundle(), registry)
        self.assertTrue(refs[0]["covers_input_regime"])
        fpr = refs[0]["records"][0]["fpr_native"]
        self.assertEqual(fpr["value"], 0.04)
        self.assertEqual(fpr["n"], 80)
        self.assertEqual(fpr["method"], "wilson")
        self.assertEqual(refs[0]["records"][0]["regime"], {"domain": "news"})

    def test_build_validation_refs_metrics_edge_cases(self):
        _, _, FakeRecord = self._fake_registry()
        no_metrics = FakeRecord("rec-1", "supported", metrics=[])
        non_mapping_metric = FakeRecord("rec-2", "supported", metrics=["not-a-dict"])
        non_mapping_fpr = FakeRecord("rec-3", "supported", metrics=[{"fpr_native": "not-a-dict"}])
        registry, _, _ = self._fake_registry(
            {"textforensics/builtin-heuristic": [no_metrics, non_mapping_metric, non_mapping_fpr]}
        )
        refs, _ = build_validation_refs(self._bundle(), registry)
        for ref in refs[0]["records"]:
            self.assertIsNone(ref["fpr_native"])

    # -- _strip_runtime_ms_from_bundle (L211-228) --------------------------

    def test_strip_runtime_ms_robustness_rows(self):
        bundle = {
            "detector_results": [{"detector_id": "d1", "runtime_ms": 1.0}],
            "robustness": {
                "detectors": [
                    {
                        "failures": [
                            {"runtime_ms": 2.0},
                            "not-a-dict",
                        ]
                    },
                    "not-a-dict",
                    {"failures": []},
                ]
            },
        }
        result = _strip_runtime_ms_from_bundle(bundle)
        self.assertNotIn("runtime_ms", result["detector_results"][0])
        self.assertNotIn("runtime_ms", result["robustness"]["detectors"][0]["failures"][0])
        self.assertEqual(result["robustness"]["detectors"][1], "not-a-dict")

    # -- write_case_file render (L1631-1669) -------------------------------

    def test_write_case_file_default_is_non_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "case.json"
            bundle = self._bundle()
            bundle["detector_results"][0]["runtime_ms"] = 1.0
            write_case_file(path, bundle)
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn("runtime_ms", payload["forensic_bundle"]["detector_results"][0])

    def test_write_case_file_render_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "case.json"
            bundle = self._bundle()
            bundle["detector_results"][0]["detector_version"] = "1.0-ü"
            write_case_file(path, bundle)
            text = path.read_text(encoding="utf-8")
            self.assertIn("ü", text)
            self.assertNotIn("\\u00fc", text)
            self.assertIn('\n  "schema": ', text)
            self.assertTrue(text.endswith("\n"))

    def test_write_case_file_creates_parent_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a" / "b" / "case.json"
            write_case_file(path, self._bundle())
            self.assertTrue(path.exists())

    # -- _replay_detectors (L1738-1820) -----------------------------------

    def _sealed_row(self):
        return self._bundle()["detector_results"][0]

    def test_replay_detectors_matching(self):
        row = self._sealed_row()
        version = "".join(["0", ".", "1", ".", "0"])
        verdict = "".join(["a", "b", "s", "t", "a", "i", "n"])
        # Guard the Is/IsNot kill: the values must be equal but distinct
        # objects, or the identity mutants are untestable here.
        self.assertIsNot(version, row["detector_version"])
        self.assertIsNot(verdict, row["verdict"])
        fake = _FakeReplayDetector(
            "textforensics/builtin-heuristic",
            version=version,
            score=row["score"],
            verdict=verdict,
        )
        errors, warnings, checks = _replay_detectors([row], [fake], TEXT, atol=1e-9)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])
        self.assertEqual(checks["detectors"][fake.detector_id]["status"], "observed")

    def test_replay_detectors_positional_atol_rejected(self):
        row = self._sealed_row()
        fake = _FakeReplayDetector(
            "textforensics/builtin-heuristic", version="0.1.0", score=row["score"]
        )
        with self.assertRaises(TypeError):
            _replay_detectors([row], [fake], TEXT, 1e-9)

    def test_replay_detectors_version_mismatch(self):
        row = self._sealed_row()
        for version in ("9.9.9", "0.0.9"):
            fake = _FakeReplayDetector(
                "textforensics/builtin-heuristic",
                version=version,
                score=row["score"],
            )
            errors, _, checks = _replay_detectors([row], [fake], TEXT, atol=1e-9)
            self.assertIn("detector_version_mismatch:textforensics/builtin-heuristic", errors)
            self.assertIs(checks["detectors"][fake.detector_id]["version_match"], False)

    def test_replay_detectors_verdict_mismatch(self):
        row = self._sealed_row()
        fake = _FakeReplayDetector(
            "textforensics/builtin-heuristic",
            version="0.1.0",
            score=row["score"],
            verdict="ai_like",
        )
        errors, _, checks = _replay_detectors([row], [fake], TEXT, atol=1e-9)
        self.assertIn("verdict_mismatch:textforensics/builtin-heuristic", errors)
        self.assertIs(checks["detectors"][fake.detector_id]["verdict_match"], False)
        # Hand-crafted sealed row so the fake verdict sorts BELOW the
        # sealed one (kills the Gt/GtE comparison mutants).
        sealed = dict(row, verdict="human_like")
        fake2 = _FakeReplayDetector(
            "textforensics/builtin-heuristic",
            version="0.1.0",
            score=row["score"],
            verdict="abstain",
        )
        errors2, _, _ = _replay_detectors([sealed], [fake2], TEXT, atol=1e-9)
        self.assertIn("verdict_mismatch:textforensics/builtin-heuristic", errors2)

    def test_replay_detectors_score_mismatch(self):
        row = self._sealed_row()
        fake = _FakeReplayDetector(
            "textforensics/builtin-heuristic",
            version="0.1.0",
            score=row["score"] + 0.5,
        )
        errors, _, checks = _replay_detectors([row], [fake], TEXT, atol=1e-9)
        self.assertIn("score_mismatch:textforensics/builtin-heuristic", errors)
        self.assertIs(checks["detectors"][fake.detector_id]["score_match"], False)
        fake_ok = _FakeReplayDetector(
            "textforensics/builtin-heuristic",
            version="0.1.0",
            score=row["score"] + 5e-10,
        )
        errors_ok, _, _ = _replay_detectors([row], [fake_ok], TEXT, atol=1e-9)
        self.assertEqual(errors_ok, [])

    def test_replay_detectors_calibration_mismatch(self):
        row = self._sealed_row()
        fake = _FakeReplayDetector(
            "textforensics/builtin-heuristic",
            version="0.1.0",
            score=row["score"],
            calibration_id="cal-1",
            calibrated_ai_probability=0.4,
        )
        errors, _, checks = _replay_detectors([row], [fake], TEXT, atol=1e-9)
        self.assertIn("calibration_id_mismatch:textforensics/builtin-heuristic", errors)
        self.assertIs(checks["detectors"][fake.detector_id]["calibration_match"], False)
        sealed = dict(row, calibration_id="cal")
        fake2 = _FakeReplayDetector(
            "textforensics/builtin-heuristic",
            version="0.1.0",
            score=row["score"],
            calibration_id="cal-1",
            calibrated_ai_probability=0.4,
        )
        errors2, _, _ = _replay_detectors([sealed], [fake2], TEXT, atol=1e-9)
        self.assertIn("calibration_id_mismatch:textforensics/builtin-heuristic", errors2)
        cal = "".join(["c", "a", "l"])
        self.assertIsNot(cal, sealed["calibration_id"])
        fake3 = _FakeReplayDetector(
            "textforensics/builtin-heuristic",
            version="0.1.0",
            score=row["score"],
            calibration_id=cal,
            calibrated_ai_probability=0.4,
        )
        errors3, _, _ = _replay_detectors([sealed], [fake3], TEXT, atol=1e-9)
        self.assertEqual(errors3, [])

    def test_replay_detectors_unexpected_and_failed_and_not_replayed(self):
        row = self._sealed_row()
        stranger = _FakeReplayDetector(
            "test/stranger", version="1.0.0", score=0.1, verdict="ai_like"
        )
        errors, _, _ = _replay_detectors([row], [stranger], TEXT, atol=1e-9)
        self.assertIn("unexpected_detector:test/stranger", errors)
        self.assertIn("detector_not_replayed:textforensics/builtin-heuristic", errors)
        failing = _FakeReplayDetector("textforensics/builtin-heuristic", fail=True)
        errors2, _, checks2 = _replay_detectors([row], [failing], TEXT, atol=1e-9)
        self.assertEqual(errors2, ["detector_failed:textforensics/builtin-heuristic"])
        failed_row = checks2["detectors"]["textforensics/builtin-heuristic"]
        self.assertEqual(failed_row["status"], "failed")
        self.assertIsInstance(failed_row["failure"], dict)
        self.assertEqual(failed_row["failure"]["detector_id"], "textforensics/builtin-heuristic")

    def test_replay_detectors_non_deterministic_declarations(self):
        row = self._sealed_row()
        fake = _FakeReplayDetector(
            "textforensics/builtin-heuristic",
            version="0.1.0",
            score=row["score"] + 0.5,
        )
        by_id = "textforensics/builtin-heuristic"
        errors, warnings, checks = _replay_detectors(
            [row],
            [fake],
            TEXT,
            atol=1e-9,
            determinism_by_detector={
                by_id: {
                    "determinism": "non_deterministic",
                    "determinism_reason": "sampled",
                }
            },
        )
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [f"not_reproducible:{by_id}:sampled"])
        self.assertEqual(checks["detectors"][by_id]["status"], "not_reproducible")
        for reason in (None, "", 123):
            _, warnings2, _ = _replay_detectors(
                [row],
                [fake],
                TEXT,
                atol=1e-9,
                determinism_by_detector={
                    by_id: {
                        "determinism": "non_deterministic",
                        "determinism_reason": reason,
                    }
                },
            )
            self.assertEqual(warnings2, [f"not_reproducible:{by_id}"])
        for declaration in ("deterministic", "unknown"):
            errors3, warnings3, _ = _replay_detectors(
                [row],
                [fake],
                TEXT,
                atol=1e-9,
                determinism_by_detector={by_id: {"determinism": declaration}},
            )
            self.assertIn(f"score_mismatch:{by_id}", errors3)
            self.assertEqual(warnings3, [])
        # No declaration at all: unknown fails closed.
        errors4, _, _ = _replay_detectors(
            [row], [fake], TEXT, atol=1e-9, determinism_by_detector=None
        )
        self.assertIn(f"score_mismatch:{by_id}", errors4)

    # -- _replay_trust_map_v3 (L1826-1901) ---------------------------------

    def _v3_replay_inputs(self, bundle=None):
        registry = _load_real_registry()
        bundle = bundle if bundle is not None else _matching_bundle()
        bundle["trust_map"] = _v3_trust_map(bundle, registry)
        conditions = conditions_from_dict(bundle["input_conditions"])
        predictions = [
            _prediction_from_dict(item)
            for item in bundle["detector_results"]
            if isinstance(item, dict)
        ]
        return registry, bundle, conditions, predictions

    def test_replay_trust_map_v3_rederives(self):
        registry, bundle, conditions, predictions = self._v3_replay_inputs()
        errors, warnings, checks = _replay_trust_map_v3(
            bundle,
            bundle["trust_map"],
            registry,
            conditions,
            predictions,
            (bundle.get("robustness") or {}).get("detectors", []),
            len(bundle.get("detector_failures", [])),
        )
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])
        self.assertEqual(checks["trust_map"]["status"], "rederived")

    def test_replay_trust_map_v3_skips_bad_refs_and_items(self):
        registry, bundle, conditions, predictions = self._v3_replay_inputs()
        trust = copy.deepcopy(bundle["trust_map"])
        trust["dimensions"] = ["not-a-dict", *trust["dimensions"]]
        trust["dimensions"][1]["evidence_refs"] = None
        trust["dimensions"][2]["evidence_refs"] = [
            123,
            "nonexistent-record-id",
            *trust["dimensions"][2].get("evidence_refs", []),
        ]
        errors, warnings, checks = _replay_trust_map_v3(
            bundle,
            trust,
            registry,
            conditions,
            predictions,
            (bundle.get("robustness") or {}).get("detectors", []),
            len(bundle.get("detector_failures", [])),
        )
        self.assertEqual(errors, [])
        self.assertEqual(checks["trust_map"]["status"], "rederived")

    def test_replay_trust_map_v3_ambiguous_detector(self):
        from types import SimpleNamespace

        class FakeValidationRegistry:
            def __init__(self, records):
                self._records = records

            def record(self, record_id):
                return self._records.get(record_id)

        conditions = conditions_from_dict(self._bundle()["input_conditions"])
        sealed = {
            "dimensions": [
                {
                    "dimension": "language",
                    "state": "supported",
                    "evidence_refs": ["rec-a", "rec-b"],
                }
            ]
        }
        two_detectors = FakeValidationRegistry(
            {
                "rec-a": SimpleNamespace(detector_id="d/one", detector_version="1"),
                "rec-b": SimpleNamespace(detector_id="d/two", detector_version="1"),
            }
        )
        _, warnings, checks = _replay_trust_map_v3({}, sealed, two_detectors, conditions, [], [], 0)
        self.assertEqual(warnings, ["trust_map_v3_derivation_detector_ambiguous"])
        self.assertEqual(checks["trust_map"]["status"], "not_rederived")
        two_versions = FakeValidationRegistry(
            {
                "rec-a": SimpleNamespace(detector_id="d/one", detector_version="1"),
                "rec-b": SimpleNamespace(detector_id="d/one", detector_version="2"),
            }
        )
        _, warnings2, _ = _replay_trust_map_v3({}, sealed, two_versions, conditions, [], [], 0)
        self.assertEqual(warnings2, ["trust_map_v3_derivation_detector_ambiguous"])
        unknown_only = FakeValidationRegistry({})
        _, warnings3, checks3 = _replay_trust_map_v3(
            {}, sealed, unknown_only, conditions, [], [], 0
        )
        self.assertEqual(warnings3, ["trust_map_v3_derivation_detector_ambiguous"])
        self.assertEqual(checks3["trust_map"]["status"], "not_rederived")
        no_refs = {"dimensions": [{"dimension": "language", "state": "supported"}]}
        _, warnings4, _ = _replay_trust_map_v3({}, no_refs, unknown_only, conditions, [], [], 0)
        self.assertEqual(warnings4, ["validation_registry_not_supplied:trust_map_not_rederived"])

    def test_replay_trust_map_v3_state_and_overall_mismatch(self):
        registry, bundle, conditions, predictions = self._v3_replay_inputs()
        tampered = copy.deepcopy(bundle["trust_map"])
        dims = tampered["dimensions"]
        dims[0]["state"] = "supported" if dims[0]["state"] != "supported" else "unknown"
        errors, _, checks = _replay_trust_map_v3(
            bundle,
            tampered,
            registry,
            conditions,
            predictions,
            (bundle.get("robustness") or {}).get("detectors", []),
            len(bundle.get("detector_failures", [])),
        )
        self.assertEqual(errors, ["trust_map_state_mismatch"])
        self.assertEqual(checks["trust_map"]["status"], "mismatch")
        tampered2 = copy.deepcopy(bundle["trust_map"])
        tampered2["overall"] = "strong"
        errors2, _, checks2 = _replay_trust_map_v3(
            bundle,
            tampered2,
            registry,
            conditions,
            predictions,
            (bundle.get("robustness") or {}).get("detectors", []),
            len(bundle.get("detector_failures", [])),
        )
        self.assertEqual(errors2, ["trust_map_overall_mismatch"])
        self.assertEqual(checks2["trust_map"]["status"], "mismatch")

    # -- _replay_trust_map dispatch + v1/v2 path (L1904-2021) --------------

    def test_replay_trust_map_missing_sections(self):
        errors, _, _ = _replay_trust_map({}, None)
        self.assertEqual(errors, ["missing_input_conditions"])
        bundle = self._bundle()
        bundle.pop("trust_map", None)
        errors2, _, _ = _replay_trust_map(bundle, None)
        self.assertEqual(errors2, ["missing_trust_map"])
        # validation_registry is keyword-only (the `*,` marker).
        with self.assertRaises(TypeError):
            _replay_trust_map(bundle, None, None)

    def test_replay_trust_map_v3_without_validation_registry(self):
        registry, bundle, _, _ = self._v3_replay_inputs()
        errors, warnings, checks = _replay_trust_map(bundle, None)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, ["validation_registry_not_supplied:trust_map_not_rederived"])
        self.assertEqual(checks["trust_map"]["status"], "not_rederived")

    def test_replay_trust_map_v3_invalid_conditions(self):
        registry, bundle, _, _ = self._v3_replay_inputs()
        for broken in (
            {},
            {"schema": "bogus"},
            {k: v for k, v in bundle["input_conditions"].items() if k != "language"},
            {**bundle["input_conditions"], "word_count": "144"},
        ):
            broken_bundle = copy.deepcopy(bundle)
            broken_bundle["input_conditions"] = broken
            errors, _, checks = _replay_trust_map(broken_bundle, None, validation_registry=registry)
            self.assertEqual(errors, ["invalid_input_conditions"])
            self.assertEqual(checks["trust_map"]["status"], "not_rederived")

    def test_replay_trust_map_v3_invalid_detector_results(self):
        registry, bundle, _, _ = self._v3_replay_inputs()
        broken = copy.deepcopy(bundle)
        broken["detector_results"] = [{}]
        errors, _, checks = _replay_trust_map(broken, None, validation_registry=registry)
        self.assertEqual(errors, ["invalid_detector_results_for_replay"])
        self.assertEqual(checks["trust_map"]["status"], "not_rederived")

    def test_replay_trust_map_v2_rederives_and_mismatches(self):
        bundle = self._bundle()
        errors, warnings, checks = _replay_trust_map(bundle, None)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])
        self.assertEqual(checks["trust_map"]["status"], "rederived")
        tampered = copy.deepcopy(bundle)
        dims = tampered["trust_map"]["dimensions"]
        dims[0]["state"] = "supported" if dims[0]["state"] != "supported" else "unknown"
        errors2, _, checks2 = _replay_trust_map(tampered, None)
        self.assertEqual(errors2, ["trust_map_state_mismatch"])
        self.assertEqual(checks2["trust_map"]["status"], "mismatch")
        tampered2 = copy.deepcopy(bundle)
        tampered2["trust_map"]["overall"] = "strong"
        errors3, _, _ = _replay_trust_map(tampered2, None)
        self.assertEqual(errors3, ["trust_map_overall_mismatch"])

    def test_replay_trust_map_v2_invalid_conditions_and_results(self):
        bundle = self._bundle()
        for broken_conditions in (
            {},
            {"schema": "bogus"},
            {k: v for k, v in bundle["input_conditions"].items() if k != "language"},
            {**bundle["input_conditions"], "word_count": "25"},
        ):
            broken = copy.deepcopy(bundle)
            broken["input_conditions"] = broken_conditions
            errors, _, checks = _replay_trust_map(broken, None)
            self.assertEqual(errors, ["invalid_input_conditions"])
            self.assertEqual(checks["trust_map"]["status"], "not_rederived")
        broken = copy.deepcopy(bundle)
        broken["detector_results"] = [{}]
        errors, _, checks = _replay_trust_map(broken, None)
        self.assertEqual(errors, ["invalid_detector_results_for_replay"])

    def test_replay_trust_map_v2_registry_rules(self):
        bundle = self._bundle()
        empty_registry = EvidenceRegistry((), created_at_utc="1970-01-01T00:00:00+00:00")
        no_supply = copy.deepcopy(bundle)
        no_supply["evidence_registry"] = {"registry_id": "e" * 64}
        errors, warnings, checks = _replay_trust_map(no_supply, None)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, ["registry_not_supplied:trust_map_not_rederived"])
        self.assertEqual(checks["trust_map"]["status"], "not_rederived")
        for sealed_id, registry_id in (("e" * 64, "d" * 64), ("d" * 64, "e" * 64)):
            mismatch = copy.deepcopy(bundle)
            mismatch["evidence_registry"] = {"registry_id": sealed_id}
            fake = EvidenceRegistry((), created_at_utc="1970-01-01T00:00:00+00:00")
            fake._registry_id = registry_id
            errors2, _, checks2 = _replay_trust_map(mismatch, fake)
            self.assertEqual(errors2, ["registry_id_mismatch"])
            self.assertEqual(checks2["trust_map"]["status"], "not_rederived")
        matching = copy.deepcopy(bundle)
        matching["evidence_registry"] = {"registry_id": empty_registry.registry_id}
        errors3, warnings3, checks3 = _replay_trust_map(matching, empty_registry)
        self.assertEqual(errors3, [])
        self.assertEqual(warnings3, [])
        self.assertEqual(checks3["trust_map"]["status"], "rederived")
        matching_id = "".join(["e"] * 64)
        self.assertIsNot(matching_id, "e" * 64)
        matching2 = copy.deepcopy(bundle)
        matching2["evidence_registry"] = {"registry_id": "e" * 64}
        fake2 = EvidenceRegistry((), created_at_utc="1970-01-01T00:00:00+00:00")
        fake2._registry_id = matching_id
        errors4, _, checks4 = _replay_trust_map(matching2, fake2)
        self.assertEqual(errors4, [])
        self.assertEqual(checks4["trust_map"]["status"], "rederived")

    def _two_family_bundle(self):
        bundle = self._bundle()
        row2 = copy.deepcopy(bundle["detector_results"][0])
        row2["detector_id"] = "test/second-detector"
        row2["detector_family"] = "other-family"
        row2["detector_version"] = "2.0.0"
        bundle["detector_results"] = [bundle["detector_results"][0], row2]
        conditions = conditions_from_dict(bundle["input_conditions"])
        predictions = [
            _prediction_from_dict(item)
            for item in bundle["detector_results"]
            if isinstance(item, dict)
        ]
        bundle["trust_map"] = assess_trust_map(
            conditions,
            predictions,
            registry=None,
            robustness=(bundle.get("robustness") or {}).get("detectors", []),
            failure_count=0,
            generated_at_utc="2025-01-01T00:00:00+00:00",
        ).to_dict()
        return bundle

    def test_replay_trust_map_failure_count_changes_diversity(self):
        bundle = self._two_family_bundle()
        errors, _, checks = _replay_trust_map(bundle, None)
        self.assertEqual(errors, [])
        self.assertEqual(checks["trust_map"]["status"], "rederived")
        failed = copy.deepcopy(bundle)
        failed["detector_failures"] = [{"detector_id": "x", "reason": "r"} for _ in range(3)]
        errors2, _, checks2 = _replay_trust_map(failed, None)
        self.assertEqual(errors2, ["trust_map_state_mismatch"])
        self.assertEqual(checks2["trust_map"]["rederived"]["detector_diversity"], "partial")
        self.assertEqual(checks2["trust_map"]["sealed"]["detector_diversity"], "supported")
        not_a_list = copy.deepcopy(bundle)
        not_a_list["detector_failures"] = {"not": "a-list"}
        errors3, _, checks3 = _replay_trust_map(not_a_list, None)
        self.assertEqual(errors3, [])
        self.assertEqual(checks3["trust_map"]["status"], "rederived")

    def test_replay_trust_map_robustness_rows(self):
        bundle = self._bundle()
        errors, _, checks = _replay_trust_map(bundle, None)
        self.assertEqual(errors, [])
        self.assertEqual(checks["trust_map"]["status"], "rederived")
        broken = copy.deepcopy(bundle)
        broken["robustness"] = "not-a-mapping"
        errors2, _, _ = _replay_trust_map(broken, None)
        self.assertEqual(errors2, ["trust_map_state_mismatch"])

    # -- _verify_manifest (L1499-1514) --------------------------------------

    def test_verify_manifest_mismatches_and_missing(self):
        case = self._sealed()
        self.assertEqual(_verify_manifest(case, case["forensic_bundle"]), [])
        for key in (
            "content_sha256",
            "registry_id",
            "registry_sha256",
            "calibration_ids",
            "schema_versions",
        ):
            tampered = copy.deepcopy(case)
            tampered["manifest"][key] = "tampered-value"
            self.assertIn(
                f"manifest_mismatch:{key}",
                _verify_manifest(tampered, tampered["forensic_bundle"]),
            )
        no_manifest = copy.deepcopy(case)
        no_manifest.pop("manifest", None)
        self.assertEqual(
            _verify_manifest(no_manifest, no_manifest["forensic_bundle"]),
            ["missing_manifest"],
        )

    # -- replay_case_file (L2024-2166) --------------------------------------

    def _matching_fake(self, bundle=None):
        row = (bundle or self._bundle())["detector_results"][0]
        return _FakeReplayDetector(
            row["detector_id"],
            version=row["detector_version"],
            score=row["score"],
            verdict=row["verdict"],
        )

    def test_replay_case_file_reproduced(self):
        case = self._sealed()
        result = replay_case_file(case, text=TEXT, detectors=[self._matching_fake()])
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["replay_outcome"], "reproduced")
        self.assertEqual(result["checks"]["text"]["status"], "matched")

    def test_replay_case_file_atol_validation(self):
        case = self._sealed()
        for bad in (True, "x", -1):
            with self.assertRaises(ValueError):
                replay_case_file(case, atol=bad)
        result = replay_case_file(case, text=TEXT, atol=0)
        self.assertTrue(result["valid"], result["errors"])

    def test_replay_case_file_text_is_keyword_only(self):
        # The `*,` marker makes text keyword-only; the Mul_Div mutant
        # turns it into `/` (positional-only) and must be rejected.
        case = self._sealed()
        with self.assertRaises(TypeError):
            replay_case_file(case, TEXT)

    def test_replay_case_file_atol_defaults(self):
        case = self._sealed()
        row = case["forensic_bundle"]["detector_results"][0]
        for diff, expect_valid in ((5e-10, True), (2e-9, False)):
            fake = _FakeReplayDetector(
                row["detector_id"],
                version=row["detector_version"],
                score=row["score"] + diff,
                verdict=row["verdict"],
            )
            result = replay_case_file(case, text=TEXT, detectors=[fake])
            self.assertEqual(result["valid"], expect_valid, diff)

    def test_replay_case_file_text_mismatch_and_missing(self):
        case = self._sealed()
        result = replay_case_file(case, text="different text entirely")
        self.assertFalse(result["valid"])
        self.assertIn("text_hash_mismatch", result["errors"])
        self.assertEqual(result["replay_outcome"], "failed")
        self.assertEqual(result["checks"]["text"]["status"], "mismatch")
        result2 = replay_case_file(case)
        self.assertTrue(result2["valid"], result2["errors"])
        self.assertEqual(result2["checks"]["text"]["status"], "not_supplied")
        self.assertEqual(result2["checks"]["detectors"]["status"], "not_supplied")

    def test_replay_case_file_detectors_require_text(self):
        case = self._sealed()
        result = replay_case_file(case, detectors=[self._matching_fake()])
        self.assertFalse(result["valid"])
        self.assertIn("text_required_for_detector_replay", result["errors"])
        self.assertEqual(result["checks"]["detectors"]["status"], "not_performed")

    def test_replay_case_file_non_mapping_bundle(self):
        case = self._sealed()
        case["forensic_bundle"] = "not-a-mapping"
        result = replay_case_file(case)
        self.assertFalse(result["valid"])
        self.assertEqual(result["replay_outcome"], "failed")

    def test_replay_case_file_inconclusive_and_failed(self):
        case = self._sealed(
            determinism={"textforensics/builtin-heuristic": "non_deterministic"},
            determinism_reasons={"textforensics/builtin-heuristic": "sampled output"},
        )
        row = case["forensic_bundle"]["detector_results"][0]
        fake = _FakeReplayDetector(
            row["detector_id"],
            version=row["detector_version"],
            score=row["score"] + 0.5,
            verdict=row["verdict"],
        )
        result = replay_case_file(case, text=TEXT, detectors=[fake])
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["replay_outcome"], "inconclusive")
        self.assertIn(
            "not_reproducible:textforensics/builtin-heuristic:sampled output",
            result["warnings"],
        )
        case2 = self._sealed()
        result2 = replay_case_file(case2, text=TEXT, detectors=[fake])
        self.assertFalse(result2["valid"])
        self.assertEqual(result2["replay_outcome"], "failed")
        self.assertIn("score_mismatch:textforensics/builtin-heuristic", result2["errors"])

    def test_replay_case_file_observation_fallback_rows(self):
        # Observations carry no declaration for the builtin: the bundle
        # row's determinism is the fallback.  Non-mapping / id-less
        # result rows are skipped without error.  (Deleting the
        # observations post-seal breaks the seal hash, so the case is
        # invalid overall; the fallback is observed through the
        # detector errors/warnings, not through validity.)
        case = self._sealed(
            determinism={"textforensics/builtin-heuristic": "non_deterministic"},
            determinism_reasons={"textforensics/builtin-heuristic": "sampled output"},
        )
        case["detector_observations"] = []
        bundle = case["forensic_bundle"]
        bundle["detector_results"] = [
            "not-a-dict",
            {"detector_id": ""},
            bundle["detector_results"][0],
        ]
        row = bundle["detector_results"][2]
        fake = _FakeReplayDetector(
            row["detector_id"],
            version=row["detector_version"],
            score=row["score"] + 0.5,
            verdict=row["verdict"],
        )
        result = replay_case_file(case, text=TEXT, detectors=[fake])
        self.assertNotIn("score_mismatch:textforensics/builtin-heuristic", result["errors"])
        self.assertIn(
            "not_reproducible:textforensics/builtin-heuristic:sampled output",
            result["warnings"],
        )

    def test_replay_case_file_declaration_collection_edge_cases(self):
        # L2103-2110: the observation loop must collect declarations only
        # from mapping, kind=="observed" rows with a detector_id, and the
        # bundle row is only a fallback.  Post-seal tampering breaks the
        # seal hash, so these assert on detector errors/warnings, not on
        # validity.
        base = self._sealed(
            determinism={"textforensics/builtin-heuristic": "non_deterministic"},
            determinism_reasons={"textforensics/builtin-heuristic": "sampled output"},
        )
        by_id = "textforensics/builtin-heuristic"

        def mismatching_fake(case):
            row = case["forensic_bundle"]["detector_results"][0]
            return _FakeReplayDetector(
                row["detector_id"],
                version=row["detector_version"],
                score=row["score"] + 0.5,
                verdict=row["verdict"],
            )

        def assert_inconclusive(case):
            result = replay_case_file(case, text=TEXT, detectors=[mismatching_fake(case)])
            self.assertNotIn(f"score_mismatch:{by_id}", result["errors"])
            self.assertIn(f"not_reproducible:{by_id}:sampled output", result["warnings"])

        # (a) A non-mapping observation row is skipped, not dereferenced.
        tampered = copy.deepcopy(base)
        tampered["detector_observations"] = [
            "not-a-dict",
            *tampered["detector_observations"],
        ]
        assert_inconclusive(tampered)
        # (b) Observations None falls back to the bundle row.
        tampered = copy.deepcopy(base)
        tampered["detector_observations"] = None
        assert_inconclusive(tampered)
        # (c) The observation declaration wins over the bundle row even
        # when the bundle row says deterministic.
        tampered = copy.deepcopy(base)
        tampered["forensic_bundle"]["detector_results"][0]["determinism"] = "deterministic"
        assert_inconclusive(tampered)
        # (e) Same as (c) after a JSON round trip, so the kind string is
        # a fresh object (kills the `is` identity mutant).
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "case.json"
            path.write_text(json.dumps(tampered), encoding="utf-8")
            reloaded = json.loads(path.read_text(encoding="utf-8"))
            self.assertIsNot(reloaded["detector_observations"][0]["kind"], "observed")
            assert_inconclusive(reloaded)

    def test_replay_case_file_failed_row_does_not_declare(self):
        # A failed-kind observation for the same detector must not
        # overwrite the observed row's declaration.
        bundle = self._bundle()
        bundle["detector_failures"] = [
            {"detector_id": "textforensics/builtin-heuristic", "reason": "x"}
        ]
        case = seal_case_file(
            bundle,
            determinism={"textforensics/builtin-heuristic": "non_deterministic"},
            determinism_reasons={"textforensics/builtin-heuristic": "sampled output"},
        )
        kinds = [o["kind"] for o in case["detector_observations"]]
        self.assertEqual(kinds[:2], ["observed", "failed"])
        row = case["forensic_bundle"]["detector_results"][0]
        fake = _FakeReplayDetector(
            row["detector_id"],
            version=row["detector_version"],
            score=row["score"] + 0.5,
            verdict=row["verdict"],
        )
        result = replay_case_file(case, text=TEXT, detectors=[fake])
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["replay_outcome"], "inconclusive")
        self.assertIn(
            "not_reproducible:textforensics/builtin-heuristic:sampled output",
            result["warnings"],
        )

    def test_replay_case_file_v3_trust_map_replay(self):
        registry = _load_real_registry()
        bundle = _matching_bundle()
        bundle["trust_map"] = _v3_trust_map(bundle, registry)
        case = seal_case_file(bundle, validation_registry=registry)
        row = bundle["detector_results"][0]
        fake = _FakeReplayDetector(
            row["detector_id"],
            version=row["detector_version"],
            score=row["score"],
            verdict=row["verdict"],
        )
        result = replay_case_file(
            case, text=_V3_TEXT, detectors=[fake], validation_registry=registry
        )
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["checks"]["trust_map"]["trust_map"]["status"], "rederived")
        self.assertEqual(result["replay_outcome"], "reproduced")

    # -- replay_case_file_path (L2172-2197) ---------------------------------

    def test_replay_case_file_path_round_trip_and_non_dict(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "case.json"
            write_case_file(path, self._bundle())
            result = replay_case_file_path(path, text=TEXT, detectors=[self._matching_fake()])
            self.assertTrue(result["valid"], result["errors"])
            self.assertEqual(result["replay_outcome"], "reproduced")
            # text is keyword-only (the `*,` marker).
            with self.assertRaises(TypeError):
                replay_case_file_path(path, TEXT)
            bad = Path(tmp) / "bad.json"
            bad.write_text("[1, 2]", encoding="utf-8")
            result2 = replay_case_file_path(bad)
            self.assertFalse(result2["valid"])
            self.assertEqual(result2["errors"], ["case_file_must_be_json_object"])
            self.assertEqual(result2["replay_outcome"], "failed")

    def test_replay_case_file_path_atol_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "case.json"
            case = self._sealed()
            write_case_file(path, case["forensic_bundle"])
            row = case["forensic_bundle"]["detector_results"][0]
            for diff, expect_valid in ((5e-10, True), (2e-9, False)):
                fake = _FakeReplayDetector(
                    row["detector_id"],
                    version=row["detector_version"],
                    score=row["score"] + diff,
                    verdict=row["verdict"],
                )
                result = replay_case_file_path(path, text=TEXT, detectors=[fake])
                self.assertEqual(result["valid"], expect_valid, diff)

    # -- Phase 2 gap kill tests (casefile mutation Phase 2) ---------------
    # One test per re-derived test gap (86). Each test pins the exact
    # distinguishing input from hidden_files/casefile-p2-classification.md
    # (gap list: hidden_files/casefile-p2-gap-kill-tests.md) so the mutant
    # at the cited position changes the observable result. "p2_gap_<idx>"
    # is the cosmic-ray work-item index of the mutant.

    def _p2_disagreement_case(self, **process_overrides):
        process = self._cons_process(**process_overrides)
        return self._cons_case(
            process,
            observations=[
                {
                    "kind": "observed",
                    "detector_id": "d1",
                    "verdict": "ai_like",
                    "disposition": "relied_on",
                },
                {
                    "kind": "observed",
                    "detector_id": "d2",
                    "verdict": "human_like",
                    "disposition": "considered",
                },
            ],
        )

    # -- D-item Eq_LtE gaps: "not_satisfied" must not fire the rule -------

    def test_p2_gap_1048_d2_not_satisfied_disagreement_does_not_fire(self):
        case = self._p2_disagreement_case(
            items={"D2": {"status": "not_satisfied"}}, contrary_evidence=[]
        )
        self.assertNotIn(
            "checklist_d2_unsupported:detector_disagreement_unaddressed",
            _checklist_consistency(case, {}),
        )

    def test_p2_gap_1051_d4_not_satisfied_reviewer_missing_does_not_fire(self):
        process = self._cons_process(items={"D4": {"status": "not_satisfied"}}, reviewer=None)
        self.assertNotIn(
            "checklist_d4_unsupported:reviewer_missing",
            _checklist_consistency(self._cons_case(process), {}),
        )

    def test_p2_gap_1054_d6_not_satisfied_incomplete_disclosure_does_not_fire(self):
        process = self._cons_process(items={"D6": {"status": "not_satisfied"}})
        case = self._cons_case(
            process, limitations={"plain_language": {}, "counterfactuals": ["c1"]}
        )
        self.assertNotIn(
            "checklist_d6_unsupported:limitations_disclosure_incomplete",
            _checklist_consistency(case, {}),
        )

    def test_p2_gap_1056_d8_not_satisfied_no_counterfactuals_does_not_fire(self):
        process = self._cons_process(items={"D8": {"status": "not_satisfied"}})
        case = self._cons_case(
            process,
            limitations={
                "plain_language": {
                    "score_not_probability": "s",
                    "authorship_warning": "a",
                    "human_fpr": "h",
                },
                "counterfactuals": [],
            },
        )
        self.assertNotIn(
            "checklist_d8_unsupported:no_counterfactuals",
            _checklist_consistency(case, {}),
        )

    def test_p2_gap_1058_d10_not_satisfied_missing_policy_does_not_fire(self):
        process = self._cons_process(
            items={"D10": {"status": "not_satisfied"}}, policy_version=None
        )
        self.assertNotIn(
            "checklist_d10_unsupported:policy_or_procedure_version_missing",
            _checklist_consistency(self._cons_case(process), {}),
        )

    # -- _observations_match comparison gaps ------------------------------

    def test_p2_gap_1061_observations_match_v3_lt_is_not_lte(self):
        self.assertFalse(_observations_match(["a"], ["b"], version="v3"))

    def test_p2_gap_1117_observations_match_v3_gt_is_not_gte(self):
        self.assertFalse(_observations_match(["b"], ["a"], version="v3"))

    def test_p2_gap_1173_observations_match_v3_is_not_identity(self):
        sealed = [{"kind": "observed", "detector_id": "d1", "score": 0.5, "determinism": "unknown"}]
        expected = [
            {"kind": "observed", "detector_id": "d1", "score": 0.9, "determinism": "unknown"}
        ]
        self.assertFalse(_observations_match(sealed, expected, version="v3"))

    def test_p2_gap_1137_d5_same_decider_by_value_not_identity(self):
        decider = "".join(["a", "l", "i", "c", "e"])
        appeal_decider = "".join(["a", "l", "i", "c", "e"])
        self.assertEqual(decider, appeal_decider)
        self.assertIsNot(decider, appeal_decider)
        process = self._cons_process()
        process["appeal"] = {
            "decider": decider,
            "appeal_decider": appeal_decider,
            "route": "r",
            "deadline": "d",
        }
        self.assertIn(
            "checklist_d5_unsupported:same_decider_for_appeal",
            _checklist_consistency(self._cons_case(process), {}),
        )

    # -- _replay_detectors / determinism overrides ------------------------

    def test_p2_gap_87_replay_extra_detector_is_not_not_replayed(self):
        row = self._sealed_row()
        stranger = _FakeReplayDetector(
            "test/stranger", version="1.0.0", score=0.1, verdict="ai_like"
        )
        errors, _, _ = _replay_detectors([row], [stranger], TEXT, atol=1e-9)
        self.assertIn("unexpected_detector:test/stranger", errors)
        self.assertIn("detector_not_replayed:textforensics/builtin-heuristic", errors)
        self.assertNotIn("detector_not_replayed:test/stranger", errors)

    def test_p2_gap_954_determinism_override_unknown_in_both_maps_raises(self):
        bundle = self._bundle()
        with self.assertRaises(ValueError):
            seal_case_file(
                bundle,
                determinism={"unknown-detector": "non_deterministic"},
                determinism_reasons={"unknown-detector": "sampled"},
            )

    def test_p2_gap_1865_determinism_override_skips_non_mapping_entry(self):
        bundle = self._bundle()
        bundle["detector_results"] = ["junk", *bundle["detector_results"]]
        case = seal_case_file(
            bundle, determinism={"textforensics/builtin-heuristic": "deterministic"}
        )
        self.assertEqual(case["detector_observations"][0]["determinism"], "deterministic")

    def test_p2_gap_2002_determinism_override_applies_after_non_mapping_entry(self):
        bundle = self._bundle()
        bundle["detector_results"] = ["junk", *bundle["detector_results"]]
        case = seal_case_file(
            bundle, determinism={"textforensics/builtin-heuristic": "non_deterministic"}
        )
        self.assertEqual(case["detector_observations"][0]["determinism"], "non_deterministic")

    def test_p2_gap_2096_invalid_determinism_value_keeps_original_message(self):
        # The mutant empties only the validation loop, so the bogus value
        # is written and fails later with a different message.
        with self.assertRaisesRegex(ValueError, "Invalid determinism for"):
            seal_case_file(
                self._bundle(),
                determinism={"textforensics/builtin-heuristic": "bogus"},
            )

    # -- validate_checklist gaps ------------------------------------------

    def test_p2_gap_1490_validate_checklist_string_evidence_is_valid(self):
        process = build_checklist({"D1": {"status": "satisfied", "evidence": ["e1"]}})
        self.assertNotIn("checklist_d1_invalid_evidence", validate_checklist(process))

    def test_p2_gap_1491_validate_checklist_valid_mapping_disposition_is_valid(self):
        process = build_checklist(evidence_dispositions={"d1": {"disposition": "relied_on"}})
        self.assertNotIn("checklist_disposition_invalid:d1", validate_checklist(process))

    def test_p2_gap_1998_validate_checklist_reports_d1_and_d2(self):
        process = build_checklist()
        process["items"]["D1"] = "not-a-mapping"
        process["items"]["D2"]["status"] = "bogus"
        errors = validate_checklist(process)
        self.assertIn("checklist_d1_missing", errors)
        self.assertIn("checklist_d2_invalid_status", errors)

    # -- D2 contrary-evidence gaps ----------------------------------------

    def test_p2_gap_1519_d2_valid_contrary_entry_is_complete(self):
        case = self._p2_disagreement_case(contrary_evidence=[{"detector_id": "d1"}])
        self.assertNotIn(
            "checklist_d2_unsupported:contrary_evidence_incomplete",
            _checklist_consistency(case, {}),
        )

    def test_p2_gap_1684_d2_valid_contrary_entry_is_complete_addnot(self):
        # Same distinguishing input as idx 1519: the two mutants coincide.
        case = self._p2_disagreement_case(contrary_evidence=[{"detector_id": "d1"}])
        self.assertNotIn(
            "checklist_d2_unsupported:contrary_evidence_incomplete",
            _checklist_consistency(case, {}),
        )

    def test_p2_gap_1993_d2_two_invalid_contrary_entries_report_once(self):
        case = self._p2_disagreement_case(contrary_evidence=[{"note": "x"}, {"note": "y"}])
        errors = _checklist_consistency(case, {})
        self.assertEqual(errors.count("checklist_d2_unsupported:contrary_evidence_incomplete"), 1)

    def test_p2_gap_1935_d5_route_present_deadline_missing(self):
        process = self._cons_process(
            appeal={"decider": "alice", "appeal_decider": "bob", "route": "r"}
        )
        self.assertIn(
            "checklist_d5_unsupported:route_or_deadline_missing",
            _checklist_consistency(self._cons_case(process), {}),
        )

    # -- build_case_input gap ----------------------------------------------

    def test_p2_gap_1914_build_case_input_non_string_acquired_by_is_gap(self):
        _, gaps = build_case_input(self._bundle(), acquired_by=123)
        self.assertIn("input.acquired_by", [gap["field"] for gap in gaps])
        _, gaps2 = build_case_input(self._bundle(), acquired_by="")
        self.assertIn("input.acquired_by", [gap["field"] for gap in gaps2])

    # -- build_validation_refs gaps --------------------------------------

    def test_p2_gap_1222_validation_refs_passes_zh_language(self):
        bundle = _matching_bundle()
        conditions = dict(bundle["input_conditions"])
        conditions["language"] = "zh"
        conditions["language_confidence"] = "high"
        bundle["input_conditions"] = conditions
        registry, calls, _ = self._fake_registry()
        build_validation_refs(bundle, registry)
        self.assertEqual(calls[0]["language"], "zh")

    def test_p2_gap_1287_validation_refs_passes_news_domain(self):
        registry, calls, _ = self._fake_registry()
        build_validation_refs(_matching_bundle(), registry)
        self.assertEqual(calls[0]["domain"], "news")

    def test_p2_gap_1288_validation_refs_passes_raw_editing_regime(self):
        registry, calls, _ = self._fake_registry()
        build_validation_refs(_matching_bundle(), registry)
        self.assertEqual(calls[0]["editing_regime"], "raw")

    def test_p2_gap_1866_validation_refs_skips_non_mapping_result_ids(self):
        bundle = self._bundle()
        bundle["detector_results"] = ["junk", *bundle["detector_results"]]
        registry, _, _ = self._fake_registry()
        refs, _ = build_validation_refs(bundle, registry)
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["detector_id"], "textforensics/builtin-heuristic")

    def test_p2_gap_1867_validation_refs_skips_non_mapping_result_rows(self):
        # Same distinguishing input as idx 1866 (the observations
        # comprehension is the second of the two identical guards).
        bundle = self._bundle()
        bundle["detector_results"] = ["junk", *bundle["detector_results"]]
        registry, _, _ = self._fake_registry()
        refs, _ = build_validation_refs(bundle, registry)
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["detector_id"], "textforensics/builtin-heuristic")

    def test_p2_gap_2041_validation_refs_first_metric_not_a_mapping(self):
        _, _, FakeRecord = self._fake_registry()
        record = FakeRecord(
            "rec-1",
            "supported",
            metrics=["not-a-dict", {"fpr_native": {"value": 0.04, "n": 80}}],
        )
        registry, _, _ = self._fake_registry({"textforensics/builtin-heuristic": [record]})
        refs, _ = build_validation_refs(self._bundle(), registry)
        self.assertIsNone(refs[0]["records"][0]["fpr_native"])

    def test_p2_gap_2043_validation_refs_reads_first_metric_fpr(self):
        _, _, FakeRecord = self._fake_registry()
        record = FakeRecord(
            "rec-1",
            "supported",
            metrics=[
                {"fpr_native": {"value": 0.04, "n": 80}},
                {"fpr_native": {"value": 0.09, "n": 50}},
            ],
        )
        registry, _, _ = self._fake_registry({"textforensics/builtin-heuristic": [record]})
        refs, _ = build_validation_refs(self._bundle(), registry)
        self.assertEqual(refs[0]["records"][0]["fpr_native"]["value"], 0.04)

    # -- _verify_case_sections gaps ----------------------------------------

    def test_p2_gap_1225_verify_sections_input_sha_greater_than_bundle(self):
        case = self._sealed()
        bundle_sha = case["forensic_bundle"]["content_sha256"]
        self.assertLess(bundle_sha, "f" * 64)
        case["input"]["content_sha256"] = "f" * 64
        self.assertIn("v3_input_content_sha256_mismatch", verify_case_file(case)["errors"])

    def test_p2_gap_1226_verify_sections_plugin_health_not_observed(self):
        case = self._sealed()
        case["detector_observations"].append({"kind": "plugin_health", "detector_id": "x"})
        self.assertNotIn(
            "v4_detector_observations_determinism_missing:x",
            verify_case_file(case)["errors"],
        )

    def test_p2_gap_1290_verify_sections_failed_not_observed(self):
        case = self._sealed()
        case["detector_observations"].append({"kind": "failed", "detector_id": "y"})
        self.assertNotIn(
            "v4_detector_observations_determinism_missing:y",
            verify_case_file(case)["errors"],
        )

    def test_p2_gap_1232_verify_sections_fingerprint_65_chars_invalid(self):
        seed = bytes(range(32))
        signer = {"identity": "strmt7", "role": "sealer"}
        case = self._sealed(signing_seed=seed, signer=signer)
        case["seal"]["signature"]["key_fingerprint"] = "a" * 65
        self.assertIn("v3_seal_signature_fingerprint_invalid", verify_case_file(case)["errors"])

    def test_p2_gap_1292_verify_sections_registry_sha_smaller_than_id(self):
        case = self._sealed()
        case["validation_refs"] = [{"registry_id": "b" * 64, "registry_sha256": "a" * 64}]
        self.assertIn(
            "v3_validation_ref_registry_sha256_mismatch", verify_case_file(case)["errors"]
        )

    def test_p2_gap_1294_verify_sections_custody_head_smaller_than_entry(self):
        case = self._sealed()
        case["seal"]["custody_head"] = "0" * 64
        self.assertIn("v3_seal_custody_head_mismatch", verify_case_file(case)["errors"])

    def test_p2_gap_1295_verify_sections_signature_algorithm_ecdsa_invalid(self):
        seed = bytes(range(32))
        signer = {"identity": "strmt7", "role": "sealer"}
        case = self._sealed(signing_seed=seed, signer=signer)
        case["seal"]["signature"]["algorithm"] = "ecdsa"
        self.assertIn("v3_seal_signature_algorithm_invalid", verify_case_file(case)["errors"])

    def test_p2_gap_1716_verify_sections_applies_evidence_dispositions(self):
        case = seal_case_file(
            self._bundle(),
            process={
                "evidence_dispositions": {
                    "textforensics/builtin-heuristic": {
                        "disposition": "relied_on",
                        "reason": "r",
                    }
                }
            },
        )
        errors = _verify_case_sections(case, case["forensic_bundle"], version="v4")
        self.assertNotIn("v3_detector_observations_mismatch", errors)

    def test_p2_gap_1941_verify_sections_process_dispositions_applied(self):
        # The (process or {}) guard is only evaluated when process IS a
        # Mapping (the ternary takes the else branch otherwise), so the
        # distinguishing input is a process carrying evidence_dispositions:
        # the original applies them when rebuilding observations, the
        # mutant drops them and the rebuild mismatches. (The
        # classification's "no process key" input cannot reach the `or`.)
        case = seal_case_file(
            self._bundle(),
            process={
                "evidence_dispositions": {
                    "textforensics/builtin-heuristic": {
                        "disposition": "relied_on",
                        "reason": "r",
                    }
                }
            },
        )
        errors = _verify_case_sections(case, case["forensic_bundle"], version="v4")
        self.assertNotIn("v3_detector_observations_mismatch", errors)

    def test_p2_gap_1994_verify_sections_two_invalid_gaps_report_once(self):
        case = self._sealed()
        case["gaps"] = [{"field": "", "reason": "r"}, {"field": "f", "reason": ""}]
        errors = verify_case_file(case)["errors"]
        self.assertEqual(errors.count("v3_gaps_invalid"), 1)

    def test_p2_gap_2004_verify_sections_skips_non_observed_before_missing(self):
        case = self._sealed()
        detector_id = str(case["detector_observations"][0]["detector_id"])
        del case["detector_observations"][0]["determinism"]
        case["detector_observations"] = [
            {"kind": "plugin_health", "detector_id": "x"},
            *case["detector_observations"],
        ]
        self.assertIn(
            f"v4_detector_observations_determinism_missing:{detector_id}",
            verify_case_file(case)["errors"],
        )

    def test_p2_gap_2005_verify_sections_reports_both_bad_refs(self):
        case = self._sealed()
        case["validation_refs"] = [
            "not-a-mapping",
            {"registry_id": "bad", "registry_sha256": "bad"},
        ]
        errors = verify_case_file(case)["errors"]
        self.assertIn("v3_validation_ref_invalid", errors)
        self.assertIn("v3_validation_ref_registry_id_invalid", errors)

    def test_p2_gap_2012_verify_sections_invalid_determinism_in_bundle_row(self):
        case = self._sealed()
        bundle = copy.deepcopy(case["forensic_bundle"])
        bundle["detector_results"][0]["determinism"] = "bogus"
        errors = _verify_case_sections(case, bundle, version="v4")
        self.assertIn("v4_detector_observations_invalid", errors)

    # -- verify_custody gaps -----------------------------------------------

    def _p2_custody_chain(self):
        chain: list = []
        chain.append(
            chain_custody_entry(
                chain, actor="a", action="sealed", at_utc="2025-01-01T00:00:00+00:00"
            )
        )
        return chain

    def test_p2_gap_1220_verify_custody_prev_hash_greater_than_genesis(self):
        chain = self._p2_custody_chain()
        chain[0]["prev_hash"] = "f" * 64
        self.assertEqual(verify_custody(chain), ["custody_chain_broken:0"])

    def test_p2_gap_1285_verify_custody_entry_hash_smaller_than_expected(self):
        chain = self._p2_custody_chain()
        chain[0]["entry_hash"] = "0" * 64
        self.assertEqual(verify_custody(chain), ["custody_entry_hash_mismatch:0"])

    # -- verify_case_file gaps ----------------------------------------------

    def test_p2_gap_1152_verify_roundtripped_v4_missing_determinism(self):
        # Probe-proven: a v4 case read from disk has its schema equal by
        # value but not identical to the constant, so it must verify as v4.
        bundle = _matching_bundle()
        case = seal_case_file(bundle, deterministic=True, fixed_timestamp="2026-01-01T00:00:00Z")
        observed = [
            item
            for item in case["detector_observations"]
            if isinstance(item, dict) and item.get("kind") == "observed"
        ]
        for item in observed:
            item.pop("determinism", None)
            item.pop("determinism_reason", None)
        reloaded = json.loads(json.dumps(case))
        self.assertEqual(reloaded["schema"], CASE_SCHEMA_V4)
        self.assertIsNot(reloaded["schema"], CASE_SCHEMA_V4)
        self.assertIn(
            "v4_detector_observations_determinism_missing:textforensics/builtin-heuristic",
            verify_case_file(reloaded)["errors"],
        )
        control = seal_case_file(
            _matching_bundle(), deterministic=True, fixed_timestamp="2026-01-01T00:00:00Z"
        )
        self.assertTrue(verify_case_file(json.loads(json.dumps(control)))["valid"])

    def test_p2_gap_1236_verify_case_sha256_65_chars_invalid(self):
        case = self._sealed()
        case["case_sha256"] = "a" * 65
        self.assertIn("missing_or_invalid_case_sha256", verify_case_file(case)["errors"])

    def test_p2_gap_1238_verify_tool_name_zulu_is_invalid(self):
        case = self._sealed()
        case["tool"]["name"] = "Zulu"
        self.assertIn("invalid_tool_identity", verify_case_file(case)["errors"])

    def test_p2_gap_1431_verify_raw_text_included_zero_is_violation(self):
        result = verify_case_file({"schema": CASE_SCHEMA, "raw_text_included": 0})
        self.assertIn("raw_text_policy_violation", result["errors"])

    def test_p2_gap_1777_verify_tampered_manifest_is_reported(self):
        case = self._sealed()
        case["manifest"]["content_sha256"] = "tampered-value"
        self.assertIn("manifest_mismatch:content_sha256", verify_case_file(case)["errors"])

    # -- seal_case_file gaps ------------------------------------------------

    def test_p2_gap_1234_seal_signing_seed_33_bytes_rejected(self):
        with self.assertRaisesRegex(ValueError, "signing_seed must be 32 bytes"):
            seal_case_file(
                self._bundle(),
                signing_seed=b"x" * 33,
                signer={"identity": "a", "role": "r"},
            )

    def test_p2_gap_1298_seal_signing_seed_16_bytes_rejected(self):
        with self.assertRaisesRegex(ValueError, "signing_seed must be 32 bytes"):
            seal_case_file(
                self._bundle(),
                signing_seed=b"x" * 16,
                signer={"identity": "a", "role": "r"},
            )

    def test_p2_gap_1969_seal_signing_seed_16_bytes_rejected_or_and(self):
        # Same distinguishing input as idx 1298 (the `or` -> `and` mutant
        # also lets a short bytes seed through to the signer).
        with self.assertRaisesRegex(ValueError, "signing_seed must be 32 bytes"):
            seal_case_file(
                self._bundle(),
                signing_seed=b"x" * 16,
                signer={"identity": "a", "role": "r"},
            )

    def test_p2_gap_1569_seal_valid_input_meta_mapping_accepted(self):
        case = seal_case_file(self._bundle(), input_meta={"acquired_by": "alice"})
        self.assertEqual(case["input"]["acquired_by"], "alice")

    def test_p2_gap_1747_seal_valid_input_meta_mapping_accepted_addnot(self):
        # Same distinguishing input as idx 1569 (the mutants coincide).
        case = seal_case_file(self._bundle(), input_meta={"acquired_by": "alice"})
        self.assertEqual(case["input"]["acquired_by"], "alice")

    def test_p2_gap_1886_seal_digest_publication_non_string_channel_rejected(self):
        with self.assertRaises(ValueError):
            seal_case_file(
                self._bundle(),
                digest_publication={
                    "channel": 123,
                    "reference": "r",
                    "published_at_utc": "t",
                },
            )

    def test_p2_gap_1953_seal_process_items_carried(self):
        case = seal_case_file(
            self._bundle(),
            process={"items": {"D1": {"status": "satisfied", "evidence": ["e1"]}}},
        )
        self.assertEqual(case["process"]["items"]["D1"]["status"], "satisfied")

    def test_p2_gap_1956_seal_process_reviewer_carried(self):
        reviewer = {
            "identity": "rev",
            "role": "reviewer",
            "reasoning": "r",
            "agreed_with_tool": True,
        }
        case = seal_case_file(self._bundle(), process={"reviewer": reviewer})
        self.assertEqual(case["process"]["reviewer"]["identity"], "rev")

    def test_p2_gap_1957_seal_process_appeal_carried(self):
        appeal = {"decider": "alice", "appeal_decider": "bob", "route": "r", "deadline": "d"}
        case = seal_case_file(self._bundle(), process={"appeal": appeal})
        self.assertEqual(case["process"]["appeal"]["decider"], "alice")

    def test_p2_gap_1958_seal_process_retention_carried(self):
        retention = {
            "period": "p",
            "legal_basis": "l",
            "access": "a",
            "disposal": "d",
            "expungement": "e",
        }
        case = seal_case_file(self._bundle(), process={"retention": retention})
        self.assertEqual(case["process"]["retention"]["period"], "p")

    def test_p2_gap_1959_seal_process_contrary_evidence_carried(self):
        case = seal_case_file(
            self._bundle(), process={"contrary_evidence": [{"detector_id": "d1"}]}
        )
        self.assertEqual(case["process"]["contrary_evidence"], [{"detector_id": "d1"}])

    def test_p2_gap_1960_seal_process_evidence_dispositions_carried(self):
        dispositions = {
            "textforensics/builtin-heuristic": {"disposition": "relied_on", "reason": "r"}
        }
        case = seal_case_file(self._bundle(), process={"evidence_dispositions": dispositions})
        self.assertEqual(
            case["process"]["evidence_dispositions"]["textforensics/builtin-heuristic"][
                "disposition"
            ],
            "relied_on",
        )

    def test_p2_gap_1961_seal_process_alternative_explanations_carried(self):
        explanations = {"short_text_limits": {"tested": "tested", "outcome": "ruled out"}}
        case = seal_case_file(self._bundle(), process={"alternative_explanations": explanations})
        self.assertEqual(
            case["process"]["alternative_explanations"]["short_text_limits"]["tested"],
            "tested",
        )

    def test_p2_gap_1962_seal_process_subject_response_carried(self):
        response = {"opportunity_given": True, "response_attached": True}
        case = seal_case_file(self._bundle(), process={"subject_response": response})
        self.assertIs(case["process"]["subject_response"]["opportunity_given"], True)

    # -- _compare_scores gap -------------------------------------------------

    def test_p2_gap_1978_compare_scores_bool_vs_number_is_not_numeric(self):
        self.assertFalse(self._cs(True, 0.5, atol=1.0))

    # -- build_limitations gaps ----------------------------------------------

    def test_p2_gap_1869_limitations_ci_lower_without_upper_uses_no_ci_text(self):
        refs = [
            {
                "records": [
                    {
                        "record_id": "r1",
                        "fpr_native": {"value": 0.05, "n": 100, "ci_lower": 0.01},
                    }
                ]
            }
        ]
        section = build_limitations({}, refs)
        self.assertIn("0.0500", section["plain_language"]["human_fpr"])
        self.assertNotIn("CI", section["plain_language"]["human_fpr"])

    def test_p2_gap_1991_limitations_first_fpr_record_wins(self):
        refs = [
            {
                "records": [
                    {"record_id": "r1", "fpr_native": {"value": 0.05, "n": 100}},
                    {"record_id": "r2", "fpr_native": {"value": 0.09, "n": 50}},
                ]
            }
        ]
        section = build_limitations({}, refs)
        self.assertIn("r1", section["plain_language"]["human_fpr"])
        self.assertNotIn("r2", section["plain_language"]["human_fpr"])

    def test_p2_gap_1992_limitations_first_ref_with_fpr_wins(self):
        refs = [
            {"records": [{"record_id": "r1", "fpr_native": {"value": 0.05, "n": 100}}]},
            {"records": [{"record_id": "r2", "fpr_native": {"value": 0.09, "n": 50}}]},
        ]
        section = build_limitations({}, refs)
        self.assertIn("r1", section["plain_language"]["human_fpr"])
        self.assertNotIn("r2", section["plain_language"]["human_fpr"])

    def test_p2_gap_2003_limitations_skips_record_without_fpr(self):
        refs = [
            {
                "records": [
                    {"record_id": "r0", "fpr_native": {"value": None}},
                    {"record_id": "r1", "fpr_native": {"value": 0.04, "n": 80}},
                ]
            }
        ]
        section = build_limitations({}, refs)
        self.assertIn("r1", section["plain_language"]["human_fpr"])

    # -- build_detector_observations / strip / calibration gaps -------------

    def test_p2_gap_1999_observations_skip_non_mapping_result_row(self):
        bundle = {
            "detector_results": [
                "not-a-dict",
                {"detector_id": "d1", "detector_version": "1.0", "score": 0.5},
            ],
            "detector_failures": [],
            "plugin_health": [],
        }
        observations = build_detector_observations(bundle)
        self.assertEqual(
            [o for o in observations if o["kind"] == "observed"][0]["detector_id"], "d1"
        )

    def test_p2_gap_2000_observations_skip_non_mapping_failure_row(self):
        bundle = {
            "detector_results": [],
            "detector_failures": ["not-a-dict", {"detector_id": "f1", "reason": "boom"}],
            "plugin_health": [],
        }
        observations = build_detector_observations(bundle)
        failed = [o for o in observations if o["kind"] == "failed"]
        self.assertEqual([o["detector_id"] for o in failed], ["f1"])

    def test_p2_gap_2001_observations_skip_non_mapping_health_row(self):
        bundle = {
            "detector_results": [],
            "detector_failures": [],
            "plugin_health": ["not-a-dict", {"detector_id": "p1"}],
        }
        observations = build_detector_observations(bundle)
        health = [o for o in observations if o["kind"] == "plugin_health"]
        self.assertEqual([o["detector_id"] for o in health], ["p1"])

    def test_p2_gap_1995_strip_runtime_ms_after_non_dict_robustness_row(self):
        bundle = {
            "detector_results": [],
            "detector_failures": [],
            "robustness": {"detectors": ["not-a-dict", {"failures": [{"runtime_ms": 2.0}]}]},
        }
        result = _strip_runtime_ms_from_bundle(bundle)
        self.assertEqual(result["robustness"]["detectors"][0], "not-a-dict")
        self.assertNotIn("runtime_ms", result["robustness"]["detectors"][1]["failures"][0])

    def test_p2_gap_1996_calibration_ids_after_non_mapping_row(self):
        bundle = {"detector_results": ["not-a-dict", {"calibration_id": "c1"}]}
        self.assertEqual(_calibration_ids(bundle), ["c1"])

    # -- write_case_file / replay_case_file gaps ------------------------------

    def test_p2_gap_2057_write_case_file_renders_two_space_indent(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "case.json"
            write_case_file(path, self._bundle())
            text = path.read_text(encoding="utf-8")
            self.assertTrue(
                text.startswith('{\n  "schema": "textforensics.case-file/v4",'), text[:80]
            )

    def test_p2_gap_2070_replay_without_text_is_reproduced(self):
        case = self._sealed()
        result = replay_case_file(case)
        self.assertEqual(result["replay_outcome"], "reproduced")

    def test_p2_gap_2071_replay_without_text_is_reproduced_negative(self):
        # Same distinguishing input as idx 2070 (initial count -1 is truthy).
        case = self._sealed()
        result = replay_case_file(case)
        self.assertEqual(result["replay_outcome"], "reproduced")

    # -- _replay_detectors second-failure gap ---------------------------------

    def test_p2_gap_2006_replay_second_detector_after_first_fails(self):
        row = self._sealed_row()
        second_row = dict(row)
        second_row["detector_id"] = "test/second"
        second_row["detector_version"] = "2.0.0"
        second_row["score"] = 0.1
        second_row["verdict"] = "ai_like"
        failing = _FakeReplayDetector("textforensics/builtin-heuristic", fail=True)
        matching = _FakeReplayDetector("test/second", version="2.0.0", score=0.1, verdict="ai_like")
        errors, _, checks = _replay_detectors(
            [row, second_row], [failing, matching], TEXT, atol=1e-9
        )
        self.assertEqual(errors, ["detector_failed:textforensics/builtin-heuristic"])
        self.assertEqual(checks["detectors"]["test/second"]["status"], "observed")

    # -- Probe-proven replay / trust-map gaps -------------------------------
    # Each test below replays the exact distinguishing input of the
    # expect-different differential probe in
    # ~/workspace/casefile-mut-tools/p2/probes/gap-<idx>.json.

    def test_p2_gap_1072_replay_failed_kind_row_does_not_declare(self):
        det = "textforensics/builtin-heuristic"
        bundle = _matching_bundle()
        row = bundle["detector_results"][0]
        row["determinism"] = "deterministic"
        bundle["detector_failures"] = [
            {
                "detector_id": det,
                "reason": "boom",
                "determinism": "non_deterministic",
                "determinism_reason": "flaky",
            }
        ]
        case = seal_case_file(
            copy.deepcopy(bundle), deterministic=True, fixed_timestamp="2026-01-01T00:00:00Z"
        )
        kinds = [o["kind"] for o in case["detector_observations"]]
        self.assertEqual(kinds[:2], ["observed", "failed"])
        fake = _FakeReplayDetector(
            det, version=row["detector_version"], score=row["score"] + 0.5, verdict=row["verdict"]
        )
        result = replay_case_file(case, text=_V3_TEXT, detectors=[fake])
        self.assertEqual(result["errors"], [f"score_mismatch:{det}"])
        self.assertEqual(result["replay_outcome"], "failed")
        fake_ok = _FakeReplayDetector(
            det, version=row["detector_version"], score=row["score"], verdict=row["verdict"]
        )
        result_ok = replay_case_file(case, text=_V3_TEXT, detectors=[fake_ok])
        self.assertEqual(result_ok["replay_outcome"], "reproduced")

    def test_p2_gap_1127_replay_tampered_trust_map_schema(self):
        registry, bundle, _, _ = self._v3_replay_inputs()
        case_ok = seal_case_file(
            copy.deepcopy(bundle), deterministic=True, fixed_timestamp="2026-01-01T00:00:00Z"
        )
        control = replay_case_file(case_ok, validation_registry=registry)
        self.assertEqual(control["replay_outcome"], "reproduced")
        deleted = copy.deepcopy(case_ok)
        del deleted["forensic_bundle"]["trust_map"]["schema"]
        result = replay_case_file(deleted, validation_registry=registry)
        self.assertEqual(
            result["errors"],
            ["case_hash_mismatch", "manifest_mismatch:schema_versions", "trust_map_state_mismatch"],
        )
        self.assertEqual(result["replay_outcome"], "failed")
        wrong_schema = copy.deepcopy(case_ok)
        wrong_schema["forensic_bundle"]["trust_map"]["schema"] = "textforensics.trust-map/v4"
        result2 = replay_case_file(wrong_schema, validation_registry=registry)
        # W2 (C23): a declared but unsupported map version is also
        # refused as a non-portable bundle by the primary verifier, in
        # addition to the hash/manifest/state errors above.
        self.assertEqual(
            result2["errors"],
            [
                "case_hash_mismatch",
                "invalid_or_nonportable_forensic_bundle",
                "manifest_mismatch:schema_versions",
                "trust_map_state_mismatch",
            ],
        )
        self.assertEqual(result2["replay_outcome"], "failed")

    def _p2_v3_replay_args(self):
        registry, bundle, conditions, predictions = self._v3_replay_inputs()
        robustness_rows = (bundle.get("robustness") or {}).get("detectors", [])
        failure_count = len(bundle.get("detector_failures", []))
        return registry, bundle, conditions, predictions, robustness_rows, failure_count

    def test_p2_gap_1309_trust_map_v3_overall_insufficient_vs_mixed(self):
        registry, bundle, conditions, predictions, rows, fc = self._p2_v3_replay_args()
        _, _, control = _replay_trust_map_v3(
            bundle, bundle["trust_map"], registry, conditions, predictions, rows, fc
        )
        self.assertEqual(control["trust_map"]["overall"], "mixed")
        tampered = copy.deepcopy(bundle["trust_map"])
        tampered["overall"] = "insufficient"
        errors, _, checks = _replay_trust_map_v3(
            bundle, tampered, registry, conditions, predictions, rows, fc
        )
        self.assertEqual(errors, ["trust_map_overall_mismatch"])
        self.assertEqual(checks["trust_map"]["status"], "mismatch")

    def test_p2_gap_1312_trust_map_v4_overall_insufficient_vs_mixed(self):
        _, bundle, conditions, predictions = self._v3_replay_inputs()
        row2 = copy.deepcopy(bundle["detector_results"][0])
        row2["detector_id"] = "other/detector"
        row2["detector_version"] = "2.0"
        row2["detector_family"] = "other-family"
        preds2 = predictions + [_prediction_from_dict(row2)]
        robustness_rows = (bundle.get("robustness") or {}).get("detectors", [])
        rederived = assess_trust_map(
            conditions,
            preds2,
            registry=None,
            robustness=robustness_rows,
            failure_count=0,
            generated_at_utc="",
        ).to_dict()
        self.assertEqual(rederived["overall"], "mixed")
        bundle2 = copy.deepcopy(bundle)
        bundle2["detector_results"].append(row2)
        bundle2["trust_map"] = {
            "schema": TRUST_SCHEMA,
            "overall": rederived["overall"],
            "dimensions": [
                {"dimension": dim["dimension"], "state": dim["state"]}
                for dim in rederived["dimensions"]
            ],
            "generated_at_utc": "",
        }
        errors, _, checks = _replay_trust_map(copy.deepcopy(bundle2), None)
        self.assertEqual(errors, [])
        self.assertEqual(checks["trust_map"]["status"], "rederived")
        bundle2["trust_map"]["overall"] = "insufficient"
        errors2, _, checks2 = _replay_trust_map(bundle2, None)
        self.assertEqual(errors2, ["trust_map_overall_mismatch"])
        self.assertEqual(checks2["trust_map"]["status"], "mismatch")

    def test_p2_gap_1391_trust_map_v3_overall_equal_by_value_not_identity(self):
        registry, bundle, conditions, predictions, rows, fc = self._p2_v3_replay_args()
        _, _, control = _replay_trust_map_v3(
            bundle, bundle["trust_map"], registry, conditions, predictions, rows, fc
        )
        rederived = control["trust_map"]["overall"]
        self.assertEqual(rederived, "mixed")
        fresh = "".join([rederived[: len(rederived) // 2], rederived[len(rederived) // 2 :]])
        self.assertEqual(fresh, rederived)
        self.assertIsNot(fresh, rederived)
        tampered = copy.deepcopy(bundle["trust_map"])
        tampered["overall"] = fresh
        errors, _, checks = _replay_trust_map_v3(
            bundle, tampered, registry, conditions, predictions, rows, fc
        )
        self.assertEqual(errors, [])
        self.assertEqual(checks["trust_map"]["status"], "rederived")

    def _p2_two_family_v3_bundle(self):
        registry, bundle, _, _ = self._v3_replay_inputs()
        row2 = copy.deepcopy(bundle["detector_results"][0])
        row2["detector_id"] = "other/detector"
        row2["detector_version"] = "2.0"
        row2["detector_family"] = "other-family"
        bundle["detector_results"].append(row2)
        return registry, bundle

    def test_p2_gap_1811_trust_map_two_failures_count_toward_diversity(self):
        registry, bundle = self._p2_two_family_v3_bundle()
        failed = copy.deepcopy(bundle)
        failed["detector_failures"] = [
            {"detector_id": "x", "reason": "r"},
            {"detector_id": "y", "reason": "r"},
        ]
        errors, _, checks = _replay_trust_map(failed, None, validation_registry=registry)
        self.assertEqual(errors, [])
        self.assertEqual(checks["trust_map"]["status"], "rederived")

    def test_p2_gap_2062_trust_map_non_list_failures_count_zero(self):
        registry, bundle = self._p2_two_family_v3_bundle()
        broken = copy.deepcopy(bundle)
        broken["detector_failures"] = {"a": 1}
        errors, _, checks = _replay_trust_map(broken, None, validation_registry=registry)
        self.assertEqual(errors, ["trust_map_state_mismatch"])
        self.assertEqual(checks["trust_map"]["status"], "mismatch")

    def test_p2_gap_2063_trust_map_non_list_failures_count_minus_one(self):
        # Same distinguishing input as idx 2062; the -1 mutant raises
        # from derive_trust_map instead of miscounting to 1.
        registry, bundle = self._p2_two_family_v3_bundle()
        broken = copy.deepcopy(bundle)
        broken["detector_failures"] = {"a": 1}
        errors, _, checks = _replay_trust_map(broken, None, validation_registry=registry)
        self.assertEqual(errors, ["trust_map_state_mismatch"])
        self.assertEqual(checks["trust_map"]["status"], "mismatch")

    def test_p2_gap_2007_trust_map_v3_missing_record_id_skipped(self):
        registry, bundle, conditions, predictions, rows, fc = self._p2_v3_replay_args()
        sealed = copy.deepcopy(bundle["trust_map"])

        def _record_ids(trust):
            found: set = set()
            for item in trust.get("dimensions", []):
                if isinstance(item, dict):
                    for ref in item.get("evidence_refs", []) or []:
                        if isinstance(ref, str):
                            found.add(ref)
            return found

        # Find a missing record id that the record-id set iterates
        # BEFORE every present id in this process (string hashing is
        # seed-dependent, so the fixture adapts; the search rebuilds
        # the exact set _replay_trust_map_v3 builds).
        missing = None
        for n in range(500):
            candidate = f"missing-record-{n}"
            tampered_probe = copy.deepcopy(sealed)
            for item in tampered_probe["dimensions"]:
                if isinstance(item, dict) and item.get("evidence_refs"):
                    item["evidence_refs"] = [candidate, *item["evidence_refs"]]
                    break
            if next(iter(_record_ids(tampered_probe))) == candidate:
                missing = candidate
                break
        self.assertIsNotNone(missing)
        tampered = copy.deepcopy(sealed)
        for item in tampered["dimensions"]:
            if isinstance(item, dict) and item.get("evidence_refs"):
                item["evidence_refs"] = [missing, *item["evidence_refs"]]
                break
        errors, _, checks = _replay_trust_map_v3(
            bundle, tampered, registry, conditions, predictions, rows, fc
        )
        self.assertEqual(errors, [])
        self.assertEqual(checks["trust_map"]["status"], "rederived")


# ---------------------------------------------------------------------------
# W1 follow-up mutation kills (audit-w1-worker-f)
#
# Each test kills the W1 new/changed-code mutants Worker E proved
# killable (audit-w1-e-stop-draft.py / audit-w1-e-probe-results.json,
# 148/148). Test IDs CF-01..CF-02 match the STOP draft.
# ---------------------------------------------------------------------------


class CasefileW1FollowUpMutationKillTests(unittest.TestCase):
    def test_verify_case_file_non_mapping_payload_is_invalid(self):
        # CF-01: 1 mutant (non-mapping payload 'valid': False -> True).
        result = verify_case_file(["not", "a", "mapping"])
        self.assertIs(result["valid"], False)
        self.assertEqual(result["errors"], ["case_must_be_a_mapping"])
        self.assertIsNone(result["schema"])

    def test_replay_trust_map_detectors_section_shape(self):
        # CF-02: 2 mutants (detectors_section is not None -> not).
        # Absent 'detectors' keeps its prior meaning: no robustness
        # evidence, no mismatch.
        without_detectors = {
            "input_conditions": {},
            "trust_map": {"schema": TRUST_SCHEMA_V3},
            "robustness": {},  # present, no 'detectors' key
        }
        errors, _, _ = _replay_trust_map(without_detectors, None)
        self.assertNotIn("trust_map_state_mismatch", errors)
        # A non-list 'detectors' section is a mismatch.
        detectors_as_dict = {
            "input_conditions": {},
            "trust_map": {"schema": TRUST_SCHEMA_V3},
            "robustness": {"detectors": {"d1": {"verdict_stability": 1.0}}},
        }
        errors2, _, checks2 = _replay_trust_map(detectors_as_dict, None)
        self.assertIn("trust_map_state_mismatch", errors2)
        self.assertEqual(checks2["trust_map"]["reason"], "robustness_detectors_not_a_list")


if __name__ == "__main__":
    unittest.main()
