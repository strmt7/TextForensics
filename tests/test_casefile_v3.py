"""Tests for the case-file v3 model (Phase 3 U2).

v4 is the default seal since the U2 not_reproducible follow-up (v3
plus per-observation determinism declarations); v3 keeps sealing and
verifying explicitly.  The D1-D10 appeal checklist lives in
``process``, custody is a hash chain in ``custody``, validation pointers
into the U1 registry live in ``validation_refs``, and an optional
Ed25519/DSSE signature lives in ``seal.signature`` (``None`` for a T1
hash-only seal).  v2 (explicit ``version="v2"``) and legacy v1 bundles
keep sealing and verifying as before.
"""

import copy
import hashlib
import importlib.util
import json
import unittest
from pathlib import Path

from textforensics.casefile import (
    CASE_SCHEMA_V3,
    CASE_SCHEMA_V4,
    append_custody_entry,
    build_checklist,
    replay_case_file,
    seal_case_file,
    validate_checklist,
    verify_case_file,
)
from textforensics.conditions import conditions_from_dict, length_band
from textforensics.report import build_forensic_bundle
from textforensics.schema import load_schema
from textforensics.trust import TrustDimension
from textforensics.validation import ValidationRegistry, _overall_state_v3, derive_trust_map
from textforensics.verify import verify_case_file as nversion_verify_case_file

TEXT = (
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
SEED = bytes(range(32))
SIGNER = {"identity": "strmt7", "role": "sealer"}
REPO_ROOT = Path(__file__).resolve().parent.parent


def load_real_registry() -> ValidationRegistry:
    payload = json.loads((REPO_ROOT / "docs" / "validation" / "registry.json").read_text())
    return ValidationRegistry.from_dict(payload, verify_id=True)


def matching_bundle() -> dict:
    """A bundle whose input conditions match real registry records.

    The real registry covers English, floor 80 words, domain "news",
    editing regime "raw" (RAID and OpAI-Bench records).
    """
    bundle = build_forensic_bundle(TEXT).to_dict()
    conditions = dict(bundle["input_conditions"])
    conditions["domain_genre"] = "news"
    conditions["domain_confidence"] = "high"
    conditions["editing_regime"] = "machine_only"
    conditions["word_count"] = 144
    conditions["char_count"] = len(TEXT)
    conditions["length_band"] = length_band(144)
    bundle["input_conditions"] = conditions
    return bundle


def v3_trust_map(bundle: dict, registry: ValidationRegistry) -> dict:
    from textforensics.casefile import _prediction_from_dict

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
        # Replay re-derives with the bundle's own robustness rows and
        # failure count, so the seal-time derivation must use the same.
        robustness=(bundle.get("robustness") or {}).get("detectors", []),
        failure_count=len(bundle.get("detector_failures", [])),
    ).to_dict()


class CaseFileV3SealTests(unittest.TestCase):
    def test_v4_is_default_and_sections_present(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle)
        self.assertEqual(case["schema"], CASE_SCHEMA_V4)
        for section in (
            "input",
            "detector_observations",
            "validation_refs",
            "limitations",
            "process",
            "custody",
            "seal",
            "gaps",
        ):
            self.assertIn(section, case)
        self.assertEqual(case["seal"]["algorithm"], "sha256")
        # T1 hash-only seal: no signature object at all.
        self.assertIsNone(case["seal"]["signature"])
        self.assertTrue(verify_case_file(case)["valid"])
        self.assertNotIn(TEXT, json.dumps(case))

    def test_v3_seal_explicit_still_works(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle, version="v3")
        self.assertEqual(case["schema"], CASE_SCHEMA_V3)
        self.assertTrue(verify_case_file(case)["valid"])

    def test_v3_gaps_cover_unrecorded_counts(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle)
        gap_fields = {gap["field"] for gap in case["gaps"]}
        self.assertIn("input.sentence_count", gap_fields)
        self.assertIn("input.paragraph_count", gap_fields)

    def test_v3_checklist_defaults_all_unknown(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle)
        process = case["process"]
        self.assertEqual(len(process["items"]), 10)
        self.assertTrue(all(item["status"] == "unknown" for item in process["items"].values()))
        self.assertIn("Template, not legal advice", process["template_notice"])

    def test_v2_seal_explicit_still_works(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle, version="v2")
        self.assertEqual(case["schema"], "textforensics.case-file/v2")
        self.assertTrue(verify_case_file(case)["valid"])

    def test_v1_legacy_bundle_seals_v1(self):
        bundle = {
            "schema": "textforensics.forensic-bundle/v1",
            "content_sha256": "a" * 64,
            "input": {"raw_text_included": False},
        }
        case = seal_case_file(bundle, version="v1")
        self.assertEqual(case["schema"], "textforensics.case-file/v1")
        self.assertTrue(verify_case_file(case)["valid"])

    def test_v3_deterministic_seal_is_reproducible(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        first = seal_case_file(bundle, deterministic=True)["case_sha256"]
        second = seal_case_file(bundle, deterministic=True)["case_sha256"]
        self.assertEqual(first, second)

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_v3_case_validates_against_packaged_schema(self):
        import jsonschema

        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle)
        jsonschema.validate(case, load_schema("case-file"))

    def test_tamper_in_process_is_detected(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle)
        case["process"]["items"]["D1"]["status"] = "satisfied"
        result = verify_case_file(case)
        self.assertFalse(result["valid"])
        self.assertIn("case_hash_mismatch", result["errors"])

    def test_tamper_in_custody_is_detected(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle)
        case["custody"][0]["action"] = "forged"
        result = verify_case_file(case)
        self.assertFalse(result["valid"])
        self.assertIn("case_hash_mismatch", result["errors"])

    def test_tamper_in_input_hash_is_detected(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle)
        case["input"]["content_sha256"] = "0" * 64
        result = verify_case_file(case)
        self.assertFalse(result["valid"])
        self.assertIn("v3_input_content_sha256_mismatch", result["errors"])

    def test_custody_chain_appends_and_verifies(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle)
        updated = append_custody_entry(
            case, actor="reviewer", action="reviewed", note="Second look."
        )
        self.assertEqual(len(updated["custody"]), 2)
        self.assertEqual(
            updated["seal"]["custody_head"],
            updated["custody"][-1]["entry_hash"],
        )
        self.assertTrue(verify_case_file(updated)["valid"])

    def test_broken_custody_link_is_detected(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle)
        updated = append_custody_entry(case, actor="reviewer", action="reviewed")
        updated["custody"][1]["prev_hash"] = "1" * 64
        result = verify_case_file(updated)
        self.assertFalse(result["valid"])
        self.assertTrue(any("custody_chain_broken" in error for error in result["errors"]))


class ChecklistTests(unittest.TestCase):
    def test_build_checklist_defaults(self):
        process = build_checklist()
        self.assertEqual(len(process["items"]), 10)
        self.assertTrue(all(item["status"] == "unknown" for item in process["items"].values()))
        self.assertIn("Template, not legal advice", process["template_notice"])

    def test_validate_checklist_rejects_bad_disposition(self):
        process = build_checklist()
        process["evidence_dispositions"]["textforensics/builtin-heuristic"] = {
            "disposition": "ignored",
            "reason": "not a valid disposition",
        }
        errors = validate_checklist(process)
        self.assertIn("checklist_disposition_invalid:textforensics/builtin-heuristic", errors)

    def test_build_checklist_rejects_bad_disposition(self):
        with self.assertRaises(ValueError):
            build_checklist(
                evidence_dispositions={
                    "textforensics/builtin-heuristic": {"disposition": "ignored"}
                }
            )

    def test_d1_satisfied_without_dispositions_is_unsupported(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle, process={"items": {"D1": {"status": "satisfied"}}})
        result = verify_case_file(case)
        self.assertFalse(result["valid"])
        self.assertTrue(any("checklist_d1_unsupported" in error for error in result["errors"]))

    def test_d1_satisfied_with_dispositions_verifies(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(
            bundle,
            process={
                "items": {"D1": {"status": "satisfied"}},
                "evidence_dispositions": {
                    "textforensics/builtin-heuristic": {
                        "disposition": "considered",
                        "reason": "Single detector, abstained; noted, not relied on.",
                    }
                },
            },
        )
        result = verify_case_file(case)
        self.assertTrue(result["valid"], result["errors"])

    def test_d4_satisfied_without_reviewer_is_unsupported(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle, process={"items": {"D4": {"status": "satisfied"}}})
        result = verify_case_file(case)
        self.assertFalse(result["valid"])
        self.assertTrue(any("checklist_d4_unsupported" in error for error in result["errors"]))

    def test_d5_same_decider_is_unsupported(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(
            bundle,
            process={
                "items": {"D5": {"status": "satisfied"}},
                "appeal": {
                    "decider": "same-person",
                    "appeal_decider": "same-person",
                    "route": "written appeal",
                    "deadline": "2026-12-01",
                },
            },
        )
        result = verify_case_file(case)
        self.assertFalse(result["valid"])
        self.assertTrue(
            any(
                "checklist_d5_unsupported:same_decider_for_appeal" in error
                for error in result["errors"]
            )
        )


class ValidationRefsTests(unittest.TestCase):
    def test_refs_match_real_registry_records(self):
        registry = load_real_registry()
        bundle = matching_bundle()
        case = seal_case_file(bundle, validation_registry=registry)
        refs = case["validation_refs"]
        self.assertTrue(refs, "expected at least one matching record")
        record_ids = {record["record_id"] for ref in refs for record in ref["records"]}
        self.assertIn("evr-20261106-raid-builtin-heuristic", record_ids)
        self.assertIn("evr-20261106-opai-bench-builtin-heuristic", record_ids)
        for ref in refs:
            self.assertEqual(ref["registry_sha256"], registry.registry_id)
            self.assertEqual(ref["registry_id"], registry.registry_id)
            for record in ref["records"]:
                self.assertIn(record["effective_status"], ("partial", "stale", "supported"))
        self.assertTrue(verify_case_file(case)["valid"])

    def test_no_registry_means_empty_refs_and_gap(self):
        bundle = matching_bundle()
        case = seal_case_file(bundle)
        self.assertEqual(case["validation_refs"], [])
        gap_fields = {gap["field"] for gap in case["gaps"]}
        self.assertIn("validation_refs", gap_fields)

    def test_limitations_name_matching_fpr_evidence(self):
        registry = load_real_registry()
        bundle = matching_bundle()
        case = seal_case_file(bundle, validation_registry=registry)
        text = case["limitations"]["plain_language"]["human_fpr"]
        # The nearest matching record is the first one in registry order
        # carrying an FPR (OpAI-Bench precedes RAID in the registry).
        self.assertIn("evr-20261106-opai-bench-builtin-heuristic", text)
        self.assertIn("0.0000", text)

    def test_limitations_without_registry_state_unknown_fpr(self):
        bundle = matching_bundle()
        case = seal_case_file(bundle)
        self.assertIn(
            "unknown",
            case["limitations"]["plain_language"]["human_fpr"].lower(),
        )


class SignatureTests(unittest.TestCase):
    def test_signed_case_verifies_with_public_key(self):
        from textforensics.sealing import public_key_from_seed

        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle, signing_seed=SEED, signer=SIGNER)
        signature = case["seal"]["signature"]
        self.assertEqual(signature["algorithm"], "ed25519")
        self.assertEqual(signature["signer"], SIGNER)
        self.assertEqual(len(signature["key_fingerprint"]), 64)
        public_key = public_key_from_seed(SEED)
        result = verify_case_file(case, public_key=public_key)
        self.assertTrue(result["valid"], result["errors"])
        self.assertNotIn("signature_absent_t1_hash_seal_only", result["warnings"])

    def test_signed_case_without_key_warns_but_passes(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle, signing_seed=SEED, signer=SIGNER)
        result = verify_case_file(case)
        self.assertTrue(result["valid"])
        self.assertTrue(
            any(
                warning.startswith("signature_present_public_key_not_supplied")
                for warning in result["warnings"]
            )
        )

    def test_t1_only_case_warns_hash_seal_only(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle)
        result = verify_case_file(case)
        self.assertTrue(result["valid"])
        self.assertTrue(
            any(
                warning.startswith("signature_absent_t1_hash_seal_only")
                for warning in result["warnings"]
            )
        )

    def test_tampered_signature_is_detected(self):
        from textforensics.sealing import public_key_from_seed

        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle, signing_seed=SEED, signer=SIGNER)
        sig = case["seal"]["signature"]["dsse"]["signatures"][0]["sig"]
        case["seal"]["signature"]["dsse"]["signatures"][0]["sig"] = (
            "A" if sig[0] != "A" else "B"
        ) + sig[1:]
        result = verify_case_file(case, public_key=public_key_from_seed(SEED))
        self.assertFalse(result["valid"])
        self.assertTrue(any(error.startswith("signature_invalid:") for error in result["errors"]))

    def test_wrong_public_key_rejects_signature(self):
        from textforensics.sealing import public_key_from_seed

        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle, signing_seed=SEED, signer=SIGNER)
        other_key = public_key_from_seed(bytes([1]) * 32)
        result = verify_case_file(case, public_key=other_key)
        self.assertFalse(result["valid"])
        self.assertTrue(any(error.startswith("signature_invalid:") for error in result["errors"]))

    def test_seed_without_signer_is_rejected(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        with self.assertRaises(ValueError):
            seal_case_file(bundle, signing_seed=SEED)


class V3ReplayTests(unittest.TestCase):
    def test_v3_trust_map_rederives_with_registry(self):
        registry = load_real_registry()
        bundle = matching_bundle()
        bundle["trust_map"] = v3_trust_map(bundle, registry)
        case = seal_case_file(bundle, validation_registry=registry)
        result = replay_case_file(case, validation_registry=registry)
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["checks"]["trust_map"]["trust_map"]["status"], "rederived")

    def test_v3_trust_map_without_registry_is_not_rederived(self):
        registry = load_real_registry()
        bundle = matching_bundle()
        bundle["trust_map"] = v3_trust_map(bundle, registry)
        case = seal_case_file(bundle, validation_registry=registry)
        result = replay_case_file(case)
        self.assertTrue(result["valid"])
        self.assertEqual(result["checks"]["trust_map"]["trust_map"]["status"], "not_rederived")
        self.assertIn(
            "validation_registry_not_supplied:trust_map_not_rederived",
            result["warnings"],
        )

    def test_v3_trust_map_mismatch_is_detected(self):
        registry = load_real_registry()
        bundle = matching_bundle()
        bundle["trust_map"] = v3_trust_map(bundle, registry)
        case = seal_case_file(bundle, validation_registry=registry)
        tampered = copy.deepcopy(case)
        dims = tampered["forensic_bundle"]["trust_map"]["dimensions"]
        dims[0]["state"] = "supported" if dims[0]["state"] != "supported" else "unknown"
        result = replay_case_file(tampered, validation_registry=registry)
        self.assertFalse(result["valid"])
        self.assertIn("trust_map_state_mismatch", result["errors"])


class VerifyV3Tests(unittest.TestCase):
    def test_nversion_verifier_accepts_v3_case_with_v3_map(self):
        registry = load_real_registry()
        bundle = matching_bundle()
        bundle["trust_map"] = v3_trust_map(bundle, registry)
        case = seal_case_file(bundle, validation_registry=registry)
        result = nversion_verify_case_file(case)
        self.assertTrue(result["valid"], result["errors"])
        self.assertTrue(result["trust_map_verified"])

    def test_nversion_verifier_accepts_stale_v3_dimension(self):
        registry = load_real_registry()
        bundle = matching_bundle()
        trust_map = v3_trust_map(bundle, registry)
        trust_map["dimensions"][0]["state"] = "stale"
        trust_map["dimensions"][0]["reason"] = "Record is stale: revalidation due."
        dims = [
            TrustDimension(d["dimension"], d["state"], d["reason"]) for d in trust_map["dimensions"]
        ]
        trust_map["overall"] = _overall_state_v3(dims)
        # W2 (C10): coverage must stay consistent with the dimensions
        # after the flip, or the map is incomplete.
        from textforensics.trust import TRUST_STATES_V3, _coverage_counts

        trust_map["coverage"] = _coverage_counts(dims, TRUST_STATES_V3)
        bundle["trust_map"] = trust_map
        case = seal_case_file(bundle, validation_registry=registry)
        result = nversion_verify_case_file(case)
        self.assertTrue(result["valid"], result["errors"])
        self.assertTrue(result["trust_map_verified"])

    def test_nversion_verifier_rejects_stale_in_v2_map(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        bundle["trust_map"]["dimensions"][0]["state"] = "stale"
        case = seal_case_file(bundle, version="v2")
        result = nversion_verify_case_file(case)
        self.assertFalse(result["valid"])
        self.assertTrue(any("invalid state 'stale'" in error for error in result["errors"]))

    def test_nversion_verifier_detects_v3_overall_mismatch(self):
        registry = load_real_registry()
        bundle = matching_bundle()
        bundle["trust_map"] = v3_trust_map(bundle, registry)
        bundle["trust_map"]["overall"] = "strong"
        case = seal_case_file(bundle, validation_registry=registry)
        result = nversion_verify_case_file(case)
        self.assertFalse(result["valid"])
        self.assertTrue(any("overall mismatch" in error for error in result["errors"]))


class TrustMapCompletenessReplayTests(unittest.TestCase):
    """C10: replay must reject an incomplete v3 map even when no
    validation registry is supplied (re-derivation is unavailable)."""

    def _reseal(self, case):
        resealed = copy.deepcopy(case)
        stripped = copy.deepcopy(resealed)
        stripped.pop("case_sha256", None)
        stripped.pop("created_at_utc", None)
        canonical = json.dumps(
            stripped, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        resealed["case_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return resealed

    def _genuine_v3_case(self):
        registry = load_real_registry()
        bundle = matching_bundle()
        bundle["trust_map"] = v3_trust_map(bundle, registry)
        return seal_case_file(bundle, validation_registry=registry)

    def test_replay_rejects_one_dimension_map_without_registry(self):
        case = self._genuine_v3_case()
        tampered = copy.deepcopy(case)
        trust_map = tampered["forensic_bundle"]["trust_map"]
        trust_map["dimensions"] = [
            {"dimension": "not-a-declared-dimension", "state": "supported", "reason": "synthetic"}
        ]
        trust_map["overall"] = "strong"
        trust_map["coverage"] = {
            "supported": 1,
            "partial": 0,
            "unknown": 0,
            "out_of_scope": 0,
            "stale": 0,
        }
        tampered = self._reseal(tampered)
        result = replay_case_file(tampered)
        self.assertFalse(result["valid"])
        self.assertTrue(any("dimension" in error for error in result["errors"]), result["errors"])

    def test_replay_rejects_subset_map_without_registry(self):
        from textforensics.trust import TRUST_DIMENSIONS

        case = self._genuine_v3_case()
        tampered = copy.deepcopy(case)
        trust_map = tampered["forensic_bundle"]["trust_map"]
        trust_map["dimensions"] = [
            {"dimension": name, "state": "supported", "reason": "synthetic"}
            for name in TRUST_DIMENSIONS[:9]
        ]
        trust_map["overall"] = "strong"
        trust_map["coverage"] = {
            "supported": 9,
            "partial": 0,
            "unknown": 0,
            "out_of_scope": 0,
            "stale": 0,
        }
        tampered = self._reseal(tampered)
        result = replay_case_file(tampered)
        self.assertFalse(result["valid"])

    def test_replay_accepts_complete_v3_map_without_registry(self):
        # Control: the genuine complete map still replays as
        # not-rederived (no registry) but valid.
        case = self._genuine_v3_case()
        result = replay_case_file(case)
        self.assertTrue(result["valid"], result["errors"])


class BundleTrustMapPairTests(unittest.TestCase):
    """C23: the sealer and the primary verifier enforce the accepted
    bundle/map version pairs."""

    def test_seal_rejects_v1_map_in_v2_bundle(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        bundle["trust_map"] = dict(bundle["trust_map"])
        bundle["trust_map"]["schema"] = "textforensics.trust-map/v1"
        with self.assertRaises(ValueError):
            seal_case_file(bundle)

    def test_primary_verify_rejects_v3_map_in_v1_bundle(self):
        registry = load_real_registry()
        bundle = matching_bundle()
        bundle["trust_map"] = v3_trust_map(bundle, registry)
        case = seal_case_file(bundle, validation_registry=registry)
        tampered = copy.deepcopy(case)
        tampered["forensic_bundle"]["schema"] = "textforensics.forensic-bundle/v1"
        tampered["manifest"]["schema_versions"]["forensic_bundle"] = (
            "textforensics.forensic-bundle/v1"
        )
        resealed = copy.deepcopy(tampered)
        stripped = copy.deepcopy(resealed)
        stripped.pop("case_sha256", None)
        stripped.pop("created_at_utc", None)
        canonical = json.dumps(
            stripped, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        resealed["case_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        result = verify_case_file(resealed)
        self.assertFalse(result["valid"])
        self.assertTrue(
            any("forensic_bundle" in error or "trust_map" in error for error in result["errors"]),
            result["errors"],
        )


if __name__ == "__main__":
    unittest.main()
