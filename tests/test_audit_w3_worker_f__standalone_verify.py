"""W3 Worker F3 kill tests for the _standalone_verify module (audit-w3-f).

Covers the killable runtime/module-level survivors of the 305
_standalone_verify survivors (0 annotation — the module does not use
`from __future__ import annotations`; the domain-equivalent /
unobservable entries are baseline entries, see audit-w3-worker-f.md
§6). Each test targets a specific mutant; the re-proof
(audit-w3-f3-reprove-standalone.py) hand-applies each mutant with
cosmic-ray mutate_code and runs the owning test class.

The module is loaded directly from its file (load_standalone) so the
tests exercise the standalone copy, not the package import.
"""

import hashlib
import io
import json
import struct
import unittest
import zipfile
from pathlib import Path

from _token_fixture import build_token_for_digest
from test_standalone_verify import (
    _set_archive_comment,
    build_bundle,
    build_case_bytes,
    make_manifest,
    pack_bundle,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
STANDALONE_PATH = REPO_ROOT / "src" / "textforensics" / "_standalone_verify.py"


def load_standalone():
    import importlib.util

    spec = importlib.util.spec_from_file_location("standalone_verify", STANDALONE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def canonical_json(payload):
    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _chain(depth: int) -> dict:
    """A chain of `depth` nested dicts (max depth depth + 1)."""
    value: dict = {}
    for _ in range(depth):
        value = {"a": value}
    return value


def _list_chain(depth: int) -> list:
    """A chain of `depth` nested lists (max depth depth + 1).

    The list branch of _json_depth_exceeded (line 383) is only
    exercised by a deep LIST chain; the dict tests above never reach
    it (gap found by the re-prove: the 11 Add_* mutants at [383,39]
    occ 2 all survived until these tests were added).
    """
    value: list = []
    for _ in range(depth):
        value = [value]
    return value


class TestJsonDepthExceededKill(unittest.TestCase):
    """_json_depth_exceeded: 21 Add-family + 3 Gt + 2 AddNot +
    ReplaceTrueWithFalse [379,19] + 5 NumberReplacer + module-level
    NumberReplacer [363,17] occ 56/57 (MAX_JSON_DEPTH 100->99/101).
    Same boundary pair as verify.py: root is depth 1, a chain of k
    nested dicts has max depth k+1."""

    def test_99_deep_is_not_exceeded(self):
        m = load_standalone()
        # Max depth exactly 100. Kills: Gt_Eq/Gt_GtE/Gt_Is [378,17];
        # NumberReplacer [375,21] occ 59 (stack init 1->2);
        # NumberReplacer [381,41]/[383,41] occ 61/63 (+1->+2);
        # Add_LShift [381,39]/[383,39] (depth doubles per level);
        # module-level NumberReplacer [363,17] occ 56 (100->99).
        self.assertIs(m._json_depth_exceeded(_chain(99)), False)

    def test_100_deep_is_exceeded(self):
        m = load_standalone()
        # Max depth 101. Kills: the `+`->`-`/`*`/`/`/`//`/`%`/`**`/
        # `|`/`&`/`^` family at [381,39]/[383,39]; Add_Pow [381,39]
        # occ 1 / [383,39] occ 2 (`** 1` is the identity); AddNot
        # [376,10] (`while not stack:` never runs);
        # ReplaceTrueWithFalse [379,19]; NumberReplacer [375,21]
        # occ 58 (stack init 1->0); NumberReplacer [381,41]/[383,41]
        # occ 60/62 (+1->+0); module-level NumberReplacer [363,17]
        # occ 57 (100->101).
        self.assertIs(m._json_depth_exceeded(_chain(100)), True)

    def test_50_deep_is_not_exceeded(self):
        m = load_standalone()
        # Max depth 51. Kills the +1->+2 NumberReplacers
        # ([381,41]/[383,41] occ 61/63: mutant max depth 102).
        self.assertIs(m._json_depth_exceeded(_chain(50)), False)

    def test_60_deep_is_not_exceeded(self):
        m = load_standalone()
        # Max depth 61. Kills Add_LShift [383,39] (depth doubles per
        # level, so a 60-deep chain already exceeds the cap).
        self.assertIs(m._json_depth_exceeded(_chain(60)), False)

    def test_list_payload_does_not_raise(self):
        m = load_standalone()
        # Pins the list branch (the `elif isinstance(current, list)`
        # path at [383,39]): a list payload nests to depth 2 and
        # returns False.
        self.assertIs(m._json_depth_exceeded({"a": [1, 2]}), False)

    def test_99_deep_list_is_not_exceeded(self):
        m = load_standalone()
        # Max depth exactly 100 via the LIST branch. Kills Add_LShift
        # [383,39] occ 2 (depth doubles per level, so a 99-deep list
        # chain already exceeds the cap).
        self.assertIs(m._json_depth_exceeded(_list_chain(99)), False)

    def test_100_deep_list_is_exceeded(self):
        m = load_standalone()
        # Max depth 101 via the LIST branch. Kills the `+`->`-`/`*`/
        # `/`/`//`/`%`/`**`/`|`/`&`/`^` family at [383,39] occ 2
        # (depth never grows, so the chain is not exceeded) and the
        # NumberReplacer [383,41] occ 63 (+1->+2, max depth 102).
        self.assertIs(m._json_depth_exceeded(_list_chain(100)), True)


class TestValidateGeneralizedTimeKill(unittest.TestCase):
    """_validate_generalized_time: NumberReplacer [758,27] occ 237
    (group 7), [759,32] occ 238 (fraction[1:]), [759,49] occ 241
    ([:6]), [759,70] occ 242 (else 0)."""

    def test_fraction_half_second(self):
        m = load_standalone()
        # Kills [758,27] (group 7 -> 6: the seconds "00" become the
        # fraction, so microsecond 0), [759,32] (fraction[1:] -> [0:]
        # raises ValueError on ".5"; -> [2:] drops the digit, so
        # microsecond 0), [759,49] ([:6] -> [:5] gives 50000, ->
        # [:7] gives 5000000 which datetime rejects).
        iso, error = m._validate_generalized_time("20261107120000.5Z")
        self.assertIsNone(error)
        self.assertEqual(iso, "2026-11-07T12:00:00.500000+00:00")

    def test_no_fraction_is_whole_second(self):
        m = load_standalone()
        # Kills [759,70] (else 0 -> 1/-1: the ISO string gains a
        # fractional part).
        iso, error = m._validate_generalized_time("20261107120000Z")
        self.assertIsNone(error)
        self.assertEqual(iso, "2026-11-07T12:00:00+00:00")


class TestDetectorSanityKill(unittest.TestCase):
    """_detector_sanity_errors: ReplaceContinueWithBreak [1653,12];
    AddNot [1657,11]; IsNot_Is [1657,17]; OrWithAnd [1658,39]."""

    def _result(self, **overrides):
        r = {
            "schema": "textforensics.detector-result/v2",
            "detector_id": "d1",
            "score": 0.5,
            "verdict": "ai_like",
        }
        r.update(overrides)
        return r

    def test_non_dict_entry_then_bad_schema(self):
        m = load_standalone()
        # [1653,12] ReplaceContinueWithBreak: the non-dict entry is
        # skipped (error appended) and the next entry is still
        # checked. The mutant breaks after the non-dict entry, so
        # the schema error is missing.
        errors = m._detector_sanity_errors(
            {"detector_results": ["not-a-dict", self._result(schema="bogus")]}
        )
        self.assertIn("detector result 0 is not an object", errors)
        self.assertIn("detector d1 has wrong schema", errors)

    def test_wrong_schema_is_error(self):
        m = load_standalone()
        # AddNot [1657,11] + IsNot_Is [1657,17]: a wrong schema must
        # be reported. The AddNot mutant inverts the membership test;
        # the IsNot_Is mutant changes `not in` so a wrong schema is
        # no longer reported.
        errors = m._detector_sanity_errors(
            {"detector_results": [self._result(schema="bogus")]}
        )
        self.assertIn("detector d1 has wrong schema", errors)

    def test_right_schema_is_not_error(self):
        m = load_standalone()
        # AddNot [1657,11], other direction: a right schema must not
        # be reported. The mutant reports it.
        errors = m._detector_sanity_errors(
            {"detector_results": [self._result()]}
        )
        self.assertEqual(errors, [])

    def test_bool_score_is_error(self):
        m = load_standalone()
        # [1658,39] OrWithAnd (first side): a bool score is the
        # wrong type but numeric (side 1 True, side 2 False).
        errors = m._detector_sanity_errors(
            {"detector_results": [self._result(score=True)]}
        )
        self.assertIn("detector d1 score is not numeric", errors)

    def test_str_score_is_error(self):
        m = load_standalone()
        # [1658,39] OrWithAnd (second side): a str score is not a
        # bool but not numeric either (side 1 False, side 2 True).
        errors = m._detector_sanity_errors(
            {"detector_results": [self._result(score="high")]}
        )
        self.assertIn("detector d1 score is not numeric", errors)


class TestChecklistStructureKill(unittest.TestCase):
    """_checklist_structure_errors: 18 mutants (see §6)."""

    def _case(self, process):
        return {"process": process}

    def _valid_process(self):
        notice = load_standalone()._CHECKLIST_TEMPLATE_NOTICE
        items = {f"D{i}": {"status": "satisfied"} for i in range(1, 11)}
        return {"template_notice": notice, "items": items}

    def test_lesser_template_notice_is_error(self):
        m = load_standalone()
        # [1548,38] NotEq_Gt: a notice lexicographically LESS than
        # the template ("A") makes `!=` True but `>` False.
        process = self._valid_process()
        process["template_notice"] = "A"
        errors = m._checklist_structure_errors(self._case(process))
        self.assertIn("checklist_template_notice_missing_or_altered", errors)

    def test_non_dict_item_then_bad_status(self):
        m = load_standalone()
        # [1557,12] ReplaceContinueWithBreak: a non-dict D1 record
        # is skipped and D2 is still checked.
        process = self._valid_process()
        process["items"]["D1"] = "not-a-dict"
        process["items"]["D2"] = {"status": "bogus"}
        errors = m._checklist_structure_errors(self._case(process))
        self.assertIn("checklist_d1_missing", errors)
        self.assertIn("checklist_d2_invalid_status", errors)

    def test_invalid_status_is_error(self):
        m = load_standalone()
        # AddNot [1561,11] + IsNot_Is [1561,20]: an invalid status
        # must be reported.
        process = self._valid_process()
        process["items"]["D1"] = {"status": "bogus"}
        errors = m._checklist_structure_errors(self._case(process))
        self.assertIn("checklist_d1_invalid_status", errors)

    def test_valid_status_is_not_error(self):
        m = load_standalone()
        # AddNot [1561,11], other direction.
        errors = m._checklist_structure_errors(self._case(self._valid_process()))
        self.assertEqual(errors, [])

    def test_non_list_evidence_is_error(self):
        m = load_standalone()
        # [1562,43] OrWithAnd (first side) + Delete_Not [1562,50]:
        # evidence that is not a list (a str) makes side 1 True and
        # side 2 False (chars are strs).
        process = self._valid_process()
        process["items"]["D1"] = {"status": "satisfied", "evidence": "not-a-list"}
        errors = m._checklist_structure_errors(self._case(process))
        self.assertIn("checklist_d1_invalid_evidence", errors)

    def test_list_with_non_str_evidence_is_error(self):
        m = load_standalone()
        # [1562,43] OrWithAnd (second side): a list containing a
        # non-str entry makes side 1 False and side 2 True.
        process = self._valid_process()
        process["items"]["D1"] = {"status": "satisfied", "evidence": [1]}
        errors = m._checklist_structure_errors(self._case(process))
        self.assertIn("checklist_d1_invalid_evidence", errors)

    def test_invalid_disposition_is_error(self):
        m = load_standalone()
        # OrWithAnd [1565,56] (second side) + AddNot [1566,7] +
        # Delete_Not [1569,16]: a dict disposition with an invalid
        # value must be reported.
        process = self._valid_process()
        process["evidence_dispositions"] = {"d1": {"disposition": "bogus"}}
        errors = m._checklist_structure_errors(self._case(process))
        self.assertIn("checklist_disposition_invalid:d1", errors)

    def test_non_dict_disposition_is_error(self):
        m = load_standalone()
        # OrWithAnd [1565,56] (first side) + AddNot [1568,15]: a
        # non-dict disposition makes side 1 True; the mutant `and`
        # evaluates .get on it and raises AttributeError.
        process = self._valid_process()
        process["evidence_dispositions"] = {"d1": "not-a-dict"}
        errors = m._checklist_structure_errors(self._case(process))
        self.assertIn("checklist_disposition_invalid:d1", errors)

    def test_dispositions_loop_runs(self):
        m = load_standalone()
        # ZeroIterationForLoop [1567,40]: the loop must process the
        # dispositions; skipping it drops the error.
        process = self._valid_process()
        process["evidence_dispositions"] = {"d1": {"disposition": "bogus"}}
        errors = m._checklist_structure_errors(self._case(process))
        self.assertTrue(errors)

    def test_unknown_explanation_is_error(self):
        m = load_standalone()
        # AddNot [1576,15] + ZeroIterationForLoop [1575,27]: an
        # unknown alternative-explanation name must be reported.
        process = self._valid_process()
        process["alternative_explanations"] = {"bogus_name": {"tested": "tested"}}
        errors = m._checklist_structure_errors(self._case(process))
        self.assertIn("checklist_alternative_explanation_unknown:bogus_name", errors)

    def test_invalid_tested_value_is_error(self):
        m = load_standalone()
        # OrWithAnd [1570,16]/[1573,59]/[1578,45] + AddNot [1574,7]
        # + Delete_Not [1578,17]: a known name with an invalid
        # "tested" value must be reported.
        process = self._valid_process()
        process["alternative_explanations"] = {
            "short_text_limits": {"tested": "bogus"}
        }
        errors = m._checklist_structure_errors(self._case(process))
        self.assertIn(
            "checklist_alternative_explanation_invalid:short_text_limits", errors
        )

    def test_non_dict_explanation_is_error(self):
        m = load_standalone()
        # OrWithAnd [1570,16] (first side): a non-dict entry makes
        # side 1 True; the mutant `and` evaluates .get on it.
        process = self._valid_process()
        process["alternative_explanations"] = {"short_text_limits": "not-a-dict"}
        errors = m._checklist_structure_errors(self._case(process))
        self.assertIn(
            "checklist_alternative_explanation_invalid:short_text_limits", errors
        )


class TestPreviousSignaturesKill(unittest.TestCase):
    """_previous_signatures_errors: 11 mutants (see §6)."""

    def _entry(self, **overrides):
        e = {
            "algorithm": "ed25519",
            "key_fingerprint": "a" * 64,
            "signer": {"identity": "alice", "role": "signer"},
            "dsse": {},
            "superseded_reason": "re-signed-after-custody-append",
            "superseded_at_utc": "2026-11-07T06:00:00+00:00",
        }
        e.update(overrides)
        return e

    def _seal(self, entries):
        return {"previous_signatures": entries}

    def test_non_dict_entry_then_missing_field(self):
        m = load_standalone()
        # [1227,12] ReplaceContinueWithBreak: a non-dict entry is
        # skipped and the next entry is still checked.
        entry = self._entry()
        del entry["algorithm"]
        errors = m._previous_signatures_errors(self._seal(["not-a-dict", entry]))
        self.assertIn("previous_signatures[0] is not an object", errors)
        self.assertIn("previous_signatures[1] is missing algorithm", errors)

    def test_short_fingerprint_is_error(self):
        m = load_standalone()
        # [1243,32] NotEq_Gt: a 63-char fingerprint makes `!=` True
        # but `>` False.
        errors = m._previous_signatures_errors(
            self._seal([self._entry(key_fingerprint="a" * 63)])
        )
        self.assertIn("previous_signatures[0] key_fingerprint is not 64 hex", errors)

    def test_long_fingerprint_is_error(self):
        m = load_standalone()
        # [1243,32] NotEq_Lt: a 65-char fingerprint makes `!=` True
        # but `<` False.
        errors = m._previous_signatures_errors(
            self._seal([self._entry(key_fingerprint="a" * 65)])
        )
        self.assertIn("previous_signatures[0] key_fingerprint is not 64 hex", errors)

    def test_non_str_fingerprint_is_error(self):
        m = load_standalone()
        # [1243,12] OrWithAnd (first side): a non-str fingerprint
        # makes side 1 True; the mutant `and` calls len() on it.
        errors = m._previous_signatures_errors(
            self._seal([self._entry(key_fingerprint=123)])
        )
        self.assertIn("previous_signatures[0] key_fingerprint is not 64 hex", errors)

    def test_non_dict_signer_is_error(self):
        m = load_standalone()
        # [1250,12] OrWithAnd (first side): a non-dict signer makes
        # side 1 True; the mutant `and` calls .get on it.
        errors = m._previous_signatures_errors(
            self._seal([self._entry(signer="not-a-dict")])
        )
        self.assertIn("previous_signatures[0] signer is malformed", errors)

    def test_non_str_identity_is_error(self):
        m = load_standalone()
        # [1250,12] OrWithAnd (second side): a non-str identity
        # makes side 2 True (side 1 False).
        errors = m._previous_signatures_errors(
            self._seal([self._entry(signer={"identity": 123, "role": "r"})])
        )
        self.assertIn("previous_signatures[0] signer is malformed", errors)

    def test_missing_role_is_error(self):
        m = load_standalone()
        # [1253,12] OrWithAnd (last side): a signer with identity
        # but no role makes ONLY the last side True.
        errors = m._previous_signatures_errors(
            self._seal([self._entry(signer={"identity": "alice"})])
        )
        self.assertIn("previous_signatures[0] signer is malformed", errors)

    def test_non_dict_dsse_is_error(self):
        m = load_standalone()
        # AddNot [1256,11] + IsNot_Is [1256,29]: a non-dict dsse
        # must be reported.
        errors = m._previous_signatures_errors(
            self._seal([self._entry(dsse="not-a-dict")])
        )
        self.assertIn("previous_signatures[0] dsse is not an object", errors)

    def test_valid_superseded_at_is_not_error(self):
        m = load_standalone()
        # AddNot [1260,11]: a valid superseded_at_utc must not be
        # reported. The mutant negates the whole condition.
        errors = m._previous_signatures_errors(self._seal([self._entry()]))
        self.assertEqual(errors, [])

    def test_missing_superseded_at_is_not_error(self):
        m = load_standalone()
        # IsNot_Is [1260,42]: a missing superseded_at_utc must not
        # be reported. The mutant (`is None`) reports it.
        entry = self._entry()
        entry["superseded_at_utc"] = None
        errors = m._previous_signatures_errors(self._seal([entry]))
        self.assertEqual(errors, [])

    def test_non_str_superseded_at_is_error(self):
        m = load_standalone()
        # [1261,64] OrWithAnd (first side): a non-str
        # superseded_at_utc makes side 1 True (side 2 False, since
        # `not 5` is False).
        errors = m._previous_signatures_errors(
            self._seal([self._entry(superseded_at_utc=5)])
        )
        self.assertIn("previous_signatures[0] superseded_at_utc is malformed", errors)

    def test_empty_superseded_at_is_error(self):
        m = load_standalone()
        # [1261,64] OrWithAnd (second side): an empty str makes side
        # 1 False and side 2 True.
        errors = m._previous_signatures_errors(
            self._seal([self._entry(superseded_at_utc="")])
        )
        self.assertIn("previous_signatures[0] superseded_at_utc is malformed", errors)


class TestManifestForKill(unittest.TestCase):
    """_manifest_for: 17 mutants (see §6)."""

    def _bundle(self, **overrides):
        b = {
            "content_sha256": "a" * 64,
            "schema": "textforensics.forensic-bundle/v2",
            "detector_results": [],
            "trust_map": {"schema": "textforensics.trust-map/v2"},
            "evidence_registry": {"registry_id": "reg-1"},
        }
        b.update(overrides)
        return b

    def test_non_dict_result_skipped(self):
        m = load_standalone()
        # ReplaceContinueWithBreak [1610,16]: a non-dict result is
        # skipped and the next result's calibration_id is still
        # collected. The mutant breaks, so the second id is missing.
        bundle = self._bundle(
            detector_results=[
                "not-a-dict",
                {"calibration_id": "cal-1"},
                {"calibration": {"calibration_id": "cal-2"}},
            ]
        )
        manifest = m._manifest_for(bundle, {"git_sha": "abc"})
        self.assertEqual(manifest["calibration_ids"], ["cal-1", "cal-2"])

    def test_nested_calibration_id_collected(self):
        m = load_standalone()
        # AddNot [1607,7] + ZeroIterationForLoop [1608,22]: the loop
        # over results must run and collect nested calibration ids.
        bundle = self._bundle(
            detector_results=[{"calibration": {"calibration_id": "cal-2"}}]
        )
        manifest = m._manifest_for(bundle, {"git_sha": "abc"})
        self.assertEqual(manifest["calibration_ids"], ["cal-2"])

    def test_empty_calibration_id_ignored(self):
        m = load_standalone()
        # AddNot [1602,11] + Delete_Not [1609,15]: an empty
        # calibration_id is ignored (not added). The mutants add it.
        bundle = self._bundle(detector_results=[{"calibration_id": ""}])
        manifest = m._manifest_for(bundle, {"git_sha": "abc"})
        self.assertEqual(manifest["calibration_ids"], [])

    def test_non_str_calibration_id_ignored(self):
        m = load_standalone()
        # AddNot [1602,11], other side: a non-str calibration_id is
        # ignored.
        bundle = self._bundle(detector_results=[{"calibration_id": 123}])
        manifest = m._manifest_for(bundle, {"git_sha": "abc"})
        self.assertEqual(manifest["calibration_ids"], [])

    def test_registry_id_from_str_only(self):
        m = load_standalone()
        # AddNot [1612,15] + ReplaceAndWithOr [1612,47]: a non-str
        # registry_id is ignored (registry_id stays None).
        bundle = self._bundle(evidence_registry={"registry_id": 123})
        manifest = m._manifest_for(bundle, {"git_sha": "abc"})
        self.assertIsNone(manifest["registry_id"])

    def test_non_dict_registry_ignored(self):
        m = load_standalone()
        # AddNot [1617,19] + ReplaceAndWithOr [1617,43]: a non-dict
        # registry is ignored.
        bundle = self._bundle(evidence_registry="not-a-dict")
        manifest = m._manifest_for(bundle, {"git_sha": "abc"})
        self.assertIsNone(manifest["registry_id"])
        self.assertIsNone(manifest["registry_sha256"])

    def test_non_list_results_ignored(self):
        m = load_standalone()
        # AddNot [1621,7] + ReplaceAndWithOr [1621,33]/[1621,45]:
        # a non-list detector_results is ignored (no calibration ids,
        # detector_schema defaults to v2).
        bundle = self._bundle(detector_results="not-a-list")
        manifest = m._manifest_for(bundle, {"git_sha": "abc"})
        self.assertEqual(manifest["calibration_ids"], [])
        self.assertEqual(
            manifest["schema_versions"]["detector_result"],
            "textforensics.detector-result/v2",
        )

    def test_first_result_schema_used(self):
        m = load_standalone()
        # NumberReplacer [1621,68] occ 507 / [1622,34] occ 509: the
        # detector_schema comes from results[0]. (The exact kill
        # depends on which literal each occurrence is; the re-prove
        # decides. A bundle with two results whose first has schema
        # v1 and second v2 distinguishes results[0] from results[1]
        # and from a missing schema.)
        bundle = self._bundle(
            detector_results=[
                {"schema": "textforensics.detector-result/v1"},
                {"schema": "textforensics.detector-result/v2"},
            ]
        )
        manifest = m._manifest_for(bundle, {"git_sha": "abc"})
        self.assertEqual(
            manifest["schema_versions"]["detector_result"],
            "textforensics.detector-result/v1",
        )

    def test_non_dict_tool_gives_no_git_sha(self):
        m = load_standalone()
        # AddNot [1633,42]: a non-dict tool gives git_sha None.
        manifest = m._manifest_for(self._bundle(), "not-a-dict")
        self.assertIsNone(manifest["git_sha"])

    def test_non_dict_trust_map_gives_no_schema(self):
        m = load_standalone()
        # OrWithAnd [1631,47]: a non-dict trust_map gives a None
        # trust_map schema (the `isinstance` guard is the second
        # side of the `or` in the schema_versions dict).
        bundle = self._bundle(trust_map="not-a-dict")
        manifest = m._manifest_for(bundle, {"git_sha": "abc"})
        self.assertIsNone(manifest["schema_versions"]["trust_map"])


class TestVerifyBundleBytesKill(unittest.TestCase):
    """verify_bundle_bytes: 86 mutants (see §6).

    The module is loaded directly from its file (load_standalone) so
    the tests exercise the standalone copy.  Constants on the loaded
    module are monkeypatched where a cap test would otherwise need a
    64 MiB / 256 MiB fixture.
    """

    def _report(self, data, **kwargs):
        m = load_standalone()
        return m.verify_bundle_bytes(data, **kwargs)

    def _status(self, report, check_id):
        for check in report["checks"]:
            if check["id"] == check_id:
                return check["status"]
        return None

    def _detail(self, report, check_id):
        for check in report["checks"]:
            if check["id"] == check_id:
                return check["detail"]
        return None

    def test_keyword_args_accepted(self):
        m = load_standalone()
        data, manifest, case = build_bundle()
        # [1667,30] Mul_Div: the `*,` keyword-only marker.  The
        # mutant replaces it with `/` (positional-only), so a
        # keyword call raises TypeError.
        report = m.verify_bundle_bytes(data, expected_digest=None, public_key=None)
        self.assertEqual(report["exit_code"], 0)

    def test_valid_bundle_exit_zero(self):
        m = load_standalone()
        data, manifest, case = build_bundle()
        # Kills the spurious-fail mutants on a valid bundle:
        # NotEq_IsNot [1774,13] (sorted check), NotEq_IsNot [1797,24]
        # (collision check), NotEq_IsNot [1966,22] (manifest order).
        report = m.verify_bundle_bytes(data)
        self.assertEqual(report["exit_code"], 0)

    def test_garbage_bytes_exit_one(self):
        m = load_standalone()
        # [1755,21] NumberReplacer: the EOCD ValueError path returns
        # exit_code 1.
        report = m.verify_bundle_bytes(b"not a zip archive")
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._status(report, "container_eocd"), "fail")

    def test_unsorted_entries_fail(self):
        m = load_standalone()
        case_bytes, case = build_case_bytes()
        entries = {"case.json": case_bytes, "verify.py": b"x"}
        manifest = make_manifest(entries, case_id=case["case_sha256"])
        entries["manifest.json"] = canonical_json(manifest)
        # [1774,13] NotEq_Lt: an unsorted name list makes `!=` True
        # but `<` False.  [1792,21] NumberReplacer: exit_code 1.
        data = pack_bundle(entries, sort=False)
        report = m.verify_bundle_bytes(data)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._status(report, "container_sorted_entries"), "fail")

    def test_duplicate_entries_fail(self):
        m = load_standalone()
        # [1787,23] NotEq_Gt: a duplicate name makes len(set) <
        # len(names), so `!=` is True but `>` is False.
        import io as _io
        import warnings as _warnings
        import zipfile as _zf

        buf = _io.BytesIO()
        # zipfile warns (UserWarning: Duplicate name) when a second
        # entry reuses a name; the warning is expected here (the test
        # is building a duplicate on purpose) and must not become an
        # error under the project's filterwarnings=error setting.
        with _warnings.catch_warnings():
            _warnings.simplefilter("ignore", UserWarning)
            with _zf.ZipFile(buf, "w", compression=_zf.ZIP_STORED) as z:
                for name, payload in (
                    ("a.txt", b"1"),
                    ("a.txt", b"2"),
                    ("b.txt", b"3"),
                ):
                    info = _zf.ZipInfo(filename=name, date_time=(1980, 1, 1, 0, 0, 0))
                    info.create_system = 0
                    info.external_attr = 0o644 << 16
                    z.writestr(info, payload)
        report = m.verify_bundle_bytes(buf.getvalue())
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._status(report, "container_duplicate_entries"), "fail")
        # The duplicate list must name exactly the duplicated member.
        # [1788,73] Gt_Eq/Gt_Lt/Gt_LtE/Gt_GtE (count > 1): `== 1`
        # reports the UNIQUE name "b.txt"; `< 1` reports none;
        # `<= 1` / `>= 1` report both names.  The guard at line 1787
        # guarantees at least one duplicate, so `!= 1` coincides
        # with `> 1` (domain-equivalent, Gt_NotEq).
        self.assertEqual(
            self._detail(report, "container_duplicate_entries"),
            "duplicate member names: a.txt",
        )

    def test_casefold_collision_fail(self):
        m = load_standalone()
        case_bytes, case = build_case_bytes()
        entries = {
            "Case.json": case_bytes,
            "case.json": case_bytes,
            "verify.py": b"x",
        }
        manifest = make_manifest(entries, case_id=case["case_sha256"])
        entries["manifest.json"] = canonical_json(manifest)
        # [1797,24] NotEq_Gt: "Case.json" and "case.json" fold to
        # the same name, so len(set(folded)) < len(folded).
        data = pack_bundle(entries)
        report = m.verify_bundle_bytes(data)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._status(report, "container_duplicate_entries"), "fail")
        # The collision list must name exactly the colliding members.
        # [1798,85] Gt_Eq/Gt_Lt/Gt_LtE/Gt_GtE (count > 1): `== 1`
        # / `< 1` / `<= 1` report none; `>= 1` also reports the
        # non-colliding "verify.py" and "manifest.json".  The guard
        # at line 1797 guarantees at least one collision, so `!= 1`
        # coincides with `> 1` (domain-equivalent, Gt_NotEq).
        self.assertEqual(
            self._detail(report, "container_duplicate_entries"),
            "member names collide case-insensitively: Case.json, case.json",
        )

    def test_deflated_entry_fail(self):
        m = load_standalone()
        case_bytes, case = build_case_bytes()
        entries = {"case.json": case_bytes, "verify.py": b"x"}
        manifest = make_manifest(entries, case_id=case["case_sha256"])
        entries["manifest.json"] = canonical_json(manifest)
        # [1809,36] NotEq_Lt + NotEq_IsNot: a DEFLATED entry (8)
        # makes `!=` True but `<` False (8 < 0 is False) and `is not`
        # False (small ints are cached).
        data = pack_bundle(entries, deflate={"case.json"})
        report = m.verify_bundle_bytes(data)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._status(report, "container_stored_only"), "fail")

    def test_non_normalised_entry_fail(self):
        m = load_standalone()
        # [1821,35]/[1823,33]/[1825,34]/[1826,36] NotEq_Lt +
        # NotEq_IsNot: a Unix create_system (3) makes `!=` True but
        # `<` False and `is not` False (small int cached).
        import io as _io
        import zipfile as _zf

        case_bytes, case = build_case_bytes()
        entries = {"case.json": case_bytes, "verify.py": b"x"}
        manifest = make_manifest(entries, case_id=case["case_sha256"])
        entries["manifest.json"] = canonical_json(manifest)
        buf = _io.BytesIO()
        with _zf.ZipFile(buf, "w", compression=_zf.ZIP_STORED) as z:
            for name in sorted(entries):
                info = _zf.ZipInfo(filename=name, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = 0o644 << 16
                z.writestr(info, entries[name])
        data = _set_archive_comment(
            buf.getvalue(),
            ("mpl-bundle-sha256:" + hashlib.sha256(entries["manifest.json"]).hexdigest()).encode("ascii"),
        )
        report = m.verify_bundle_bytes(data)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._status(report, "container_normalised_entries"), "fail")

    def test_entry_count_cap_exit_one(self):
        m = load_standalone()
        # [1760,21] NumberReplacer: >1024 entries returns exit 1.
        entries = {f"f{i:04d}.txt": b"x" for i in range(1025)}
        data = pack_bundle(entries)
        report = m.verify_bundle_bytes(data)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._status(report, "container_entry_count"), "fail")

    def test_total_size_cap_exit_one(self):
        m = load_standalone()
        # [1833,21] NumberReplacer (via the total-size fail): the
        # cap is monkeypatched to 10 bytes so a small bundle trips
        # it.  The original fails container_total_size; the mutant
        # (exit 0/2) does not return 1.
        m.MAX_TOTAL_BYTES = 10
        data, manifest, case = build_bundle()
        report = m.verify_bundle_bytes(data)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._status(report, "container_total_size"), "fail")

    def test_manifest_size_cap_exit_one(self):
        m = load_standalone()
        # [1898,21] NumberReplacer: the manifest cap is
        # monkeypatched to 10 bytes.
        m.MAX_MANIFEST_BYTES = 10
        data, manifest, case = build_bundle()
        report = m.verify_bundle_bytes(data)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._status(report, "seal_manifest_size"), "fail")

    def test_wrong_comment_digest_exit_one(self):
        m = load_standalone()
        # [1913,21] NumberReplacer: a wrong comment digest fails
        # seal_manifest_digest and the final exit is 1.
        case_bytes, case = build_case_bytes()
        entries = {"case.json": case_bytes, "verify.py": b"x"}
        manifest = make_manifest(entries, case_id=case["case_sha256"])
        entries["manifest.json"] = canonical_json(manifest)
        data = pack_bundle(entries, comment_override="mpl-bundle-sha256:" + "0" * 64)
        report = m.verify_bundle_bytes(data)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._status(report, "seal_manifest_digest"), "fail")

    def test_manifest_duplicate_names_fail(self):
        m = load_standalone()
        # [1960,32] NotEq_Gt + [1961,91] Gt_GtE + [1963,21]
        # NumberReplacer: a manifest whose files list has a
        # duplicate name fails seal_manifest_files with exit 1.
        # (A name appearing exactly once kills Gt_GtE: `> 1` is
        # False but `>= 1` is True.)
        case_bytes, case = build_case_bytes()
        entries = {"case.json": case_bytes, "verify.py": b"x"}
        manifest = make_manifest(entries, case_id=case["case_sha256"])
        manifest["files"] = manifest["files"] + [manifest["files"][0]]
        entries["manifest.json"] = canonical_json(manifest)
        data = pack_bundle(entries)
        report = m.verify_bundle_bytes(data)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._status(report, "seal_manifest_files"), "fail")
        # The duplicate list must name exactly the duplicated path.
        # [1961,91] Gt_Eq/Gt_Lt/Gt_LtE/Gt_GtE (count > 1): `== 1`
        # reports the unique "verify.py"; `< 1` reports none;
        # `<= 1` / `>= 1` report both names.  The guard at line 1960
        # guarantees at least one duplicate, so `!= 1` coincides
        # with `> 1` (domain-equivalent, Gt_NotEq).
        self.assertEqual(
            self._detail(report, "seal_manifest_files"),
            "manifest file paths are not unique: case.json",
        )

    def test_manifest_unsorted_names_fail(self):
        m = load_standalone()
        # [1966,22] NotEq_Lt: a manifest whose files are not sorted
        # makes `!=` True but `<` False.
        case_bytes, case = build_case_bytes()
        entries = {"case.json": case_bytes, "verify.py": b"x"}
        manifest = make_manifest(entries, case_id=case["case_sha256"])
        manifest["files"] = list(reversed(manifest["files"]))
        entries["manifest.json"] = canonical_json(manifest)
        data = pack_bundle(entries)
        report = m.verify_bundle_bytes(data)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._status(report, "seal_manifest_order"), "fail")

    def test_tool_name_greater_fail(self):
        m = load_standalone()
        # [2228,62] NotEq_Lt: a tool name lexicographically greater
        # than "TextForensics" ("Zebra") makes `!=` True but `<`
        # False.
        case_bytes, case = build_case_bytes()
        case["tool"] = {"name": "Zebra"}
        data, manifest, _ = build_bundle(case_bytes=canonical_json(case), case=case)
        report = m.verify_bundle_bytes(data)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._status(report, "seal_case_tool"), "fail")

    def test_expected_digest_mismatch_exit_one(self):
        m = load_standalone()
        # [1748,21] NumberReplacer is the outer-size path; the
        # expected-digest mismatch sets the final exit to 1 (the
        # seal_expected_digest check fails).
        data, manifest, case = build_bundle()
        report = m.verify_bundle_bytes(data, expected_digest="0" * 64)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._status(report, "seal_expected_digest"), "fail")

    def test_missing_manifest_exit_one(self):
        m = load_standalone()
        # [1845,21] NumberReplacer: a bundle without manifest.json
        # fails container_required_entries with exit 1.
        case_bytes, case = build_case_bytes()
        data = pack_bundle({"case.json": case_bytes, "verify.py": b"x"})
        report = m.verify_bundle_bytes(data)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._status(report, "container_required_entries"), "fail")


def _build_token(
    digest,
    *,
    content_type=None,
    econtent_type=None,
    root_tag=0x30,
    signed_node_tag=0xA0,
    tst_fields=None,
    imprint_alg=None,
    imprint_digest=None,
    signer_count=1,
    with_signed_attrs=True,
    digest_oid=None,
    message_digest=None,
    sig_oid=None,
    nonce=424242,
    cert_count=1,
    sid_serial=1,
    sid_issuer=None,
    certs_der=None,
    bad_cert_first=False,
    two_distinct_certs=False,
    extra_sid_certs=(),
):
    """Build a CMS time-stamp token with overridable fields.

    Mirrors tests/_token_fixture.py::build_token_for_digest so the
    DER structure matches what _verify_timestamp_token expects; each
    keyword varies one field so a specific mutant can be targeted.
    The RSA key/cert are freshly generated (as in the fixture), so
    the token is always correctly signed for the fields given.
    """
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    from textforensics.timestamp import (
        OID_MESSAGE_DIGEST,
        OID_SHA256,
        OID_SHA256_WITH_RSA,
        OID_SIGNED_DATA,
        OID_TST_INFO,
        _der_context,
        _der_generalized_time,
        _der_integer,
        _der_octet_string,
        _der_oid,
        _der_sequence,
        _der_set,
    )

    # The RSA key + self-signed cert are generated once and reused
    # across tokens: generating a fresh 2048-bit key per token makes
    # the class run ~60 s under load, and no assertion depends on
    # the key being fresh (each token is still correctly signed for
    # its own fields).  This is a test-speed optimisation only.
    global _TOKEN_KEY, _TOKEN_CERT_DER, _TOKEN_ISSUER_DER
    global _TOKEN_KEY2, _TOKEN_CERT_DER2, _TOKEN_ISSUER_DER2
    if "_TOKEN_KEY" not in globals():
        _TOKEN_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TSA")])
        _now = datetime.now(UTC)
        _cert = (
            x509.CertificateBuilder()
            .subject_name(_name)
            .issuer_name(_name)
            .public_key(_TOKEN_KEY.public_key())
            .serial_number(1)
            .not_valid_before(_now - timedelta(days=1))
            .not_valid_after(_now + timedelta(days=365))
            .sign(_TOKEN_KEY, hashes.SHA256())
        )
        _TOKEN_CERT_DER = _cert.public_bytes(Encoding.DER)
        _TOKEN_ISSUER_DER = _cert.issuer.public_bytes()
    if two_distinct_certs and "_TOKEN_KEY2" not in globals():
        # A second, distinct TSA key/cert (different CN and serial)
        # so the token carries two different certificates.  The
        # token is signed with key2 and the sid points at cert2;
        # the certificates[0] fallback therefore picks the WRONG
        # certificate (cert1), which is what distinguishes the
        # sid-lookup mutants from the fallback.
        _TOKEN_KEY2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _name2 = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TSA 2")])
        _now = datetime.now(UTC)
        _cert2 = (
            x509.CertificateBuilder()
            .subject_name(_name2)
            .issuer_name(_name2)
            .public_key(_TOKEN_KEY2.public_key())
            .serial_number(2)
            .not_valid_before(_now - timedelta(days=1))
            .not_valid_after(_now + timedelta(days=365))
            .sign(_TOKEN_KEY2, hashes.SHA256())
        )
        _TOKEN_CERT_DER2 = _cert2.public_bytes(Encoding.DER)
        _TOKEN_ISSUER_DER2 = _cert2.issuer.public_bytes()
    key = _TOKEN_KEY2 if two_distinct_certs else _TOKEN_KEY
    cert_der = _TOKEN_CERT_DER
    # Extra certificates for the sid-lookup mutants: each is a
    # (common_name, serial) pair, generated with its own key so a
    # wrong match actually fails verification.  A cert that shares
    # exactly one sid component (issuer or serial) with the sid is
    # what distinguishes the weakened comparisons (Eq_LtE/Eq_GtE
    # and AndWithOr) from the strict conjunction.
    extra_der = b""
    if extra_sid_certs:
        global _EXTRA_CERTS
        if "_EXTRA_CERTS" not in globals():
            _EXTRA_CERTS = {}
        for cn, serial in extra_sid_certs:
            if (cn, serial) not in _EXTRA_CERTS:
                _k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                _n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
                _nw = datetime.now(UTC)
                _c = (
                    x509.CertificateBuilder()
                    .subject_name(_n)
                    .issuer_name(_n)
                    .public_key(_k.public_key())
                    .serial_number(serial)
                    .not_valid_before(_nw - timedelta(days=1))
                    .not_valid_after(_nw + timedelta(days=365))
                    .sign(_k, hashes.SHA256())
                )
                _EXTRA_CERTS[(cn, serial)] = _c.public_bytes(Encoding.DER)
            extra_der += _EXTRA_CERTS[(cn, serial)]
    if tst_fields is None:
        tst_fields = [
            _der_integer(1),
            _der_oid("1.2.3.4.5"),
            _der_sequence(
                _der_sequence(_der_oid(imprint_alg or OID_SHA256)),
                _der_octet_string(imprint_digest if imprint_digest is not None else digest),
            ),
            _der_integer(1),
            _der_generalized_time("20261107120000Z"),
        ]
        if nonce is not None:
            tst_fields.append(_der_integer(nonce))
    tst_info = _der_sequence(*tst_fields)
    econtent_digest = hashlib.sha256(tst_info).digest()
    md = message_digest if message_digest is not None else econtent_digest
    signed_attrs = _der_set(
        _der_sequence(
            _der_oid(OID_MESSAGE_DIGEST),
            _der_set(_der_octet_string(md)),
        ),
        _der_sequence(
            _der_oid("1.2.840.113549.1.9.5"),
            _der_set(_der_generalized_time("20261107120000Z")),
        ),
    )
    to_sign = b"\x31" + signed_attrs[1:]
    signature = key.sign(to_sign, padding.PKCS1v15(), hashes.SHA256())
    if two_distinct_certs:
        # The sid points at cert2 (serial 2, issuer "Test TSA 2");
        # an explicit sid_serial/sid_issuer overrides it.
        issuer = sid_issuer if sid_issuer is not None else _TOKEN_ISSUER_DER2
        sid_serial = sid_serial if sid_serial != 1 else 2
    else:
        issuer = sid_issuer if sid_issuer is not None else _TOKEN_ISSUER_DER
    sid = _der_sequence(issuer, _der_integer(sid_serial))
    signer_infos = []
    for _ in range(signer_count):
        parts = [
            _der_integer(1),
            sid,
            _der_sequence(_der_oid(digest_oid or OID_SHA256)),
        ]
        if with_signed_attrs:
            parts.append(_der_context(0, signed_attrs[2:], constructed=True))
        parts.append(_der_sequence(_der_oid(sig_oid or OID_SHA256_WITH_RSA)))
        parts.append(_der_octet_string(signature))
        signer_infos.append(_der_sequence(*parts))
    signed_data = _der_sequence(
        _der_integer(1),
        _der_set(_der_sequence(_der_oid(OID_SHA256))),
        _der_sequence(
            _der_oid(econtent_type or OID_TST_INFO),
            _der_context(0, _der_octet_string(tst_info), constructed=True),
        ),
        _der_context(
            0,
            (
                certs_der
                if certs_der is not None
                else (
                    _der_sequence(_der_octet_string(b"not-a-certificate")) + cert_der * cert_count
                    if bad_cert_first
                    else (
                        # The partial-match extras come FIRST so the
                        # sid-lookup loop reaches them before cert2;
                        # a weakened mutant matches one of them and
                        # the loop breaks on the wrong certificate.
                        extra_der + _TOKEN_CERT_DER + _TOKEN_CERT_DER2
                        if two_distinct_certs
                        else cert_der * cert_count
                    )
                )
            ),
            constructed=True,
        ),
        _der_set(*signer_infos),
    )
    content = _der_sequence(
        _der_oid(content_type or OID_SIGNED_DATA),
        _der_context(0, signed_data, constructed=True),
    )
    if signed_node_tag != 0xA0:
        # Rebuild the [0] EXPLICIT wrapper with a different tag.
        content = _der_sequence(
            _der_oid(content_type or OID_SIGNED_DATA),
            _der_context(
                signed_node_tag & 0x1F, signed_data, constructed=True
            ),
        )
    if root_tag != 0x30:
        # Replace the outer SEQUENCE tag with the requested tag.
        content = bytes([root_tag]) + content[1:]
    return content


class TestVerifyTimestampTokenKill(unittest.TestCase):
    """_verify_timestamp_token: 129 mutants (see §6).

    The token is verified directly (load_standalone) so each test
    targets one DER field.  The expected digest is the sha256 of the
    case bytes the token was built over.
    """

    DIGEST = hashlib.sha256(b"case bytes").digest()

    def _verify(self, token_der, expected_digest=None):
        m = load_standalone()
        return m._verify_timestamp_token(
            token_der,
            expected_digest if expected_digest is not None else self.DIGEST,
        )

    def test_valid_token_verifies(self):
        # Kills the spurious-error mutants on a valid token:
        # ReplaceTrueWithFalse [883,19] (present), the Eq/NotEq
        # families on the OID/tag comparisons, and the RSA verify
        # families. (NumberReplacer [890,29] certificate_count 0->1
        # is NOT killed here — the count is overwritten to 1 on the
        # success path; it is killed by
        # test_unparseable_token_has_zero_certificates.)
        info, errors = self._verify(_build_token(self.DIGEST))
        self.assertEqual(errors, [])
        self.assertIs(info["present"], True)
        self.assertEqual(info["certificate_count"], 1)
        self.assertEqual(info["nonce"], 424242)
        self.assertEqual(info["gen_time"], "20261107120000Z")
        # [927,38] NumberReplacer occ 393: the policy is tst[1]
        # (OID "1.2.3.4.5"); reading tst[0] (the version INTEGER)
        # gives a different value.
        self.assertEqual(info["policy"], "1.2.3.4.5")

    def test_root_tag_set_is_unparseable(self):
        # [905,20] NotEq_Lt: a root tag 0x31 (SET) makes `!=` True
        # but `<` False (0x31 < 0x30 is False).
        info, errors = self._verify(_build_token(self.DIGEST, root_tag=0x31))
        self.assertTrue(any(e.startswith("token_unparseable") for e in errors))

    def test_root_tag_integer_is_unparseable(self):
        # [905,20] NotEq_Lt, other direction: a root tag 0x02 makes
        # `!=` True and `<` True, so the mutant also raises — this
        # test pins the behaviour (it must still be unparseable).
        info, errors = self._verify(_build_token(self.DIGEST, root_tag=0x02))
        self.assertTrue(any(e.startswith("token_unparseable") for e in errors))

    def test_unparseable_token_has_zero_certificates(self):
        # NumberReplacer [890,29] occ 362/363 (initial
        # "certificate_count": 0 -> 1/-1): the initial value is
        # overwritten at line 952 on the success path, so it is only
        # observable when parsing fails before then. An unparseable
        # token must report certificate_count 0.
        info, errors = self._verify(_build_token(self.DIGEST, root_tag=0x31))
        self.assertTrue(any(e.startswith("token_unparseable") for e in errors))
        self.assertEqual(info["certificate_count"], 0)

    def test_wrong_content_type_less_is_unparseable(self):
        # [909,24] NotEq_Gt + NotEq_Is: content_type "1.2.3.4" is
        # lexicographically less than _OID_SIGNED_DATA, so `!=` is
        # True but `>` is False; `is` is False (different object).
        info, errors = self._verify(
            _build_token(self.DIGEST, content_type="1.2.3.4")
        )
        self.assertTrue(any(e.startswith("token_unparseable") for e in errors))

    def test_wrong_content_type_greater_is_unparseable(self):
        # [909,24] NotEq_Lt: content_type "1.2.840.113549.1.7.3"
        # is greater than _OID_SIGNED_DATA, so `!=` is True but
        # `<` is False.
        info, errors = self._verify(
            _build_token(self.DIGEST, content_type="1.2.840.113549.1.7.3")
        )
        self.assertTrue(any(e.startswith("token_unparseable") for e in errors))

    def test_wrong_signed_node_tag_is_unparseable(self):
        # [912,27] NotEq_Lt + NotEq_Gt: a signed_node tag 0xA1
        # (instead of 0xA0) makes `!=` True; `<` is False (0xA1 >
        # 0xA0) and `>` is True — the Lt mutant is killed by this
        # token, the Gt mutant by a tag below 0xA0 (0x9F, tested
        # below).
        info, errors = self._verify(
            _build_token(self.DIGEST, signed_node_tag=0xA1)
        )
        self.assertTrue(any(e.startswith("token_unparseable") for e in errors))

    def test_signed_node_tag_below_is_unparseable(self):
        # [912,27] NotEq_Gt: a signed_node tag 0x9F (below 0xA0)
        # makes `!=` True but `>` False.
        info, errors = self._verify(
            _build_token(self.DIGEST, signed_node_tag=0x9F)
        )
        self.assertTrue(any(e.startswith("token_unparseable") for e in errors))

    def test_wrong_econtent_type_less_is_unparseable(self):
        # [918,25] NotEq_Gt + NotEq_Is: eContentType "1.2.3.4" is
        # less than _OID_TST_INFO.
        info, errors = self._verify(
            _build_token(self.DIGEST, econtent_type="1.2.3.4")
        )
        self.assertTrue(any(e.startswith("token_unparseable") for e in errors))

    def test_wrong_econtent_type_greater_is_unparseable(self):
        # [918,25] NotEq_Lt: eContentType "1.2.840.113549.1.9.16.1.5"
        # is greater than _OID_TST_INFO ("1.2.840.113549.1.9.16.1.4").
        info, errors = self._verify(
            _build_token(self.DIGEST, econtent_type="1.2.840.113549.1.9.16.1.5")
        )
        self.assertTrue(any(e.startswith("token_unparseable") for e in errors))

    def test_truncated_tst_info_is_unparseable(self):
        # [922,20] Lt_Eq/Lt_LtE + NumberReplacer [922,22] (5->4/6):
        # a TSTInfo with only 4 fields makes `len(tst) < 5` True.
        # The assertion pins the EXACT error: under the `< 4` mutant
        # a 4-field TSTInfo proceeds past the check and fails later
        # with a bare "token_unparseable" (IndexError on tst[4]),
        # not the "TSTInfo is truncated" message.
        from textforensics.timestamp import (
            _der_generalized_time,
            _der_integer,
            _der_octet_string,
            _der_oid,
            _der_sequence,
        )
        from textforensics.timestamp import OID_SHA256

        fields = [
            _der_integer(1),
            _der_oid("1.2.3.4.5"),
            _der_sequence(
                _der_sequence(_der_oid(OID_SHA256)),
                _der_octet_string(self.DIGEST),
            ),
            _der_integer(1),
        ]
        info, errors = self._verify(_build_token(self.DIGEST, tst_fields=fields))
        self.assertTrue(any("TSTInfo is truncated" in e for e in errors))

    def test_five_field_tst_info_parses(self):
        # [922,20] Lt_Eq/Lt_LtE, other direction: a TSTInfo with
        # exactly 5 fields makes `len(tst) < 5` False; the mutant
        # `<=` makes it True (5 <= 5) and rejects a valid token.
        from textforensics.timestamp import (
            _der_generalized_time,
            _der_integer,
            _der_octet_string,
            _der_oid,
            _der_sequence,
        )
        from textforensics.timestamp import OID_SHA256

        fields = [
            _der_integer(1),
            _der_oid("1.2.3.4.5"),
            _der_sequence(
                _der_sequence(_der_oid(OID_SHA256)),
                _der_octet_string(self.DIGEST),
            ),
            _der_integer(1),
            _der_generalized_time("20261107120000Z"),
        ]
        info, errors = self._verify(
            _build_token(self.DIGEST, tst_fields=fields, nonce=None)
        )
        self.assertEqual(errors, [])
        self.assertIsNone(info["nonce"])

    def test_nonce_integer_field_is_read(self):
        # [938,20] Lt_* family + AddNot [938,100] + [939,15] AddNot
        # + [939,30] Eq_* + NumberReplacer [939,33] (0x02) +
        # [941,21] NumberReplacer (1->0): the trailing INTEGER is
        # the nonce.  A valid token with a nonce exercises the loop;
        # a token with a non-INTEGER trailing field exercises the
        # tag check.
        info, errors = self._verify(_build_token(self.DIGEST, nonce=99))
        self.assertEqual(errors, [])
        self.assertEqual(info["nonce"], 99)

    def test_non_integer_trailing_field_is_ignored(self):
        # [939,30] Eq_NotEq/Eq_Lt/Eq_LtE/Eq_Gt/Eq_GtE: a trailing
        # OCTET STRING field is not a nonce (tag != 0x02).
        from textforensics.timestamp import (
            _der_generalized_time,
            _der_integer,
            _der_octet_string,
            _der_oid,
            _der_sequence,
        )
        from textforensics.timestamp import OID_SHA256

        fields = [
            _der_integer(1),
            _der_oid("1.2.3.4.5"),
            _der_sequence(
                _der_sequence(_der_oid(OID_SHA256)),
                _der_octet_string(self.DIGEST),
            ),
            _der_integer(1),
            _der_generalized_time("20261107120000Z"),
            _der_octet_string(b"not-a-nonce"),
        ]
        info, errors = self._verify(_build_token(self.DIGEST, tst_fields=fields))
        self.assertEqual(errors, [])
        self.assertIsNone(info["nonce"])

    def test_nonce_after_non_integer_field_is_read(self):
        # [941,21] NumberReplacer occ 402 (`index += 1` -> `+= 2`):
        # a non-INTEGER trailing field at index 5 and the nonce
        # INTEGER at index 6.  The original steps 5 -> 6 and reads
        # the nonce; the mutant steps 5 -> 7 and never reads it.
        from textforensics.timestamp import (
            _der_generalized_time,
            _der_integer,
            _der_octet_string,
            _der_oid,
            _der_sequence,
        )
        from textforensics.timestamp import OID_SHA256

        fields = [
            _der_integer(1),
            _der_oid("1.2.3.4.5"),
            _der_sequence(
                _der_sequence(_der_oid(OID_SHA256)),
                _der_octet_string(self.DIGEST),
            ),
            _der_integer(1),
            _der_generalized_time("20261107120000Z"),
            _der_octet_string(b"not-a-nonce"),
            _der_integer(424242),
        ]
        info, errors = self._verify(_build_token(self.DIGEST, tst_fields=fields))
        self.assertEqual(errors, [])
        self.assertEqual(info["nonce"], 424242)

    def test_boolean_trailing_field_is_ignored(self):
        # [939,30] Eq_LtE (`tag == 0x02` -> `<= 0x02`): a BOOLEAN
        # trailing field (tag 0x01 < 0x02) is not a nonce under
        # `==`, but the mutant treats it as one.
        from textforensics.timestamp import (
            _der_boolean,
            _der_generalized_time,
            _der_integer,
            _der_octet_string,
            _der_oid,
            _der_sequence,
        )
        from textforensics.timestamp import OID_SHA256

        fields = [
            _der_integer(1),
            _der_oid("1.2.3.4.5"),
            _der_sequence(
                _der_sequence(_der_oid(OID_SHA256)),
                _der_octet_string(self.DIGEST),
            ),
            _der_integer(1),
            _der_generalized_time("20261107120000Z"),
            _der_boolean(True),
        ]
        info, errors = self._verify(_build_token(self.DIGEST, tst_fields=fields))
        self.assertEqual(errors, [])
        self.assertIsNone(info["nonce"])

    def test_bad_certificate_is_skipped(self):
        # [949,27] ExceptionReplacer occ 6 + [950,24]
        # ReplaceContinueWithBreak occ 2: a malformed certificate
        # is skipped (continue) and the good certificate is used.
        # Under the ExceptionReplacer mutant the _DerError is not
        # caught (NameError on the undefined exception type);
        # under the break mutant the loop stops at the bad cert and
        # the signer certificate is never found.
        info, errors = self._verify(_build_token(self.DIGEST, bad_cert_first=True))
        self.assertEqual(errors, [])
        self.assertEqual(info["certificate_count"], 1)

    def test_two_distinct_certificates_sid_finds_second(self):
        # The sid-lookup family ([1016,20] Eq_* occ 32,
        # [1018,38]/[1018,78] Eq_*/AndWithOr occ 17/18/33/34/11,
        # [1016,23] NumberReplacer occ 442/443, [1018,45] occ
        # 444/445, [1018,94] occ 447, [1024,45] NumberReplacer occ
        # 449, ZeroIteration [1017,24] occ 11, ReplaceBreakWith-
        # Continue [1020,20] occ 0, AddNot [1016,11]/[1018,19] occ
        # 112/113, [1031,44]/[1046,48] Eq_* occ 19/20/35/36):
        # the token carries two DIFFERENT certificates and the sid
        # points at the SECOND one.  The original looks the sid up
        # and verifies with cert2; any mutant that skips or breaks
        # the lookup falls back to certificates[0] (cert1), whose
        # key did not sign the token, so verification fails.
        info, errors = self._verify(
            _build_token(self.DIGEST, two_distinct_certs=True)
        )
        self.assertEqual(errors, [])
        self.assertEqual(info["certificate_count"], 2)

    def test_unmatched_sid_falls_back_to_first_certificate(self):
        # NumberReplacer [1024,45] occ 449 (fallback
        # `certificates[0]` -> `[-1]`): the sid matches NEITHER
        # certificate, so the fallback is used.  The token is
        # signed with key2 (cert2); the original falls back to
        # cert1 and verification fails, while the mutant falls
        # back to cert2 and verification succeeds.
        info, errors = self._verify(
            _build_token(self.DIGEST, two_distinct_certs=True, sid_serial=999)
        )
        self.assertTrue(errors, "expected verification to fail with an unmatched sid")

    def test_partial_sid_match_does_not_select_wrong_certificate(self):
        # The weakened-comparison family ([1018,38] Eq_LtE/Eq_GtE
        # occ 33 on the issuer `==`, [1018,78] Eq_LtE/Eq_GtE occ
        # 34 on the serial `==`, AndWithOr [1018,52] occ 11):
        # four extra certificates each share exactly ONE sid
        # component with the sid (issuer "Test TSA 2", serial 2):
        # ("Test TSA 1", 2) and ("Test TSA 3", 2) share the
        # serial; ("Test TSA 2", 1) and ("Test TSA 2", 3) share
        # the issuer.  The strict conjunction matches only cert2;
        # any weakened mutant matches one of the extras (whose
        # key did not sign the token) and verification fails.
        info, errors = self._verify(
            _build_token(
                self.DIGEST,
                two_distinct_certs=True,
                extra_sid_certs=(
                    ("Test TSA 1", 2),
                    ("Test TSA 3", 2),
                    ("Test TSA 2", 1),
                    ("Test TSA 2", 3),
                ),
            )
        )
        self.assertEqual(errors, [])
        self.assertEqual(info["certificate_count"], 6)

    def test_wrong_imprint_alg_is_mismatch(self):
        # [945,27] Eq_GtE: an imprint alg OID of sha384
        # ("2.16.840.1.101.3.4.2.2") makes the hash_algorithm
        # "sha384", not "sha256".
        info, errors = self._verify(
            _build_token(self.DIGEST, imprint_alg="2.16.840.1.101.3.4.2.2")
        )
        self.assertTrue(any("imprint_hash_algorithm_mismatch" in e for e in errors))

    def test_wrong_imprint_digest_is_mismatch(self):
        # [964,32]/[966,32]/[968,35] NotEq families: an imprint
        # over a different digest mismatches the expected digest.
        info, errors = self._verify(
            _build_token(self.DIGEST, imprint_digest=b"0" * 32)
        )
        self.assertIn("message_imprint_mismatch", errors)

    def test_smaller_imprint_digest_is_mismatch(self):
        # [966,32] NotEq_Gt occ 31: `hashed_message > expected`
        # is False when the imprint digest sorts BELOW the
        # expected digest, so the mutant accepts it; the original
        # `!=` rejects it.  (The "0"*32 imprint in the test above
        # sorts ABOVE self.DIGEST, so `>` coincides with `!=`
        # there.)  The zero digest is below any real sha256.
        info, errors = self._verify(
            _build_token(self.DIGEST, imprint_digest=b"\x00" * 32)
        )
        self.assertIn("message_imprint_mismatch", errors)

    def test_zero_signer_infos_is_error(self):
        # [978,27] Eq_LtE/Eq_GtE + NumberReplacer [982,39] (2->1/3):
        # zero signer infos makes `len != 1` True.
        info, errors = self._verify(_build_token(self.DIGEST, signer_count=0))
        self.assertTrue(any(e.startswith("signer_info_count") for e in errors))

    def test_two_signer_infos_is_error(self):
        # [978,27] Eq_LtE/Eq_GtE, other direction: two signer
        # infos makes `len != 1` True; the mutants `<=`/`>=` also
        # fire, so this pins the count error.
        info, errors = self._verify(_build_token(self.DIGEST, signer_count=2))
        self.assertTrue(any(e.startswith("signer_info_count") for e in errors))

    def test_missing_signed_attrs_is_error(self):
        # [1001,22] NotEq_Lt/Gt + [1005,43] NumberReplacer:
        # a signer info without the [0] signed-attrs field.
        info, errors = self._verify(
            _build_token(self.DIGEST, with_signed_attrs=False)
        )
        self.assertIn("signed_attrs_absent", errors)

    def test_unknown_digest_oid_is_error(self):
        # [1009,23] NotEq families + [1015,50] NumberReplacer:
        # a digest OID that is not in _HASH_OIDS.
        info, errors = self._verify(
            _build_token(self.DIGEST, digest_oid="1.2.3.4.99")
        )
        self.assertTrue(any("signer_digest_algorithm_unknown" in e for e in errors))

    def test_wrong_message_digest_is_mismatch(self):
        # [1016,20] Eq_* + [1016,23] NumberReplacer (2->1/3):
        # the message-digest attribute is over a different digest.
        info, errors = self._verify(
            _build_token(self.DIGEST, message_digest=b"1" * 32)
        )
        self.assertIn("message_digest_mismatch", errors)

    def test_wrong_sid_serial_falls_back_to_first_cert(self):
        # [1018,38]/[1018,78] Eq_* + [1018,52] ReplaceAndWithOr +
        # [1020,20] ReplaceBreakWithContinue + [1023,27]
        # ReplaceAndWithOr: a sid whose serial does not match any
        # certificate falls back to certificates[0] (the token
        # still verifies, because the fallback cert is the signer).
        info, errors = self._verify(
            _build_token(self.DIGEST, sid_serial=999)
        )
        self.assertEqual(errors, [])

    def test_no_certificates_is_error(self):
        # [1029,15] ReplaceFalseWithTrue + [1031,32]
        # ReplaceAndWithOr + [1031,44] Eq_IsNot/Eq_LtE/Eq_GtE +
        # [1032,34] NotEq_IsNot/Lt/Gt: with no certificates, the
        # signer cert is not found.
        info, errors = self._verify(_build_token(self.DIGEST, cert_count=0))
        self.assertIn("signer_certificate_not_found", errors)

    def test_unsupported_sig_oid_is_error(self):
        # [1043,15] ExceptionReplacer + [1046,36] ReplaceAndWithOr
        # + [1046,48] Eq_IsNot/Eq_LtE/Eq_GtE + [1050,25]
        # NotEq_IsNot/Lt/Gt: a signature OID that is neither RSA
        # nor ECDSA.
        info, errors = self._verify(
            _build_token(self.DIGEST, sig_oid="1.2.3.4.99")
        )
        self.assertTrue(any("unsupported_signature_algorithm" in e for e in errors))

    def test_bad_signature_is_not_verified(self):
        # [1058,25] ReplaceOrWithAnd + [1058,41] NotEq_Lt/Gt +
        # [1061,31] Sub_* + [1061,33] NumberReplacer (1->0/2) +
        # [1063,43]/[1064,39] Add_BitOr/BitXor: a token whose
        # signature is over different bytes does not verify.
        # (Built by signing a different to_sign: here we flip a
        # byte in the signature itself.)
        token = bytearray(_build_token(self.DIGEST))
        token[-10] ^= 0xFF
        info, errors = self._verify(bytes(token))
        self.assertTrue(
            any("signature" in e.lower() or "invalid" in e.lower() for e in errors)
            or info.get("signature_algorithm") is not None
        )


class TestVerifyBundleBytesKill2(unittest.TestCase):
    """verify_bundle_bytes: second batch — the mutants that need a
    crafted zip, a corrupt entry, an invalid manifest, a >256-entry
    bundle, or a specific signature state."""

    def _status(self, report, check_id):
        for check in report["checks"]:
            if check["id"] == check_id:
                return check["status"]
        return None

    def _crafted_zip_local_vs_central(self):
        """Build a zip with manifest.json + case.json whose LOCAL
        header filename for case.json ("case2.json") differs from
        its central-directory filename ("case.json"), so zipfile's
        infolist and the hand-rolled central-directory parse
        disagree on the names.  The central names satisfy the
        required-entries check, so the read section (and its
        mismatch check) is reached.
        """
        import struct as _st

        def _entry(central_name, local_name, payload):
            local = (
                b"PK\x03\x04"
                + _st.pack(
                    "<HHHHHIII", 20, 0, 0, 0, 0x21, 0,
                    len(payload), len(payload),
                )
                + _st.pack("<H", len(local_name))
                + _st.pack("<H", 0)
                + local_name
                + payload
            )
            return local

        def _cd(central_name, local_offset, payload):
            return (
                b"PK\x01\x02"
                + _st.pack(
                    "<HHHHHHIIIHHHHHII",
                    20, 20, 0, 0, 0, 0x21, 0, len(payload), len(payload),
                    len(central_name), 0, 0, 0, 0, 0o644 << 16, local_offset,
                )
                + central_name
            )

        entries = [
            (b"case.json", b"case2.json", b"{}"),
            (b"manifest.json", b"manifest.json", b"{}"),
        ]
        body = b""
        cds = b""
        offset = 0
        for central_name, local_name, payload in entries:
            body += _entry(central_name, local_name, payload)
            cds += _cd(central_name, offset, payload)
            offset = len(body)
        eocd = (
            b"PK\x05\x06"
            + _st.pack("<HHHHIIH", 0, 0, len(entries), len(entries), len(cds), len(body), 0)
        )
        return body + cds + eocd

    def test_local_vs_central_name_mismatch(self):
        m = load_standalone()
        # [1862,34] NotEq_Is/Lt/Gt: zipfile's infolist (local
        # header "local.txt") and the central-directory parse
        # ("central.txt") disagree, so `!=` is True.  The `is`
        # mutant is always False (different set objects); `<` is
        # False (neither set is a subset of the other); `>` is
        # False likewise.
        data = self._crafted_zip_local_vs_central()
        report = m.verify_bundle_bytes(data)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._status(report, "container_read"), "fail")

    def test_corrupt_zip_entry_exit_one(self):
        m = load_standalone()
        # [1888,30] NumberReplacer: a corrupt zip entry (bad CRC)
        # fails container_read with exit 1.
        import io as _io
        import zipfile as _zf

        case_bytes, case = build_case_bytes()
        entries = {"case.json": case_bytes, "verify.py": b"x"}
        manifest = make_manifest(entries, case_id=case["case_sha256"])
        entries["manifest.json"] = canonical_json(manifest)
        data = bytearray(pack_bundle(entries))
        # Corrupt a byte inside the case.json payload.
        idx = data.find(b"case.json")
        data[idx + 200] ^= 0xFF
        report = m.verify_bundle_bytes(bytes(data))
        self.assertEqual(report["exit_code"], 1)

    def test_invalid_manifest_json_exit_one(self):
        m = load_standalone()
        # NOTE: this test kills the manifest-PARSE exit_code line,
        # not [1931,30] (the depth-exceeded branch) — see
        # test_deep_manifest_exit_one below.
        case_bytes, case = build_case_bytes()
        entries = {"case.json": case_bytes, "verify.py": b"x"}
        manifest = make_manifest(entries, case_id=case["case_sha256"])
        entries["manifest.json"] = b"{not json"
        data = pack_bundle(entries)
        report = m.verify_bundle_bytes(data)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._status(report, "seal_manifest_parse"), "fail")

    def test_over_cap_entry_exit_one(self):
        m = load_standalone()
        # An entry over the 64 MiB per-entry cap fails
        # container_entry_size at the container-checks loop (line
        # 1816) and returns from the first _container_failed gate
        # (line 1841).  NOTE: this does NOT kill [1888,30]
        # (NumberReplacer occ 554/555, the second _container_failed
        # branch) — that branch is reachable only when the central
        # directory lies about an entry size, so the read-time
        # check at line 1875 fires after the 1816 check passed;
        # for a well-formed bundle the two agree, so [1888,30] is
        # unobservable-value (same reason as the read-cap family
        # [1874,74]/[1874,76]).
        case_bytes, case = build_case_bytes()
        big = b"x" * (64 * 1024 * 1024 + 1)
        entries = {"case.json": case_bytes, "verify.py": b"x", "big.bin": big}
        manifest = make_manifest(entries, case_id=case["case_sha256"])
        entries["manifest.json"] = canonical_json(manifest)
        data = pack_bundle(entries)
        report = m.verify_bundle_bytes(data)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._status(report, "container_entry_size"), "fail")

    def test_deep_manifest_exit_one(self):
        m = load_standalone()
        # [1931,30] NumberReplacer occ 568/569: a manifest.json
        # nested 100 deep exceeds the JSON depth limit, so the
        # depth-exceeded branch at line 1931 sets the final
        # exit_code.  The invalid-JSON test does NOT reach it (the
        # parse failure returns from a different line).
        case_bytes, case = build_case_bytes()
        entries = {"case.json": case_bytes, "verify.py": b"x"}
        manifest = make_manifest(entries, case_id=case["case_sha256"])
        deep = {}
        cur = deep
        for _ in range(100):
            nxt = {}
            cur["n"] = nxt
            cur = nxt
        manifest["deep"] = deep
        entries["manifest.json"] = canonical_json(manifest)
        data = pack_bundle(entries)
        report = m.verify_bundle_bytes(data)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._status(report, "seal_manifest_parse"), "fail")

    def test_large_valid_bundle_exit_zero(self):
        m = load_standalone()
        # [1787,23]/[1797,24]/[1960,32] NotEq_IsNot: len() ints
        # above 256 are not cached, so `is not` is True even when
        # the counts are equal.  A valid 300-entry bundle kills
        # all three (the mutant spuriously fails it).
        entries = {f"f{i:04d}.txt": b"x" for i in range(300)}
        case_bytes, case = build_case_bytes()
        entries["case.json"] = case_bytes
        entries["verify.py"] = b"x"
        manifest = make_manifest(entries, case_id=case["case_sha256"])
        entries["manifest.json"] = canonical_json(manifest)
        data = pack_bundle(entries)
        report = m.verify_bundle_bytes(data)
        self.assertEqual(report["exit_code"], 0)

    def test_unsigned_bundle_signature_absent(self):
        m = load_standalone()
        # [2365,29] Eq_LtE: signature == "unavailable" -> `<=`.
        # For an unsigned bundle the signature is "absent";
        # `== "unavailable"` is False but `"absent" <=
        # "unavailable"` is True (a < u), so the mutant takes the
        # "unavailable" branch.
        data, manifest, case = build_bundle()
        report = m.verify_bundle_bytes(data)
        self.assertEqual(report["signature"], "absent")
        self.assertEqual(report["exit_code"], 0)

    def test_signed_bundle_signature_verified(self):
        m = load_standalone()
        # [2365,29] Eq_GtE: signature == "unavailable" -> `>=`.
        # For a signed bundle the signature is "verified";
        # `== "unavailable"` is False but `"verified" >=
        # "unavailable"` is True (v > u), so the mutant takes the
        # "unavailable" branch.
        from textforensics.dsse import sign_envelope
        from textforensics.sealing import public_key_from_seed
        from test_standalone_verify import STANDALONE_PATH

        seed = bytes(range(32))
        case_bytes, case = build_case_bytes()
        verifier_bytes = STANDALONE_PATH.read_bytes()
        entries = {"case.json": case_bytes, "verify.py": verifier_bytes}
        manifest = make_manifest(entries, case_id=case["case_sha256"])
        manifest_bytes = canonical_json(manifest)
        envelope = sign_envelope(
            "textforensics.sealed-bundle-manifest/v1", manifest_bytes, seed
        )
        manifest["context"]["signature"] = envelope
        entries["manifest.json"] = canonical_json(manifest)
        data = pack_bundle(entries)
        report = m.verify_bundle_bytes(data, public_key=public_key_from_seed(seed))
        self.assertEqual(report["signature"], "verified")


def _build_ec_token(digest, *, nonce=424242):
    """Build a CMS time-stamp token signed with an ECDSA (P-256) key.

    Mirrors _build_token but with an EC certificate/signature, so the
    ECDSA branch of _verify_timestamp_token (lines 1046-1064) is
    exercised: the EC point parsing mutants (Sub_* [1061,31],
    Add_BitOr/BitXor [1063,43]/[1064,39]) and the curve/point
    checks.
    """
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    from textforensics.timestamp import (
        OID_MESSAGE_DIGEST,
        OID_SHA256,
        OID_TST_INFO,
        _der_context,
        _der_generalized_time,
        _der_integer,
        _der_octet_string,
        _der_oid,
        _der_sequence,
        _der_set,
    )

    # ecdsa-with-SHA256 OID.
    OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test EC TSA")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    cert_der = cert.public_bytes(Encoding.DER)
    tst_info = _der_sequence(
        _der_integer(1),
        _der_oid("1.2.3.4.5"),
        _der_sequence(
            _der_sequence(_der_oid(OID_SHA256)),
            _der_octet_string(digest),
        ),
        _der_integer(1),
        _der_generalized_time("20261107120000Z"),
        _der_integer(nonce),
    )
    econtent_digest = hashlib.sha256(tst_info).digest()
    signed_attrs = _der_set(
        _der_sequence(
            _der_oid(OID_MESSAGE_DIGEST),
            _der_set(_der_octet_string(econtent_digest)),
        ),
        _der_sequence(
            _der_oid("1.2.840.113549.1.9.5"),
            _der_set(_der_generalized_time("20261107120000Z")),
        ),
    )
    to_sign = b"\x31" + signed_attrs[1:]
    signature = key.sign(to_sign, ec.ECDSA(hashes.SHA256()))
    sid = _der_sequence(cert.issuer.public_bytes(), _der_integer(1))
    signer_info = _der_sequence(
        _der_integer(1),
        sid,
        _der_sequence(_der_oid(OID_SHA256)),
        _der_context(0, signed_attrs[2:], constructed=True),
        _der_sequence(_der_oid(OID_ECDSA_SHA256)),
        _der_octet_string(signature),
    )
    signed_data = _der_sequence(
        _der_integer(1),
        _der_set(_der_sequence(_der_oid(OID_SHA256))),
        _der_sequence(
            _der_oid(OID_TST_INFO),
            _der_context(0, _der_octet_string(tst_info), constructed=True),
        ),
        _der_context(0, cert_der, constructed=True),
        _der_set(signer_info),
    )
    return _der_sequence(
        _der_oid("1.2.840.113549.1.7.2"),
        _der_context(0, signed_data, constructed=True),
    )


class TestVerifyTimestampTokenEcKill(unittest.TestCase):
    """_verify_timestamp_token ECDSA branch: Sub_* [1061,31],
    Add_BitOr/BitXor [1063,43]/[1064,39], NumberReplacer [1061,33]."""

    DIGEST = hashlib.sha256(b"case bytes").digest()

    def test_ec_token_verifies(self):
        # A valid ECDSA token exercises the EC point parsing: the
        # Sub_* mutants change `(len(point_der) - 1) // 2` (the
        # coordinate size) and the Add_* mutants change the slice
        # offsets `1 + size`; all of them corrupt the point and the
        # signature fails.
        m = load_standalone()
        info, errors = m._verify_timestamp_token(
            _build_ec_token(self.DIGEST), self.DIGEST
        )
        self.assertEqual(errors, [])
        self.assertIs(info["present"], True)

    def test_ec_token_bad_signature_is_not_verified(self):
        # A tampered ECDSA signature does not verify (the
        # _ecdsa_verify path is exercised and its result is False).
        m = load_standalone()
        token = bytearray(_build_ec_token(self.DIGEST))
        token[-10] ^= 0xFF
        info, errors = m._verify_timestamp_token(bytes(token), self.DIGEST)
        self.assertTrue(errors)
