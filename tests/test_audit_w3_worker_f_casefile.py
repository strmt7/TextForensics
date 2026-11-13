"""W3 Worker F3 kill tests for the casefile module (audit-w3-f).

Covers the 21 killable runtime survivors of the 54 casefile survivors
(22 annotation + 3 domain-equivalent `*,` markers are baseline entries,
see audit-w3-worker-f.md §6). Each test targets a specific mutant; the
re-proof (audit-w3-f3-reprove-casefile.py) hand-applies each mutant
with cosmic-ray mutate_code and runs the owning test class.

CORRECTIONS to the F2 classify-notes (verified against the source):
- The `!=` -> `<` / `>` kill inputs are the OPPOSITE of what the notes
  say: for `x != K` -> `x < K` the distinguishing input has x > K
  (`<` False while `!=` True); for `-> x > K` it has x < K. So:
  [1146,30] Lt <- algorithm "ed2551:", Gt <- "ed25518";
  [1151,28] Lt <- 65-char fingerprint, Gt <- 63-char;
  [1734,78] Lt <- 33-byte seed, Gt <- 31-byte seed.
- The version-comparison mutants in seal_case_file / _verify_case_sections
  / verify_case_file are DOMAIN-EQUIVALENT, not killable: seal_case_file
  rejects every version outside {"v1","v2","v3","v4"} up front, and
  _verify_case_sections is called only with "v3"/"v4" (verify_case_file
  + tests). On those domains `==` and `<=` / `>=` coincide. The notes'
  version="v0"/"v5" kill plans cannot reach the checks (v0 raises at
  the guard; v5 is out of contract). See §6 for the full reasons.
"""

import unittest

from textforensics.casefile import (
    CASE_SCHEMA_V3,
    _is_superseded_signature,
    _verify_case_sections,
    append_custody_entry,
    verify_case_file,
)

VALID_FINGERPRINT = "ab" * 32  # 64 hex chars


def _valid_superseded_entry(**overrides):
    entry = {
        "algorithm": "ed25519",
        "key_fingerprint": VALID_FINGERPRINT,
        "signer": {"identity": "a", "role": "b"},
        "dsse": {"payload": "x"},
        "superseded_reason": "re-signed-after-custody-append",
        "superseded_at_utc": "2026-01-01T00:00:00+00:00",
    }
    entry.update(overrides)
    return entry


class TestIsSupersededSignatureKill(unittest.TestCase):
    """ReplaceFalseWithTrue [1145,15]/[1147,15]/[1154,15]/[1156,15]/
    [1158,15]/[1160,15]; ReplaceComparisonOperator_NotEq_Lt/Gt
    [1146,30]/[1151,28]; ReplaceAndWithOr [1161,59];
    ReplaceOrWithAnd [1151,8]/[1152,8]/[1159,59] — all in
    `_is_superseded_signature`."""

    def test_valid_entry_is_true(self):
        self.assertIs(_is_superseded_signature(_valid_superseded_entry()), True)

    def test_non_mapping_entry_is_false(self):
        # [1145,15] ReplaceFalseWithTrue (entry not a Mapping).
        self.assertIs(_is_superseded_signature("not-a-mapping"), False)

    def test_non_ed25519_algorithm_is_false(self):
        # [1147,15] ReplaceFalseWithTrue.
        self.assertIs(_is_superseded_signature(_valid_superseded_entry(algorithm="rsa")), False)

    def test_bad_fingerprint_shape_is_false(self):
        # [1154,15] ReplaceFalseWithTrue (non-hex, len 2).
        self.assertIs(
            _is_superseded_signature(_valid_superseded_entry(key_fingerprint="zz")),
            False,
        )

    def test_non_mapping_signer_is_false(self):
        # [1156,15] ReplaceFalseWithTrue.
        self.assertIs(_is_superseded_signature(_valid_superseded_entry(signer="x")), False)

    def test_non_mapping_dsse_is_false(self):
        # [1158,15] ReplaceFalseWithTrue.
        self.assertIs(_is_superseded_signature(_valid_superseded_entry(dsse="x")), False)

    def test_empty_reason_is_false(self):
        # [1160,15] ReplaceFalseWithTrue.
        self.assertIs(
            _is_superseded_signature(_valid_superseded_entry(superseded_reason="")),
            False,
        )

    def test_algorithm_greater_than_ed25519_kills_not_eq_lt(self):
        # [1146,30] NotEq_Lt: "ed2551:" > "ed25519", so `!=` is True
        # (original returns False) but `<` is False (mutant proceeds
        # to True). "ed25518" would NOT kill Lt (it is <, so the
        # mutant also returns False).
        self.assertIs(
            _is_superseded_signature(_valid_superseded_entry(algorithm="ed2551:")),
            False,
        )

    def test_algorithm_less_than_ed25519_kills_not_eq_gt(self):
        # [1146,30] NotEq_Gt: "ed25518" < "ed25519", so `!=` is True
        # but `>` is False (mutant proceeds to True).
        self.assertIs(
            _is_superseded_signature(_valid_superseded_entry(algorithm="ed25518")),
            False,
        )

    def test_long_fingerprint_kills_len_not_eq_lt(self):
        # [1151,28] NotEq_Lt: 65 chars, so `!= 64` is True (original
        # returns False) but `65 < 64` is False (mutant proceeds).
        self.assertIs(
            _is_superseded_signature(_valid_superseded_entry(key_fingerprint="a" * 65)),
            False,
        )

    def test_short_fingerprint_kills_len_not_eq_gt(self):
        # [1151,28] NotEq_Gt: 63 chars, so `!= 64` is True but
        # `63 > 64` is False (mutant proceeds to True).
        self.assertIs(
            _is_superseded_signature(_valid_superseded_entry(key_fingerprint="a" * 63)),
            False,
        )

    def test_empty_or_non_string_timestamp_is_false(self):
        # [1161,59] ReplaceAndWithOr: "" is a str (side 1 True) with
        # bool False; 123 is not a str (side 1 False) with bool True.
        # Original False in both; mutant `or` True.
        self.assertIs(
            _is_superseded_signature(_valid_superseded_entry(superseded_at_utc="")),
            False,
        )
        self.assertIs(
            _is_superseded_signature(_valid_superseded_entry(superseded_at_utc=123)),
            False,
        )

    def test_length_only_fingerprint_kills_first_or(self):
        # [1151,8] ReplaceOrWithAnd (first `or` of the fingerprint
        # guard -> `and`): 63-char all-hex makes ONLY side 2 True.
        # Original (A or B) or C True -> False; mutant (A and B) or C
        # False -> proceeds to True.
        self.assertIs(
            _is_superseded_signature(_valid_superseded_entry(key_fingerprint="a" * 63)),
            False,
        )

    def test_non_hex_fingerprint_kills_second_or(self):
        # [1152,8] ReplaceOrWithAnd (second `or` -> `and`): a 64-char
        # fingerprint with one non-hex char makes ONLY side 3 True.
        # Original True -> False; mutant A or (B and C) False ->
        # proceeds to True.
        self.assertIs(
            _is_superseded_signature(_valid_superseded_entry(key_fingerprint="a" * 63 + "g")),
            False,
        )

    def test_empty_or_non_string_reason_is_false(self):
        # [1159,59] ReplaceOrWithAnd: "" (side 1 False, side 2 True)
        # and 123 (side 1 True, side 2 False) both make the original
        # guard True -> False; the mutant `and` is False -> True.
        self.assertIs(
            _is_superseded_signature(_valid_superseded_entry(superseded_reason="")),
            False,
        )
        self.assertIs(
            _is_superseded_signature(_valid_superseded_entry(superseded_reason=123)),
            False,
        )


class TestVerifyCaseSectionsKill(unittest.TestCase):
    """ReplaceOrWithAnd [1288,12] in `_verify_case_sections`."""

    def test_malformed_previous_signature_is_error(self):
        # previous_signatures is a LIST containing one malformed entry:
        # side 1 (not a list) False, side 2 (any malformed) True ->
        # original appends the error; mutant `and` False -> no error.
        case = {"seal": {"previous_signatures": ["not-a-mapping"]}}
        errors = _verify_case_sections(case, {}, version="v3")
        self.assertIn("v3_seal_previous_signatures_invalid", errors)


class TestVerifyCaseFileKill(unittest.TestCase):
    """ReplaceAndWithOr [1661,42] in `verify_case_file`."""

    def test_empty_previous_signatures_no_warning(self):
        # previous_signatures is an EMPTY list: isinstance True, bool
        # False -> original appends no warning; mutant `or` True ->
        # appends the prior_signature_superseded warning.
        payload = {
            "schema": CASE_SCHEMA_V3,
            "seal": {"previous_signatures": []},
            "raw_text_included": False,
            "case_sha256": "0" * 64,
            "forensic_bundle": {},
        }
        result = verify_case_file(payload)
        self.assertFalse(
            any(w.startswith("prior_signature_superseded") for w in result["warnings"])
        )


class TestAppendCustodyKill(unittest.TestCase):
    """ReplaceComparisonOperator_NotEq_Lt/Gt [1734,78];
    ReplaceOrWithAnd [1734,57]/[1738,40]/[1738,70] — all in
    `append_custody_entry` (case schema v3, no current signature)."""

    def _case(self):
        return {"schema": CASE_SCHEMA_V3}

    def test_long_seed_kills_len_not_eq_lt(self):
        # [1734,78] NotEq_Lt: 33 bytes, so `!= 32` True (original
        # raises) but `33 < 32` False (mutant proceeds).
        with self.assertRaisesRegex(ValueError, "signing_seed must be 32 bytes"):
            append_custody_entry(
                self._case(),
                actor="a",
                action="b",
                signing_seed=b"x" * 33,
                signer={"identity": "i", "role": "r"},
            )

    def test_short_seed_kills_len_not_eq_gt(self):
        # [1734,78] NotEq_Gt: 31 bytes, so `!= 32` True but
        # `31 > 32` False (mutant proceeds).
        with self.assertRaisesRegex(ValueError, "signing_seed must be 32 bytes"):
            append_custody_entry(
                self._case(),
                actor="a",
                action="b",
                signing_seed=b"x" * 31,
                signer={"identity": "i", "role": "r"},
            )

    def test_wrong_type_or_length_seed_is_error(self):
        # [1734,57] ReplaceOrWithAnd: a 32-char str (side 1 True,
        # side 2 False) and 31-byte bytes (side 1 False, side 2
        # True) both make the original guard True -> raise; the
        # mutant `and` is False in both -> proceeds.
        with self.assertRaisesRegex(ValueError, "signing_seed must be 32 bytes"):
            append_custody_entry(
                self._case(),
                actor="a",
                action="b",
                signing_seed="x" * 32,
                signer={"identity": "i", "role": "r"},
            )
        with self.assertRaisesRegex(ValueError, "signing_seed must be 32 bytes"):
            append_custody_entry(
                self._case(),
                actor="a",
                action="b",
                signing_seed=b"x" * 31,
                signer={"identity": "i", "role": "r"},
            )

    def test_signer_without_identity_is_error(self):
        # [1738,40] ReplaceOrWithAnd (first `or` -> `and`):
        # {"role": "y"} makes side 2 (no identity) alone True.
        # Original (A and B) or C -> True -> raise; mutant
        # (A and B) or C with A False, B True, C False -> False.
        with self.assertRaisesRegex(ValueError, "signer needs identity and role"):
            append_custody_entry(
                self._case(),
                actor="a",
                action="b",
                signing_seed=b"x" * 32,
                signer={"role": "y"},
            )

    def test_signer_without_role_is_error(self):
        # [1738,70] ReplaceOrWithAnd (second `or` -> `and`):
        # {"identity": "x"} makes side 3 (no role) alone True.
        # Original True -> raise; mutant A or (B and C) False.
        with self.assertRaisesRegex(ValueError, "signer needs identity and role"):
            append_custody_entry(
                self._case(),
                actor="a",
                action="b",
                signing_seed=b"x" * 32,
                signer={"identity": "x"},
            )
