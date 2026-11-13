"""W3 Worker F3 kill tests for the sealing module (audit-w3-f).

Covers the 38 killable runtime survivors of the 113 sealing survivors
(11 annotation + 7 domain-equivalent + 2 unobservable-value + 55
platform-gated entries are baseline entries, see audit-w3-worker-f.md
§6). Each test targets a specific mutant; the re-proof
(audit-w3-f3-reprove-sealing.py) hand-applies each mutant with
cosmic-ray mutate_code and runs the owning test class.

CORRECTIONS to the F2 classify-notes (verified against the source):
- The `!=` -> `<` / `>` kill inputs are the OPPOSITE of what the notes
  say: for `x != K` -> `x < K` the distinguishing input has x > K
  (`<` False while `!=` True); for `-> x > K` it has x < K. So:
  [547,73]/[683,73] Lt <- 33-byte key, Gt <- 31-byte;
  [578,34]/[701,34] Lt <- "ed2551:", Gt <- "ed25518";
  [581,40]/[703,40] Lt <- "f"*64, Gt <- "0"*64.
- The platform-gated count is 55, not 54 (F2 undercounted the
  NumberReplacer mutants in _restrict_to_owner_windows: 30, not 24).
- The [644,16] Eq_GtE timeout mutant is killable with contract="zz"
  (the contract guard runs inside case_signing_payload, called AFTER
  the line-644 dispatch, so "zz" reaches the check).
"""

import base64
import errno
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from textforensics.sealing import (
    CASE_SIGNING_CONTRACT_V1,
    CASE_SIGNING_CONTRACT_V2,
    _publish_no_clobber,
    _require_signature_record,
    _restrict_to_owner_windows,
    build_signature_record,
    case_signing_payload,
    fingerprint,
    generate_sealing_key,
    public_key_from_seed,
    save_sealing_key,
    sign_case_body,
    verify_case_signature,
)

SEED = bytes(range(32))
PUBLIC_KEY = public_key_from_seed(SEED)
EXPECTED_FINGERPRINT = fingerprint(PUBLIC_KEY)


def _case_static():
    return {
        "schema": "textforensics.case-file/v2",
        "tool": {"name": "TextForensics", "version": "0.2.0"},
        "created_at_utc": "2026-11-07T06:00:00+00:00",
        "case_sha256": "a" * 64,
        "raw_text_included": False,
        "seal": {"sha256": "b" * 64},
        "forensic_bundle": {"schema": "textforensics.forensic-bundle/v2"},
    }


def _signed_v2_case():
    key = generate_sealing_key("auditor@example.test", "auditor")
    seed = base64.b64decode(key["seed_b64"])
    public_key = base64.b64decode(key["public_key_b64"])
    case = _case_static()
    case["seal"]["signature"] = build_signature_record(
        public_key, "auditor@example.test", "auditor"
    )
    envelope = sign_case_body(case, seed)
    case["seal"]["signature"]["dsse"] = envelope
    return case, public_key, key


def _signed_v1_case():
    key = generate_sealing_key("auditor@example.test", "auditor")
    seed = base64.b64decode(key["seed_b64"])
    public_key = base64.b64decode(key["public_key_b64"])
    case = _case_static()
    envelope = sign_case_body(case, seed, contract=CASE_SIGNING_CONTRACT_V1)
    case["seal"]["signature"] = {
        "algorithm": "ed25519",
        "key_fingerprint": fingerprint(public_key),
        "signer": {"identity": "auditor@example.test", "role": "auditor"},
        "dsse": envelope,
    }
    return case, public_key, key


def _valid_record(**overrides):
    record = build_signature_record(PUBLIC_KEY, "alice", "signer")
    record.update(overrides)
    return record


def _case_with_record(**overrides):
    return {"seal": {"signature": _valid_record(**overrides)}}


class TestSaveSealingKeyKill(unittest.TestCase):
    """ReplaceTrueWithFalse [250,61] (sort_keys); NumberReplacer
    [250,48] occ 2/3 (indent=2)."""

    def test_keys_saved_sorted(self):
        # [250,61]: the key dict is inserted in reverse-sorted order;
        # the file bytes must list the keys sorted. The mutant
        # (sort_keys=False) keeps insertion order.
        key = generate_sealing_key("auditor@example.test", "auditor")
        reversed_key = dict(reversed(list(key.items())))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "k.key.json"
            save_sealing_key(path, reversed_key)
            raw = path.read_text()
        positions = [raw.index(f'"{name}"') for name in sorted(key)]
        self.assertEqual(positions, sorted(positions))

    def test_exact_saved_bytes(self):
        # [250,48] occ 2/3: indent 1 and 3 both change the file bytes.
        key = generate_sealing_key("auditor@example.test", "auditor")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "k.key.json"
            save_sealing_key(path, key)
            raw = path.read_bytes()
        expected = json.dumps(dict(key), indent=2, sort_keys=True).encode("utf-8") + b"\n"
        self.assertEqual(raw, expected)


class TestRestrictToOwnerWindowsKill(unittest.TestCase):
    """ExceptionReplacer [324,11] (AttributeError -> OSError)."""

    def test_direct_call_raises_oserror_on_posix(self):
        # On POSIX ctypes.windll does not exist, so the AttributeError
        # at line 321 is converted to OSError at [324,11]. The mutant
        # (except CosmicRayTestingException) propagates AttributeError.
        with self.assertRaisesRegex(
            OSError, "Windows owner-only ACL restriction requires Windows APIs"
        ):
            _restrict_to_owner_windows(Path("/tmp/x.key"))


class TestPublishNoClobberKill(unittest.TestCase):
    """ExceptionReplacer [304,11] (OSError)."""

    def test_non_file_exists_oserror_is_wrapped(self):
        # os.link raising a non-FileExistsError OSError (EXDEV) must
        # be wrapped in "could not publish sealing key file". The
        # mutant propagates the raw OSError.
        with tempfile.TemporaryDirectory() as tmp:
            temp_path = Path(tmp) / "t.tmp"
            temp_path.write_bytes(b"x")
            destination = Path(tmp) / "d.key.json"
            with (
                mock.patch(
                    "textforensics.sealing.os.link",
                    side_effect=OSError(errno.EXDEV, "Invalid cross-device link"),
                ),
                self.assertRaisesRegex(OSError, "could not publish sealing key file"),
            ):
                _publish_no_clobber(temp_path, destination)


class TestBuildSignatureRecordKill(unittest.TestCase):
    """ReplaceComparisonOperator_NotEq_Lt/Gt [547,73];
    ReplaceOrWithAnd [547,54]/[549,37]/[551,33]."""

    def test_long_key_kills_len_not_eq_lt(self):
        # [547,73] Lt: 33 bytes, so `!= 32` True (raise) but
        # `33 < 32` False (mutant proceeds and returns a record).
        with self.assertRaisesRegex(ValueError, "^public key must be exactly 32 bytes$"):
            build_signature_record(b"x" * 33, "alice", "signer")

    def test_short_key_kills_len_not_eq_gt(self):
        # [547,73] Gt: 31 bytes, so `!= 32` True but `31 > 32` False.
        with self.assertRaisesRegex(ValueError, "^public key must be exactly 32 bytes$"):
            build_signature_record(b"x" * 31, "alice", "signer")

    def test_str_key_kills_type_or_length_or(self):
        # [547,54] OrWithAnd: a 32-char str is the wrong type but the
        # right length (side 1 True, side 2 False) -> original raises;
        # mutant `and` False -> proceeds (bytes(str) raises TypeError).
        with self.assertRaisesRegex(ValueError, "^public key must be exactly 32 bytes$"):
            build_signature_record("x" * 32, "alice", "signer")

    def test_short_bytes_key_kills_type_or_length_or(self):
        # [547,54] OrWithAnd: 31-byte bytes is the right type but the
        # wrong length (side 1 False, side 2 True) -> original raises;
        # mutant `and` False -> proceeds and returns a record.
        with self.assertRaisesRegex(ValueError, "^public key must be exactly 32 bytes$"):
            build_signature_record(b"x" * 31, "alice", "signer")

    def test_empty_or_non_string_identity_is_error(self):
        # [549,37] OrWithAnd: "" (side 1 False, side 2 True) and 123
        # (side 1 True, side 2 False) both make the original guard
        # True -> raise; the mutant `and` is False in both.
        with self.assertRaisesRegex(ValueError, "signer identity must be a non-empty string"):
            build_signature_record(PUBLIC_KEY, "", "signer")
        with self.assertRaisesRegex(ValueError, "signer identity must be a non-empty string"):
            build_signature_record(PUBLIC_KEY, 123, "signer")

    def test_empty_or_non_string_role_is_error(self):
        # [551,33] OrWithAnd: same shape for the role guard.
        with self.assertRaisesRegex(ValueError, "signer role must be a non-empty string"):
            build_signature_record(PUBLIC_KEY, "alice", "")
        with self.assertRaisesRegex(ValueError, "signer role must be a non-empty string"):
            build_signature_record(PUBLIC_KEY, "alice", 123)


class TestRequireSignatureRecordKill(unittest.TestCase):
    """ReplaceComparisonOperator_NotEq_Lt/Gt [578,34]/[581,40];
    NotEq_Is [581,40]; NotEq_IsNot [578,34];
    ReplaceOrWithAnd [586,8]/[587,8]/[588,8]/[589,8]."""

    def test_greater_algorithm_kills_not_eq_lt(self):
        # [578,34] Lt: "ed2551:" > "ed25519", so `!=` True (raise)
        # but `<` False (mutant proceeds).
        case = _case_with_record(algorithm="ed2551:")
        with self.assertRaisesRegex(ValueError, "signer record algorithm must be ed25519"):
            _require_signature_record(case, SEED)

    def test_lesser_algorithm_kills_not_eq_gt(self):
        # [578,34] Gt: "ed25518" < "ed25519", so `!=` True but
        # `>` False (mutant proceeds).
        case = _case_with_record(algorithm="ed25518")
        with self.assertRaisesRegex(ValueError, "signer record algorithm must be ed25519"):
            _require_signature_record(case, SEED)

    def test_runtime_built_algorithm_passes(self):
        # [578,34] NotEq_IsNot: a runtime-built "ed25519" is a
        # distinct object, so the mutant `is not` is True -> raises;
        # the original `!=` is False -> passes.
        runtime_alg = "".join(["ed255", "19"])
        self.assertIsNot(runtime_alg, "ed25519")
        case = _case_with_record(algorithm=runtime_alg)
        _require_signature_record(case, SEED)  # must not raise

    def test_max_fingerprint_kills_not_eq_lt(self):
        # [581,40] Lt: "f"*64 is the maximum hex string, so it is
        # greater than the expected fingerprint: `!=` True (raise)
        # but `<` False (mutant proceeds).
        case = _case_with_record(key_fingerprint="f" * 64)
        with self.assertRaisesRegex(ValueError, "signer record key_fingerprint does not match"):
            _require_signature_record(case, SEED)

    def test_min_fingerprint_kills_not_eq_gt(self):
        # [581,40] Gt: "0"*64 is the minimum hex string: `!=` True
        # but `>` False (mutant proceeds).
        case = _case_with_record(key_fingerprint="0" * 64)
        with self.assertRaisesRegex(ValueError, "signer record key_fingerprint does not match"):
            _require_signature_record(case, SEED)

    def test_runtime_built_fingerprint_passes(self):
        # [581,40] NotEq_Is: a runtime-built equal fingerprint is a
        # distinct object, so the mutant `is` is True -> raises; the
        # original `!=` is False -> passes.
        runtime_fp = "".join([EXPECTED_FINGERPRINT[:32], EXPECTED_FINGERPRINT[32:]])
        self.assertIsNot(runtime_fp, EXPECTED_FINGERPRINT)
        case = _case_with_record(key_fingerprint=runtime_fp)
        _require_signature_record(case, SEED)  # must not raise

    def test_non_mapping_signer_is_error(self):
        # [586,8] OrWithAnd (first `or`): signer "x" makes ONLY side
        # 1 (not a Mapping) True.
        case = _case_with_record(signer="x")
        with self.assertRaisesRegex(
            ValueError, "signer record needs a non-empty identity and role"
        ):
            _require_signature_record(case, SEED)

    def test_non_string_identity_is_error(self):
        # [587,8] OrWithAnd (second `or`): identity=123 makes ONLY
        # side 2 (identity not a str) True.
        case = _case_with_record(signer={"identity": 123, "role": "r"})
        with self.assertRaisesRegex(
            ValueError, "signer record needs a non-empty identity and role"
        ):
            _require_signature_record(case, SEED)

    def test_empty_identity_is_error(self):
        # [588,8] OrWithAnd (third `or`): identity="" makes ONLY
        # side 3 (empty identity) True.
        case = _case_with_record(signer={"identity": "", "role": "r"})
        with self.assertRaisesRegex(
            ValueError, "signer record needs a non-empty identity and role"
        ):
            _require_signature_record(case, SEED)

    def test_non_string_role_is_error(self):
        # [589,8] OrWithAnd (fourth `or`): role=123 makes ONLY side
        # 4 (role not a str) True.
        case = _case_with_record(signer={"identity": "i", "role": 123})
        with self.assertRaisesRegex(
            ValueError, "signer record needs a non-empty identity and role"
        ):
            _require_signature_record(case, SEED)


class TestCaseSigningPayloadKill(unittest.TestCase):
    """ReplaceComparisonOperator_Eq_Is [621,20]."""

    def test_runtime_built_v1_contract_removes_signature(self):
        # [621,20] Eq_Is: a runtime-built V1 contract is a distinct
        # object, so the mutant `is` is False -> else branch (only
        # dsse removed); the original `==` is True -> the whole
        # seal.signature is removed.
        runtime_v1 = "".join([CASE_SIGNING_CONTRACT_V1[:20], CASE_SIGNING_CONTRACT_V1[20:]])
        self.assertIsNot(runtime_v1, CASE_SIGNING_CONTRACT_V1)
        case = _case_static()
        case["seal"]["signature"] = _valid_record()
        payload = json.loads(case_signing_payload(case, contract=runtime_v1))
        self.assertNotIn("signature", payload["seal"])


class TestSignCaseBodyKill(unittest.TestCase):
    """ReplaceComparisonOperator_Eq_Is [644,16];
    ReplaceComparisonOperator_Eq_GtE [644,16] (timeout mutant)."""

    def test_runtime_built_v2_contract_requires_record(self):
        # [644,16] Eq_Is: a runtime-built V2 contract is a distinct
        # object, so the mutant `is` is False -> skips the require
        # check and signs; the original `==` is True -> raises via
        # _require_signature_record on the record-less case.
        runtime_v2 = "".join([CASE_SIGNING_CONTRACT_V2[:20], CASE_SIGNING_CONTRACT_V2[20:]])
        self.assertIsNot(runtime_v2, CASE_SIGNING_CONTRACT_V2)
        with self.assertRaisesRegex(ValueError, "no pre-placed signer record"):
            sign_case_body(_case_static(), SEED, contract=runtime_v2)

    def test_unknown_contract_message(self):
        # [644,16] Eq_GtE: "zz" sorts above V2, so the mutant `>=`
        # is True -> calls _require_signature_record first (record
        # error); the original `==` is False -> case_signing_payload
        # raises the unknown-contract error. The contract guard runs
        # inside case_signing_payload, AFTER the line-644 dispatch.
        case = _case_static()
        case["seal"] = {}
        with self.assertRaisesRegex(ValueError, "unknown case signing contract: 'zz'"):
            sign_case_body(case, SEED, contract="zz")


class TestVerifyCaseSignatureKill(unittest.TestCase):
    """ReplaceComparisonOperator_NotEq_Lt/Gt [683,73]/[701,34]/
    [703,40]; NotEq_IsNot [701,34]; ReplaceOrWithAnd [683,54]/
    [708,8]/[709,8]/[710,8]/[711,8]; ReplaceComparisonOperator_Eq_Is
    [695,20]/[697,22]; ExceptionReplacer [717,12]/[717,24];
    ReplaceFalseWithTrue [722,21]."""

    def test_long_key_fails(self):
        # [683,73] Lt: 33 bytes, so `!= 32` True (_fail) but
        # `33 < 32` False (mutant proceeds).
        case, _, _ = _signed_v2_case()
        result = verify_case_signature(case, b"x" * 33)
        self.assertIs(result["valid"], False)
        self.assertIn("public key must be exactly 32 bytes", result["errors"])

    def test_short_key_fails(self):
        # [683,73] Gt: 31 bytes, so `!= 32` True but `31 > 32` False.
        case, _, _ = _signed_v2_case()
        result = verify_case_signature(case, b"x" * 31)
        self.assertIs(result["valid"], False)
        self.assertIn("public key must be exactly 32 bytes", result["errors"])

    def test_str_or_short_key_fails(self):
        # [683,54] OrWithAnd: a 32-char str (side 1 True, side 2
        # False) and 31-byte bytes (side 1 False, side 2 True) both
        # make the original guard True -> _fail; the mutant `and`
        # is False in both -> proceeds.
        case, _, _ = _signed_v2_case()
        result = verify_case_signature(case, "x" * 32)
        self.assertIs(result["valid"], False)
        self.assertIn("public key must be exactly 32 bytes", result["errors"])
        result = verify_case_signature(case, b"x" * 31)
        self.assertIs(result["valid"], False)
        self.assertIn("public key must be exactly 32 bytes", result["errors"])

    def test_runtime_built_v2_payload_type_dispatches_v2(self):
        # [695,20] Eq_Is: a runtime-built V2 payloadType is a
        # distinct object, so the mutant `is` is False -> "unknown
        # contract" _fail; the original dispatches to v2.
        case, public_key, _ = _signed_v2_case()
        runtime_v2 = "".join([CASE_SIGNING_CONTRACT_V2[:20], CASE_SIGNING_CONTRACT_V2[20:]])
        self.assertIsNot(runtime_v2, CASE_SIGNING_CONTRACT_V2)
        case["seal"]["signature"]["dsse"]["payloadType"] = runtime_v2
        result = verify_case_signature(case, public_key)
        self.assertEqual(result["signing_contract"], "v2")

    def test_runtime_built_v1_payload_type_dispatches_v1(self):
        # [697,22] Eq_Is: same shape for the v1 contract.
        case, public_key, _ = _signed_v1_case()
        runtime_v1 = "".join([CASE_SIGNING_CONTRACT_V1[:20], CASE_SIGNING_CONTRACT_V1[20:]])
        self.assertIsNot(runtime_v1, CASE_SIGNING_CONTRACT_V1)
        case["seal"]["signature"]["dsse"]["payloadType"] = runtime_v1
        result = verify_case_signature(case, public_key)
        self.assertEqual(result["signing_contract"], "v1")

    def test_lesser_algorithm_fails(self):
        # [701,34] Gt: "ed25518" < "ed25519", so `!=` True but
        # `>` False (mutant proceeds).
        case, public_key, _ = _signed_v2_case()
        case["seal"]["signature"]["algorithm"] = "ed25518"
        result = verify_case_signature(case, public_key)
        self.assertIs(result["valid"], False)
        self.assertIn("case seal signature algorithm is not ed25519", result["errors"])

    def test_runtime_built_algorithm_passes(self):
        # [701,34] NotEq_IsNot: a runtime-built "ed25519" is a
        # distinct object, so the mutant `is not` is True -> _fail;
        # the original `!=` is False -> the valid case verifies.
        case, public_key, _ = _signed_v2_case()
        runtime_alg = "".join(["ed255", "19"])
        self.assertIsNot(runtime_alg, "ed25519")
        case["seal"]["signature"]["algorithm"] = runtime_alg
        result = verify_case_signature(case, public_key)
        self.assertIs(result["valid"], True)

    def test_max_fingerprint_fails(self):
        # [703,40] Lt: "f"*64 is the maximum hex string, so `!=`
        # True (_fail) but `<` False (mutant proceeds).
        case, public_key, _ = _signed_v2_case()
        case["seal"]["signature"]["key_fingerprint"] = "f" * 64
        result = verify_case_signature(case, public_key)
        self.assertIs(result["valid"], False)
        self.assertIn(
            "case seal key_fingerprint does not match the supplied public key",
            result["errors"],
        )

    def test_non_mapping_signer_fails(self):
        # [708,8] OrWithAnd (first `or`): signer "x" makes ONLY side
        # 1 (not a Mapping) True.
        case, public_key, _ = _signed_v2_case()
        case["seal"]["signature"]["signer"] = "x"
        result = verify_case_signature(case, public_key)
        self.assertIs(result["valid"], False)
        self.assertIn(
            "case seal signer must carry a non-empty identity and role",
            result["errors"],
        )

    def test_non_string_identity_fails(self):
        # [709,8] OrWithAnd (second `or`): identity=123 makes ONLY
        # side 2 True.
        case, public_key, _ = _signed_v2_case()
        case["seal"]["signature"]["signer"] = {"identity": 123, "role": "r"}
        result = verify_case_signature(case, public_key)
        self.assertIs(result["valid"], False)
        self.assertIn(
            "case seal signer must carry a non-empty identity and role",
            result["errors"],
        )

    def test_empty_identity_fails(self):
        # [710,8] OrWithAnd (third `or`): identity="" makes ONLY
        # side 3 True.
        case, public_key, _ = _signed_v2_case()
        case["seal"]["signature"]["signer"] = {"identity": "", "role": "r"}
        result = verify_case_signature(case, public_key)
        self.assertIs(result["valid"], False)
        self.assertIn(
            "case seal signer must carry a non-empty identity and role",
            result["errors"],
        )

    def test_non_string_role_fails(self):
        # [711,8] OrWithAnd (fourth `or`): role=123 makes ONLY side
        # 4 True.
        case, public_key, _ = _signed_v2_case()
        case["seal"]["signature"]["signer"] = {"identity": "i", "role": 123}
        result = verify_case_signature(case, public_key)
        self.assertIs(result["valid"], False)
        self.assertIn(
            "case seal signer must carry a non-empty identity and role",
            result["errors"],
        )

    def test_circular_body_is_canonicalisation_fail(self):
        # [717,12] ExceptionReplacer (ValueError): a circular body
        # makes json.dumps raise ValueError, caught as the
        # "case body cannot be canonicalised" _fail. The mutant
        # propagates the ValueError.
        case, public_key, _ = _signed_v2_case()
        case["self"] = case
        result = verify_case_signature(case, public_key)
        self.assertIs(result["valid"], False)
        self.assertTrue(any("case body cannot be canonicalised" in e for e in result["errors"]))

    def test_set_value_body_is_canonicalisation_fail(self):
        # [717,24] ExceptionReplacer (TypeError): a set value makes
        # json.dumps raise TypeError, caught as the same _fail.
        case, public_key, _ = _signed_v2_case()
        case["extra"] = {1, 2}
        result = verify_case_signature(case, public_key)
        self.assertIs(result["valid"], False)
        self.assertTrue(any("case body cannot be canonicalised" in e for e in result["errors"]))

    def test_tampered_payload_is_invalid(self):
        # [722,21] ReplaceFalseWithTrue ("valid": False in the
        # verify_envelope-failure return): tampering the envelope
        # signature makes verify_envelope fail, so the function
        # returns valid False at line 722; the mutant returns True.
        # (Tampering the case body instead is caught later, at the
        # "signed payload does not match the case body" _fail, and
        # never reaches line 722.)
        case, public_key, _ = _signed_v2_case()
        sig = case["seal"]["signature"]["dsse"]["signatures"][0]["sig"]
        flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
        case["seal"]["signature"]["dsse"]["signatures"][0]["sig"] = flipped
        result = verify_case_signature(case, public_key)
        self.assertIs(result["valid"], False)
