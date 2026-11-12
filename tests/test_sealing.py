"""Tests for pure-stdlib Ed25519 (RFC 8032), DSSE envelopes and sealing keys."""

from __future__ import annotations

import base64
import copy
import json
import os
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from textforensics.casefile import canonical_json_bytes
from textforensics.dsse import (
    PAYLOAD_TYPE_CASE_FILE,
    PAYLOAD_TYPE_SEALED_BUNDLE_MANIFEST,
    pae,
    sign_envelope,
    verify_envelope,
)
from textforensics.ed25519 import (
    fingerprint,
    keygen,
    public_key_from_seed,
    sign,
    verify,
)
from textforensics.sealing import (
    case_signing_payload,
    generate_sealing_key,
    load_sealing_key,
    public_key_info,
    save_sealing_key,
    sign_case_body,
    verify_case_signature,
)

# RFC 8032 section 7.1 test vectors, copied from
# https://www.rfc-editor.org/rfc/rfc8032.txt (fetched 2026-11-07).
# Each entry is (secret key / seed, public key, message, signature), hex.
RFC8032_VECTORS = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]


class Ed25519Tests(unittest.TestCase):
    def test_rfc8032_vectors(self):
        for seed_hex, public_hex, message_hex, signature_hex in RFC8032_VECTORS:
            with self.subTest(vector=seed_hex[:8]):
                seed = bytes.fromhex(seed_hex)
                public_key = bytes.fromhex(public_hex)
                message = bytes.fromhex(message_hex)
                signature = bytes.fromhex(signature_hex)
                self.assertEqual(public_key_from_seed(seed), public_key)
                self.assertEqual(sign(seed, message), signature)
                self.assertTrue(verify(public_key, message, signature))

    def test_cryptography_cross_check_both_directions(self):
        # The dev extra installs cryptography; this check must run, not
        # silently skip, so a missing import fails the test outright.
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
                Ed25519PublicKey,
            )
        except ImportError as exc:  # pragma: no cover - dev venv has it
            self.fail(f"cryptography is required for the cross-check: {exc}")
        for _ in range(5):
            seed, public_key = keygen()
            message = os.urandom(37)
            ours = sign(seed, message)
            # Our signature verifies with cryptography's implementation.
            Ed25519PublicKey.from_public_bytes(public_key).verify(ours, message)
            # cryptography's signature verifies with our implementation.
            private = Ed25519PrivateKey.from_private_bytes(seed)
            theirs = private.sign(message)
            self.assertTrue(verify(public_key, message, theirs))
            self.assertEqual(private.public_key().public_bytes_raw(), public_key)

    def test_verify_returns_false_never_raises(self):
        seed, public_key = keygen()
        message = b"case file body"
        signature = sign(seed, message)
        flipped = bytearray(signature)
        flipped[0] ^= 1
        bad_cases = [
            (public_key, message, bytes(flipped)),  # flipped-bit signature
            (public_key, b"different message", signature),  # wrong message
            (public_key, message, signature[:32]),  # short signature
            (public_key, message, signature + b"\x00"),  # long signature
            (public_key, message, b""),  # empty signature
            (public_key[:31], message, signature),  # short public key
            (public_key + b"\x00", message, signature),  # long public key
            (b"", message, signature),  # empty public key
            (b"\x00" * 32, message, signature),  # wrong key, valid length
            (public_key, b"", signature),  # empty message
        ]
        for key, msg, sig in bad_cases:
            with self.subTest(key=len(key), msg=len(msg), sig=len(sig)):
                self.assertFalse(verify(key, msg, sig))
        self.assertFalse(verify(b"", b"", b""))
        self.assertTrue(verify(public_key, message, signature))

    def test_keygen_and_fingerprint(self):
        seed, public_key = keygen()
        self.assertEqual(len(seed), 32)
        self.assertEqual(len(public_key), 32)
        self.assertEqual(public_key_from_seed(seed), public_key)
        digest = fingerprint(public_key)
        self.assertEqual(len(digest), 64)
        self.assertEqual(digest, digest.lower())
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        other_seed, other_key = keygen()
        self.assertNotEqual(seed, other_seed)
        self.assertNotEqual(public_key, other_key)
        self.assertNotEqual(fingerprint(public_key), fingerprint(other_key))

    def test_wrong_length_inputs_raise(self):
        with self.assertRaises(ValueError):
            public_key_from_seed(b"\x00" * 31)
        with self.assertRaises(ValueError):
            sign(b"\x00" * 33, b"message")
        with self.assertRaises(ValueError):
            fingerprint(b"\x00" * 31)


class DsseTests(unittest.TestCase):
    def test_pae_exact_bytes(self):
        self.assertEqual(pae("test", b"abc"), b"DSSEv1 4 test 3 abc")
        self.assertEqual(
            pae(PAYLOAD_TYPE_CASE_FILE, b"{}"),
            b"DSSEv1 26 textforensics.case-file/v3 2 {}",
        )
        self.assertEqual(
            pae(PAYLOAD_TYPE_SEALED_BUNDLE_MANIFEST, b""),
            b"DSSEv1 39 textforensics.sealed-bundle-manifest/v1 0 ",
        )

    def test_round_trip(self):
        seed, public_key = keygen()
        payload = b'{"schema": "textforensics.case-file/v3"}'
        envelope = sign_envelope(PAYLOAD_TYPE_CASE_FILE, payload, seed)
        self.assertEqual(envelope["payloadType"], PAYLOAD_TYPE_CASE_FILE)
        self.assertEqual(envelope["payload"], base64.b64encode(payload).decode())
        self.assertEqual(len(envelope["signatures"]), 1)
        self.assertEqual(envelope["signatures"][0]["keyid"], fingerprint(public_key))
        result = verify_envelope(envelope, public_key, expected_payload_type=PAYLOAD_TYPE_CASE_FILE)
        self.assertTrue(result["valid"])
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["payload"], payload)
        self.assertEqual(result["keyid"], fingerprint(public_key))

    def test_tampered_payload_fails(self):
        seed, public_key = keygen()
        envelope = sign_envelope("test", b"abc", seed)
        tampered = copy.deepcopy(envelope)
        tampered["payload"] = base64.b64encode(b"abd").decode()
        result = verify_envelope(tampered, public_key)
        self.assertFalse(result["valid"])
        self.assertTrue(result["errors"])
        self.assertIsNone(result["payload"])

    def test_tampered_signature_fails(self):
        seed, public_key = keygen()
        envelope = sign_envelope("test", b"abc", seed)
        tampered = copy.deepcopy(envelope)
        sig = bytearray(base64.b64decode(tampered["signatures"][0]["sig"]))
        sig[10] ^= 1
        tampered["signatures"][0]["sig"] = base64.b64encode(bytes(sig)).decode()
        self.assertFalse(verify_envelope(tampered, public_key)["valid"])

    def test_wrong_payload_type_fails_when_expected(self):
        seed, public_key = keygen()
        envelope = sign_envelope("test", b"abc", seed)
        result = verify_envelope(envelope, public_key, expected_payload_type="other")
        self.assertFalse(result["valid"])
        self.assertTrue(any("payloadType" in e for e in result["errors"]))
        # Without an expectation the same envelope verifies.
        self.assertTrue(verify_envelope(envelope, public_key)["valid"])

    def test_keyid_mismatch_fails(self):
        _, public_key = keygen()
        other_seed, _ = keygen()
        envelope = sign_envelope("test", b"abc", other_seed)
        result = verify_envelope(envelope, public_key)
        self.assertFalse(result["valid"])
        self.assertTrue(any("keyid" in e for e in result["errors"]))

    def test_malformed_envelopes_fail_without_raising(self):
        seed, public_key = keygen()
        good = sign_envelope("test", b"abc", seed)
        malformed = []
        missing = copy.deepcopy(good)
        del missing["payload"]
        malformed.append(missing)
        extra = copy.deepcopy(good)
        extra["extra"] = "field"
        malformed.append(extra)
        bad_b64 = copy.deepcopy(good)
        bad_b64["payload"] = "!!!not-base64!!!"
        malformed.append(bad_b64)
        non_canonical_b64 = copy.deepcopy(good)
        non_canonical_b64["payload"] = base64.b64encode(b"abc").decode() + "="
        malformed.append(non_canonical_b64)
        two_sigs = copy.deepcopy(good)
        two_sigs["signatures"] = [good["signatures"][0], good["signatures"][0]]
        malformed.append(two_sigs)
        no_sigs = copy.deepcopy(good)
        no_sigs["signatures"] = []
        malformed.append(no_sigs)
        bad_sig_b64 = copy.deepcopy(good)
        bad_sig_b64["signatures"][0]["sig"] = "not base64!"
        malformed.append(bad_sig_b64)
        malformed.append("not a mapping")
        malformed.append(None)
        malformed.append([])
        for envelope in malformed:
            with self.subTest(envelope=repr(envelope)[:60]):
                result = verify_envelope(envelope, public_key)
                self.assertFalse(result["valid"])
                self.assertTrue(result["errors"])
        # A short public key also fails without raising.
        self.assertFalse(verify_envelope(good, b"\x00" * 16)["valid"])


class SealingKeyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def test_save_load_round_trip_and_mode(self):
        key = generate_sealing_key("auditor@example.test", "auditor")
        path = self.dir / "sealing-key.json"
        saved = save_sealing_key(path, key)
        self.assertEqual(saved, path)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        loaded = load_sealing_key(path)
        self.assertEqual(loaded, key)
        self.assertEqual(loaded["seed_b64"], key["seed_b64"])
        self.assertEqual(loaded["keyid"], fingerprint(base64.b64decode(key["public_key_b64"])))

    def test_save_refuses_to_overwrite(self):
        key = generate_sealing_key("auditor@example.test", "auditor")
        path = self.dir / "sealing-key.json"
        save_sealing_key(path, key)
        with self.assertRaises(FileExistsError):
            save_sealing_key(path, generate_sealing_key("other", "auditor"))
        # The original file is untouched.
        self.assertEqual(load_sealing_key(path), key)

    def test_load_refuses_mismatched_public_key(self):
        key = generate_sealing_key("auditor@example.test", "auditor")
        _, other_key = keygen()
        tampered = dict(key)
        tampered["public_key_b64"] = base64.b64encode(other_key).decode()
        path = self.dir / "tampered.json"
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600), "w") as handle:
            json.dump(tampered, handle)
        with self.assertRaises(ValueError):
            load_sealing_key(path)

    def test_load_refuses_mismatched_keyid(self):
        key = generate_sealing_key("auditor@example.test", "auditor")
        tampered = dict(key)
        tampered["keyid"] = "0" * 64
        path = self.dir / "tampered-keyid.json"
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600), "w") as handle:
            json.dump(tampered, handle)
        with self.assertRaises(ValueError):
            load_sealing_key(path)

    def test_load_refuses_world_readable_key_file(self):
        key = generate_sealing_key("auditor@example.test", "auditor")
        path = self.dir / "readable.json"
        save_sealing_key(path, key)
        os.chmod(path, 0o644)
        with self.assertRaises(ValueError):
            load_sealing_key(path)
        os.chmod(path, 0o600)
        self.assertEqual(load_sealing_key(path), key)

    def test_public_key_info_exposes_no_seed(self):
        key = generate_sealing_key("auditor@example.test", "auditor")
        info = public_key_info(key)
        self.assertEqual(info["algorithm"], "ed25519")
        self.assertEqual(info["public_key_b64"], key["public_key_b64"])
        self.assertEqual(info["keyid"], key["keyid"])
        self.assertEqual(info["identity"], key["identity"])
        self.assertEqual(info["role"], key["role"])
        self.assertNotIn("seed_b64", info)
        self.assertNotIn("seed_b64", json.dumps(info))

    def test_generate_validates_identity_and_role(self):
        with self.assertRaises(ValueError):
            generate_sealing_key("", "auditor")
        with self.assertRaises(ValueError):
            generate_sealing_key("auditor", "")


def _signed_v2_case():
    """A case signed under the current (v2) contract, with its key.

    Returns ``(case, public_key, key_dict)``.
    """
    from textforensics.sealing import build_signature_record

    key = generate_sealing_key("auditor@example.test", "auditor")
    seed = base64.b64decode(key["seed_b64"])
    public_key = base64.b64decode(key["public_key_b64"])
    case = CaseSigningTests._case_static()
    case["seal"]["signature"] = build_signature_record(
        public_key, "auditor@example.test", "auditor"
    )
    envelope = sign_case_body(case, seed)
    case["seal"]["signature"]["dsse"] = envelope
    return case, public_key, key


def _signed_v1_case():
    """A legacy (v1) case: the whole signature mapping is outside the
    signed body, so the record is attached after signing.

    Returns ``(case, public_key, key_dict)``.
    """
    from textforensics.sealing import CASE_SIGNING_CONTRACT_V1

    key = generate_sealing_key("auditor@example.test", "auditor")
    seed = base64.b64decode(key["seed_b64"])
    public_key = base64.b64decode(key["public_key_b64"])
    case = CaseSigningTests._case_static()
    envelope = sign_case_body(case, seed, contract=CASE_SIGNING_CONTRACT_V1)
    case["seal"]["signature"] = {
        "algorithm": "ed25519",
        "key_fingerprint": fingerprint(public_key),
        "signer": {"identity": "auditor@example.test", "role": "auditor"},
        "dsse": envelope,
    }
    return case, public_key, key


class CaseSigningTests(unittest.TestCase):
    @staticmethod
    def _case_static() -> dict:
        return {
            "schema": "textforensics.case-file/v2",
            "tool": {"name": "TextForensics", "version": "0.2.0"},
            "created_at_utc": "2026-11-07T06:00:00+00:00",
            "case_sha256": "a" * 64,
            "raw_text_included": False,
            "seal": {"sha256": "b" * 64},
            "forensic_bundle": {"schema": "textforensics.forensic-bundle/v2"},
        }

    def _case(self) -> dict:
        return self._case_static()

    def _signed_v2_case(self):
        return _signed_v2_case()

    def _signed_v1_case(self):
        return _signed_v1_case()

    def test_case_signing_payload_matches_casefile_canonicalisation(self):
        case = self._case()
        expected_body = copy.deepcopy(case)
        expected_body.pop("case_sha256")
        expected_body.pop("created_at_utc")
        expected_body["seal"] = {k: v for k, v in expected_body["seal"].items() if k != "signature"}
        self.assertEqual(case_signing_payload(case), canonical_json_bytes(expected_body))

    def test_case_signing_payload_ignores_seal_and_wall_clock(self):
        # W3 (C02): under the LEGACY v1 contract the whole signature
        # mapping is outside the signed body, so changing it (or the
        # wall clock) does not change the payload.  Under v2 the signer
        # record IS signed — see test_v2_payload_binds_signer_record.
        from textforensics.sealing import CASE_SIGNING_CONTRACT_V1

        case = self._case()
        first = case_signing_payload(case, contract=CASE_SIGNING_CONTRACT_V1)
        case["created_at_utc"] = "2026-11-08T06:00:00+00:00"
        case["case_sha256"] = "c" * 64
        case["seal"]["signature"] = {"dsse": {"payloadType": "stale"}}
        self.assertEqual(case_signing_payload(case, contract=CASE_SIGNING_CONTRACT_V1), first)

    def test_v2_payload_binds_signer_record_but_excludes_dsse(self):
        # W3 (C02): the v2 signed body includes the signer record and
        # excludes only the recursive DSSE envelope.
        from textforensics.sealing import CASE_SIGNING_CONTRACT_V2, build_signature_record

        key = generate_sealing_key("auditor@example.test", "auditor")
        public_key = base64.b64decode(key["public_key_b64"])
        case = self._case()
        case["seal"]["signature"] = build_signature_record(
            public_key, "auditor@example.test", "auditor"
        )
        first = case_signing_payload(case, contract=CASE_SIGNING_CONTRACT_V2)
        # Changing the envelope or the wall clock does not change it.
        case["seal"]["signature"]["dsse"] = {"payloadType": "stale"}
        case["created_at_utc"] = "2026-11-08T06:00:00+00:00"
        case["case_sha256"] = "c" * 64
        self.assertEqual(case_signing_payload(case, contract=CASE_SIGNING_CONTRACT_V2), first)
        # Changing the signer record DOES change it.
        case["seal"]["signature"]["signer"] = {
            "identity": "mallory@example.test",
            "role": "admin",
        }
        self.assertNotEqual(case_signing_payload(case, contract=CASE_SIGNING_CONTRACT_V2), first)

    def test_sign_and_verify_case_body(self):
        from textforensics.sealing import CASE_SIGNING_CONTRACT_V2

        case, public_key, key = self._signed_v2_case()
        envelope = case["seal"]["signature"]["dsse"]
        self.assertEqual(envelope["payloadType"], CASE_SIGNING_CONTRACT_V2)
        result = verify_case_signature(case, public_key)
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["keyid"], key["keyid"])
        self.assertEqual(result["signing_contract"], "v2")
        self.assertEqual(result["warnings"], [])

    def test_sign_case_body_requires_signer_record_for_v2(self):
        # W3 (C02): signing a body and attaching a signer record
        # afterwards would leave the record unauthenticated, so v2
        # signing refuses a case with no pre-placed record.
        key = generate_sealing_key("auditor@example.test", "auditor")
        seed = base64.b64decode(key["seed_b64"])
        with self.assertRaises(ValueError):
            sign_case_body(self._case(), seed)

    def test_verify_case_signature_fails_on_tampered_body(self):
        case, public_key, _key = self._signed_v2_case()
        case["forensic_bundle"]["schema"] = "textforensics.forensic-bundle/v9"
        result = verify_case_signature(case, public_key)
        self.assertFalse(result["valid"])
        self.assertTrue(result["errors"])

    def test_verify_case_signature_never_raises(self):
        _, public_key = keygen()
        bad_cases: list = [
            {},
            {"seal": {}},
            {"seal": {"signature": {}}},
            {"seal": {"signature": {"dsse": "not a mapping"}}},
            {"seal": {"signature": {"dsse": {}}}},
            {"seal": "not a mapping"},
            "not a mapping",
            None,
        ]
        for case in bad_cases:
            with self.subTest(case=repr(case)[:40]):
                result = verify_case_signature(case, public_key)
                self.assertFalse(result["valid"])
                self.assertTrue(result["errors"])


class CaseSignerBindingTests(unittest.TestCase):
    """W3 (C02): a valid bare-case signature must bind the displayed
    signer, role and fingerprint.  Each mutation is tested individually
    against a v2-signed case; the legacy v1 contract keeps explicit
    legacy semantics (fingerprint/algorithm still fail, identity/role
    are reported unauthenticated, never silently accepted as bound)."""

    def _mutated(self, case, mutate):
        mutated = copy.deepcopy(case)
        mutate(mutated["seal"]["signature"])
        return mutated

    def test_identity_mutation_fails_v2(self):
        case, public_key, _key = _signed_v2_case()
        mutated = self._mutated(
            case, lambda sig: sig["signer"].update({"identity": "mallory@example.test"})
        )
        result = verify_case_signature(mutated, public_key)
        self.assertFalse(result["valid"])
        self.assertTrue(result["errors"])

    def test_role_mutation_fails_v2(self):
        case, public_key, _key = _signed_v2_case()
        mutated = self._mutated(case, lambda sig: sig["signer"].update({"role": "admin"}))
        result = verify_case_signature(mutated, public_key)
        self.assertFalse(result["valid"])
        self.assertTrue(result["errors"])

    def test_fingerprint_mutation_fails_v2(self):
        case, public_key, _key = _signed_v2_case()
        mutated = self._mutated(case, lambda sig: sig.update({"key_fingerprint": "0" * 64}))
        result = verify_case_signature(mutated, public_key)
        self.assertFalse(result["valid"])
        self.assertTrue(any("fingerprint" in err for err in result["errors"]), result["errors"])

    def test_algorithm_mutation_fails_v2(self):
        case, public_key, _key = _signed_v2_case()
        mutated = self._mutated(case, lambda sig: sig.update({"algorithm": "rsa"}))
        result = verify_case_signature(mutated, public_key)
        self.assertFalse(result["valid"])
        self.assertTrue(result["errors"])

    def test_v1_legacy_case_verifies_with_unauthenticated_signer_warning(self):
        case, public_key, _key = _signed_v1_case()
        result = verify_case_signature(case, public_key)
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["signing_contract"], "v1")
        self.assertTrue(
            any(
                w.startswith("signer_identity_role_not_authenticated_legacy_contract")
                for w in result["warnings"]
            ),
            result["warnings"],
        )

    def test_v1_identity_mutation_is_valid_but_flagged_unauthenticated(self):
        case, public_key, _key = _signed_v1_case()
        mutated = self._mutated(
            case, lambda sig: sig["signer"].update({"identity": "mallory@example.test"})
        )
        result = verify_case_signature(mutated, public_key)
        # Legacy semantics: the identity is NOT in the v1 signed body,
        # so the signature still verifies — but the result must say so
        # unmistakably instead of presenting it as bound.
        self.assertTrue(result["valid"], result["errors"])
        self.assertTrue(
            any(
                w.startswith("signer_identity_role_not_authenticated_legacy_contract")
                for w in result["warnings"]
            ),
            result["warnings"],
        )

    def test_v1_fingerprint_mutation_fails(self):
        case, public_key, _key = _signed_v1_case()
        mutated = self._mutated(case, lambda sig: sig.update({"key_fingerprint": "0" * 64}))
        result = verify_case_signature(mutated, public_key)
        self.assertFalse(result["valid"])
        self.assertTrue(any("fingerprint" in err for err in result["errors"]), result["errors"])

    def test_v1_algorithm_mutation_fails(self):
        case, public_key, _key = _signed_v1_case()
        mutated = self._mutated(case, lambda sig: sig.update({"algorithm": "rsa"}))
        result = verify_case_signature(mutated, public_key)
        self.assertFalse(result["valid"])

    def test_unknown_payload_type_is_rejected(self):
        case, public_key, _key = _signed_v2_case()
        mutated = copy.deepcopy(case)
        mutated["seal"]["signature"]["dsse"] = dict(
            mutated["seal"]["signature"]["dsse"],
            payloadType="textforensics.case-file/v9",
        )
        result = verify_case_signature(mutated, public_key)
        self.assertFalse(result["valid"])
        self.assertTrue(result["errors"])


class SealingKeyWindowsTests(unittest.TestCase):
    """W3 (C11): key generation must work without ``os.fchmod``
    (Windows has none), must never leak the ``mkstemp`` descriptor,
    and no-clobber publication must be genuinely atomic."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def _tracked_mkstemp(self, fds):
        real_mkstemp = tempfile.mkstemp

        def tracking(*args, **kwargs):
            fd, name = real_mkstemp(*args, **kwargs)
            fds.append(fd)
            return fd, name

        return tracking

    def _assert_fd_closed(self, fd):
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_save_without_fchmod_succeeds(self):
        # Simulate Windows: no os.fchmod; the Windows owner-private
        # restrictor is stubbed (its real ctypes implementation runs
        # on Windows CI — see test_windows_acl_is_owner_only).
        import textforensics.sealing as sealing_module

        calls: list = []

        def fake_restrict(path):
            calls.append(path)

        fds: list = []
        had_fchmod = hasattr(os, "fchmod")
        orig_fchmod = getattr(os, "fchmod", None)
        if had_fchmod:
            delattr(os, "fchmod")
        try:
            with (
                mock.patch.object(
                    sealing_module,
                    "_restrict_to_owner_windows",
                    fake_restrict,
                    create=True,
                ),
                mock.patch.object(tempfile, "mkstemp", self._tracked_mkstemp(fds)),
            ):
                key = generate_sealing_key("auditor@example.test", "auditor")
                path = self.dir / "sealing-key.json"
                saved = save_sealing_key(path, key)
                self.assertEqual(saved, path)
                self.assertEqual(len(calls), 1)
                self.assertEqual(load_sealing_key(path), key)
                self.assertEqual(len(fds), 1)
                self._assert_fd_closed(fds[0])
                self.assertEqual(list(self.dir.iterdir()), [path])
        finally:
            # Restore os.fchmod for the rest of the suite.
            if had_fchmod:
                os.fchmod = orig_fchmod
            elif hasattr(os, "fchmod"):
                delattr(os, "fchmod")

    def test_save_closes_descriptor_when_fchmod_fails(self):
        fds: list = []
        with (
            mock.patch.object(tempfile, "mkstemp", self._tracked_mkstemp(fds)),
            mock.patch.object(os, "fchmod", side_effect=OSError("simulated fchmod failure")),
        ):
            key = generate_sealing_key("auditor@example.test", "auditor")
            with self.assertRaises(OSError):
                save_sealing_key(self.dir / "k.json", key)
        self.assertEqual(len(fds), 1)
        self._assert_fd_closed(fds[0])
        self.assertEqual(list(self.dir.iterdir()), [])
        self.assertFalse((self.dir / "k.json").exists())

    def test_save_closes_descriptor_when_write_fails(self):
        fds: list = []
        with (
            mock.patch.object(tempfile, "mkstemp", self._tracked_mkstemp(fds)),
            mock.patch.object(os, "fsync", side_effect=OSError("simulated fsync failure")),
        ):
            key = generate_sealing_key("auditor@example.test", "auditor")
            with self.assertRaises(OSError):
                save_sealing_key(self.dir / "k.json", key)
        self.assertEqual(len(fds), 1)
        self._assert_fd_closed(fds[0])
        self.assertEqual(list(self.dir.iterdir()), [])
        self.assertFalse((self.dir / "k.json").exists())

    def test_no_clobber_publication_is_atomic(self):
        # A racing writer that creates the destination between the
        # existence check and publication must NOT be overwritten:
        # publication via link fails with FileExistsError instead.
        real_link = os.link
        destination = self.dir / "sealing-key.json"

        def racing_link(src, dst, *args, **kwargs):
            # Simulate the racer winning first, then publish.
            Path(dst).write_bytes(b"racer-key-bytes")
            return real_link(src, dst, *args, **kwargs)

        key = generate_sealing_key("auditor@example.test", "auditor")
        with (
            mock.patch.object(os, "link", racing_link),
            self.assertRaises(FileExistsError),
        ):
            save_sealing_key(destination, key)
        self.assertEqual(destination.read_bytes(), b"racer-key-bytes")
        self.assertEqual(
            [p.name for p in self.dir.iterdir()],
            ["sealing-key.json"],
        )

    def test_concurrent_no_clobber_two_writers(self):
        # Deterministic two-writer/no-clobber regression: N writers race
        # on one destination; exactly one succeeds, the rest get
        # FileExistsError, the winner's key is intact, no temp files
        # are left behind.  (The audit's residual hypothesis 1 notes
        # native POSIX concurrency was NOT executed on the Windows audit
        # host; this test executes it.)
        destination = self.dir / "sealing-key.json"
        barrier = threading.Barrier(8)
        results: list = []

        def writer(index):
            key = generate_sealing_key(f"writer{index}@example.test", "auditor")
            barrier.wait(timeout=30)
            try:
                save_sealing_key(destination, key)
                results.append(("saved", key))
            except FileExistsError:
                results.append(("exists", key))
            except Exception as exc:  # pragma: no cover - failure surface
                results.append(("error", exc))

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        saved = [key for status, key in results if status == "saved"]
        self.assertEqual(len(saved), 1, results)
        self.assertEqual(sum(1 for status, _ in results if status == "exists"), 7, results)
        self.assertEqual(load_sealing_key(destination), saved[0])
        self.assertEqual(list(self.dir.iterdir()), [destination])

    @unittest.skipUnless(os.name == "nt", "Windows ACL assertions need Windows")
    def test_windows_acl_is_owner_only(self):
        # Real Windows run: the saved key file's DACL must grant access
        # only to the current user (one ACE, current-user SID).
        import ctypes
        from ctypes import wintypes

        key = generate_sealing_key("auditor@example.test", "auditor")
        path = self.dir / "sealing-key.json"
        save_sealing_key(path, key)
        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32
        SE_FILE_OBJECT = 1
        DACL_SECURITY_INFORMATION = 0x00000004
        p_sd = wintypes.LPVOID()
        result = advapi32.GetNamedSecurityInfoW(
            str(path),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            ctypes.byref(wintypes.LPVOID()),
            None,
            ctypes.byref(p_sd),
        )
        self.assertEqual(result, 0)
        try:
            p_dacl = wintypes.LPVOID()
            present = wintypes.BOOL()
            defaulted = wintypes.BOOL()
            self.assertTrue(
                advapi32.GetSecurityDescriptorDacl(
                    p_sd, ctypes.byref(present), ctypes.byref(p_dacl), ctypes.byref(defaulted)
                )
            )
            self.assertTrue(present.value)
            acl_size = ctypes.create_string_buffer(64)
            # ACL_SIZE_INFORMATION: AceCount is the second DWORD.
            self.assertTrue(
                advapi32.GetAclInformation(
                    p_dacl,
                    acl_size,
                    ctypes.sizeof(acl_size),
                    2,  # AclSizeInformation
                )
            )
            ace_count = int.from_bytes(acl_size.raw[4:8], "little")
            self.assertEqual(ace_count, 1)
        finally:
            kernel32.LocalFree(p_sd)


if __name__ == "__main__":
    unittest.main()
