"""Tests for pure-stdlib Ed25519 (RFC 8032), DSSE envelopes and sealing keys."""

from __future__ import annotations

import base64
import copy
import os
import unittest

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


if __name__ == "__main__":
    unittest.main()
