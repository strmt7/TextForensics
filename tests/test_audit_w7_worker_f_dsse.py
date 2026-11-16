"""Worker F (W7) — kill tests for the textforensics.dsse proofset.

Covers pae, _b64decode_strict, sign_envelope and verify_envelope
with exact-byte oracles and one malformed input per _fail branch.
Test methods are numbered so the cheap exact-byte tests run before
the sign/verify tests (which each pay one Ed25519 sign/verify):
cosmic-ray runs the file with ``-x``, so a mutant killed by a cheap
test fails fast. Each test names the mutant classes it kills.

The seed/public key are RFC 8032 test vector 1 (see
tests/test_sealing.py).
"""

from __future__ import annotations

import base64
import unittest

from textforensics.dsse import (
    _b64decode_strict,
    pae,
    sign_envelope,
    verify_envelope,
)
from textforensics.ed25519 import fingerprint, sign

SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
PUBKEY = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
OTHER_SEED = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
OTHER_PUBKEY = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
PAYLOAD_TYPE = "textforensics.case-file/v3"
PAYLOAD = b'{"case": "payload"}'


def _valid_envelope(payload_type=PAYLOAD_TYPE, payload=PAYLOAD, seed=SEED):
    return sign_envelope(payload_type, payload, seed)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class DsseKillTests(unittest.TestCase):
    def test_00_pae_exact_bytes(self):
        # Kills the pae mutants (every Add_* replacement on the seven
        # '+' concatenations, NumberReplacer on the lengths): the
        # output bytes are exact, including multi-digit decimal
        # lengths and byte-count (not char-count) lengths.
        self.assertEqual(pae("test", b""), b"DSSEv1 4 test 0 ")
        self.assertEqual(pae("a", b"x"), b"DSSEv1 1 a 1 x")
        self.assertEqual(pae("", b"x"), b"DSSEv1 0  1 x")
        self.assertEqual(pae("abcdefghij", b"y"), b"DSSEv1 10 abcdefghij 1 y")
        self.assertEqual(pae("t", b"x" * 100), b"DSSEv1 1 t 100 " + b"x" * 100)
        self.assertEqual(pae("t", b"x" * 9), b"DSSEv1 1 t 9 " + b"x" * 9)
        # Non-ASCII payload type: the length is the UTF-8 byte count.
        self.assertEqual(pae("é", b""), b"DSSEv1 2 \xc3\xa9 0 ")
        self.assertEqual(pae("t", bytearray(b"ab")), b"DSSEv1 1 t 2 ab")
        for bad_type in (None, 42, b"bytes", ["t"]):
            with self.subTest(bad_type=repr(bad_type)), self.assertRaises(ValueError):
                pae(bad_type, b"x")  # type: ignore[arg-type]
        for bad_payload in ("str", None, 42, ["x"]):
            with (
                self.subTest(bad_payload=repr(bad_payload)),
                self.assertRaises(ValueError),
            ):
                pae("t", bad_payload)  # type: ignore[arg-type]

    def test_01_b64decode_strict(self):
        # Kills the _b64decode_strict mutants (the isinstance guard,
        # validate=True, the re-encode identity check): canonical
        # encodings decode, non-canonical padding bits and bad input
        # return None.
        self.assertEqual(_b64decode_strict(_b64(b"hello")), b"hello")
        self.assertEqual(_b64decode_strict(_b64(b"")), b"")
        self.assertEqual(_b64decode_strict(_b64(b"\x00\xff")), b"\x00\xff")
        self.assertEqual(_b64decode_strict(""), b"")
        for bad in (b"bytes", None, 42, ["YWI="], "!!!", "AB*C", "YQ", "YWI"):
            with self.subTest(bad=repr(bad)):
                self.assertIsNone(_b64decode_strict(bad))  # type: ignore[arg-type]
        # Non-canonical: "AB==" decodes to b"\x00" but re-encodes to
        # "AA==", so it must be rejected.
        self.assertIsNone(_b64decode_strict("AB=="))
        self.assertIsNone(_b64decode_strict("AR=="))
        # Re-encoding can also be lexicographically GREATER than the
        # input (the base64 alphabet order is not ASCII order: "P0=="
        # re-encodes to "Pw=="). These kill the `!=` -> `<` mutant at
        # _b64decode_strict line 66, which the "AB==" cases miss.
        self.assertIsNone(_b64decode_strict("P0=="))
        self.assertIsNone(_b64decode_strict("J0=="))
        self.assertIsNone(_b64decode_strict("6LmZf0=="))
        # Non-ASCII str raises UnicodeEncodeError inside, caught -> None.
        self.assertIsNone(_b64decode_strict("é"))
        self.assertIsNone(_b64decode_strict("YWI=é"))

    def test_02_sign_envelope_exact(self):
        # Kills the sign_envelope mutants (the validation guards, the
        # keyid fingerprint, the PAE binding): the envelope is exact
        # against independently computed parts.
        envelope = _valid_envelope()
        self.assertEqual(set(envelope), {"payloadType", "payload", "signatures"})
        self.assertEqual(envelope["payloadType"], PAYLOAD_TYPE)
        self.assertEqual(envelope["payload"], _b64(PAYLOAD))
        self.assertEqual(len(envelope["signatures"]), 1)
        entry = envelope["signatures"][0]
        self.assertEqual(set(entry), {"keyid", "sig"})
        self.assertEqual(entry["keyid"], fingerprint(PUBKEY))
        self.assertEqual(
            entry["sig"],
            _b64(sign(SEED, pae(PAYLOAD_TYPE, PAYLOAD))),
        )
        # Deterministic: signing twice gives the same envelope.
        self.assertEqual(_valid_envelope(), envelope)
        # A different payload type binds a different signature.
        other = _valid_envelope("other/type", PAYLOAD)
        self.assertNotEqual(other["signatures"][0]["sig"], entry["sig"])
        # Bytearray payload is accepted and identical.
        self.assertEqual(_valid_envelope(payload=PAYLOAD, seed=SEED), envelope)
        self.assertEqual(sign_envelope(PAYLOAD_TYPE, bytearray(PAYLOAD), SEED), envelope)
        for bad_type in ("", None, 42, b"t"):
            with self.subTest(bad_type=repr(bad_type)), self.assertRaises(ValueError):
                sign_envelope(bad_type, PAYLOAD, SEED)  # type: ignore[arg-type]
        for bad_payload in ("str", None, 42):
            with (
                self.subTest(bad_payload=repr(bad_payload)),
                self.assertRaises(ValueError),
            ):
                sign_envelope(PAYLOAD_TYPE, bad_payload, SEED)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            sign_envelope(PAYLOAD_TYPE, PAYLOAD, b"short seed")

    def test_03_verify_envelope_valid(self):
        # Kills the verify_envelope success-path mutants (the final
        # verify() call, the keyid/payload return): a valid envelope
        # verifies with its payload and keyid and no errors.
        envelope = _valid_envelope()
        result = verify_envelope(envelope, PUBKEY)
        self.assertEqual(
            result,
            {
                "valid": True,
                "errors": [],
                "payload": PAYLOAD,
                "keyid": fingerprint(PUBKEY),
            },
        )
        self.assertEqual(
            verify_envelope(envelope, bytearray(PUBKEY))["valid"],
            True,
        )
        self.assertTrue(
            verify_envelope(envelope, PUBKEY, expected_payload_type=PAYLOAD_TYPE)["valid"]
        )
        # An equal-but-not-identical expected type must also verify:
        # this kills the `!=` -> `is not` mutant at line 124, which
        # rejects equal strings that are distinct objects (the
        # constant above is identical by construction). The guard
        # fails loudly if interning ever makes them identical.
        runtime_built = "".join(["textforensics.case-file/", "v3"])
        self.assertIsNot(runtime_built, PAYLOAD_TYPE)
        self.assertEqual(runtime_built, PAYLOAD_TYPE)
        self.assertTrue(
            verify_envelope(envelope, PUBKEY, expected_payload_type=runtime_built)["valid"]
        )

    def test_04_verify_envelope_key_checks(self):
        # Kills the public-key guard mutants (len != 32, the
        # isinstance check, every comparison replacement): every bad
        # key fails with the key error, and the right key for the
        # wrong envelope fails on keyid.
        envelope = _valid_envelope()
        for bad_key in (b"", b"\x00" * 31, b"\x00" * 33, "str", None, 42):
            with self.subTest(bad_key=repr(bad_key)[:16]):
                result = verify_envelope(envelope, bad_key)  # type: ignore[arg-type]
                self.assertFalse(result["valid"])
                self.assertIn("public key must be exactly 32 bytes", result["errors"])
                self.assertIsNone(result["payload"])
        result = verify_envelope(envelope, OTHER_PUBKEY)
        self.assertFalse(result["valid"])
        self.assertIn(
            "signature keyid does not match the supplied public key",
            result["errors"],
        )
        # The keyid reported is the envelope's keyid even on failure.
        self.assertEqual(result["keyid"], fingerprint(PUBKEY))

    def test_05_verify_envelope_shape(self):
        # Kills the envelope-shape mutants (the Mapping check, the
        # exact-fields set comparison, the payloadType guard, the
        # expected-type comparison): one malformed input per _fail.
        good = _valid_envelope()
        for bad_env in ([], "envelope", None, 42, {"payloadType": PAYLOAD_TYPE}):
            with self.subTest(bad_env=repr(bad_env)[:24]):
                self.assertFalse(verify_envelope(bad_env, PUBKEY)["valid"])
        extra = dict(good)
        extra["extra"] = 1
        self.assertFalse(verify_envelope(extra, PUBKEY)["valid"])
        for missing in ("payloadType", "payload", "signatures"):
            env = {k: v for k, v in good.items() if k != missing}
            with self.subTest(missing=missing):
                self.assertFalse(verify_envelope(env, PUBKEY)["valid"])
        for bad_type in ("", None, 42, b"t"):
            env = dict(good)
            env["payloadType"] = bad_type
            with self.subTest(bad_type=repr(bad_type)):
                result = verify_envelope(env, PUBKEY)
                self.assertFalse(result["valid"])
                self.assertIn("payloadType must be a non-empty string", result["errors"])
        result = verify_envelope(good, PUBKEY, expected_payload_type="other/type")
        self.assertFalse(result["valid"])
        self.assertTrue(any("does not match expected" in e for e in result["errors"]))

    def test_06_verify_envelope_payload(self):
        # Kills the payload-decode mutants (the _b64decode_strict
        # call, the None check): non-canonical payloads fail, an
        # empty payload round-trips.
        good = _valid_envelope()
        for bad_payload in (b"bytes", None, 42, "!!!", "AB=="):
            env = dict(good)
            env["payload"] = bad_payload
            with self.subTest(bad_payload=repr(bad_payload)):
                result = verify_envelope(env, PUBKEY)
                self.assertFalse(result["valid"])
                self.assertIn("payload is not canonical base64", result["errors"])
        empty = _valid_envelope(payload=b"")
        result = verify_envelope(empty, PUBKEY)
        self.assertTrue(result["valid"])
        self.assertEqual(result["payload"], b"")

    def test_07_verify_envelope_signatures(self):
        # Kills the signature-list mutants (the list/length check,
        # the entry Mapping/fields/keyid checks, the sig decode and
        # length checks): one malformed signature per _fail branch.
        good = _valid_envelope()
        entry = good["signatures"][0]
        for bad_sigs in ({}, "sigs", None, [], [entry, entry]):
            env = dict(good)
            env["signatures"] = bad_sigs
            with self.subTest(bad_sigs=repr(bad_sigs)[:24]):
                self.assertFalse(verify_envelope(env, PUBKEY)["valid"])
        for bad_entry in ("entry", None, 42, [entry]):
            env = dict(good)
            env["signatures"] = [bad_entry]
            with self.subTest(bad_entry=repr(bad_entry)[:16]):
                self.assertFalse(verify_envelope(env, PUBKEY)["valid"])
        extra = dict(entry)
        extra["extra"] = 1
        env = dict(good)
        env["signatures"] = [extra]
        self.assertFalse(verify_envelope(env, PUBKEY)["valid"])
        missing = {k: v for k, v in entry.items() if k != "sig"}
        env = dict(good)
        env["signatures"] = [missing]
        self.assertFalse(verify_envelope(env, PUBKEY)["valid"])
        for bad_keyid in (None, 42, b"keyid"):
            env = dict(good)
            env["signatures"] = [dict(entry, keyid=bad_keyid)]
            with self.subTest(bad_keyid=repr(bad_keyid)):
                result = verify_envelope(env, PUBKEY)
                self.assertFalse(result["valid"])
                self.assertIn("signature keyid must be a string", result["errors"])
        env = dict(good)
        env["signatures"] = [dict(entry, keyid=fingerprint(OTHER_PUBKEY))]
        result = verify_envelope(env, PUBKEY)
        self.assertFalse(result["valid"])
        self.assertEqual(result["keyid"], fingerprint(OTHER_PUBKEY))
        # Each bad signature must fail with its own error, not just
        # valid=False: the length cases kill the `!=` -> `<` / `>`
        # mutants at line 150, which proceed to verify() (still
        # valid=False, but with the PAE error instead of the length
        # error) for a 65-byte (`<`) / 63-byte (`>`) signature.
        for bad_sig, message in (
            (b"bytes", "signature is not canonical base64"),
            (None, "signature is not canonical base64"),
            (42, "signature is not canonical base64"),
            ("!!!", "signature is not canonical base64"),
            ("AB==", "signature is not canonical base64"),
            (_b64(b"\x00" * 63), "signature must be exactly 64 bytes"),
            (_b64(b"\x00" * 65), "signature must be exactly 64 bytes"),
        ):
            env = dict(good)
            env["signatures"] = [dict(entry, sig=bad_sig)]
            with self.subTest(bad_sig=repr(bad_sig)[:16]):
                result = verify_envelope(env, PUBKEY)
                self.assertFalse(result["valid"])
                self.assertIn(message, result["errors"])

    def test_09_verify_envelope_positional_type_raises(self):
        # Kills the `*` -> `/` mutant at line 95 (the keyword-only
        # marker in the verify_envelope signature): the expected type
        # must stay keyword-only, so a third positional argument
        # raises TypeError.
        envelope = _valid_envelope()
        with self.assertRaises(TypeError):
            verify_envelope(envelope, PUBKEY, PAYLOAD_TYPE)  # type: ignore[call-arg]

    def test_08_verify_envelope_signature_binding(self):
        # Kills the final-verify mutants (the verify() call over the
        # PAE, the keyid binding): a flipped signature bit, a
        # signature over a different payload type, and a tampered
        # payload all fail at the Ed25519 check.
        good = _valid_envelope()
        entry = good["signatures"][0]
        raw_sig = base64.b64decode(entry["sig"])
        flipped = bytearray(raw_sig)
        flipped[0] ^= 1
        env = dict(good)
        env["signatures"] = [dict(entry, sig=_b64(bytes(flipped)))]
        result = verify_envelope(env, PUBKEY)
        self.assertFalse(result["valid"])
        self.assertIn("Ed25519 signature does not verify over the PAE", result["errors"])
        other_type = _valid_envelope("other/type", PAYLOAD)
        result = verify_envelope(other_type, PUBKEY, expected_payload_type=PAYLOAD_TYPE)
        self.assertFalse(result["valid"])
        # Payload type swapped in the envelope (no expected type, so
        # the type check passes): the signature was computed over the
        # original PAE, so the Ed25519 check must fail.
        env = dict(good)
        env["payloadType"] = "other/type"
        result = verify_envelope(env, PUBKEY)
        self.assertFalse(result["valid"])
        self.assertIn("Ed25519 signature does not verify over the PAE", result["errors"])
        # Same envelope, payload replaced by a different valid payload
        # (signature still over the original PAE).
        env = dict(good)
        env["payload"] = _b64(b"tampered payload")
        self.assertFalse(verify_envelope(env, PUBKEY)["valid"])
        # The other seed's envelope does not verify under this key.
        other_seed_envelope = _valid_envelope(seed=OTHER_SEED)
        self.assertFalse(verify_envelope(other_seed_envelope, PUBKEY)["valid"])
        self.assertTrue(verify_envelope(other_seed_envelope, OTHER_PUBKEY)["valid"])
