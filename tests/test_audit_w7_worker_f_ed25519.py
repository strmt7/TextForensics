"""Worker F (W7) — kill tests for the textforensics.ed25519 proofset.

Covers every function in textforensics.ed25519 with direct oracles
(RFC 8032 section 7.1 vectors, an independent Edwards-addition
reference, direct helper boundary tests, and a cryptography
cross-check). Test methods are numbered so the cheap deterministic
unit tests run before the slow sign/verify vector tests: cosmic-ray
runs the file with ``-x``, so a mutant killed by a cheap test fails
fast. Each test names the mutant classes it kills.

Vectors copied from tests/test_sealing.py (RFC 8032 section 7.1).
"""

from __future__ import annotations

import hashlib
import unittest

from textforensics.ed25519 import (
    _BASE_POINT,
    _D,
    _I,
    _L,
    _Q,
    _clamp,
    _decode_point,
    _decode_scalar,
    _encode_point,
    _point_add,
    _scalar_mult,
    _sha512,
    _x_recover,
    _y_on_curve,
    fingerprint,
    keygen,
    public_key_from_seed,
    sign,
    verify,
)

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

SEED1 = bytes.fromhex(RFC8032_VECTORS[0][0])
PUB1 = bytes.fromhex(RFC8032_VECTORS[0][1])
IDENTITY = (0, 1)
IDENTITY_ENC = b"\x01" + b"\x00" * 31


def _add_reference(point_p, point_q):
    """Independent Edwards addition (RFC 8032 5.1.4) for the tests.

    Uses pow(x, -1, _Q) for the modular inverse, a different code
    path from the module's pow(x, _Q - 2, _Q), so a mutant in the
    module's formula cannot hide behind the same computation here.
    """
    x1, y1 = point_p
    x2, y2 = point_q
    denom_x = pow(1 + _D * x1 * x2 * y1 * y2, -1, _Q)
    denom_y = pow(1 - _D * x1 * x2 * y1 * y2, -1, _Q)
    x3 = (x1 * y2 + x2 * y1) * denom_x % _Q
    y3 = (y1 * y2 + x1 * x2) * denom_y % _Q
    return (x3, y3)


def _x_recover_reference(y):
    """Independent copy of the _x_recover algorithm for the tests."""
    xx = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


def _clamp_reference(digest):
    clamped = bytearray(digest[:32])
    clamped[0] &= 248
    clamped[31] &= 127
    clamped[31] |= 64
    return int.from_bytes(clamped, "little")


class Ed25519KillTests(unittest.TestCase):
    def test_00_clamp_direct(self):
        # Kills the _clamp mutants (ReplaceBinaryOperator on &248 /
        # &127 / |64, NumberReplacer on the masks, int.from_bytes
        # byte-order/length mutants): any change alters the scalar.
        digests = [
            bytes(range(64)),
            b"\xff" * 64,
            b"\x00" * 64,
            _sha512(b"clamp probe"),
            _sha512(b""),
        ]
        for digest in digests:
            with self.subTest(digest=digest[:4].hex()):
                self.assertEqual(_clamp(digest), _clamp_reference(digest))
        # Bit-level spot checks: low bits of byte 0 cleared, top bits
        # of byte 31 forced to 01.
        self.assertEqual(_clamp(b"\xff" * 64) & 7, 0)
        self.assertEqual(_clamp(b"\xff" * 64) >> 253, 0b11)
        self.assertEqual(_clamp(b"\x00" * 64) >> 254, 1)

    def test_01_point_add_direct(self):
        # Kills the _point_add mutants (all ReplaceBinaryOperator /
        # ReplaceComparisonOperator sites in the addition formula):
        # the reference uses a different inverse path, so any formula
        # change alters at least one of these points.
        b = _BASE_POINT
        two_b = _add_reference(b, b)
        three_b = _add_reference(two_b, b)
        neg_b = (_Q - b[0], b[1])
        self.assertEqual(_point_add(IDENTITY, b), b)
        self.assertEqual(_point_add(b, IDENTITY), b)
        self.assertEqual(_point_add(IDENTITY, IDENTITY), IDENTITY)
        self.assertEqual(_point_add(b, b), two_b)
        self.assertEqual(_point_add(two_b, b), three_b)
        self.assertEqual(_point_add(b, three_b), _add_reference(b, three_b))
        self.assertEqual(_point_add(b, neg_b), IDENTITY)
        self.assertEqual(_point_add(neg_b, neg_b), _add_reference(neg_b, neg_b))
        self.assertTrue(_y_on_curve(*_point_add(b, b)))
        self.assertTrue(_y_on_curve(*_point_add(two_b, three_b)))

    def test_02_scalar_mult_small(self):
        # Kills the _scalar_mult mutants (loop/bit/ZeroIterationForLoop
        # / ReplaceBinaryOperator sites): 0 -> identity, 1 -> B,
        # 2 -> 2B, 3 -> 3B, _L -> identity (group order), _L + 1 -> B.
        b = _BASE_POINT
        self.assertEqual(_scalar_mult(b, 0), IDENTITY)
        self.assertEqual(_scalar_mult(b, 1), b)
        self.assertEqual(_scalar_mult(b, 2), _add_reference(b, b))
        self.assertEqual(_scalar_mult(b, 3), _add_reference(_add_reference(b, b), b))
        self.assertEqual(_scalar_mult(b, _L), IDENTITY)
        self.assertEqual(_scalar_mult(b, _L + 1), b)
        self.assertEqual(_scalar_mult(IDENTITY, 12345), IDENTITY)

    def test_03_x_recover_direct(self):
        # Kills the _x_recover mutants (pow exponents, the _I branch
        # condition, the parity branch): the battery covers y values
        # taking the _I branch (0, 2, 3, 4, 5, ...) and y values
        # whose recovered point is off-curve (2, 7, 8, ...), plus the
        # base-point y and _Q - 1.
        battery = list(range(0, 21)) + [7, 8, 11, 12, _Q - 1]
        base_y = _BASE_POINT[1]
        battery.append(base_y)
        for y in battery:
            with self.subTest(y=y if y < 100 else "base/_Q-1"):
                self.assertEqual(_x_recover(y), _x_recover_reference(y))
        # The base point recovers exactly (even-x convention).
        self.assertEqual(_x_recover(base_y), _BASE_POINT[0])
        self.assertEqual(_x_recover(base_y) % 2, 0)
        # On-curve y values satisfy x^2 == xx after recovery.
        for y in (0, 1, base_y, _Q - 1):
            xx = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q) % _Q
            self.assertEqual((_x_recover(y) ** 2 - xx) % _Q, 0)

    def test_04_encode_decode_round_trip(self):
        # Kills the _encode_point / _decode_point mutants (the
        # (x & 1) << 255 top-bit term, the 255-bit mask, the parity
        # flip, the y >= _Q guard): round trips in both parities and
        # exact identity encoding.
        b = _BASE_POINT
        two_b = _add_reference(b, b)
        for point in (IDENTITY, b, two_b, _add_reference(two_b, b)):
            with self.subTest(point=point == IDENTITY):
                self.assertEqual(_decode_point(_encode_point(point)), point)
        self.assertEqual(_encode_point(IDENTITY), IDENTITY_ENC)
        self.assertEqual(_encode_point(b)[31] >> 7, 0)
        # Odd-x point: decode y=1 with the top bit set, then re-encode.
        odd = _decode_point((1 | (1 << 255)).to_bytes(32, "little"))
        assert odd is not None
        self.assertEqual(odd[0] % 2, 1)
        self.assertEqual(_encode_point(odd), (1 | (1 << 255)).to_bytes(32, "little"))
        self.assertEqual(_decode_point(_encode_point(odd)), odd)

    def test_05_decode_point_boundaries(self):
        # Kills the _decode_point guard mutants (len != 32, y >= _Q,
        # the parity comparison, the _y_on_curve check): y=2 is
        # off-curve (recovered x is not on the curve), y=_Q is out of
        # range, y=_Q-1 is on-curve.
        self.assertIsNone(_decode_point(b""))
        self.assertIsNone(_decode_point(b"\x00" * 31))
        self.assertIsNone(_decode_point(b"\x00" * 33))
        self.assertIsNone(_decode_point((2).to_bytes(32, "little")))
        self.assertIsNone(_decode_point((2 | (1 << 255)).to_bytes(32, "little")))
        self.assertIsNone(_decode_point(_Q.to_bytes(32, "little")))
        # y just above _Q (up to 2**255 - 1) is out of range too:
        # this kills the `y >= _Q` -> `y == _Q` mutant, which
        # accepts _Q+1..2**255-1 when the on-curve check passes
        # mod _Q (e.g. _Q+1 recovers x=0 on the curve).
        self.assertIsNone(_decode_point((_Q + 1).to_bytes(32, "little")))
        self.assertIsNone(_decode_point(((2**255) - 1).to_bytes(32, "little")))
        self.assertIsNotNone(_decode_point((_Q - 1).to_bytes(32, "little")))
        self.assertIsNotNone(_decode_point(IDENTITY_ENC))
        self.assertEqual(_decode_point(IDENTITY_ENC), IDENTITY)
        self.assertEqual(_decode_point((1).to_bytes(32, "little")), IDENTITY)

    def test_06_decode_scalar_boundaries(self):
        # Kills the _decode_scalar guard mutants (len != 32,
        # scalar >= _L and every comparison replacement): _L itself
        # must be rejected, _L - 1 accepted, _L + 1 rejected.
        self.assertIsNone(_decode_scalar(b""))
        self.assertIsNone(_decode_scalar(b"\x00" * 31))
        self.assertIsNone(_decode_scalar(b"\x00" * 33))
        self.assertIsNone(_decode_scalar(_L.to_bytes(32, "little")))
        self.assertIsNone(_decode_scalar((_L + 1).to_bytes(32, "little")))
        self.assertEqual(_decode_scalar((_L - 1).to_bytes(32, "little")), _L - 1)
        self.assertEqual(_decode_scalar((0).to_bytes(32, "little")), 0)
        self.assertEqual(_decode_scalar((1).to_bytes(32, "little")), 1)

    def test_07_y_on_curve_direct(self):
        # Kills the _y_on_curve mutants (every operator in the curve
        # equation -x^2 + y^2 = 1 + d*x^2*y^2 (mod q)): on-curve and
        # off-curve points on both sides of the equation.
        self.assertTrue(_y_on_curve(0, 1))
        self.assertTrue(_y_on_curve(*_BASE_POINT))
        self.assertTrue(_y_on_curve(*_add_reference(_BASE_POINT, _BASE_POINT)))
        self.assertFalse(_y_on_curve(1, 1))
        self.assertFalse(_y_on_curve(2, 2))
        self.assertFalse(_y_on_curve(0, 0))
        self.assertFalse(_y_on_curve(1, 0))

    def test_08_public_key_from_seed_vectors_and_validation(self):
        # Kills the public_key_from_seed mutants (seed-length guard,
        # _sha512/_clamp/_scalar_mult/_encode_point chain): the RFC
        # public keys are exact external oracles.
        for seed_hex, public_hex, _msg, _sig in RFC8032_VECTORS:
            # Plain loop (no subTest): the first mismatch aborts the
            # method, so a killed mutant fails fast under -x.
            self.assertEqual(
                public_key_from_seed(bytes.fromhex(seed_hex)),
                bytes.fromhex(public_hex),
            )
        for bad in (b"", b"\x00" * 31, b"\x00" * 33, "not bytes", None, 1234):
            with self.subTest(bad=repr(bad)[:20]), self.assertRaises(ValueError):
                public_key_from_seed(bad)  # type: ignore[arg-type]
        self.assertEqual(public_key_from_seed(bytearray(SEED1)), PUB1)

    def test_09_sign_rfc_vectors_and_determinism(self):
        # Kills the sign mutants (nonce derivation, challenge, the
        # signature-scalar equation, to_bytes length): the RFC
        # signatures are exact external oracles, and signing is
        # deterministic.
        for seed_hex, _pub, message_hex, signature_hex in RFC8032_VECTORS:
            # Plain loop (no subTest): see test_08.
            seed = bytes.fromhex(seed_hex)
            message = bytes.fromhex(message_hex)
            self.assertEqual(sign(seed, message), bytes.fromhex(signature_hex))
        self.assertEqual(sign(SEED1, b"deterministic"), sign(SEED1, b"deterministic"))
        self.assertNotEqual(sign(SEED1, b"a"), sign(SEED1, b"b"))
        self.assertEqual(sign(SEED1, bytearray(b"abc")), sign(SEED1, b"abc"))
        for bad_seed in (b"", b"\x00" * 31, b"\x00" * 33, "seed", None):
            with (
                self.subTest(bad_seed=repr(bad_seed)[:16]),
                self.assertRaises(ValueError),
            ):
                sign(bad_seed, b"m")  # type: ignore[arg-type]
        for bad_msg in ("message", None, 42):
            with (
                self.subTest(bad_msg=repr(bad_msg)[:16]),
                self.assertRaises(ValueError),
            ):
                sign(SEED1, bad_msg)  # type: ignore[arg-type]

    def test_10_verify_vectors_and_tampers(self):
        # Kills the verify mutants (length guards, _decode_point /
        # _decode_scalar calls, the challenge hash, left == right):
        # valid signatures verify; every tamper class fails, including
        # the two crafted out-of-range-S cases that distinguish the
        # _decode_scalar comparison replacements (>= -> > and >= -> ==).
        # One vector verify here (all three vectors are already
        # covered exactly by test_08/test_09); the tamper battery
        # below exercises verify() itself.
        seed_hex, public_hex, message_hex, signature_hex = RFC8032_VECTORS[0]
        self.assertTrue(
            verify(
                bytes.fromhex(public_hex),
                bytes.fromhex(message_hex),
                bytes.fromhex(signature_hex),
            )
        )
        message = b"case file body"
        signature = sign(SEED1, message)
        self.assertTrue(verify(PUB1, message, signature))
        self.assertTrue(verify(PUB1, bytearray(message), bytearray(signature)))
        flipped = bytearray(signature)
        flipped[0] ^= 1
        flipped_r = bytearray(signature)
        flipped_r[40] ^= 1
        bad_cases = [
            (PUB1, message, bytes(flipped)),
            (PUB1, message, bytes(flipped_r)),
            (PUB1, b"different message", signature),
            (PUB1, message, signature[:32]),
            (PUB1, message, signature + b"\x00"),
            (PUB1, message, b""),
            (PUB1[:31], message, signature),
            (PUB1 + b"\x00", message, signature),
            (b"", message, signature),
            (b"\x00" * 32, message, signature),
            (PUB1, b"", signature),
            (b"", b"", b""),
            # R not on the curve (y=2) and A not on the curve (y=2).
            (PUB1, message, (2).to_bytes(32, "little") + signature[32:]),
            ((2).to_bytes(32, "little"), message, signature),
            # R = identity, S = _L (rejected by _decode_scalar): the
            # >= -> > mutant accepts S == _L and then verifies (both
            # sides are the identity), so this kills it.
            (
                IDENTITY_ENC,
                message,
                IDENTITY_ENC + _L.to_bytes(32, "little"),
            ),
            # S = S_valid + _L (rejected by _decode_scalar): the
            # >= -> == mutant accepts it and then verifies (B*S' ==
            # B*S_valid), so this kills it.
            (
                PUB1,
                message,
                signature[:32]
                + (int.from_bytes(signature[32:], "little") + _L).to_bytes(32, "little"),
            ),
        ]
        for key, msg, sig in bad_cases:
            # Plain loop (no subTest): the first wrong verdict aborts
            # the method, so a killed mutant fails fast under -x.
            self.assertFalse(verify(key, msg, sig))
        # Non-bytes inputs never raise.
        self.assertFalse(verify("key", message, signature))  # type: ignore[arg-type]
        self.assertFalse(verify(PUB1, "message", signature))  # type: ignore[arg-type]
        self.assertFalse(verify(PUB1, message, "signature"))  # type: ignore[arg-type]
        self.assertFalse(verify(None, None, None))  # type: ignore[arg-type]
        # Lists of ints are not bytes, but bytes(list-of-ints)
        # succeeds, so verify must reject them explicitly. This
        # kills the `or` -> `and` mutants on the first two `or`s
        # of the isinstance chain (occ 2 and occ 3), which proceed
        # past the guard and then verify True via the bytes()
        # normalisation at line 188 (list-msg kills both, list-pk
        # kills occ 2).
        self.assertFalse(verify(list(PUB1), message, signature))  # type: ignore[arg-type]
        self.assertFalse(verify(PUB1, list(message), signature))  # type: ignore[arg-type]

        # A bytes subclass whose slicing raises must still be caught
        # by verify's broad except (the documented never-raises
        # contract): this kills the ExceptionReplacer mutant on the
        # `except Exception` handler if it narrows the caught type.
        class _RaisingBytes(bytes):
            def __getitem__(self, key):  # type: ignore[override]
                raise RuntimeError("hostile slice")

        self.assertFalse(verify(PUB1, message, _RaisingBytes(signature)))

    def test_11_keygen_and_fingerprint(self):
        # Kills the keygen mutants (token_bytes length) and the
        # fingerprint mutants (length guard, sha256 hexdigest).
        seed, public_key = keygen()
        self.assertEqual(len(seed), 32)
        self.assertEqual(len(public_key), 32)
        self.assertEqual(public_key_from_seed(seed), public_key)
        self.assertEqual(
            fingerprint(PUB1),
            hashlib.sha256(PUB1).hexdigest(),
        )
        self.assertEqual(len(fingerprint(PUB1)), 64)
        for bad in (b"", b"\x00" * 31, b"\x00" * 33, "key", None):
            with self.subTest(bad=repr(bad)[:16]), self.assertRaises(ValueError):
                fingerprint(bad)  # type: ignore[arg-type]
        self.assertEqual(fingerprint(bytearray(PUB1)), fingerprint(PUB1))

    def test_12_cryptography_cross_check(self):
        # Kills any remaining arithmetic mutant that the vectors miss
        # (fresh random keys/messages, both directions).
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
                Ed25519PublicKey,
            )
        except ImportError as exc:  # pragma: no cover - dev venv has it
            self.fail(f"cryptography is required for the cross-check: {exc}")
        for _ in range(2):
            seed, public_key = keygen()
            message = hashlib.sha256(seed).digest()
            ours = sign(seed, message)
            Ed25519PublicKey.from_public_bytes(public_key).verify(ours, message)
            private = Ed25519PrivateKey.from_private_bytes(seed)
            theirs = private.sign(message)
            self.assertTrue(verify(public_key, message, theirs))
            self.assertEqual(private.public_key().public_bytes_raw(), public_key)
