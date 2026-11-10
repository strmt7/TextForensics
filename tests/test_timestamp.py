"""Tests for the RFC 3161 timestamp module (Phase 3 U2, T3 seal).

Fixtures are real CMS tokens built in the test helper with the
production DER encoder plus ``cryptography`` signing (imported inside
the test methods, so this file still collects in a bare core-only
venv).  No test touches the network: live-TSA interop is a manual
development check, recorded in the U2 report, not a CI test.
"""

import hashlib
import unittest
import urllib.error
from datetime import UTC, datetime, timedelta
from unittest import mock

from textforensics.timestamp import (
    OID_ECDSA_WITH_SHA256,
    OID_ECDSA_WITH_SHA384,
    OID_ECDSA_WITH_SHA512,
    OID_MESSAGE_DIGEST,
    OID_SHA256,
    OID_SHA256_WITH_RSA,
    OID_SHA384,
    OID_SHA384_WITH_RSA,
    OID_SHA512,
    OID_SHA512_WITH_RSA,
    OID_TST_INFO,
    TimestampError,
    _der_context,
    _der_generalized_time,
    _der_integer,
    _der_octet_string,
    _der_oid,
    _der_sequence,
    _der_set,
    build_timestamp_request,
    parse_timestamp_response,
    parse_timestamp_token,
    request_timestamp,
    verify_timestamp_token,
)

# The true id-signedData OID, written out as a literal on purpose: the
# token fixtures must NOT import OID_SIGNED_DATA from production code.
# Importing it made the fixtures self-consistent with the wrong value
# (1.2.840.113549.1.9.16.1.2, id-ct-authData) and hid the defect until
# a live freeTSA token was rejected on 2026-11-10.
OID_SIGNED_DATA_TRUE = "1.2.840.113549.1.7.2"

DIGEST = hashlib.sha256(b"sealed-bundle-digest-fixture").digest()
NONCE = 1234567890123456789
GEN_TIME = "20261107120000Z"
POLICY = "1.2.3.4.5"


def _build_token(
    private_key,
    cert_der,
    issuer_name_der,
    serial=1,
    *,
    nonce=NONCE,
    digest=DIGEST,
    gen_time=GEN_TIME,
    tamper_signature=False,
    hash_algorithm="sha256",
    content_type_oid=OID_SIGNED_DATA_TRUE,
):
    """Build a TimeStampResp carrying a CMS-signed TSTInfo.

    ``private_key``/``cert_der`` come from ``cryptography`` in the test;
    all DER structure uses the production encoder in timestamp.py.

    ``content_type_oid`` defaults to the hardcoded true id-signedData
    OID (see ``OID_SIGNED_DATA_TRUE``) — never the production constant
    — so a regression in the production constant fails this builder's
    tokens instead of being baked into them. ``hash_algorithm`` selects
    the imprint hash, the signer digest algorithm, and the signature
    algorithm (RSA PKCS#1 v1.5 or ECDSA over the matching curve).
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    hash_oids = {
        "sha256": OID_SHA256,
        "sha384": OID_SHA384,
        "sha512": OID_SHA512,
    }
    hash_classes = {
        "sha256": hashes.SHA256,
        "sha384": hashes.SHA384,
        "sha512": hashes.SHA512,
    }
    rsa_sig_oids = {
        "sha256": OID_SHA256_WITH_RSA,
        "sha384": OID_SHA384_WITH_RSA,
        "sha512": OID_SHA512_WITH_RSA,
    }
    ec_sig_oids = {
        "sha256": OID_ECDSA_WITH_SHA256,
        "sha384": OID_ECDSA_WITH_SHA384,
        "sha512": OID_ECDSA_WITH_SHA512,
    }
    hash_oid = hash_oids[hash_algorithm]
    hash_cls = hash_classes[hash_algorithm]

    tst_info = _der_sequence(
        _der_integer(1),
        _der_oid(POLICY),
        _der_sequence(
            _der_sequence(_der_oid(hash_oid)),
            _der_octet_string(digest),
        ),
        _der_integer(serial),
        _der_generalized_time(gen_time),
        _der_integer(nonce),
    )
    econtent_digest = hashlib.new(hash_algorithm, tst_info).digest()
    message_digest_attr = _der_sequence(
        _der_oid(OID_MESSAGE_DIGEST),
        _der_set(_der_octet_string(econtent_digest)),
    )
    signing_time_attr = _der_sequence(
        _der_oid("1.2.840.113549.1.9.5"),
        _der_set(_der_generalized_time(gen_time)),
    )
    signed_attrs = _der_set(message_digest_attr, signing_time_attr)
    # CMS signs the SET OF encoding (tag 0x31), not the [0] wrapper.
    to_sign = b"\x31" + signed_attrs[1:]
    if isinstance(private_key, _rsa_key_type()):
        signature = private_key.sign(to_sign, padding.PKCS1v15(), hash_cls())
        sig_oid = rsa_sig_oids[hash_algorithm]
    else:
        from cryptography.hazmat.primitives.asymmetric import ec

        signature = private_key.sign(to_sign, ec.ECDSA(hash_cls()))
        # cryptography returns a raw r||s pair for ECDSA; CMS needs the
        # ASN.1 ECDSA-Sig-Value SEQUENCE.
        from cryptography.hazmat.primitives.asymmetric.utils import (
            decode_dss_signature,
        )

        r, s = decode_dss_signature(signature)
        signature = _der_sequence(_der_integer(r), _der_integer(s))
        sig_oid = ec_sig_oids[hash_algorithm]
    if tamper_signature:
        # Flip a bit in the middle of the signature. Zeroing the first
        # byte was a no-op for RSA when that byte is already 0x00
        # (probability ~1/256), which made test_tampered_signature_fails
        # flaky — the middle byte is inside the signature value for
        # both RSA and ECDSA, so the flip always changes the value
        # while keeping the DER structure parseable.
        mid = len(signature) // 2
        signature = signature[:mid] + bytes([signature[mid] ^ 0x01]) + signature[mid + 1 :]
    # sid = IssuerAndSerialNumber: the issuer Name DER + serial.
    sid = _der_sequence(issuer_name_der, _der_integer(serial))
    signer_info = _der_sequence(
        _der_integer(1),
        sid,
        _der_sequence(_der_oid(hash_oid)),
        # signedAttrs is [0] IMPLICIT SET OF: tag 0xA0 around the raw
        # Attribute encodings (the SET OF tag itself is not included).
        _der_context(0, _signed_attrs_content(signed_attrs), constructed=True),
        _der_sequence(_der_oid(sig_oid)),
        _der_octet_string(signature),
    )
    signed_data = _der_sequence(
        _der_integer(1),
        _der_set(_der_sequence(_der_oid(hash_oid))),
        _der_sequence(
            _der_oid(OID_TST_INFO),
            _der_context(0, _der_octet_string(tst_info), constructed=True),
        ),
        _der_context(0, cert_der, constructed=True),
        _der_set(signer_info),
    )
    token = _der_sequence(
        _der_oid(content_type_oid),
        _der_context(0, signed_data, constructed=True),
    )
    response = _der_sequence(
        _der_sequence(_der_integer(0)),
        token,
    )
    return response


def _signed_attrs_content(signed_attrs_set_der):
    """Content bytes of a DER SET OF (everything after tag+length)."""
    # signed_attrs_set_der starts 0x31 <len> <content...>.
    first = signed_attrs_set_der[1]
    if first & 0x80 == 0:
        return signed_attrs_set_der[2:]
    nbytes = first & 0x7F
    return signed_attrs_set_der[2 + nbytes :]


def _rsa_key_type():
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

    return RSAPrivateKey


def _make_rsa_fixture():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TSA")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    cert_der = cert.public_bytes(Encoding.DER)
    issuer_der = cert.issuer.public_bytes()
    return key, cert_der, issuer_der


def _make_chain_fixture():
    """CA + leaf, leaf signed by the CA (serial 7) — the live chain shape.

    Returns ``(leaf_key, chain_der, leaf_der, leaf_issuer_der)`` where
    ``chain_der`` is the CA certificate followed by the leaf, i.e. the
    signer is second: sid matching, not first-certificate fallback,
    must find it.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TSA CA")])
    now = datetime.now(UTC)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TSA Leaf")])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(7)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    ca_der = ca_cert.public_bytes(Encoding.DER)
    leaf_der = leaf_cert.public_bytes(Encoding.DER)
    return leaf_key, ca_der + leaf_der, leaf_der, leaf_cert.issuer.public_bytes()


def _make_ec_fixture():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test EC TSA")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(7)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return key, cert.public_bytes(Encoding.DER), cert.issuer.public_bytes()


def _make_ec384_fixture():
    """SECP384R1 signer — the live freeTSA shape (P-384, ECDSA-SHA512).

    Returns ``(key, cert_der, issuer_der)`` like ``_make_ec_fixture``.
    The certificate itself is signed with SHA-384.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP384R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test EC384 TSA")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(7)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA384())
    )
    return key, cert.public_bytes(Encoding.DER), cert.issuer.public_bytes()


class TimestampRequestTests(unittest.TestCase):
    def test_build_request_structure(self):
        request, nonce = build_timestamp_request(DIGEST, nonce=NONCE)
        self.assertEqual(nonce, NONCE)
        # Parse it back with the production parser: version 1, imprint,
        # nonce, certReq TRUE.
        from textforensics.timestamp import _children, _parse_all, _parse_integer

        root = _parse_all(request)
        fields = _children(root)
        self.assertEqual(_parse_integer(fields[0]), 1)
        imprint = _children(fields[1])
        self.assertEqual(imprint[1].content, DIGEST)
        self.assertEqual(_parse_integer(fields[2]), NONCE)
        self.assertEqual(fields[3].content, b"\xff")

    def test_build_request_random_nonce(self):
        _, nonce1 = build_timestamp_request(DIGEST)
        _, nonce2 = build_timestamp_request(DIGEST)
        self.assertNotEqual(nonce1, nonce2)

    def test_build_request_rejects_wrong_digest_length(self):
        with self.assertRaises(TimestampError):
            build_timestamp_request(b"short")

    def test_build_request_rejects_unknown_hash(self):
        with self.assertRaises(TimestampError):
            build_timestamp_request(DIGEST, hash_algorithm="md5")

    def test_request_timestamp_refuses_plain_http_url(self):
        # B310 fix: a plain-http TSA would let a network attacker
        # substitute the token endpoint. Fails before any network use.
        with (
            mock.patch("textforensics.timestamp._guarded_urlopen") as urlopen,
            self.assertRaises(TimestampError) as ctx,
        ):
            request_timestamp(DIGEST, "http://example.invalid/tsa")
        self.assertIn("https", str(ctx.exception))
        urlopen.assert_not_called()

    def test_request_timestamp_refuses_file_url(self):
        with (
            mock.patch("textforensics.timestamp._guarded_urlopen") as urlopen,
            self.assertRaises(TimestampError),
        ):
            request_timestamp(DIGEST, "file:///tmp/tsa")
        urlopen.assert_not_called()

    def test_request_timestamp_https_reaches_network(self):
        # An https URL passes validation and attempts the fetch: a
        # transport failure surfaces as "unreachable", not a refusal.
        with (
            mock.patch(
                "textforensics.timestamp._guarded_urlopen",
                side_effect=urllib.error.URLError("down"),
            ),
            self.assertRaises(TimestampError) as ctx,
        ):
            request_timestamp(DIGEST, "https://example.invalid/tsa")
        self.assertIn("unreachable", str(ctx.exception))

    def test_request_timestamp_loopback_http_reaches_network(self):
        # Local TSA fixtures on loopback stay usable.
        with (
            mock.patch(
                "textforensics.timestamp._guarded_urlopen",
                side_effect=urllib.error.URLError("down"),
            ),
            self.assertRaises(TimestampError) as ctx,
        ):
            request_timestamp(DIGEST, "http://127.0.0.1:9/tsa")
        self.assertIn("unreachable", str(ctx.exception))


class TimestampResponseTests(unittest.TestCase):
    def test_parse_response_granted_with_token(self):
        key, cert_der, issuer_der = _make_rsa_fixture()
        response = _build_token(key, cert_der, issuer_der)
        status, token = parse_timestamp_response(response)
        self.assertEqual(status, 0)
        self.assertIsNotNone(token)

    def test_parse_response_rejection_without_token(self):
        response = _der_sequence(_der_sequence(_der_integer(2)))
        status, token = parse_timestamp_response(response)
        self.assertEqual(status, 2)
        self.assertIsNone(token)

    def test_parse_response_rejects_trailing_bytes(self):
        key, cert_der, issuer_der = _make_rsa_fixture()
        response = _build_token(key, cert_der, issuer_der) + b"junk"
        with self.assertRaises(TimestampError):
            parse_timestamp_response(response)


class TimestampVerifyTests(unittest.TestCase):
    def _rsa_token(self, **kwargs):
        key, cert_der, issuer_der = _make_rsa_fixture()
        response = _build_token(key, cert_der, issuer_der, **kwargs)
        _, token = parse_timestamp_response(response)
        assert token is not None
        return token

    def test_rsa_token_verifies(self):
        token = self._rsa_token()
        report = verify_timestamp_token(token, expected_digest=DIGEST, expected_nonce=NONCE)
        self.assertTrue(report["valid"], report["errors"])
        self.assertEqual(report["gen_time"], GEN_TIME)
        self.assertEqual(report["policy"], POLICY)
        self.assertEqual(report["serial_number"], 1)
        self.assertEqual(report["signature_algorithm"], OID_SHA256_WITH_RSA)
        self.assertEqual(report["certificate_count"], 1)
        self.assertIsNotNone(report["signer_cert_fingerprint"])
        # Offline: qualification is always unknown, honestly labelled.
        self.assertEqual(report["qualified"], "unknown")
        self.assertEqual(report["qualification_label"], "RFC 3161 timestamp (non-qualified)")

    def test_chain_token_verifies_with_signer_second(self):
        # Live shape: a chain (CA first, leaf/signer second). Sid
        # matching must pick the leaf, not the first certificate.
        leaf_key, chain_der, leaf_der, leaf_issuer_der = _make_chain_fixture()
        response = _build_token(leaf_key, chain_der, leaf_issuer_der, serial=7)
        _, token = parse_timestamp_response(response)
        assert token is not None
        report = verify_timestamp_token(token, expected_digest=DIGEST, expected_nonce=NONCE)
        self.assertTrue(report["valid"], report["errors"])
        self.assertEqual(report["certificate_count"], 2)
        self.assertEqual(report["signer_cert_fingerprint"], hashlib.sha256(leaf_der).hexdigest())

    def test_ec_token_verifies(self):
        key, cert_der, issuer_der = _make_ec_fixture()
        response = _build_token(key, cert_der, issuer_der, serial=7)
        _, token = parse_timestamp_response(response)
        assert token is not None
        report = verify_timestamp_token(token, expected_digest=DIGEST, expected_nonce=NONCE)
        self.assertTrue(report["valid"], report["errors"])
        self.assertEqual(report["signature_algorithm"], OID_ECDSA_WITH_SHA256)
        self.assertEqual(report["serial_number"], 7)

    def test_token_with_hardcoded_signed_data_oid_verifies(self):
        # The ContentInfo contentType is the literal id-signedData OID
        # 1.2.840.113549.1.7.2 — written out here, NOT imported from
        # production code. With the old production constant
        # (1.2.840.113549.1.9.16.1.2, id-ct-authData) this token was
        # rejected as token_unparseable, exactly like the live freeTSA
        # token on 2026-11-10.
        key, cert_der, issuer_der = _make_rsa_fixture()
        response = _build_token(key, cert_der, issuer_der, content_type_oid="1.2.840.113549.1.7.2")
        _, token = parse_timestamp_response(response)
        assert token is not None
        report = verify_timestamp_token(token, expected_digest=DIGEST, expected_nonce=NONCE)
        self.assertTrue(report["valid"], report["errors"])

    def test_p384_sha512_token_verifies(self):
        # Live shape: SECP384R1 signer, ecdsa-with-SHA512 — the exact
        # algorithm freeTSA uses. With the old P-384 table (wrong gy
        # and n) this failed with signature_verification_failed even
        # once the OID gate was passed.
        digest = hashlib.sha512(b"sealed-bundle-digest-fixture").digest()
        key, cert_der, issuer_der = _make_ec384_fixture()
        response = _build_token(
            key, cert_der, issuer_der, serial=7, digest=digest, hash_algorithm="sha512"
        )
        _, token = parse_timestamp_response(response)
        assert token is not None
        report = verify_timestamp_token(
            token,
            expected_digest=digest,
            expected_hash_algorithm="sha512",
            expected_nonce=NONCE,
        )
        self.assertTrue(report["valid"], report["errors"])
        self.assertEqual(report["signature_algorithm"], OID_ECDSA_WITH_SHA512)
        self.assertEqual(report["serial_number"], 7)
        self.assertEqual(report["certificate_count"], 1)

    def test_ec_curve_generators_are_on_curve_with_correct_order(self):
        # The P-384 table shipped with a wrong gy (64 hex chars, not
        # on the curve) and a wrong n (104 hex chars, n > p). Pin the
        # table itself: each generator must lie on its curve, the
        # order must be below p, and n*G must be the point at
        # infinity. Arithmetic here is local to the test, not the
        # module's own helpers, so a table error cannot hide behind
        # shared code.
        from textforensics.timestamp import _EC_CURVES

        def add(p1, p2, p, a):
            if p1 is None:
                return p2
            if p2 is None:
                return p1
            if p1[0] == p2[0] and (p1[1] + p2[1]) % p == 0:
                return None
            if p1 == p2:
                lam = (3 * p1[0] * p1[0] + a) * pow(2 * p1[1], -1, p) % p
            else:
                lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], -1, p) % p
            x3 = (lam * lam - p1[0] - p2[0]) % p
            return (x3, (lam * (p1[0] - x3) - p1[1]) % p)

        def mult(k, point, p, a):
            result = None
            addend = point
            while k:
                if k & 1:
                    result = add(result, addend, p, a)
                addend = add(addend, addend, p, a)
                k >>= 1
            return result

        for name in ("P-256", "P-384"):
            curve = _EC_CURVES[name]
            p, a, b, n = curve["p"], curve["a"], curve["b"], curve["n"]
            gx, gy = curve["gx"], curve["gy"]
            self.assertEqual((gy * gy) % p, (gx * gx * gx + a * gx + b) % p, f"{name} G on curve")
            self.assertLess(n, p, f"{name} order below p")
            self.assertIsNone(mult(n, (gx, gy), p, a), f"{name} n*G is infinity")

    def test_wrong_digest_fails(self):
        token = self._rsa_token()
        report = verify_timestamp_token(
            token,
            expected_digest=hashlib.sha256(b"other").digest(),
            expected_nonce=NONCE,
        )
        self.assertFalse(report["valid"])
        self.assertIn("message_imprint_mismatch", report["errors"])

    def test_wrong_nonce_fails(self):
        token = self._rsa_token()
        report = verify_timestamp_token(token, expected_digest=DIGEST, expected_nonce=NONCE + 1)
        self.assertFalse(report["valid"])
        self.assertIn("nonce_mismatch", report["errors"])

    def test_tampered_signature_fails(self):
        token = self._rsa_token(tamper_signature=True)
        report = verify_timestamp_token(token, expected_digest=DIGEST, expected_nonce=NONCE)
        self.assertFalse(report["valid"])
        self.assertIn("signature_verification_failed", report["errors"])

    def test_tampered_token_bytes_fail_closed(self):
        # Flip a byte inside the CMS signature (the last bytes of the
        # token): the signature check must fail.  A flip inside the
        # embedded certificate's non-key fields is NOT detected by this
        # verifier — the certificate itself is not authenticated offline
        # (see the module docstring: qualification is "unknown").
        token = bytearray(self._rsa_token())
        token[-10] ^= 0xFF
        report = verify_timestamp_token(bytes(token), expected_digest=DIGEST, expected_nonce=NONCE)
        self.assertFalse(report["valid"])
        self.assertIn("signature_verification_failed", report["errors"])

    def test_parse_token_exposes_tst_info(self):
        token = self._rsa_token()
        parsed = parse_timestamp_token(token)
        self.assertEqual(parsed["tst_info"]["hashed_message"], DIGEST)
        self.assertEqual(parsed["tst_info"]["nonce"], NONCE)
        self.assertEqual(parsed["tst_info"]["gen_time"], GEN_TIME)
        self.assertEqual(parsed["tst_info"]["hash_algorithm"], "sha256")

    def test_garbage_token_is_an_error_not_an_exception(self):
        report = verify_timestamp_token(b"not a token", expected_digest=DIGEST)
        self.assertFalse(report["valid"])
        self.assertTrue(report["errors"])


if __name__ == "__main__":
    unittest.main()
