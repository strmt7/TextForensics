"""Shared test helper: build a real CMS time-stamp token fixture.

Used by the standalone-verifier and sealed-bundle tests.  Builds a
token with the production DER encoder from ``textforensics.timestamp``
plus ``cryptography`` RSA signing (imported inside the function, so
test files using it still collect in a bare core-only venv).
"""

import hashlib


def build_token_for_digest(digest, *, nonce=424242):
    """Build a real CMS time-stamp token over *digest*."""
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

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TSA")])
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
    signature = key.sign(to_sign, padding.PKCS1v15(), hashes.SHA256())
    sid = _der_sequence(cert.issuer.public_bytes(), _der_integer(1))
    signer_info = _der_sequence(
        _der_integer(1),
        sid,
        _der_sequence(_der_oid(OID_SHA256)),
        _der_context(0, signed_attrs[2:], constructed=True),
        _der_sequence(_der_oid(OID_SHA256_WITH_RSA)),
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
        _der_oid(OID_SIGNED_DATA),
        _der_context(0, signed_data, constructed=True),
    )
