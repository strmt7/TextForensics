"""W3 Worker F (recovery) kill tests for timestamp (audit-w3-f).

Each test kills one or more proof survivors from the W3 re-proof
(hidden_files/audit-w3-f2-survivors-timestamp.json): the test asserts
the original behaviour on a distinguishing input, so the mutant
fails it. Distinguishing inputs are reversed-order values for the
``!=`` -> ``<`` / ``>`` mutants (a lesser value kills ``>``, a
greater value kills ``<``), runtime-built distinct-but-equal values
for the ``is`` / ``is not`` mutants, mixed key/certificate tokens
for the signature-dispatch mutants, and multi-signer / multi-value /
malformed-field tokens for the count and handler mutants. The tokens
are built by ``_build_token_k``, a copy of the stock builder in
tests/test_timestamp.py extended with knobs for the signer count,
the message-digest attribute values, the sid bytes, the signer
digest OID and the signature OID. See
hidden_files/audit-w3-worker-f.md §5 for the per-mutant kill
evidence (mutate_code re-proof) and §6 for the proven-equivalent
survivors (the ``*,`` marker, the dead ``verified`` initial value,
and the shared-interned-constant ``is not`` mutants).
"""

import hashlib
from datetime import UTC, datetime, timedelta

from test_timestamp import (  # noqa: E402
    DIGEST,
    GEN_TIME,
    NONCE,
    OID_SIGNED_DATA_TRUE,
    POLICY,
    _make_ec_fixture,
    _make_rsa_fixture,
    _signed_attrs_content,
)

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
    _der_context,
    _der_generalized_time,
    _der_integer,
    _der_octet_string,
    _der_oid,
    _der_sequence,
    _der_set,
    parse_timestamp_response,
    verify_timestamp_token,
)

OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
OID_DSA = "1.2.840.10040.4.1"
OID_ED25519 = "1.3.101.112"


def _build_token_k(
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
    signer_count=1,
    tamper_extra_signer=False,
    md_values=None,
    md_extra=None,
    sid_raw=None,
    digest_oid=None,
    sig_oid=None,
    certs_der=None,
):
    """Stock token builder plus knobs for the mutation kills.

    ``md_values`` are the raw DER values inside the single
    message-digest attribute's SET (default: the correct octet
    string); ``md_extra`` is appended after the correct octet
    string (a second value); ``sid_raw`` replaces the
    IssuerAndSerialNumber bytes; ``digest_oid`` / ``sig_oid``
    override the signer digest / signature algorithm OIDs;
    ``signer_count`` duplicates the signer_info; ``certs_der``
    replaces the certificates blob.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    hash_oids = {"sha256": OID_SHA256, "sha384": OID_SHA384, "sha512": OID_SHA512}
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
    # The messageDigest attribute is computed with the SIGNER's digest
    # algorithm (RFC 5652), which is digest_oid when overridden — not
    # the imprint hash. Otherwise a token whose signer digest differs
    # from the imprint hash fails the content check before the
    # signature-hash comparison under test.
    _digest_name_by_oid = {
        OID_SHA256: "sha256",
        OID_SHA384: "sha384",
        OID_SHA512: "sha512",
    }
    signer_digest_name = _digest_name_by_oid[digest_oid if digest_oid is not None else hash_oid]
    md_digest = hashlib.new(signer_digest_name, tst_info).digest()
    if md_values is not None:
        values = list(md_values)
    elif md_extra is not None:
        values = [_der_octet_string(md_digest), md_extra]
    else:
        values = [_der_octet_string(md_digest)]
    message_digest_attr = _der_sequence(
        _der_oid(OID_MESSAGE_DIGEST),
        _der_set(*values),
    )
    signing_time_attr = _der_sequence(
        _der_oid("1.2.840.113549.1.9.5"),
        _der_set(_der_generalized_time(gen_time)),
    )
    signed_attrs = _der_set(message_digest_attr, signing_time_attr)
    to_sign = b"\x31" + signed_attrs[1:]
    if isinstance(private_key, _rsa_key_type()):
        signature = private_key.sign(to_sign, padding.PKCS1v15(), hash_cls())
        default_sig_oid = rsa_sig_oids[hash_algorithm]
    else:
        from cryptography.hazmat.primitives.asymmetric import ec

        signature = private_key.sign(to_sign, ec.ECDSA(hash_cls()))
        from cryptography.hazmat.primitives.asymmetric.utils import (
            decode_dss_signature,
        )

        r, s = decode_dss_signature(signature)
        signature = _der_sequence(_der_integer(r), _der_integer(s))
        default_sig_oid = ec_sig_oids[hash_algorithm]
    if tamper_signature:
        mid = len(signature) // 2
        signature = signature[:mid] + bytes([signature[mid] ^ 0x01]) + signature[mid + 1 :]
    sid = sid_raw if sid_raw is not None else _der_sequence(issuer_name_der, _der_integer(serial))
    digest_oid = digest_oid if digest_oid is not None else hash_oid
    sig_oid = sig_oid if sig_oid is not None else default_sig_oid

    def _one_signer(sig_bytes):
        return _der_sequence(
            _der_integer(1),
            sid,
            _der_sequence(_der_oid(digest_oid)),
            _der_context(0, _signed_attrs_content(signed_attrs), constructed=True),
            _der_sequence(_der_oid(sig_oid)),
            _der_octet_string(sig_bytes),
        )

    signers = [_one_signer(signature)] if signer_count >= 1 else []
    for _ in range(1, signer_count):
        extra = signature
        if tamper_extra_signer:
            mid = len(extra) // 2
            extra = extra[:mid] + bytes([extra[mid] ^ 0x01]) + extra[mid + 1 :]
        signers.append(_one_signer(extra))
    signed_data = _der_sequence(
        _der_integer(1),
        _der_set(_der_sequence(_der_oid(hash_oid))),
        _der_sequence(
            _der_oid(OID_TST_INFO),
            _der_context(0, _der_octet_string(tst_info), constructed=True),
        ),
        _der_context(0, certs_der if certs_der is not None else cert_der, constructed=True),
        _der_set(*signers),
    )
    token = _der_sequence(
        _der_oid(content_type_oid),
        _der_context(0, signed_data, constructed=True),
    )
    response = _der_sequence(
        _der_sequence(_der_integer(0)),
        token,
    )
    # _build_token returns a TimeStampResp; verification takes the
    # TimeStampToken inside it.
    _, token_der = parse_timestamp_response(response)
    assert token_der is not None
    return token_der


def _rsa_key_type():
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

    return RSAPrivateKey


def _make_cert(key, subject_name, issuer_name, serial, signing_key=None):
    """One self-signed (or CA-signed) certificate; returns its DER."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.serialization import Encoding

    now = datetime.now(UTC)
    signing = signing_key if signing_key is not None else key
    # Ed25519 signs with algorithm=None; RSA/DSA/EC use SHA-256.
    algorithm = None if isinstance(signing, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(signing, algorithm)
    )
    return cert.public_bytes(Encoding.DER)


def _name(common_name):
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _make_chain(serial=7, ca_name="Test TSA CA", leaf_name="Test TSA Leaf"):
    """CA + leaf, leaf signed by the CA. Returns
    ``(leaf_key, chain_der, leaf_der, ca_der, leaf_issuer_der)``
    with the CA certificate FIRST in ``chain_der``."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca = _name(ca_name)
    ca_der = _make_cert(ca_key, ca, ca, 1)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = _name(leaf_name)
    leaf_der = _make_cert(leaf_key, leaf, ca, serial, signing_key=ca_key)
    return leaf_key, ca_der + leaf_der, leaf_der, ca_der, ca.public_bytes()


def _make_ed25519_fixture():
    """Ed25519 key + self-signed cert (key OID 1.3.101.112)."""
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = ed25519.Ed25519PrivateKey.generate()
    name = _name("Test Ed TSA")
    return key, _make_cert(key, name, name, 1), name.public_bytes()


def _make_dsa_fixture():
    """DSA key + self-signed cert (key OID 1.2.840.10040.4.1)."""
    from cryptography.hazmat.primitives.asymmetric import dsa

    key = dsa.generate_private_key(key_size=2048)
    name = _name("Test DSA TSA")
    return key, _make_cert(key, name, name, 1), name.public_bytes()


def _rsa_key_der_inner(key):
    """The inner RSAPublicKey DER (SEQUENCE of modulus, exponent)
    for one RSA private key."""
    numbers = key.public_key().public_numbers()
    return _der_sequence(_der_integer(numbers.n), _der_integer(numbers.e))


def _tamper_rsa_key_in_cert(key, cert_der):
    """Flip the inner RSAPublicKey SEQUENCE tag (0x30 -> 0x31) inside
    a certificate: the certificate still parses (the BIT STRING is
    opaque to the cert parser) but _parse_rsa_public_key fails."""
    inner = _rsa_key_der_inner(key)
    offset = cert_der.find(inner)
    assert offset >= 0, "RSA key DER not found in certificate"
    assert cert_der[offset] == 0x30
    return cert_der[:offset] + b"\x31" + cert_der[offset + 1 :]


def _tamper_ec_point_in_cert(key, cert_der):
    """Flip the uncompressed-point tag (0x04 -> 0x02) inside an EC
    certificate: the certificate still parses but
    _parse_ec_public_key fails."""
    numbers = key.public_key().public_numbers()
    size = (numbers.curve.key_size + 7) // 8
    point = b"\x04" + numbers.x.to_bytes(size, "big") + numbers.y.to_bytes(size, "big")
    offset = cert_der.find(point)
    assert offset >= 0, "EC point not found in certificate"
    return cert_der[:offset] + b"\x02" + cert_der[offset + 1 :]


def _errors(report):
    return report["errors"]


def _has_error(report, prefix):
    return any(e.startswith(prefix) for e in report["errors"])


def _rsa_token(**kwargs):
    key, cert_der, issuer_der = _make_rsa_fixture()
    return _build_token_k(key, cert_der, issuer_der, **kwargs)


def _verify(token, **kwargs):
    params = {"expected_digest": DIGEST, "expected_nonce": NONCE}
    params.update(kwargs)
    return verify_timestamp_token(token, **params)


class TestWorkerFTimestampImprintKill:
    """Kill the imprint / nonce / certificate-count mutants."""

    def test_hash_algorithm_greater_mismatch(self):
        """NotEq_Lt [936,29]: a sha384 imprint against a sha256
        expectation must report the mismatch. The mutant (``<``)
        only reports lesser algorithms, so it stays silent."""
        key, cert_der, issuer_der = _make_rsa_fixture()
        digest384 = hashlib.sha384(b"sealed-bundle-digest-fixture").digest()
        token = _build_token_k(
            key,
            cert_der,
            issuer_der,
            hash_algorithm="sha384",
            digest=digest384,
        )
        report = _verify(token, expected_digest=digest384, expected_hash_algorithm="sha256")
        assert _has_error(report, "imprint_hash_algorithm_mismatch:sha384")

    def test_hash_algorithm_lesser_mismatch(self):
        """NotEq_Gt [936,29]: a sha256 imprint against a sha384
        expectation must report the mismatch. The mutant (``>``)
        only reports greater algorithms, so it stays silent."""
        token = _rsa_token()
        report = _verify(token, expected_hash_algorithm="sha384")
        assert _has_error(report, "imprint_hash_algorithm_mismatch:sha256")

    def test_hash_algorithm_distinct_object(self):
        """NotEq_IsNot [936,29]: the hash algorithm must be
        compared by VALUE. A runtime-built ``"sha256"`` is equal,
        so the token verifies; the mutant (``is not``) reports a
        mismatch. The name is built with ``"".join`` — the ``+``
        form is constant-folded to the interned literal, which is
        the SAME object as the module's ``_HASH_OIDS`` value
        (``"sha256"`` is identifier-like) and would not distinguish
        the mutant. Line 936 compares the algorithm NAME (a
        string), not the digest bytes."""
        token = _rsa_token()
        name = "".join(["sha", "256"])
        assert name != "sha256"
        report = _verify(token, expected_hash_algorithm=name)
        assert report["valid"] is True

    def test_hashed_message_greater_mismatch(self):
        """NotEq_Lt [938,29]: a hashed message GREATER than the
        expected digest must report the mismatch. The mutant
        (``<``) only reports lesser digests, so it stays silent."""
        other = hashlib.sha256(b"other-input").digest()
        assert other > DIGEST
        token = _rsa_token(digest=other)
        report = _verify(token)
        assert _has_error(report, "message_imprint_mismatch")

    def test_nonce_greater_mismatch(self):
        """NotEq_Lt [940,51]: a nonce GREATER than expected must
        report the mismatch. The mutant (``<``) only reports
        lesser nonces, so it stays silent."""
        token = _rsa_token(nonce=NONCE + 1)
        report = _verify(token)
        assert _has_error(report, "nonce_mismatch")

    def test_error_token_certificate_count_is_zero(self):
        """NumberReplacer [911,29] occ 468/469: an unparseable
        token returns the initial certificate_count of 0. The
        mutants report 1 / -1."""
        report = verify_timestamp_token(b"not a token", expected_digest=DIGEST)
        assert report["valid"] is False
        assert report["certificate_count"] == 0


class TestWorkerFTimestampSignerCountKill:
    """Kill the signer-info / message-digest count mutants."""

    def test_two_signer_infos_rejected(self):
        """NotEq_Lt [942,35]: two signer infos must report the
        count. The mutant (``<``) only reports fewer than one, so
        it proceeds and verifies with the first."""
        token = _rsa_token(signer_count=2)
        report = _verify(token)
        assert _has_error(report, "signer_info_count:2")

    def test_zero_signer_infos_rejected(self):
        """NotEq_Gt [942,35]: zero signer infos must report the
        count. The mutant (``>``) only reports more than one, so
        it proceeds and crashes on the missing first entry."""
        token = _rsa_token(signer_count=0)
        report = _verify(token)
        assert _has_error(report, "signer_info_count:0")

    def test_two_message_digests_rejected(self):
        """NotEq_Lt [952,34]: two message-digest values must report
        the ambiguity. The mutant (``<``) only reports fewer than
        one, so it proceeds with the first (correct) value and
        verifies."""
        token = _rsa_token(md_extra=_der_octet_string(b"\xff" * 32))
        report = _verify(token)
        assert _has_error(report, "message_digest_attribute_missing_or_ambiguous")

    def test_zero_message_digests_rejected(self):
        """NotEq_Gt [952,34]: zero message-digest values must
        report the ambiguity. The mutant (``>``) only reports more
        than one, so it proceeds and crashes on the missing first
        value."""
        token = _rsa_token(md_values=[])
        report = _verify(token)
        assert _has_error(report, "message_digest_attribute_missing_or_ambiguous")

    def test_first_signer_selected(self):
        """NumberReplacer [945,36] (``signer_infos[0]`` -> ``[1]``):
        the single signer must be used and the token must verify.
        The ``[1]`` mutant indexes past the one-element list and
        raises IndexError. (``[0]`` -> ``[-1]`` would select the
        same sole element — see §6 if that is the surviving
        replacement — because two signers are rejected earlier by
        the count check at line 942.)"""
        token = _rsa_token()
        report = _verify(token)
        assert report["valid"] is True

    def test_first_digest_selected(self):
        """NumberReplacer [956,55] (``message_digest_values[0]``
        -> ``[1]``): the single digest value must be used and the
        token must verify. The ``[1]`` mutant indexes past the
        one-element list and raises IndexError. (``[0]`` -> ``[-1]``
        would select the same sole element — see §6 if that is the
        surviving replacement — because two values are rejected
        earlier by the count check at line 952.)"""
        token = _rsa_token()
        report = _verify(token)
        assert report["valid"] is True


class TestWorkerFTimestampDigestAttrKill:
    """Kill the message-digest tag / content mutants."""

    def test_digest_tag_greater_not_octet_string(self):
        """NotEq_Lt [960,23]: a NULL (tag 0x05) message digest
        must report not-an-octet-string. The mutant (``<``) only
        reports lesser tags, so it proceeds to a content mismatch
        instead."""
        token = _rsa_token(md_values=[b"\x05\x00"])
        report = _verify(token)
        assert _has_error(report, "message_digest_attribute_not_octet_string")

    def test_digest_tag_lesser_not_octet_string(self):
        """NotEq_Gt [960,23]: an INTEGER (tag 0x02) message digest
        holding the right bytes must report not-an-octet-string.
        The mutant (``>``) only reports greater tags, so it
        proceeds past the tag check and verifies."""
        token = _rsa_token(md_values=[_der_integer(int.from_bytes(DIGEST, "big"))])
        report = _verify(token)
        assert _has_error(report, "message_digest_attribute_not_octet_string")

    def test_digest_content_greater_mismatch(self):
        """NotEq_Lt [968,27]: a digest GREATER than the expected
        econtent digest must report the mismatch. The mutant
        (``<``) only reports lesser digests, so it proceeds and
        verifies."""
        token = _rsa_token(md_values=[_der_octet_string(b"\xff" * 32)])
        report = _verify(token)
        assert _has_error(report, "message_digest_mismatch")

    def test_digest_content_lesser_mismatch(self):
        """NotEq_Gt [968,27] and NotEq_Is [968,27]: a digest LESS
        than the expected econtent digest must report the mismatch.
        The ``>`` mutant only reports greater digests and the
        ``is`` mutant never fires on distinct bytes objects, so
        both proceed and verify."""
        token = _rsa_token(md_values=[_der_octet_string(b"\x00" * 32)])
        report = _verify(token)
        assert _has_error(report, "message_digest_mismatch")

    def test_unparseable_digest_attribute(self):
        """ExceptionReplacer [957,11] is PROVEN EQUIVALENT (see §6):
        the handler is dead — ``_parse_all`` cannot fail on a value
        that already parsed as a SET element (its only extra check
        over ``_parse_tlv`` is the trailing-bytes check, and a
        single TLV has none). There is no distinguishing input, so
        no kill test exists for it. This test documents the
        neighbouring live behaviour instead: a garbage value makes
        the whole token unparseable, fail-closed."""
        token = _rsa_token(md_values=[b"\xff\xff\xff"])
        report = _verify(token)
        assert report["valid"] is False
        assert _has_error(report, "token_unparseable")


class TestWorkerFTimestampSidKill:
    """Kill the sid / certificate-matching mutants."""

    def test_one_field_sid_verifies(self):
        """NotEq_Lt / ReplaceComparisonOperator_Eq_LtE [978,27]:
        a one-field sid must be skipped (fallback to the first
        certificate) and the token must verify. The mutant enters
        the matching block and crashes on the missing second
        field."""
        key, cert_der, issuer_der = _make_rsa_fixture()
        token = _build_token_k(key, cert_der, issuer_der, sid_raw=_der_sequence(issuer_der))
        report = _verify(token)
        assert report["valid"] is True

    def test_three_field_sid_falls_back(self):
        """ReplaceComparisonOperator_Eq_GtE [978,27]: a three-field
        sid must be skipped (fallback to the first certificate,
        the CA, which fails the leaf signature). The mutant enters
        the matching block, finds the leaf, and verifies."""
        leaf_key, chain_der, leaf_der, ca_der, leaf_issuer_der = _make_chain()
        token = _build_token_k(
            leaf_key,
            chain_der,
            leaf_issuer_der,
            serial=7,
            sid_raw=_der_sequence(leaf_issuer_der, _der_integer(7), _der_integer(999)),
        )
        report = _verify(token)
        assert report["valid"] is False
        assert _has_error(report, "signature_verification_failed")

    def test_wrong_issuer_lesser_not_matched(self):
        """ReplaceComparisonOperator_Eq_LtE [982,38] and
        NotEq_IsNot [982,38]: a certificate whose issuer is
        lexicographically LESS than the sid issuer (same serial)
        must not match. Both mutants match it, verify with the
        wrong key, and fail."""
        from cryptography.hazmat.primitives.asymmetric import rsa

        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca = _name("ZZZ")
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_der = _make_cert(leaf_key, _name("Test TSA Leaf"), ca, 7, signing_key=ca_key)
        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        wrong_der = _make_cert(wrong_key, _name("AAA"), _name("AAA"), 7)
        token = _build_token_k(leaf_key, wrong_der + leaf_der, ca.public_bytes(), serial=7)
        report = _verify(token)
        assert report["valid"] is True

    def test_wrong_issuer_greater_not_matched(self):
        """ReplaceComparisonOperator_Eq_GtE [982,38]: a certificate
        whose issuer is lexicographically GREATER than the sid
        issuer (same serial) must not match. The mutant matches
        it, verifies with the wrong key, and fails."""
        from cryptography.hazmat.primitives.asymmetric import rsa

        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca = _name("AAA")
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_der = _make_cert(leaf_key, _name("Test TSA Leaf"), ca, 7, signing_key=ca_key)
        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        wrong_der = _make_cert(wrong_key, _name("ZZZ"), _name("ZZZ"), 7)
        token = _build_token_k(leaf_key, wrong_der + leaf_der, ca.public_bytes(), serial=7)
        report = _verify(token)
        assert report["valid"] is True

    def test_wrong_serial_greater_not_matched(self):
        """ReplaceComparisonOperator_Eq_GtE [982,78]: a certificate
        whose serial is GREATER than the sid serial (same issuer)
        must not match. The mutant matches it, verifies with the
        wrong key, and fails."""
        from cryptography.hazmat.primitives.asymmetric import rsa

        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca = _name("Test TSA CA")
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_der = _make_cert(leaf_key, _name("Test TSA Leaf"), ca, 7, signing_key=ca_key)
        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        wrong_der = _make_cert(wrong_key, _name("Test TSA Wrong"), ca, 8, signing_key=ca_key)
        token = _build_token_k(leaf_key, wrong_der + leaf_der, ca.public_bytes(), serial=7)
        report = _verify(token)
        assert report["valid"] is True

    def test_large_serial_matches_by_value(self):
        """ReplaceComparisonOperator_Eq_Is [982,78]: the serial
        must be compared by VALUE. At serial 1000 the parsed
        integers are distinct objects (small-int caching ends at
        256), so the mutant (``is``) never matches, falls back to
        the CA, and fails."""
        leaf_key, chain_der, leaf_der, ca_der, leaf_issuer_der = _make_chain(serial=1000)
        token = _build_token_k(leaf_key, chain_der, leaf_issuer_der, serial=1000)
        report = _verify(token)
        assert report["valid"] is True

    def test_first_matching_cert_wins(self):
        """ReplaceBreakWithContinue [984,20]: the first
        certificate matching the sid must win. The mutant keeps
        scanning and overwrites it with the second same-sid
        certificate (a different key), so verification fails."""
        from cryptography.hazmat.primitives.asymmetric import rsa

        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca = _name("Test TSA CA")
        leaf_a_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_a_der = _make_cert(leaf_a_key, _name("Test TSA Leaf"), ca, 7, signing_key=ca_key)
        leaf_b_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_b_der = _make_cert(leaf_b_key, _name("Test TSA Leaf"), ca, 7, signing_key=ca_key)
        token = _build_token_k(leaf_a_key, leaf_a_der + leaf_b_der, ca.public_bytes(), serial=7)
        report = _verify(token)
        assert report["valid"] is True

    def test_unmatched_sid_falls_back_to_first(self):
        """NumberReplacer [988,45] (``certificates[0]``): with no
        sid match the FIRST certificate must be used. The mutants
        use the second (the CA) and fail."""
        leaf_key, chain_der, leaf_der, ca_der, leaf_issuer_der = _make_chain()
        token = _build_token_k(leaf_key, leaf_der + ca_der, leaf_issuer_der, serial=999)
        report = _verify(token)
        assert report["valid"] is True

    def test_unparseable_sid_falls_back(self):
        """ExceptionReplacer [985,11]: a sid whose second field is
        not an INTEGER must fall back to the first certificate, not
        raise. The mutant replaces the caught type, so the
        TimestampError propagates. (``_parse_all`` itself cannot
        fail on a single TLV — the live failure is
        ``_parse_integer`` on the non-INTEGER second field.)"""
        key, cert_der, issuer_der = _make_rsa_fixture()
        token = _build_token_k(
            key,
            cert_der,
            issuer_der,
            sid_raw=_der_sequence(issuer_der, _der_octet_string(b"\x01")),
        )
        report = _verify(token)
        assert report["valid"] is True


class TestWorkerFTimestampDispatchKill:
    """Kill the signature-dispatch mutants."""

    def test_rsa_sig_with_ec_key_is_unsupported(self):
        """ReplaceComparisonOperator_Eq_LtE [995,50]: an RSA
        signature OID with an EC key (OID below the RSA OID) must
        report unsupported. The mutant (``<=``) enters the RSA
        branch and reports an unparseable RSA key instead."""
        rsa_key, _rsa_cert, _rsa_issuer = _make_rsa_fixture()
        _ec_key, ec_cert, ec_issuer = _make_ec_fixture()
        token = _build_token_k(rsa_key, ec_cert, ec_issuer)
        report = _verify(token)
        assert _has_error(report, "unsupported_signature_algorithm")

    def test_rsa_sig_with_ed25519_key_is_unsupported(self):
        """ReplaceComparisonOperator_Eq_GtE [995,50]: an RSA
        signature OID with an Ed25519 key (OID above the RSA OID)
        must report unsupported. The mutant (``>=``) enters the
        RSA branch and reports an unparseable RSA key instead."""
        rsa_key, _rsa_cert, _rsa_issuer = _make_rsa_fixture()
        ed_key, ed_cert, ed_issuer = _make_ed25519_fixture()
        token = _build_token_k(rsa_key, ed_cert, ed_issuer)
        report = _verify(token)
        assert _has_error(report, "unsupported_signature_algorithm")

    def test_ec_sig_with_dsa_key_is_unsupported(self):
        """ReplaceComparisonOperator_Eq_LtE [1011,54]: an ECDSA
        signature OID with a DSA key (OID below the EC OID) must
        report unsupported. The mutant (``<=``) enters the ECDSA
        branch and reports an unsupported curve instead."""
        ec_key, _ec_cert, _ec_issuer = _make_ec_fixture()
        _dsa_key, dsa_cert, dsa_issuer = _make_dsa_fixture()
        token = _build_token_k(ec_key, dsa_cert, dsa_issuer)
        report = _verify(token)
        assert _has_error(report, "unsupported_signature_algorithm")

    def test_ec_sig_with_rsa_key_is_unsupported(self):
        """ReplaceComparisonOperator_Eq_GtE [1011,54] and
        NotEq_IsNot [1011,54]: an ECDSA signature OID with an RSA
        key (OID above the EC OID, and distinct from it) must
        report unsupported. Both mutants enter the ECDSA branch
        and report an unsupported curve instead."""
        ec_key, _ec_cert, _ec_issuer = _make_ec_fixture()
        rsa_key, rsa_cert, rsa_issuer = _make_rsa_fixture()
        token = _build_token_k(ec_key, rsa_cert, rsa_issuer)
        report = _verify(token)
        assert _has_error(report, "unsupported_signature_algorithm")

    def test_rsa_sig_hash_greater_than_signer_digest(self):
        """NotEq_Lt [996,40]: an RSA-SHA384 signature OID with a
        SHA-256 signer digest must report the hash mismatch. The
        mutant (``<``) only reports lesser OID hashes, so it
        proceeds and verifies."""
        key, cert_der, issuer_der = _make_rsa_fixture()
        digest384 = hashlib.sha384(b"sealed-bundle-digest-fixture").digest()
        token = _build_token_k(
            key,
            cert_der,
            issuer_der,
            hash_algorithm="sha384",
            digest=digest384,
            digest_oid=OID_SHA256,
        )
        report = _verify(token, expected_digest=digest384, expected_hash_algorithm="sha384")
        assert _has_error(report, "signature_hash_mismatch")

    def test_rsa_sig_hash_lesser_than_signer_digest(self):
        """NotEq_Gt [996,40]: an RSA-SHA256 signature OID with a
        SHA-384 signer digest must report the hash mismatch. The
        mutant (``>``) only reports greater OID hashes, so it
        proceeds and verifies."""
        token = _rsa_token(digest_oid=OID_SHA384)
        report = _verify(token)
        assert _has_error(report, "signature_hash_mismatch")

    def test_ec_sig_hash_lesser_than_signer_digest(self):
        """NotEq_Gt [1015,25]: an ECDSA-SHA256 signature OID with
        a SHA-384 signer digest must report the hash mismatch. The
        mutant (``>``) only reports greater OID hashes, so it
        proceeds and verifies."""
        ec_key, ec_cert, ec_issuer = _make_ec_fixture()
        token = _build_token_k(ec_key, ec_cert, ec_issuer, digest_oid=OID_SHA384)
        report = _verify(token)
        assert _has_error(report, "signature_hash_mismatch")


class TestWorkerFTimestampKeyParseKill:
    """Kill the key-parse handler mutants."""

    def test_unparseable_rsa_key(self):
        """ExceptionReplacer [1008,15]: an RSA certificate whose
        public-key SEQUENCE tag is corrupt must report an
        unparseable RSA key, not raise. The mutant replaces the
        caught type, so the TimestampError propagates."""
        key, cert_der, issuer_der = _make_rsa_fixture()
        bad_cert = _tamper_rsa_key_in_cert(key, cert_der)
        token = _build_token_k(key, bad_cert, issuer_der)
        report = _verify(token)
        assert _has_error(report, "rsa_key_unparseable")

    def test_unparseable_ec_key(self):
        """ExceptionReplacer [1025,15]: an EC certificate whose
        public point is not uncompressed must report an
        unparseable EC key, not raise. The mutant replaces the
        caught type, so the TimestampError propagates."""
        key, cert_der, issuer_der = _make_ec_fixture()
        bad_cert = _tamper_ec_point_in_cert(key, cert_der)
        token = _build_token_k(key, bad_cert, issuer_der)
        report = _verify(token)
        assert _has_error(report, "ec_key_unparseable")
