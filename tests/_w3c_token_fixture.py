"""Independent RFC 3161 token builder for W3 Worker C (C13/C14).

Test-only DER encoder plus literal OIDs.  This module imports
NOTHING from ``textforensics.timestamp`` — no production encoder,
no production OID constant, no production parsing constant — so a
regression in a production constant cannot be baked into the
fixtures (the OID_SIGNED_DATA precedent: the live-TSA defect hid
until a freeTSA token was rejected because the old fixture imported
the wrong production constant).  Keys, certificates and signatures
come from ``cryptography`` (the independent engine).

Builds a raw TimeStampToken (CMS ContentInfo, not a TimeStampResp)
over a caller-supplied imprint digest.  The imprint hash and the
signer/signature hash are independent parameters, which is exactly
what C14 needs: a P-256 certificate signing with ECDSA-SHA-384 while
the imprint stays SHA-256.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

# Literal OIDs (RFC 3161 / RFC 5652 / RFC 5758).  Written out here, not
# imported, so the fixture is independent of production constants.
_OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
_OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
_OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
_OID_SIGNING_TIME = "1.2.840.113549.1.9.5"
_OID_SHA256 = "2.16.840.1.101.3.4.2.1"
_OID_SHA384 = "2.16.840.1.101.3.4.2.2"
_OID_SHA512 = "2.16.840.1.101.3.4.2.3"
_OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
_OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3"
_OID_ECDSA_SHA512 = "1.2.840.10045.4.3.4"
_OID_RSA_SHA256 = "1.2.840.113549.1.1.11"

_HASH_OIDS = {"sha256": _OID_SHA256, "sha384": _OID_SHA384, "sha512": _OID_SHA512}
_EC_SIG_OIDS = {
    "sha256": _OID_ECDSA_SHA256,
    "sha384": _OID_ECDSA_SHA384,
    "sha512": _OID_ECDSA_SHA512,
}
_POLICY = "1.2.3.4.5"


# ---------------------------------------------------------------------------
# Minimal DER encoder (test-only; definite lengths only)
# ---------------------------------------------------------------------------


def _der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _int(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _tlv(0x02, raw)


def _oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.split(".")]
    encoded = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        groups = [part & 0x7F]
        part >>= 7
        while part:
            groups.append(0x80 | (part & 0x7F))
            part >>= 7
        encoded += bytes(reversed(groups))
    return _tlv(0x06, encoded)


def _octets(data: bytes) -> bytes:
    return _tlv(0x04, data)


def _seq(*children: bytes) -> bytes:
    return _tlv(0x30, b"".join(children))


def _set(*children: bytes) -> bytes:
    return _tlv(0x31, b"".join(children))


def _ctx(number: int, content: bytes) -> bytes:
    return _tlv(0xA0 | number, content)


def _gentime(raw_ascii: str) -> bytes:
    # Deliberately raw: the caller supplies the exact GeneralizedTime
    # bytes (valid or invalid) to be encoded.
    return _tlv(0x18, raw_ascii.encode("ascii"))


def _alg_id(oid: str) -> bytes:
    return _seq(_oid(oid))


# ---------------------------------------------------------------------------
# Fixture keys / certificates (cryptography = independent engine)
# ---------------------------------------------------------------------------


def make_ec_cert(curve_name: str = "P-256", *, serial: int = 7):
    """Return ``(private_key, cert_der, issuer_name_der)`` for an EC TSA.

    ``curve_name`` is ``"P-256"``, ``"P-384"`` or ``"P-521"`` (the last
    is a genuinely unsupported curve for the product verifiers).
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    curves = {
        "P-256": ec.SECP256R1(),
        "P-384": ec.SECP384R1(),
        "P-521": ec.SECP521R1(),
    }
    key = ec.generate_private_key(curves[curve_name])
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Test EC {curve_name} TSA")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return key, cert.public_bytes(Encoding.DER), cert.issuer.public_bytes()


def verify_token_with_cryptography(token_der: bytes, cert_der: bytes) -> bool:
    """Independently verify a token's ECDSA signature with cryptography.

    Parses the CMS structure with a minimal local decoder (no product
    code) and checks the signature over the signed attributes.  Returns
    True only when the independent engine accepts the signature.
    Raises AssertionError on structural problems in the fixture.
    """
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        Prehashed,
        decode_dss_signature,
        encode_dss_signature,
    )

    # Minimal TLV walk: ContentInfo(SEQ) -> [0](SignedData SEQ) ->
    # SignerInfos SET -> SignerInfo SEQ.
    def parse(data, off=0):
        assert data[off] in (0x30, 0x31, 0xA0, 0x06, 0x04, 0x02, 0x18, 0x03), hex(data[off])
        tag = data[off]
        pos = off + 1
        first = data[pos]
        pos += 1
        if first & 0x80 == 0:
            length = first
        else:
            n = first & 0x7F
            length = int.from_bytes(data[pos : pos + n], "big")
            pos += n
        return tag, data[pos : pos + length], data[off : pos + length], pos + length

    def children(content):
        out, pos = [], 0
        while pos < len(content):
            _, _, _, end = parse(content, pos)
            out.append(content[pos:end])
            pos = end
        return out

    _, ci_content, _, _ = parse(token_der)
    ci_fields = children(ci_content)
    assert len(ci_fields) == 2
    _, sd_seq_der, _, _ = parse(ci_fields[1])
    _, sd_content, _, _ = parse(sd_seq_der)
    sd_fields = children(sd_content)
    # SignedData: version, digestAlgorithms, encapContentInfo, [0] certs, SignerInfos SET
    signer_infos = None
    digest_alg_oid = None
    for field in sd_fields:
        tag, content, _, _ = parse(field)
        if tag == 0x31:
            signer_infos = children(content)
        if tag == 0x30 and digest_alg_oid is None:
            # digestAlgorithms is a SET, not SEQ; skip
            pass
    assert signer_infos and len(signer_infos) == 1
    _, si_content, _, _ = parse(signer_infos[0])
    si_fields = children(si_content)
    # version, sid, digestAlgorithm, [0] signedAttrs, sigAlgorithm, signature
    _, digest_alg_content, _, _ = parse(children(si_content)[2])
    oid_tlv = children(digest_alg_content)[0]
    _, oid_content, _, _ = parse(oid_tlv)
    # decode OID content bytes to dotted string
    parts = [oid_content[0] // 40, oid_content[0] % 40]
    value = 0
    for byte in oid_content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if byte & 0x80 == 0:
            parts.append(value)
            value = 0
    digest_oid = ".".join(str(p) for p in parts)
    hash_cls = {"2.16.840.1.101.3.4.2.1": hashes.SHA256,
                "2.16.840.1.101.3.4.2.2": hashes.SHA384,
                "2.16.840.1.101.3.4.2.3": hashes.SHA512}[digest_oid]
    signed_attrs_field = si_fields[3]
    _, attrs_content, _, _ = parse(signed_attrs_field)
    signed_attrs_set_der = b"\x31" + _der_len(len(attrs_content)) + attrs_content
    sig_field = si_fields[5]
    _, sig_octets, _, _ = parse(sig_field)
    _, sig_content, _, _ = parse(sig_octets)

    def der_ints(content):
        out, pos = [], 0
        while pos < len(content):
            _, c, _, end = parse(content, pos)
            out.append(int.from_bytes(c, "big"))
            pos = end
        return out

    r, s = der_ints(sig_content)
    cert = x509.load_der_x509_certificate(cert_der)
    pub = cert.public_key()
    try:
        # cryptography's ECDSA() hashes its input; the token signature
        # is over the already-hashed signed attributes, so verify with
        # Prehashed over that digest.
        pub.verify(
            encode_dss_signature(r, s),
            hashlib.new(hash_cls().name, signed_attrs_set_der).digest(),
            ec.ECDSA(Prehashed(hash_cls())),
        )
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# Token builder
# ---------------------------------------------------------------------------


def build_w3c_token(
    digest: bytes,
    cert: tuple,
    *,
    curve_name: str = "P-256",
    imprint_hash: str = "sha256",
    sig_hash: str = "sha256",
    digest_hash: str | None = None,
    gen_time: str = "20261107120000Z",
    gen_time_bytes: bytes | None = None,
    nonce: int = 424242,
    serial: int = 1,
    tamper_signature: bool = False,
) -> bytes:
    """Build a raw TimeStampToken (CMS ContentInfo) over *digest*.

    ``cert`` is the ``(private_key, cert_der, issuer_der)`` triple from
    :func:`make_ec_cert`.  ``digest`` must be the imprint-hash digest of
    the timestamped bytes (32 bytes for SHA-256).  ``gen_time`` is
    encoded verbatim as the TSTInfo GeneralizedTime (and as the
    signingTime attribute), so invalid strings exercise the parsers;
    ``gen_time_bytes`` overrides it with raw bytes (for non-ASCII
    inputs the str form cannot express).  ``digest_hash`` defaults to
    ``sig_hash``; passing a different value builds a token whose
    signer digest algorithm disagrees with its signature algorithm.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    private_key, cert_der, issuer_der = cert
    hash_classes = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}
    digest_hash = digest_hash or sig_hash
    gen_time_tlv = _tlv(0x18, gen_time_bytes) if gen_time_bytes is not None else _gentime(gen_time)

    tst_info = _seq(
        _int(1),
        _oid(_POLICY),
        _seq(_alg_id(_HASH_OIDS[imprint_hash]), _octets(digest)),
        _int(serial),
        gen_time_tlv,
        _int(nonce),
    )
    econtent_digest = hashlib.new(digest_hash, tst_info).digest()
    signed_attrs = _set(
        _seq(_oid(_OID_MESSAGE_DIGEST), _set(_octets(econtent_digest))),
        _seq(_oid(_OID_SIGNING_TIME), _set(gen_time_tlv)),
    )
    to_sign = b"\x31" + signed_attrs[1:]
    raw_sig = private_key.sign(to_sign, ec.ECDSA(hash_classes[sig_hash]()))
    r, s = decode_dss_signature(raw_sig)
    signature = _seq(_int(r), _int(s))
    if tamper_signature:
        mid = len(signature) // 2
        signature = signature[:mid] + bytes([signature[mid] ^ 0x01]) + signature[mid + 1 :]
    # sid is IssuerAndSerialNumber = SEQ { issuer Name, serial }.
    sid = _seq(issuer_der, _int(serial))
    signer_info = _seq(
        _int(1),
        sid,
        _alg_id(_HASH_OIDS[digest_hash]),
        _ctx(0, signed_attrs[2:]),
        _alg_id(_EC_SIG_OIDS[sig_hash]),
        _octets(signature),
    )
    signed_data = _seq(
        _int(1),
        _set(_alg_id(_HASH_OIDS[digest_hash])),
        _seq(_oid(_OID_TST_INFO), _ctx(0, _octets(tst_info))),
        _ctx(0, cert_der),
        _set(signer_info),
    )
    return _seq(_oid(_OID_SIGNED_DATA), _ctx(0, signed_data))
