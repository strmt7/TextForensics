#!/usr/bin/env python3
"""Standalone verifier for TextForensics sealed bundles (Phase 3 U2).

Self-contained: standard library only, no TextForensics install needed.
A third party runs it against a sealed ``.zip`` bundle:

    python3 verify.py bundle.zip [--expect-digest <hex>] [--public-key <hex-or-path>]

It performs the container checks, the seal checks, the signature check
(if a signature is present), the timestamp check (if a token is
present), the case-file checks and the checklist re-derivation, then
prints a JSON verification report plus a one-line scope statement.

Exit codes (MPL contract): 0 = every runnable check passed; 1 = at
least one check failed; 2 = incomplete (a check could not run, e.g. a
signature is present but no public key was supplied, or replay was
requested — the standalone verifier cannot re-run detectors).

Two honest limits, stated wherever this verifier reports:

1. A hash seal cannot prove the underlying analysis was RUN — a
   fabricated but internally consistent bundle passes seal checks;
   only an independent anchor (timestamp, second-party signature,
   transparency log) binds the artifact to a time and an actor.
2. Nothing protects entries written AFTER an attacker controls the
   writer, and nothing prevents deletion — the guarantee is DETECTION
   of later change, not prevention.

This file is a self-contained copy of the verification algorithms in
``textforensics.ed25519``, ``textforensics.dsse``,
``textforensics.timestamp`` and ``textforensics.casefile``; it imports
nothing from the package so it runs anywhere Python 3.11+ runs.  The
package test suite cross-checks this file against those modules.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import struct
import sys
import zipfile

TOOL = "textforensics-standalone-verify"
REPORT_SCHEMA = "textforensics.verification-report/v1"
MANIFEST_SCHEMA = "textforensics.sealed-bundle-manifest/v1"
BUNDLE_SCHEMA = "textforensics.sealed-bundle/v1"
CASE_SCHEMA_V3 = "textforensics.case-file/v3"
CASE_SCHEMA_V2 = "textforensics.case-file/v2"
CASE_SCHEMA_V1 = "textforensics.case-file/v1"

# MPL caps, enforced in order, before content is read.
MAX_BUNDLE_BYTES = 288 * 1024 * 1024
MAX_ENTRIES = 1024
MAX_ENTRY_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_SEALED_RESULTS_BYTES = 32 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_TIMESTAMP_TOKEN_BYTES = 1024 * 1024

COMMENT_PREFIX = "mpl-bundle-sha256:"
ZIP_STORED = 0

HONEST_LIMITS = [
    "A hash seal cannot prove the underlying analysis was RUN: a "
    "fabricated but internally consistent bundle passes seal checks. "
    "Only an independent anchor (timestamp, second-party signature, "
    "transparency log) binds the artifact to a time and an actor.",
    "Nothing protects entries written AFTER an attacker controls the "
    "writer, and nothing prevents deletion: the guarantee is DETECTION "
    "of later change, not prevention.",
]

# ---------------------------------------------------------------------------
# Canonical JSON
# ---------------------------------------------------------------------------


def _canonical_json_bytes(payload):
    """MPL canonical JSON: sorted keys, tight separators, ASCII only."""
    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _case_canonical_json_bytes(payload):
    """Case-file canonical JSON (as sealed by the package)."""
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Ed25519 verification (RFC 8032, verify-only; copied from the package)
# ---------------------------------------------------------------------------

_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _x_recover(y):
    xx = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_BY = (4 * pow(5, _Q - 2, _Q)) % _Q
_BX = _x_recover(_BY)
_BASE_POINT = (_BX, _BY)


def _ed_point_add(point_p, point_q):
    x1, y1 = point_p
    x2, y2 = point_q
    denom_x = pow(1 + _D * x1 * x2 * y1 * y2, _Q - 2, _Q)
    denom_y = pow(1 - _D * x1 * x2 * y1 * y2, _Q - 2, _Q)
    x3 = (x1 * y2 + x2 * y1) * denom_x % _Q
    # The curve has a = -1, so the y numerator is y1*y2 + x1*x2
    # (RFC 8032 section 5.1.4).
    y3 = (y1 * y2 + x1 * x2) * denom_y % _Q
    return (x3, y3)


def _ed_scalar_mult(point, scalar):
    result = (0, 1)
    addend = point
    for bit in bin(scalar)[2:]:
        result = _ed_point_add(result, result)
        if bit == "1":
            result = _ed_point_add(result, addend)
    return result


def _ed_decode_point(encoded):
    if len(encoded) != 32:
        return None
    y = int.from_bytes(encoded, "little") & ((1 << 255) - 1)
    if y >= _Q:
        return None
    x = _x_recover(y)
    if x & 1 != (encoded[31] >> 7):
        x = _Q - x
    if (-x * x + y * y - 1 - _D * x * x * y * y) % _Q != 0:
        return None
    return (x, y)


def _ed_decode_scalar(encoded):
    if len(encoded) != 32:
        return None
    scalar = int.from_bytes(encoded, "little")
    if scalar >= _L:
        return None
    return scalar


def _ed25519_verify(public_key, message, signature):
    """Verify an Ed25519 signature.  False (never raises) on bad input."""
    try:
        if len(public_key) != 32 or len(signature) != 64:
            return False
        point_a = _ed_decode_point(bytes(public_key))
        if point_a is None:
            return False
        commitment = _ed_decode_point(bytes(signature[:32]))
        if commitment is None:
            return False
        scalar_s = _ed_decode_scalar(bytes(signature[32:]))
        if scalar_s is None:
            return False
        challenge = (
            int.from_bytes(
                hashlib.sha512(bytes(signature[:32]) + bytes(public_key) + bytes(message)).digest(),
                "little",
            )
            % _L
        )
        left = _ed_scalar_mult(_BASE_POINT, scalar_s)
        right = _ed_point_add(commitment, _ed_scalar_mult(point_a, challenge))
        return left == right
    except Exception:
        return False


# ---------------------------------------------------------------------------
# DSSE envelope (Dead Simple Signing Envelope, v1)
# ---------------------------------------------------------------------------


def _dsse_pae(payload_type, payload):
    return (
        b"DSSEv1 "
        + str(len(payload_type)).encode("ascii")
        + b" "
        + payload_type.encode("ascii")
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def _b64decode_padded(data):
    import base64

    if isinstance(data, str):
        data = data.encode("ascii")
    padding = b"=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _dsse_verify(envelope, public_key, expected_payload_type):
    """Verify a DSSE envelope. Returns (ok, detail, payload_or_None).

    The caller must ALSO check that the payload equals the bytes the
    signature is supposed to cover (here: the canonical manifest with
    the signature field itself set to null); a valid signature over
    some other payload proves nothing about this manifest.
    """
    if not isinstance(envelope, dict):
        return False, "envelope is not an object", None
    if set(envelope.keys()) != {"payloadType", "payload", "signatures"}:
        return False, "envelope has unexpected fields", None
    if envelope.get("payloadType") != expected_payload_type:
        return False, "payloadType mismatch", None
    try:
        payload = _b64decode_padded(envelope["payload"])
    except Exception:
        return False, "payload is not canonical base64", None
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 1:
        return False, "expected exactly one signature", None
    signature = signatures[0]
    if not isinstance(signature, dict) or set(signature.keys()) != {"keyid", "sig"}:
        return False, "signature entry is malformed", None
    keyid = signature["keyid"]
    if keyid != _sha256(bytes(public_key)):
        return False, "keyid does not match the supplied public key", None
    try:
        raw_sig = _b64decode_padded(signature["sig"])
    except Exception:
        return False, "signature is not canonical base64", None
    pae = _dsse_pae(expected_payload_type, payload)
    if not _ed25519_verify(public_key, pae, raw_sig):
        return False, "Ed25519 verification failed", None
    return True, "signature verifies", payload


# ---------------------------------------------------------------------------
# DER parsing (minimal, strict; copied from the package timestamp module)
# ---------------------------------------------------------------------------

_OID_SHA256 = "2.16.840.1.101.3.4.2.1"
_OID_SHA384 = "2.16.840.1.101.3.4.2.2"
_OID_SHA512 = "2.16.840.1.101.3.4.2.3"
_OID_SHA1 = "1.3.14.3.2.26"
_OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
_OID_SIGNED_DATA = "1.2.840.113549.1.9.16.1.2"
_OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
_OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
_OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
_OID_SHA384_WITH_RSA = "1.2.840.113549.1.1.12"
_OID_SHA512_WITH_RSA = "1.2.840.113549.1.1.13"
_OID_SHA1_WITH_RSA = "1.2.840.113549.1.1.5"
_OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
_OID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2"
_OID_ECDSA_WITH_SHA384 = "1.2.840.10045.4.3.3"
_OID_ECDSA_WITH_SHA512 = "1.2.840.10045.4.3.4"
_OID_PRIME256V1 = "1.2.840.10045.3.1.7"
_OID_SECP384R1 = "1.3.132.0.34"

_HASH_OIDS = {
    _OID_SHA1: "sha1",
    _OID_SHA256: "sha256",
    _OID_SHA384: "sha384",
    _OID_SHA512: "sha512",
}
_RSA_SIG_OIDS = {
    _OID_SHA1_WITH_RSA: "sha1",
    _OID_SHA256_WITH_RSA: "sha256",
    _OID_SHA384_WITH_RSA: "sha384",
    _OID_SHA512_WITH_RSA: "sha512",
}
_ECDSA_SIG_OIDS = {
    _OID_ECDSA_WITH_SHA256: ("sha256", "P-256"),
    _OID_ECDSA_WITH_SHA384: ("sha384", "P-384"),
    _OID_ECDSA_WITH_SHA512: ("sha512", "P-384"),
}
_DIGEST_INFO_PREFIX = {
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}
_EC_CURVES = {
    "P-256": {
        "p": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        "a": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
        "b": 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        "n": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
        "gx": 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        "gy": 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    },
    "P-384": {
        "p": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
        "a": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC,
        "b": 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
        "n": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
        "gx": 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
        "gy": 0x3617DE4A96262C6F5D9E98BF9292DC29F8F5701BD08A8E7C2A8E9B6E5B6B0B0B,
    },
}


class _DerError(ValueError):
    pass


class _DerNode:
    __slots__ = ("tag", "content", "raw", "children")

    def __init__(self, tag, content, raw):
        self.tag = tag
        self.content = content
        self.raw = raw
        self.children = None


def _der_parse_tlv(data, offset=0):
    if offset + 2 > len(data):
        raise _DerError("Truncated DER value.")
    tag = data[offset]
    pos = offset + 1
    first = data[pos]
    pos += 1
    if first & 0x80 == 0:
        length = first
    else:
        nbytes = first & 0x7F
        if nbytes == 0:
            raise _DerError("Indefinite DER length is not accepted.")
        if nbytes > 4 or pos + nbytes > len(data):
            raise _DerError("Invalid DER length.")
        length = int.from_bytes(data[pos : pos + nbytes], "big")
        pos += nbytes
    if pos + length > len(data):
        raise _DerError("DER length exceeds input.")
    return _DerNode(tag, data[pos : pos + length], data[offset : pos + length]), pos + length


def _der_parse_all(data):
    node, end = _der_parse_tlv(data, 0)
    if end != len(data):
        raise _DerError("Trailing bytes after DER value.")
    return node


def _der_children(node):
    if node.children is None:
        children = []
        pos = 0
        while pos < len(node.content):
            child, pos = _der_parse_tlv(node.content, pos)
            children.append(child)
        node.children = children
    return node.children


def _der_oid(content):
    if not content:
        raise _DerError("Empty OID.")
    parts = [content[0] // 40, content[0] % 40]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if byte & 0x80 == 0:
            parts.append(value)
            value = 0
    if content[-1] & 0x80:
        raise _DerError("Truncated OID.")
    return ".".join(str(part) for part in parts)


def _der_int(node):
    if node.tag != 0x02:
        raise _DerError("Expected DER INTEGER.")
    return int.from_bytes(node.content, "big", signed=False)


def _der_generalized_time(node):
    if node.tag != 0x18:
        raise _DerError("Expected GeneralizedTime.")
    return node.content.decode("ascii")


def _rsa_verify(modulus, exponent, signature, digest, hash_name):
    key_bytes = (modulus.bit_length() + 7) // 8
    if len(signature) != key_bytes:
        return False
    em = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(key_bytes, "big")
    prefix = _DIGEST_INFO_PREFIX[hash_name]
    expected = (
        b"\x00\x01"
        + b"\xff" * (key_bytes - len(prefix) - len(digest) - 3)
        + b"\x00"
        + prefix
        + digest
    )
    return em == expected


def _ec_add(p1, p2, curve):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    p, a = curve["p"], curve["a"]
    if p1[0] == p2[0] and (p1[1] + p2[1]) % p == 0:
        return None
    if p1 == p2:
        lam = (3 * p1[0] * p1[0] + a) * pow(2 * p1[1], -1, p) % p
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], -1, p) % p
    x3 = (lam * lam - p1[0] - p2[0]) % p
    y3 = (lam * (p1[0] - x3) - p1[1]) % p
    return (x3, y3)


def _ec_mult(k, point, curve):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _ec_add(result, addend, curve)
        addend = _ec_add(addend, addend, curve)
        k >>= 1
    return result


def _ecdsa_verify(curve_name, public_point, signature_der, digest):
    curve = _EC_CURVES[curve_name]
    root = _der_parse_all(signature_der)
    if root.tag != 0x30:
        return False
    fields = _der_children(root)
    if len(fields) != 2:
        return False
    r = int.from_bytes(fields[0].content, "big")
    s = int.from_bytes(fields[1].content, "big")
    n = curve["n"]
    if not 1 <= r < n or not 1 <= s < n:
        return False
    z = int.from_bytes(digest[: (n.bit_length() + 7) // 8], "big")
    w = pow(s, -1, n)
    point = _ec_add(
        _ec_mult((z * w) % n, (curve["gx"], curve["gy"]), curve),
        _ec_mult((r * w) % n, public_point, curve),
        curve,
    )
    if point is None:
        return False
    return point[0] % n == r


# ---------------------------------------------------------------------------
# RFC 3161 token verification (self-contained copy of timestamp.py)
# ---------------------------------------------------------------------------


def _parse_certificate(der):
    root = _der_parse_all(der)
    if root.tag != 0x30:
        raise _DerError("Certificate is not a SEQUENCE.")
    fields = _der_children(root)
    if not fields or fields[0].tag != 0x30:
        raise _DerError("Certificate TBSCertificate is missing.")
    tbs = _der_children(fields[0])
    index = 1 if tbs and tbs[0].tag == 0xA0 else 0
    if len(tbs) < index + 6:
        raise _DerError("TBSCertificate is truncated.")
    serial = _der_int(tbs[index])
    issuer_raw = tbs[index + 2].raw
    subject_raw = tbs[index + 4].raw
    spki = _der_children(tbs[index + 5])
    if len(spki) < 2:
        raise _DerError("subjectPublicKeyInfo is malformed.")
    alg_fields = _der_children(spki[0])
    if not alg_fields:
        raise _DerError("subjectPublicKeyInfo has no algorithm.")
    key_oid = _der_oid(alg_fields[0].content)
    key_params = None
    if len(alg_fields) > 1 and alg_fields[1].tag == 0x06:
        key_params = _der_oid(alg_fields[1].content)
    key_bits = spki[1]
    if key_bits.tag != 0x03 or not key_bits.content or key_bits.content[0] != 0:
        raise _DerError("subjectPublicKeyInfo BIT STRING is malformed.")
    return {
        "serial_number": serial,
        "issuer_raw": issuer_raw,
        "subject_raw": subject_raw,
        "key_algorithm_oid": key_oid,
        "key_params_oid": key_params,
        "key_der": key_bits.content[1:],
        "fingerprint_sha256": _sha256(der),
    }


def _verify_timestamp_token(token_der, expected_digest):
    """Verify an RFC 3161 token. Returns (report_dict, errors)."""
    errors = []
    info = {
        "present": True,
        "gen_time": None,
        "policy": None,
        "serial_number": None,
        "nonce": None,
        "signer_cert_fingerprint": None,
        "signature_algorithm": None,
        "certificate_count": 0,
        "qualified": "unknown",
        "qualification_method": (
            "No EU Trusted List snapshot was available offline; "
            "qualification cannot be established from the token alone."
        ),
        "qualification_label": "RFC 3161 timestamp (non-qualified)",
        "note": (
            "A time-stamp token proves the digest existed at genTime; "
            "it does not prove receipt, authorship, or what the file "
            "looked like before."
        ),
    }
    try:
        root = _der_parse_all(token_der)
        if root.tag != 0x30:
            raise _DerError("ContentInfo is not a SEQUENCE.")
        parts = _der_children(root)
        content_type = _der_oid(parts[0].content)
        if content_type != _OID_SIGNED_DATA:
            raise _DerError("ContentInfo is not id-signedData.")
        signed_node = parts[1]
        if signed_node.tag != 0xA0:
            raise _DerError("SignedData is not [0] EXPLICIT.")
        inner = _der_children(signed_node)
        fields = _der_children(inner[0])
        encap = _der_children(fields[2])
        econtent_type = _der_oid(encap[0].content)
        if econtent_type != _OID_TST_INFO:
            raise _DerError("eContentType is not id-ct-TSTInfo.")
        econtent = _der_children(encap[1])[0].content
        tst = _der_children(_der_parse_all(econtent))
        if len(tst) < 5:
            raise _DerError("TSTInfo is truncated.")
        imprint = _der_children(tst[2])
        imprint_alg = _der_oid(_der_children(imprint[0])[0].content)
        hashed_message = imprint[1].content
        info["policy"] = _der_oid(tst[1].content)
        info["serial_number"] = _der_int(tst[3])
        info["gen_time"] = _der_generalized_time(tst[4])
        index = 5
        while index < len(tst):
            if tst[index].tag == 0x02:
                info["nonce"] = _der_int(tst[index])
            index += 1
        certificates = []
        signer_infos = []
        for field in fields[3:]:
            if field.tag == 0xA0:
                for cert in _der_children(field):
                    try:
                        certificates.append(_parse_certificate(cert.raw))
                    except _DerError:
                        continue
            elif field.tag == 0x31:
                signer_infos = _der_children(field)
        info["certificate_count"] = len(certificates)
        parsed = {
            "econtent": econtent,
            "hash_algorithm": _HASH_OIDS.get(imprint_alg),
            "hashed_message": hashed_message,
            "signer_infos": signer_infos,
            "certificates": certificates,
        }
    except (_DerError, UnicodeDecodeError, IndexError) as exc:
        errors.append(f"token_unparseable:{exc}")
        return info, errors
    if parsed["hash_algorithm"] != "sha256":
        errors.append("imprint_hash_algorithm_mismatch:{}".format(parsed["hash_algorithm"]))
    if parsed["hashed_message"] != expected_digest:
        errors.append("message_imprint_mismatch")
    if len(parsed["signer_infos"]) != 1:
        errors.append(f"signer_info_count:{len(parsed['signer_infos'])}")
        return info, errors
    try:
        signer = _der_children(parsed["signer_infos"][0])
        digest_oid = _der_oid(_der_children(signer[2])[0].content)
        hash_name = _HASH_OIDS.get(digest_oid)
        signed_attrs_raw = None
        idx = 3
        attributes = {}
        if signer[idx].tag == 0xA0:
            signed_attrs_raw = b"\x31" + signer[idx].raw[1:]
            for attr in _der_children(signer[idx]):
                attr_fields = _der_children(attr)
                if len(attr_fields) >= 2:
                    attributes[_der_oid(attr_fields[0].content)] = [
                        v.raw for v in _der_children(attr_fields[1])
                    ]
            idx += 1
        sig_oid = _der_oid(_der_children(signer[idx])[0].content)
        idx += 1
        signature = signer[idx].content
    except (_DerError, IndexError) as exc:
        errors.append(f"signer_info_unparseable:{exc}")
        return info, errors
    info["signature_algorithm"] = sig_oid
    if signed_attrs_raw is None:
        errors.append("signed_attrs_absent")
        return info, errors
    if hash_name is None:
        errors.append(f"signer_digest_algorithm_unknown:{digest_oid}")
        return info, errors
    md_values = attributes.get(_OID_MESSAGE_DIGEST, [])
    if len(md_values) != 1:
        errors.append("message_digest_attribute_missing_or_ambiguous")
        return info, errors
    try:
        md_node = _der_parse_all(md_values[0])
    except _DerError as exc:
        errors.append(f"message_digest_attribute_unparseable:{exc}")
        return info, errors
    if md_node.content != hashlib.new(hash_name, parsed["econtent"]).digest():
        errors.append("message_digest_mismatch")
        return info, errors
    signed_data = hashlib.new(hash_name, signed_attrs_raw).digest()
    signer_cert = None
    try:
        sid = _der_children(_der_parse_all(signer[1].raw))
        if len(sid) == 2:
            for cert in parsed["certificates"]:
                if cert["issuer_raw"] == sid[0].raw and cert["serial_number"] == _der_int(sid[1]):
                    signer_cert = cert
                    break
    except _DerError:
        signer_cert = None
    if signer_cert is None and parsed["certificates"]:
        signer_cert = parsed["certificates"][0]
    if signer_cert is None:
        errors.append("signer_certificate_not_found")
        return info, errors
    info["signer_cert_fingerprint"] = signer_cert["fingerprint_sha256"]
    verified = False
    key_oid = signer_cert["key_algorithm_oid"]
    if sig_oid in _RSA_SIG_OIDS and key_oid == _OID_RSA_ENCRYPTION:
        if _RSA_SIG_OIDS[sig_oid] != hash_name:
            errors.append("signature_hash_mismatch")
            return info, errors
        try:
            key_root = _der_parse_all(signer_cert["key_der"])
            key_fields = _der_children(key_root)
            modulus = int.from_bytes(key_fields[0].content, "big")
            exponent = int.from_bytes(key_fields[1].content, "big")
            verified = _rsa_verify(
                modulus, exponent, signature, signed_data, _RSA_SIG_OIDS[sig_oid]
            )
        except _DerError as exc:
            errors.append(f"rsa_key_unparseable:{exc}")
            return info, errors
    elif sig_oid in _ECDSA_SIG_OIDS and key_oid == _OID_EC_PUBLIC_KEY:
        hash_name_sig, curve_name = _ECDSA_SIG_OIDS[sig_oid]
        if hash_name_sig != hash_name:
            errors.append("signature_hash_mismatch")
            return info, errors
        expected_curve_oid = _OID_PRIME256V1 if curve_name == "P-256" else _OID_SECP384R1
        if signer_cert["key_params_oid"] != expected_curve_oid:
            errors.append("ec_curve_mismatch")
            return info, errors
        point_der = signer_cert["key_der"]
        if not point_der or point_der[0] != 0x04:
            errors.append("ec_key_unparseable:not uncompressed")
            return info, errors
        size = (len(point_der) - 1) // 2
        point = (
            int.from_bytes(point_der[1 : 1 + size], "big"),
            int.from_bytes(point_der[1 + size :], "big"),
        )
        verified = _ecdsa_verify(curve_name, point, signature, signed_data)
    else:
        errors.append(f"unsupported_signature_algorithm:{sig_oid}")
        return info, errors
    if not verified:
        errors.append("signature_verification_failed")
    return info, errors


# ---------------------------------------------------------------------------
# Bundle verification
# ---------------------------------------------------------------------------


def _check(checks, check_id, status, detail):
    checks.append({"id": check_id, "status": status, "detail": detail})


def _find_eocd(data):
    """Pre-parse the End Of Central Directory record (MPL order).

    Returns (eocd_offset, total_entries, cd_size, cd_offset, comment).
    Raises ValueError on any structural problem, before zipfile runs.
    """
    if len(data) < 22:
        raise ValueError("bundle too small for an End Of Central Directory record")
    tail_start = max(0, len(data) - (65535 + 22))
    offset = data.rfind(b"PK\x05\x06", tail_start)
    if offset < 0:
        raise ValueError("End Of Central Directory record not found")
    if offset + 22 > len(data):
        raise ValueError("truncated End Of Central Directory record")
    (
        _sig,
        disk,
        cd_disk,
        entries_disk,
        entries_total,
        cd_size,
        cd_offset,
        comment_len,
    ) = struct.unpack("<IHHHHIIH", data[offset : offset + 22])
    if disk != 0 or cd_disk != 0:
        raise ValueError("multi-disk archives are not accepted")
    if entries_disk != entries_total:
        raise ValueError("central directory entry counts disagree")
    if offset + 22 + comment_len != len(data):
        raise ValueError("archive comment length disagrees with file size")
    comment = data[offset + 22 : offset + 22 + comment_len]
    return offset, entries_total, cd_size, cd_offset, comment


def _parse_central_directory(data, cd_offset, cd_size, entry_count):
    """Parse central-directory headers; returns a list of entry dicts."""
    entries = []
    pos = cd_offset
    end = cd_offset + cd_size
    if end > len(data):
        raise ValueError("central directory extends past end of file")
    for _ in range(entry_count):
        if pos + 46 > end or data[pos : pos + 4] != b"PK\x01\x02":
            raise ValueError("central directory entry is malformed")
        fields = struct.unpack("<IHHHHHHIIIHHHHHII", data[pos : pos + 46])
        (
            _sig,
            _version_made_by,
            _version_needed,
            _flags,
            compress_method,
            _mod_time,
            _mod_date,
            _crc,
            compressed_size,
            uncompressed_size,
            name_len,
            extra_len,
            comment_len,
            _disk,
            _internal_attrs,
            external_attrs,
            _local_offset,
        ) = fields
        name_start = pos + 46
        name_end = name_start + name_len
        extra_end = name_end + extra_len
        comment_end = extra_end + comment_len
        if comment_end > end:
            raise ValueError("central directory entry overruns its directory")
        name = data[name_start:name_end].decode("utf-8", "surrogateescape")
        extra = data[name_end:extra_end]
        comment = data[extra_end:comment_end]
        # Normalised ZipInfo (MPL): 1980-01-01, create_system 0,
        # external_attr 0o644<<16, no extra fields, no per-entry comment.
        create_system = _version_made_by >> 8
        entries.append(
            {
                "name": name,
                "compress_method": compress_method,
                "compressed_size": compressed_size,
                "uncompressed_size": uncompressed_size,
                "external_attrs": external_attrs,
                "create_system": create_system,
                "mod_date": _mod_date,
                "mod_time": _mod_time,
                "extra_len": extra_len,
                "comment_len": comment_len,
                "extra": extra,
                "comment": comment,
            }
        )
        pos = comment_end
    if pos != end:
        raise ValueError("central directory size disagrees with entries")
    return entries


def _case_hash(case):
    body = {
        key: value for key, value in case.items() if key not in ("case_sha256", "created_at_utc")
    }
    return _sha256(_case_canonical_json_bytes(body))


def _custody_entry_hash(actor, action, at_utc, note, prev_hash):
    payload = {
        "actor": actor,
        "action": action,
        "at_utc": at_utc,
        "note": note,
        "prev_hash": prev_hash,
    }
    return _sha256(_case_canonical_json_bytes(payload))


def _verify_custody(custody):
    errors = []
    if not isinstance(custody, list) or not custody:
        return ["custody_missing_or_empty"]
    prev_hash = "0" * 64
    for index, entry in enumerate(custody):
        if not isinstance(entry, dict):
            errors.append(f"custody_entry_not_a_mapping:{index}")
            return errors
        if entry.get("prev_hash") != prev_hash:
            errors.append(f"custody_chain_broken:{index}")
            return errors
        expected = _custody_entry_hash(
            str(entry.get("actor")),
            str(entry.get("action")),
            str(entry.get("at_utc")),
            entry.get("note"),
            prev_hash,
        )
        if entry.get("entry_hash") != expected:
            errors.append(f"custody_entry_hash_mismatch:{index}")
            return errors
        prev_hash = str(entry.get("entry_hash"))
    return errors


def _build_observations(bundle, dispositions=None):
    """Rebuild the v3 detector_observations view of a bundle.

    Mirrors ``textforensics.casefile.build_detector_observations``.
    """
    dispositions = dispositions or {}
    observations = []
    for result in bundle.get("detector_results", []):
        if not isinstance(result, dict):
            continue
        detector_id = result.get("detector_id")
        disposition = dispositions.get(str(detector_id)) or {}
        if not isinstance(disposition, dict):
            disposition = {}
        observations.append(
            {
                "kind": "observed",
                "detector_id": detector_id,
                "detector_version": result.get("detector_version"),
                "checkpoint_or_provider_version": result.get("checkpoint_version")
                or result.get("provider_version")
                or result.get("model_version"),
                "config_hash": result.get("config_hash"),
                "runtime": result.get("runtime"),
                "calibration_id": result.get("calibration_id"),
                "score": result.get("score"),
                "score_semantics": result.get("score_semantics"),
                "verdict": result.get("verdict"),
                "native_score_direction": result.get("native_score_direction"),
                "score_range": result.get("score_range"),
                "supported_languages": result.get("supported_languages"),
                "min_words": result.get("min_words"),
                "disposition": disposition.get("disposition"),
                "disposition_reason": disposition.get("reason"),
            }
        )
    for failure in bundle.get("detector_failures", []):
        if not isinstance(failure, dict):
            continue
        observations.append(
            {
                "kind": "failed",
                "detector_id": failure.get("detector_id"),
                "detector_version": None,
                "checkpoint_or_provider_version": None,
                "config_hash": None,
                "runtime": None,
                "calibration_id": None,
                "score": None,
                "score_semantics": None,
                "verdict": None,
                "native_score_direction": None,
                "score_range": None,
                "supported_languages": None,
                "min_words": None,
                "disposition": None,
                "disposition_reason": None,
                "reason": failure.get("reason") or failure.get("error") or "detector failed",
                "detail": dict(failure),
            }
        )
    for row in bundle.get("plugin_health", []):
        if not isinstance(row, dict):
            continue
        observations.append(
            {
                "kind": "plugin_health",
                "detector_id": row.get("detector_id") or row.get("plugin"),
                "detector_version": None,
                "checkpoint_or_provider_version": None,
                "config_hash": None,
                "runtime": None,
                "calibration_id": None,
                "score": None,
                "score_semantics": None,
                "verdict": None,
                "native_score_direction": None,
                "score_range": None,
                "supported_languages": None,
                "min_words": None,
                "disposition": None,
                "disposition_reason": None,
                "reason": None,
                "detail": dict(row),
            }
        )
    return observations


def _checklist_consistency(case, bundle):
    """Re-derive the D1-D10 consistency rules from the sealed evidence."""
    errors = []
    process = case.get("process")
    if not isinstance(process, dict):
        return ["checklist_missing"]
    items = process.get("items")
    if not isinstance(items, dict):
        return errors + ["checklist_items_missing"]

    def status(item_id):
        record = items.get(item_id)
        return record.get("status") if isinstance(record, dict) else None

    observations = case.get("detector_observations") or []
    observed = [item for item in observations if isinstance(item, dict)]
    if status("D1") == "satisfied":
        missing = sorted(
            {
                str(item.get("detector_id"))
                for item in observed
                if item.get("kind") == "observed" and not item.get("disposition")
            }
        )
        if missing:
            errors.append("checklist_d1_unsupported:missing_disposition:" + ",".join(missing))
    if status("D2") == "satisfied":
        verdicts = {item.get("verdict") for item in observed if item.get("kind") == "observed"}
        if "ai_like" in verdicts and "human_like" in verdicts:
            contrary = process.get("contrary_evidence")
            if not isinstance(contrary, list) or not contrary:
                errors.append("checklist_d2_unsupported:detector_disagreement_unaddressed")
    if status("D3") == "satisfied":
        explanations = process.get("alternative_explanations")
        if not isinstance(explanations, dict) or not explanations:
            errors.append("checklist_d3_unsupported:no_alternative_explanations_recorded")
    if status("D4") == "satisfied":
        reviewer = process.get("reviewer")
        if not isinstance(reviewer, dict):
            errors.append("checklist_d4_unsupported:reviewer_missing")
        else:
            if not reviewer.get("identity") or not reviewer.get("role"):
                errors.append("checklist_d4_unsupported:reviewer_unidentified")
            if not reviewer.get("reasoning"):
                errors.append("checklist_d4_unsupported:reasoning_missing")
            if reviewer.get("agreed_with_tool") not in (True, False):
                errors.append("checklist_d4_unsupported:position_missing")
    if status("D5") == "satisfied":
        appeal = process.get("appeal")
        if not isinstance(appeal, dict):
            errors.append("checklist_d5_unsupported:appeal_missing")
        else:
            decider = appeal.get("decider")
            appeal_decider = appeal.get("appeal_decider")
            if not decider or not appeal_decider:
                errors.append("checklist_d5_unsupported:deciders_missing")
            elif decider == appeal_decider:
                errors.append("checklist_d5_unsupported:same_decider_for_appeal")
            if not appeal.get("route") or not appeal.get("deadline"):
                errors.append("checklist_d5_unsupported:route_or_deadline_missing")
    if status("D6") == "satisfied":
        limitations = case.get("limitations")
        plain = limitations.get("plain_language") if isinstance(limitations, dict) else None
        if not isinstance(plain, dict) or not all(
            isinstance(plain.get(key), str) and plain[key].strip()
            for key in ("score_not_probability", "authorship_warning", "human_fpr")
        ):
            errors.append("checklist_d6_unsupported:limitations_disclosure_incomplete")
    if status("D7") == "satisfied":
        response = process.get("subject_response")
        if not isinstance(response, dict):
            errors.append("checklist_d7_unsupported:subject_response_missing")
        elif not response.get("opportunity_given"):
            errors.append("checklist_d7_unsupported:opportunity_not_given")
        elif not response.get("response_attached") and not response.get("note"):
            errors.append("checklist_d7_unsupported:absence_not_recorded")
    if status("D8") == "satisfied":
        limitations = case.get("limitations")
        counterfactuals = (
            limitations.get("counterfactuals") if isinstance(limitations, dict) else None
        )
        if not isinstance(counterfactuals, list) or not counterfactuals:
            errors.append("checklist_d8_unsupported:no_counterfactuals")
    if status("D9") == "satisfied":
        retention = process.get("retention")
        if not isinstance(retention, dict) or not all(
            isinstance(retention.get(key), str) and retention[key].strip()
            for key in ("period", "legal_basis", "access", "disposal", "expungement")
        ):
            errors.append("checklist_d9_unsupported:retention_terms_incomplete")
    if status("D10") == "satisfied" and (
        not process.get("policy_version") or not process.get("procedure_version")
    ):
        errors.append("checklist_d10_unsupported:policy_or_procedure_version_missing")
    return errors


def verify_bundle_bytes(data, *, expected_digest=None, public_key=None):
    """Verify sealed-bundle bytes. Returns the verification report dict."""
    checks = []
    gaps = []
    warnings = []
    report = {
        "schema": REPORT_SCHEMA,
        "tool": TOOL,
        "bundle_sha256": _sha256(data) if len(data) <= MAX_BUNDLE_BYTES else None,
        "checks": checks,
        "gaps": gaps,
        "warnings": warnings,
        "signature": "absent",
        "timestamp": None,
        "replay": {
            "status": "unavailable",
            "reason": "detectors are not available in the standalone verifier",
        },
        "scope_statement": "",
        "exit_code": 2,
        "honest_limits": list(HONEST_LIMITS),
    }
    failed = False
    unavailable = False

    def fail(check_id, detail):
        nonlocal failed
        failed = True
        _check(checks, check_id, "fail", detail)

    def ok(check_id, detail):
        _check(checks, check_id, "pass", detail)

    def unavail(check_id, detail):
        nonlocal unavailable
        unavailable = True
        _check(checks, check_id, "unavailable", detail)

    # -- (1) container checks, MPL order: caps and EOCD before reads. --
    if len(data) > MAX_BUNDLE_BYTES:
        fail("container_outer_size", "bundle exceeds the 288 MiB outer cap")
        report["exit_code"] = 1
        report["scope_statement"] = "seal: not verified (bundle exceeds size cap)"
        return report
    ok("container_outer_size", "bundle is within the 288 MiB outer cap")
    try:
        _eocd_offset, entry_count, cd_size, cd_offset, comment = _find_eocd(data)
    except ValueError as exc:
        fail("container_eocd", str(exc))
        report["exit_code"] = 1
        report["scope_statement"] = "seal: not verified (no valid End Of Central Directory record)"
        return report
    ok("container_eocd", "End Of Central Directory record parses")
    if entry_count > MAX_ENTRIES:
        fail("container_entry_count", f"bundle has {entry_count} entries (cap {MAX_ENTRIES})")
        report["exit_code"] = 1
        report["scope_statement"] = "seal: not verified (entry count exceeds cap)"
        return report
    ok("container_entry_count", f"{entry_count} entries")
    try:
        entries = _parse_central_directory(data, cd_offset, cd_size, entry_count)
    except ValueError as exc:
        fail("container_central_directory", str(exc))
        report["exit_code"] = 1
        report["scope_statement"] = "seal: not verified (central directory malformed)"
        return report
    ok("container_central_directory", "central directory parses")
    names = [entry["name"] for entry in entries]
    if names != sorted(names):
        fail("container_sorted_entries", "entries are not in sorted order")
    else:
        ok("container_sorted_entries", "entries are in sorted order")
    total_uncompressed = 0
    for entry in entries:
        if entry["compress_method"] != ZIP_STORED:
            fail(
                "container_stored_only",
                f"entry {entry['name']} uses compression method {entry['compress_method']} (only STORED is accepted)",
            )
        if entry["uncompressed_size"] > MAX_ENTRY_BYTES:
            fail(
                "container_entry_size",
                "entry {} exceeds the 64 MiB per-entry cap".format(entry["name"]),
            )
        total_uncompressed += entry["uncompressed_size"]
        if (
            entry["create_system"] != 0
            or entry["mod_date"] != 0x21
            or entry["mod_time"] != 0
            or entry["external_attrs"] != (0o644 << 16)
            or entry["extra_len"] != 0
            or entry["comment_len"] != 0
        ):
            fail(
                "container_normalised_entries",
                "entry {} is not normalised (1980-01-01, create_system 0, "
                "0o644, no extra fields, no comment)".format(entry["name"]),
            )
    if total_uncompressed > MAX_TOTAL_BYTES:
        fail(
            "container_total_size",
            "total uncompressed size exceeds the 256 MiB cap",
        )
    else:
        ok("container_total_size", "total uncompressed size is within the 256 MiB cap")
    if failed:
        report["exit_code"] = 1
        report["scope_statement"] = "seal: not verified (container checks failed)"
        return report
    if "manifest.json" not in names or "case.json" not in names:
        fail("container_required_entries", "bundle must contain manifest.json and case.json")
        report["exit_code"] = 1
        report["scope_statement"] = "seal: not verified (required entries missing)"
        return report
    ok("container_required_entries", "manifest.json and case.json are present")

    # Read entries (single in-memory buffer, capped reads, no extraction).
    contents = {}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for entry in entries:
                if entry["uncompressed_size"] > MAX_ENTRY_BYTES:
                    continue
                with zf.open(entry["name"]) as stream:
                    contents[entry["name"]] = stream.read(MAX_ENTRY_BYTES + 1)
                    if len(contents[entry["name"]]) > MAX_ENTRY_BYTES:
                        fail(
                            "container_entry_size",
                            "entry {} exceeds the 64 MiB per-entry cap on read".format(
                                entry["name"]
                            ),
                        )
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        fail("container_read", f"could not read bundle entries: {exc}")
        report["exit_code"] = 1
        report["scope_statement"] = "seal: not verified (bundle unreadable)"
        return report
    if failed:
        report["exit_code"] = 1
        report["scope_statement"] = "seal: not verified (container checks failed)"
        return report

    # -- (2) seal checks: comment digest, manifest, per-file digests. --
    manifest_bytes = contents.get("manifest.json", b"")
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        fail("seal_manifest_size", "manifest.json exceeds the 1 MiB cap")
        report["exit_code"] = 1
        report["scope_statement"] = "seal: not verified (manifest too large)"
        return report
    try:
        comment_text = comment.decode("ascii")
    except UnicodeDecodeError:
        fail("seal_comment", "archive comment is not ASCII")
        report["exit_code"] = 1
        report["scope_statement"] = "seal: not verified (archive comment malformed)"
        return report
    if not comment_text.startswith(COMMENT_PREFIX):
        fail("seal_comment", "archive comment does not carry an mpl-bundle-sha256 digest")
        report["exit_code"] = 1
        report["scope_statement"] = "seal: not verified (archive comment malformed)"
        return report
    comment_digest = comment_text[len(COMMENT_PREFIX) :]
    if len(comment_digest) != 64 or any(c not in "0123456789abcdef" for c in comment_digest):
        fail("seal_comment", "archive comment digest is not 64 lowercase hex")
        report["exit_code"] = 1
        report["scope_statement"] = "seal: not verified (archive comment malformed)"
        return report
    ok("seal_comment", "archive comment carries an mpl-bundle-sha256 digest")
    if comment_digest != _sha256(manifest_bytes):
        fail("seal_manifest_digest", "archive comment digest does not match manifest.json bytes")
    else:
        ok("seal_manifest_digest", "archive comment digest matches manifest.json")
    if expected_digest is not None:
        if expected_digest != report["bundle_sha256"]:
            fail(
                "seal_expected_digest",
                "bundle digest does not match the expected digest",
            )
        else:
            ok("seal_expected_digest", "bundle digest matches the expected digest")
    else:
        warnings.append(
            "digest compared only to the value inside the bundle — origin not authenticated"
        )
        _check(
            checks,
            "seal_expected_digest",
            "pass",
            "no --expect-digest was given; the digest was compared only to "
            "the value inside the bundle — origin not authenticated",
        )
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        fail("seal_manifest_parse", f"manifest.json does not parse: {exc}")
        report["exit_code"] = 1
        report["scope_statement"] = "seal: not verified (manifest unparseable)"
        return report
    if not isinstance(manifest, dict) or manifest.get("schema") != MANIFEST_SCHEMA:
        fail("seal_manifest_schema", f"manifest.json schema is not {MANIFEST_SCHEMA}")
        report["exit_code"] = 1
        report["scope_statement"] = "seal: not verified (manifest schema wrong)"
        return report
    ok("seal_manifest_schema", f"manifest schema is {MANIFEST_SCHEMA}")
    manifest_files = manifest.get("files")
    if not isinstance(manifest_files, list):
        fail("seal_manifest_files", "manifest files list is missing")
        report["exit_code"] = 1
        report["scope_statement"] = "seal: not verified (manifest malformed)"
        return report
    manifest_names = [f.get("path") for f in manifest_files if isinstance(f, dict)]
    if manifest_names != sorted(manifest_names):
        fail("seal_manifest_order", "manifest files are not in sorted order")
    digest_errors = []
    for item in manifest_files:
        if not isinstance(item, dict):
            digest_errors.append("manifest entry is not an object")
            continue
        path = item.get("path")
        if path not in contents:
            digest_errors.append(f"manifest lists {path}, which is not in the bundle")
            continue
        actual = contents[path]
        if item.get("sha256") != _sha256(actual):
            digest_errors.append(f"digest mismatch for {path}")
        if item.get("size") != len(actual):
            digest_errors.append(f"size mismatch for {path}")
    for name in contents:
        if name not in manifest_names and name != "manifest.json":
            digest_errors.append(f"bundle contains {name}, which the manifest does not list")
    if digest_errors:
        fail("seal_manifest_digests", "; ".join(digest_errors))
    else:
        ok("seal_manifest_digests", "every listed file digest and size matches")
    context = manifest.get("context")
    if not isinstance(context, dict):
        fail("seal_manifest_context", "manifest context is missing")
        report["exit_code"] = 1
        report["scope_statement"] = "seal: not verified (manifest malformed)"
        return report
    case_id = context.get("case_id")
    case_bytes = contents.get("case.json", b"")
    if len(case_bytes) > MAX_SEALED_RESULTS_BYTES:
        fail("seal_case_size", "case.json exceeds the 32 MiB sealed-results cap")
        report["exit_code"] = 1
        report["scope_statement"] = "seal: not verified (case too large)"
        return report

    # -- Case-file checks (hash, v3 sections, custody, checklist). --
    try:
        case = json.loads(case_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        fail("seal_case_parse", f"case.json does not parse: {exc}")
        report["exit_code"] = 1
        report["scope_statement"] = "seal: not verified (case unparseable)"
        return report
    if not isinstance(case, dict):
        fail("seal_case_parse", "case.json is not an object")
        report["exit_code"] = 1
        report["scope_statement"] = "seal: not verified (case unparseable)"
        return report
    if case.get("case_sha256") != _case_hash(case):
        fail("seal_case_hash", "case_sha256 does not match the recomputed case hash")
    else:
        ok("seal_case_hash", "case_sha256 matches the recomputed case hash")
    if case_id is not None and case_id != case.get("case_sha256"):
        fail("seal_case_id", "manifest case_id does not match case_sha256")
    elif case_id is not None:
        ok("seal_case_id", "manifest case_id matches case_sha256")
    else:
        gaps.append({"field": "manifest.context.case_id", "reason": "manifest records no case_id"})
    schema = case.get("schema")
    if schema == CASE_SCHEMA_V3:
        bundle = case.get("forensic_bundle")
        if not isinstance(bundle, dict):
            fail("seal_case_bundle", "case file has no forensic bundle")
        else:
            input_section = case.get("input")
            if not isinstance(input_section, dict):
                fail("seal_case_input", "v3 input section is missing")
            elif input_section.get("content_sha256") != bundle.get("content_sha256"):
                fail("seal_case_input", "v3 input content hash does not match the bundle")
            else:
                ok("seal_case_input", "v3 input content hash matches the bundle")
            observations = case.get("detector_observations")
            if not isinstance(observations, list):
                fail("seal_case_observations", "v3 detector observations are missing")
            else:
                process = case.get("process")
                dispositions = (
                    process.get("evidence_dispositions") if isinstance(process, dict) else None
                )
                expected = _build_observations(bundle, dispositions)
                if observations != expected:
                    fail(
                        "seal_case_observations", "v3 detector observations do not match the bundle"
                    )
                else:
                    ok("seal_case_observations", "v3 detector observations match the bundle")
            refs = case.get("validation_refs")
            if not isinstance(refs, list):
                fail("seal_case_validation_refs", "v3 validation refs are missing")
            else:
                ref_errors = []
                for ref in refs:
                    if not isinstance(ref, dict):
                        ref_errors.append("validation ref is not an object")
                        continue
                    if ref.get("registry_sha256") != ref.get("registry_id"):
                        ref_errors.append("validation ref registry digest mismatch")
                if ref_errors:
                    fail("seal_case_validation_refs", "; ".join(ref_errors))
                else:
                    ok("seal_case_validation_refs", "v3 validation refs are well-formed")
            limitations = case.get("limitations")
            plain = limitations.get("plain_language") if isinstance(limitations, dict) else None
            if not isinstance(plain, dict) or not all(
                isinstance(plain.get(key), str) and plain[key].strip()
                for key in ("score_not_probability", "authorship_warning", "human_fpr")
            ):
                fail("seal_case_limitations", "v3 limitations disclosure is incomplete")
            else:
                ok("seal_case_limitations", "v3 limitations disclosure is complete")
            custody_errors = _verify_custody(case.get("custody"))
            if custody_errors:
                fail("seal_custody", "; ".join(custody_errors))
            else:
                ok("seal_custody", "custody hash chain verifies")
            seal = case.get("seal")
            if not isinstance(seal, dict):
                fail("seal_case_seal", "v3 seal section is missing")
            elif seal.get("algorithm") != "sha256":
                fail("seal_case_seal", "v3 seal algorithm is not sha256")
            elif (
                isinstance(case.get("custody"), list)
                and case["custody"]
                and seal.get("custody_head") != case["custody"][-1].get("entry_hash")
            ):
                fail("seal_case_seal", "v3 seal custody head does not match the chain")
            else:
                ok("seal_case_seal", "v3 seal section is consistent")
            gaps_in_case = case.get("gaps")
            if not isinstance(gaps_in_case, list):
                fail("seal_case_gaps", "v3 gaps list is missing")
            else:
                ok("seal_case_gaps", f"{len(gaps_in_case)} gaps declared")
                for gap in gaps_in_case:
                    if isinstance(gap, dict):
                        gaps.append(gap)
            checklist_errors = _checklist_consistency(case, bundle)
            if checklist_errors:
                fail("seal_checklist", "; ".join(checklist_errors))
            else:
                ok("seal_checklist", "checklist statuses are consistent with the sealed evidence")
    elif schema in (CASE_SCHEMA_V2, CASE_SCHEMA_V1):
        ok("seal_case_legacy", f"legacy case file {schema}: hash check only")
        gaps.append(
            {
                "field": "case.checklist",
                "reason": f"legacy case file {schema} carries no D1-D10 checklist",
            }
        )
    else:
        fail("seal_case_schema", f"case file schema is not recognised: {schema!r}")

    # -- (3) signature check (DSSE over the canonical manifest). --
    signature = context.get("signature") if isinstance(context, dict) else None
    if signature is None:
        report["signature"] = "absent"
        _check(checks, "seal_signature", "pass", "signature: absent (T1 hash seal only)")
        warnings.append(
            "signature: absent — integrity since sealing only, origin not authenticated"
        )
    else:
        if public_key is None:
            report["signature"] = "unavailable"
            unavail(
                "seal_signature",
                "a signature is present but no public key was supplied; "
                "origin was not authenticated",
            )
        else:
            ok_sig, detail, payload = _dsse_verify(
                signature, public_key, "textforensics.sealed-bundle-manifest/v1"
            )
            if not ok_sig:
                report["signature"] = "failed"
                fail("seal_signature", detail)
            else:
                # The envelope must sign THIS manifest (with the
                # signature field itself null), not some other payload.
                unsigned = dict(manifest)
                unsigned["context"] = dict(context)
                unsigned["context"]["signature"] = None
                if payload != _canonical_json_bytes(unsigned):
                    report["signature"] = "failed"
                    fail(
                        "seal_signature",
                        "signature payload does not match this manifest",
                    )
                else:
                    report["signature"] = "verified"
                    ok("seal_signature", f"DSSE signature verifies ({detail})")

    # -- (4) timestamp check, if a token entry is present. --
    token_bytes = contents.get("timestamp-token.der")
    if token_bytes is None:
        gaps.append(
            {
                "field": "timestamp",
                "reason": "no RFC 3161 token is present in the bundle",
            }
        )
        _check(checks, "seal_timestamp", "pass", "timestamp: absent (no token in bundle)")
    else:
        if len(token_bytes) > MAX_TIMESTAMP_TOKEN_BYTES:
            fail("seal_timestamp", "timestamp token exceeds the 1 MiB cap")
        else:
            token_info, token_errors = _verify_timestamp_token(
                token_bytes, hashlib.sha256(case_bytes).digest()
            )
            report["timestamp"] = token_info
            if token_errors:
                fail("seal_timestamp", "; ".join(token_errors))
            else:
                ok(
                    "seal_timestamp",
                    "RFC 3161 token verifies (genTime {}, non-qualified)".format(
                        token_info.get("gen_time")
                    ),
                )

    # -- Scope statement. --
    if report["signature"] == "verified":
        origin = f"key fingerprint {_sha256(bytes(public_key))}" if public_key else "verified"
    elif report["signature"] == "absent":
        origin = "unauthenticated"
    elif report["signature"] == "unavailable":
        origin = "not checked (no public key supplied)"
    else:
        origin = "signature failed"
    if report["timestamp"] is not None:
        time_part = "RFC 3161 genTime {} (non-qualified)".format(
            report["timestamp"].get("gen_time")
        )
    else:
        time_part = "local claim only"
    replay_status = report["replay"]["status"]
    report["scope_statement"] = (
        f"seal: integrity since sealing only — origin: {origin} — time: {time_part} — replay: {replay_status}"
    )
    if failed:
        report["exit_code"] = 1
    elif unavailable:
        report["exit_code"] = 2
    else:
        report["exit_code"] = 0
    return report


def _load_public_key(value):
    """Load a 32-byte Ed25519 public key from hex text or a file path."""
    import os

    if os.path.exists(value):
        with open(value, "rb") as handle:
            raw = handle.read()
        text = raw.decode("ascii", "ignore").strip()
        if len(raw) == 32:
            return raw
        data = bytes.fromhex(text)
        if len(data) == 32:
            return data
        raise ValueError("public key file does not hold 32 bytes")
    data = bytes.fromhex(value)
    if len(data) != 32:
        raise ValueError("public key must be 32 bytes")
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="verify.py",
        description="Verify a TextForensics sealed bundle (stdlib only).",
    )
    parser.add_argument("bundle", help="path to the sealed .zip bundle")
    parser.add_argument(
        "--expect-digest",
        default=None,
        help="expected SHA-256 of the bundle bytes (compared out-of-band)",
    )
    parser.add_argument(
        "--public-key",
        default=None,
        help="Ed25519 public key as 64 hex chars, or a path to a key file",
    )
    args = parser.parse_args(argv)
    try:
        with open(args.bundle, "rb") as handle:
            data = handle.read(MAX_BUNDLE_BYTES + 1)
    except OSError as exc:
        print(f"cannot read bundle: {exc}", file=sys.stderr)
        return 2
    public_key = None
    if args.public_key:
        try:
            public_key = _load_public_key(args.public_key)
        except (ValueError, OSError) as exc:
            print(f"cannot load public key: {exc}", file=sys.stderr)
            return 2
    expected_digest = None
    if args.expect_digest:
        expected_digest = args.expect_digest.strip().lower()
        if len(expected_digest) != 64 or any(c not in "0123456789abcdef" for c in expected_digest):
            print("--expect-digest must be 64 lowercase hex chars", file=sys.stderr)
            return 2
    report = verify_bundle_bytes(data, expected_digest=expected_digest, public_key=public_key)
    print(json.dumps(report, indent=2, sort_keys=True))
    print(report["scope_statement"])
    return report["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
