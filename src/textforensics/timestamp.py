"""RFC 3161 time-stamping for sealed case files (Phase 3 U2, T3 seal).

Stdlib only.  A time-stamp token proves that a digest existed *at* the
TSA's genTime; it proves nothing about receipt, authorship, or what the
file looked like before.  A free TSA's token is labelled
"RFC 3161 timestamp (non-qualified)" — never "legally timestamped".

What verification here establishes, and what it does not:

- The token parses as a CMS SignedData whose encapsulated content is a
  TSTInfo, the message imprint equals the expected digest, the nonce
  echoes the request nonce, and the signer's signature verifies against
  the public key in the embedded signer certificate.
- It does NOT establish that the certificate is trusted: offline, with
  no trust store, ``qualified`` is always ``"unknown"`` with the method
  recorded.  A caller with an EU Trusted List snapshot may re-check
  qualification out of band; this module never claims ``qualified``
  from the token alone.
- A local hash ledger is NOT a trusted timestamp and is never treated
  as one here.

References: RFC 3161 (Time-Stamp Protocol), RFC 5652 (CMS),
RFC 5911 (TSTInfo / id-ct-TSTInfo OID).
"""

from __future__ import annotations

import hashlib
import secrets
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from typing import Any

# ---------------------------------------------------------------------------
# OIDs
# ---------------------------------------------------------------------------

OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
OID_SIGNED_DATA = "1.2.840.113549.1.9.16.1.2"
OID_DATA = "1.2.840.113549.1.9.7.1"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_TIME = "1.2.840.113549.1.9.5"
OID_SHA1 = "1.3.14.3.2.26"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SHA384 = "2.16.840.1.101.3.4.2.2"
OID_SHA512 = "2.16.840.1.101.3.4.2.3"
OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_SHA1_WITH_RSA = "1.2.840.113549.1.1.5"
OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
OID_SHA384_WITH_RSA = "1.2.840.113549.1.1.12"
OID_SHA512_WITH_RSA = "1.2.840.113549.1.1.13"
OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
OID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2"
OID_ECDSA_WITH_SHA384 = "1.2.840.10045.4.3.3"
OID_ECDSA_WITH_SHA512 = "1.2.840.10045.4.3.4"
OID_PRIME256V1 = "1.2.840.10045.3.1.7"
OID_SECP384R1 = "1.3.132.0.34"

_HASH_OIDS = {
    OID_SHA1: "sha1",
    OID_SHA256: "sha256",
    OID_SHA384: "sha384",
    OID_SHA512: "sha512",
}

# Signature algorithms this module verifies, mapped to the hash they
# use.  RSA PKCS#1 v1.5 and ECDSA over P-256/P-384 only; nothing else
# is accepted, and an unknown algorithm is a verification error, not
# a silent pass.
_RSA_SIGNATURE_OIDS = {
    OID_SHA1_WITH_RSA: "sha1",
    OID_SHA256_WITH_RSA: "sha256",
    OID_SHA384_WITH_RSA: "sha384",
    OID_SHA512_WITH_RSA: "sha512",
}
_ECDSA_SIGNATURE_OIDS = {
    OID_ECDSA_WITH_SHA256: ("sha256", "P-256"),
    OID_ECDSA_WITH_SHA384: ("sha384", "P-384"),
    OID_ECDSA_WITH_SHA512: ("sha512", "P-384"),
}

# DigestInfo prefixes for RSA PKCS#1 v1.5 verification (RFC 8017 §9.2).
_DIGEST_INFO_PREFIX = {
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}

# P-256 / P-384 domain parameters (FIPS 186-4 §D.2).
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

# A time-stamp response is a small CMS object; anything larger is not a
# token, it is an abuse attempt.  Enforced before the bytes are parsed.
MAX_TIMESTAMP_RESPONSE_BYTES = 1024 * 1024
MAX_TIMESTAMP_REQUEST_BYTES = 4096

# Free TSAs used for the manual interop check during development.  The
# request path never depends on a particular TSA: any RFC 3161 TSA URL
# works.  Tokens from free TSAs are non-qualified (see module docstring).
FREE_TSA_URLS = (
    "https://freetsa.org/tsr",
    "https://timestamp.digicert.com",
)

TIMESTAMP_QUALIFICATION_LABEL = "RFC 3161 timestamp (non-qualified)"


class TimestampError(ValueError):
    """Raised when a time-stamp request or token cannot be processed."""


# ---------------------------------------------------------------------------
# DER encoding helpers
# ---------------------------------------------------------------------------


def _der_length(length: int) -> bytes:
    if length < 0:
        raise TimestampError("Negative DER length.")
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(content)) + content


def _der_integer(value: int) -> bytes:
    if value < 0:
        raise TimestampError("DER INTEGER must be non-negative here.")
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _tlv(0x02, raw)


def _der_oid(oid: str) -> bytes:
    parts = [int(part) for part in oid.split(".")]
    if len(parts) < 2 or parts[0] > 2 or parts[1] > 39:
        raise TimestampError(f"Invalid OID: {oid!r}.")
    encoded = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        if part < 0:
            raise TimestampError(f"Invalid OID: {oid!r}.")
        groups = [part & 0x7F]
        part >>= 7
        while part:
            groups.append(0x80 | (part & 0x7F))
            part >>= 7
        encoded += bytes(reversed(groups))
    return _tlv(0x06, encoded)


def _der_octet_string(data: bytes) -> bytes:
    return _tlv(0x04, data)


def _der_boolean(value: bool) -> bytes:
    return _tlv(0x01, b"\xff" if value else b"\x00")


def _der_generalized_time(value: str) -> bytes:
    return _tlv(0x18, value.encode("ascii"))


def _der_sequence(*children: bytes) -> bytes:
    return _tlv(0x30, b"".join(children))


def _der_set(*children: bytes) -> bytes:
    return _tlv(0x31, b"".join(children))


def _der_context(tag_number: int, content: bytes, *, constructed: bool) -> bytes:
    tag = 0xA0 | tag_number if constructed else 0x80 | tag_number
    return _tlv(tag, content)


def _algorithm_identifier(oid: str) -> bytes:
    # AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY
    # OPTIONAL }.  Hash algorithms carry an ABSENT parameters field in
    # practice (NULL is also seen); we encode without parameters.
    return _der_sequence(_der_oid(oid))


# ---------------------------------------------------------------------------
# DER parsing helpers (strict: definite lengths only, no trailing bytes)
# ---------------------------------------------------------------------------


class _DerNode:
    __slots__ = ("tag", "content", "raw", "children")

    def __init__(self, tag: int, content: bytes, raw: bytes) -> None:
        self.tag = tag
        self.content = content
        self.raw = raw
        self.children: list[_DerNode] | None = None


def _parse_tlv(data: bytes, offset: int = 0) -> tuple[_DerNode, int]:
    if offset + 2 > len(data):
        raise TimestampError("Truncated DER value.")
    tag = data[offset]
    pos = offset + 1
    first = data[pos]
    pos += 1
    if first & 0x80 == 0:
        length = first
    else:
        nbytes = first & 0x7F
        if nbytes == 0:
            raise TimestampError("Indefinite DER length is not accepted.")
        if nbytes > 4 or pos + nbytes > len(data):
            raise TimestampError("Invalid DER length.")
        length = int.from_bytes(data[pos : pos + nbytes], "big")
        pos += nbytes
    if pos + length > len(data):
        raise TimestampError("DER length exceeds input.")
    content = data[pos : pos + length]
    raw = data[offset : pos + length]
    return _DerNode(tag, content, raw), pos + length


def _parse_all(data: bytes) -> _DerNode:
    node, end = _parse_tlv(data, 0)
    if end != len(data):
        raise TimestampError("Trailing bytes after DER value.")
    return node


def _children(node: _DerNode) -> list[_DerNode]:
    if node.children is None:
        children: list[_DerNode] = []
        pos = 0
        while pos < len(node.content):
            child, pos = _parse_tlv(node.content, pos)
            children.append(child)
        node.children = children
    return node.children


def _parse_oid_bytes(content: bytes) -> str:
    if not content:
        raise TimestampError("Empty OID.")
    parts = [content[0] // 40, content[0] % 40]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if byte & 0x80 == 0:
            parts.append(value)
            value = 0
    if content[-1] & 0x80:
        raise TimestampError("Truncated OID.")
    return ".".join(str(part) for part in parts)


def _parse_integer(node: _DerNode) -> int:
    if node.tag != 0x02:
        raise TimestampError("Expected DER INTEGER.")
    return int.from_bytes(node.content, "big", signed=False)


def _parse_generalized_time(node: _DerNode) -> str:
    if node.tag != 0x18:
        raise TimestampError("Expected GeneralizedTime.")
    try:
        text = node.content.decode("ascii")
    except UnicodeDecodeError as exc:
        raise TimestampError("GeneralizedTime is not ASCII.") from exc
    return text


def _generalized_time_to_datetime(text: str) -> datetime:
    cleaned = text.rstrip("Z")
    if "." in cleaned:
        whole, fraction = cleaned.split(".", 1)
        fraction = (fraction + "000000")[:6]
        cleaned = f"{whole}.{fraction}"
        parsed = datetime.strptime(cleaned, "%Y%m%d%H%M%S.%f")
    else:
        parsed = datetime.strptime(cleaned, "%Y%m%d%H%M%S")
    return parsed.replace(tzinfo=UTC)


# ---------------------------------------------------------------------------
# Time-stamp request
# ---------------------------------------------------------------------------


def build_timestamp_request(
    digest: bytes,
    *,
    hash_algorithm: str = "sha256",
    nonce: int | None = None,
    cert_req: bool = True,
) -> tuple[bytes, int]:
    """Build a TimeStampReq for *digest* (already hashed with *hash_algorithm*).

    Returns ``(request_der, nonce)``.  The nonce is a fresh 63-bit random
    integer unless one is supplied (tests may pin it).
    """
    oid = {
        "sha1": OID_SHA1,
        "sha256": OID_SHA256,
        "sha384": OID_SHA384,
        "sha512": OID_SHA512,
    }.get(hash_algorithm)
    if oid is None:
        raise TimestampError(f"Unsupported hash algorithm: {hash_algorithm!r}.")
    if len(digest) != hashlib.new(hash_algorithm).digest_size:
        raise TimestampError(f"Digest length {len(digest)} does not match {hash_algorithm}.")
    if nonce is None:
        nonce = secrets.randbits(63)
    if nonce < 0:
        raise TimestampError("Nonce must be non-negative.")
    message_imprint = _der_sequence(
        _algorithm_identifier(oid),
        _der_octet_string(digest),
    )
    children = [_der_integer(1), message_imprint, _der_integer(nonce)]
    if cert_req:
        children.append(_der_boolean(True))
    request = _der_sequence(*children)
    if len(request) > MAX_TIMESTAMP_REQUEST_BYTES:
        raise TimestampError("Time-stamp request exceeds the size cap.")
    return request, nonce


# Plain http is only ever allowed to loopback (local TSA fixtures);
# the dataset downloader enforces the same policy (see
# ``_require_https_or_loopback_http`` in datasets.py).
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def _require_https_tsa_url(tsa_url: str) -> None:
    """Refuse any TSA URL that is not https (or http on loopback).

    The URL comes from the user (``--timestamp-url``), but a
    plain-http TSA would let a network attacker substitute the token
    endpoint, and ``urllib`` would also honour non-http schemes such
    as ``file://``. https everywhere; plain http only for loopback
    fixtures. Raises :class:`TimestampError` before any network use.
    """
    parsed = urllib.parse.urlparse(tsa_url)
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and (parsed.hostname or "").lower() in _LOOPBACK_HOSTS:
        return
    raise TimestampError(
        f"TSA URL must be https (loopback http only): {parsed.scheme}://{parsed.hostname or '?'}"
    )


class _NoDowngradeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """HTTPRedirectHandler that refuses any redirect the TSA scheme policy refuses.

    ``urllib`` follows redirects silently, so an https TSA URL could
    redirect to http and the request (and the token) would travel in
    the clear — bounded only by the token's cryptographic verification
    afterwards. Two checks run on every hop: the target must pass
    :func:`_require_https_tsa_url`, the same rule the original URL
    already passed, and a hop from https to http is refused even
    when the target is loopback (a downgrade is a downgrade). Only
    an origin that was itself http on loopback may stay on http
    loopback. The refusal raises :class:`TimestampError` before any
    request to the target is made.
    (The dataset downloader enforces the same rule with its own
    handler; the two modules keep separate validators and error
    types, so the handler lives here too.)
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _require_https_tsa_url(newurl)
        target = urllib.parse.urlparse(newurl)
        if urllib.parse.urlparse(req.full_url).scheme == "https" and target.scheme == "http":
            raise TimestampError(
                "refuses https-to-http redirect downgrade for TSA URL: "
                f"http://{target.hostname or '?'}"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _guarded_urlopen(request: urllib.request.Request, *, timeout: float) -> Any:
    """``urllib.request.urlopen`` through an opener carrying the redirect guard.

    Same call shape as ``urlopen`` (request + timeout); the opener is
    the default one ``build_opener`` assembles with the default
    redirect handler replaced by :class:`_NoDowngradeRedirectHandler`.
    """
    return urllib.request.build_opener(_NoDowngradeRedirectHandler()).open(request, timeout=timeout)


def request_timestamp(
    digest: bytes,
    tsa_url: str,
    *,
    hash_algorithm: str = "sha256",
    nonce: int | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Ask *tsa_url* to time-stamp *digest* and verify the returned token.

    Returns the verification report from :func:`verify_timestamp_token`
    with the raw token bytes attached under ``token_der``.  Raises
    :class:`TimestampError` on any transport, status, parse or
    verification failure.
    """
    _require_https_tsa_url(tsa_url)
    request_der, used_nonce = build_timestamp_request(
        digest, hash_algorithm=hash_algorithm, nonce=nonce
    )
    http_request = urllib.request.Request(
        tsa_url,
        data=request_der,
        headers={
            "Content-Type": "application/timestamp-query",
            "Content-Length": str(len(request_der)),
        },
        method="POST",
    )
    try:
        # B310 reviewed: tsa_url validated at the top of request_timestamp
        # by _require_https_tsa_url (https, or http on loopback only);
        # the body is only a hash digest, the response is size-capped
        # and the token is cryptographically verified before use.
        # Redirects go through _guarded_urlopen, which refuses any hop
        # the TSA scheme policy refuses (no https→http downgrade).
        with _guarded_urlopen(http_request, timeout=timeout) as response:
            raw = response.read(MAX_TIMESTAMP_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise TimestampError(f"TSA HTTP error: {exc.code} {exc.reason}.") from exc
    except urllib.error.URLError as exc:
        raise TimestampError(f"TSA unreachable: {exc.reason}.") from exc
    if len(raw) > MAX_TIMESTAMP_RESPONSE_BYTES:
        raise TimestampError("Time-stamp response exceeds the size cap.")
    status, token_der = parse_timestamp_response(raw)
    if status not in (0, 1):
        raise TimestampError(f"TSA did not grant the token (status {status}).")
    if token_der is None:
        raise TimestampError("TSA granted no token.")
    report = verify_timestamp_token(
        token_der,
        expected_digest=digest,
        expected_hash_algorithm=hash_algorithm,
        expected_nonce=used_nonce,
    )
    report["token_der"] = token_der
    report["tsa_url"] = tsa_url
    if not report["valid"]:
        raise TimestampError("TSA token failed verification: " + "; ".join(report["errors"]))
    return report


# ---------------------------------------------------------------------------
# Time-stamp response / token parsing
# ---------------------------------------------------------------------------

_PKI_STATUS_NAMES = {
    0: "granted",
    1: "grantedWithMods",
    2: "rejection",
    3: "waiting",
    4: "revocationWarning",
    5: "revocationNotification",
}


def parse_timestamp_response(data: bytes) -> tuple[int, bytes | None]:
    """Parse a TimeStampResp. Returns ``(status, token_der_or_None)``."""
    if len(data) > MAX_TIMESTAMP_RESPONSE_BYTES:
        raise TimestampError("Time-stamp response exceeds the size cap.")
    root = _parse_all(data)
    if root.tag != 0x30:
        raise TimestampError("TimeStampResp is not a SEQUENCE.")
    parts = _children(root)
    if not parts or parts[0].tag != 0x30:
        raise TimestampError("TimeStampResp has no PKIStatusInfo.")
    status_parts = _children(parts[0])
    if not status_parts:
        raise TimestampError("PKIStatusInfo is empty.")
    status = _parse_integer(status_parts[0])
    token_der = None
    if len(parts) > 1:
        token_der = parts[1].raw
    return status, token_der


def _parse_content_info(data: bytes) -> tuple[str, _DerNode]:
    root = _parse_all(data)
    if root.tag != 0x30:
        raise TimestampError("ContentInfo is not a SEQUENCE.")
    parts = _children(root)
    if not parts or parts[0].tag != 0x06:
        raise TimestampError("ContentInfo has no content type OID.")
    content_type = _parse_oid_bytes(parts[0].content)
    if len(parts) < 2:
        raise TimestampError("ContentInfo has no content.")
    return content_type, parts[1]


def _parse_signed_data(node: _DerNode) -> dict[str, Any]:
    if node.tag != 0xA0:
        raise TimestampError("SignedData is not [0] EXPLICIT.")
    inner = _children(node)
    if len(inner) != 1 or inner[0].tag != 0x30:
        raise TimestampError("SignedData content is not a SEQUENCE.")
    fields = _children(inner[0])
    if len(fields) < 4:
        raise TimestampError("SignedData is truncated.")
    digest_algorithms = []
    for child in _children(fields[1]):
        if child.tag != 0x30:
            continue
        alg_fields = _children(child)
        if alg_fields and alg_fields[0].tag == 0x06:
            digest_algorithms.append(_parse_oid_bytes(alg_fields[0].content))
    encap = _children(fields[2])
    if len(encap) < 1 or encap[0].tag != 0x06:
        raise TimestampError("EncapsulatedContentInfo has no content type.")
    econtent_type = _parse_oid_bytes(encap[0].content)
    econtent: bytes | None = None
    if len(encap) > 1:
        explicit = _children(encap[1])
        if len(explicit) != 1 or explicit[0].tag != 0x04:
            raise TimestampError("Encapsulated content is not an OCTET STRING.")
        econtent = explicit[0].content
    certificates: list[bytes] = []
    signer_infos: list[_DerNode] = []
    for field in fields[3:]:
        if field.tag == 0xA0:
            for cert in _children(field):
                certificates.append(cert.raw)
        elif field.tag == 0x31:
            signer_infos = _children(field)
    return {
        "digest_algorithms": digest_algorithms,
        "econtent_type": econtent_type,
        "econtent": econtent,
        "certificates": certificates,
        "signer_infos": signer_infos,
    }


def _parse_tst_info(data: bytes) -> dict[str, Any]:
    root = _parse_all(data)
    if root.tag != 0x30:
        raise TimestampError("TSTInfo is not a SEQUENCE.")
    fields = _children(root)
    if len(fields) < 5:
        raise TimestampError("TSTInfo is truncated.")
    version = _parse_integer(fields[0])
    policy = _parse_oid_bytes(fields[1].content)
    imprint_fields = _children(fields[2])
    if len(imprint_fields) != 2:
        raise TimestampError("MessageImprint is malformed.")
    imprint_alg_fields = _children(imprint_fields[0])
    if not imprint_alg_fields:
        raise TimestampError("MessageImprint has no hash algorithm.")
    hash_oid = _parse_oid_bytes(imprint_alg_fields[0].content)
    hashed_message = imprint_fields[1].content
    serial = _parse_integer(fields[3])
    gen_time_text = _parse_generalized_time(fields[4])
    nonce: int | None = None
    index = 5
    # Optional: accuracy (SEQUENCE), ordering (BOOLEAN), nonce (INTEGER),
    # tsa [0], extensions [1].  Walk them in order.
    while index < len(fields):
        field = fields[index]
        if field.tag == 0x02:
            nonce = _parse_integer(field)
        index += 1
    return {
        "version": version,
        "policy": policy,
        "hash_algorithm_oid": hash_oid,
        "hash_algorithm": _HASH_OIDS.get(hash_oid),
        "hashed_message": hashed_message,
        "serial_number": serial,
        "gen_time": gen_time_text,
        "gen_time_utc": _generalized_time_to_datetime(gen_time_text).isoformat(),
        "nonce": nonce,
    }


def _parse_signer_info(node: _DerNode) -> dict[str, Any]:
    if node.tag != 0x30:
        raise TimestampError("SignerInfo is not a SEQUENCE.")
    fields = _children(node)
    if len(fields) < 6:
        raise TimestampError("SignerInfo is truncated.")
    version = _parse_integer(fields[0])
    sid = fields[1]
    digest_alg_fields = _children(fields[2])
    digest_oid = _parse_oid_bytes(digest_alg_fields[0].content) if digest_alg_fields else None
    signed_attrs: _DerNode | None = None
    signed_attrs_raw: bytes | None = None
    index = 3
    if index < len(fields) and fields[index].tag == 0xA0:
        signed_attrs = fields[index]
        # CMS: the signature is computed over the DER encoding of the
        # signed attributes as a SET OF (tag 0x31), not [0] (0xA0).
        signed_attrs_raw = b"\x31" + signed_attrs.raw[1:]
        index += 1
    if index >= len(fields):
        raise TimestampError("SignerInfo has no signature algorithm.")
    sig_alg_fields = _children(fields[index])
    sig_oid = _parse_oid_bytes(sig_alg_fields[0].content) if sig_alg_fields else None
    index += 1
    if index >= len(fields) or fields[index].tag != 0x04:
        raise TimestampError("SignerInfo has no signature value.")
    signature = fields[index].content
    attributes: dict[str, list[bytes]] = {}
    if signed_attrs is not None:
        for attr in _children(signed_attrs):
            attr_fields = _children(attr)
            if len(attr_fields) < 2:
                continue
            attr_oid = _parse_oid_bytes(attr_fields[0].content)
            values = [value.raw for value in _children(attr_fields[1])]
            attributes[attr_oid] = values
    return {
        "version": version,
        "sid_raw": sid.raw,
        "digest_algorithm_oid": digest_oid,
        "digest_algorithm": _HASH_OIDS.get(digest_oid) if digest_oid else None,
        "signed_attrs_raw": signed_attrs_raw,
        "signature_algorithm_oid": sig_oid,
        "signature": signature,
        "attributes": attributes,
    }


def _parse_certificate(der: bytes) -> dict[str, Any]:
    """Parse an X.509 certificate just far enough to extract its key."""
    root = _parse_all(der)
    if root.tag != 0x30:
        raise TimestampError("Certificate is not a SEQUENCE.")
    fields = _children(root)
    if not fields or fields[0].tag != 0x30:
        raise TimestampError("Certificate TBSCertificate is missing.")
    tbs = _children(fields[0])
    # TBSCertificate: [0] version (optional), serial, signature, issuer,
    # validity, subject, subjectPublicKeyInfo, ...
    index = 0
    if tbs and tbs[0].tag == 0xA0:
        index = 1
    if len(tbs) < index + 6:
        raise TimestampError("TBSCertificate is truncated.")
    serial = _parse_integer(tbs[index])
    issuer_raw = tbs[index + 2].raw
    subject_raw = tbs[index + 4].raw
    spki = _children(tbs[index + 5])
    if len(spki) < 2:
        raise TimestampError("subjectPublicKeyInfo is malformed.")
    alg_fields = _children(spki[0])
    if not alg_fields:
        raise TimestampError("subjectPublicKeyInfo has no algorithm.")
    key_oid = _parse_oid_bytes(alg_fields[0].content)
    key_params: str | None = None
    if len(alg_fields) > 1 and alg_fields[1].tag == 0x06:
        key_params = _parse_oid_bytes(alg_fields[1].content)
    key_bits = spki[1]
    if key_bits.tag != 0x03:
        raise TimestampError("subjectPublicKeyInfo has no BIT STRING key.")
    if not key_bits.content or key_bits.content[0] != 0:
        raise TimestampError("subjectPublicKeyInfo BIT STRING has unused bits.")
    key_der = key_bits.content[1:]
    return {
        "serial_number": serial,
        "issuer_raw": issuer_raw,
        "subject_raw": subject_raw,
        "key_algorithm_oid": key_oid,
        "key_params_oid": key_params,
        "key_der": key_der,
        "fingerprint_sha256": hashlib.sha256(der).hexdigest(),
    }


def _parse_rsa_public_key(der: bytes) -> tuple[int, int]:
    root = _parse_all(der)
    if root.tag != 0x30:
        raise TimestampError("RSA public key is not a SEQUENCE.")
    fields = _children(root)
    if len(fields) != 2:
        raise TimestampError("RSA public key is malformed.")
    modulus = int.from_bytes(fields[0].content, "big")
    exponent = int.from_bytes(fields[1].content, "big")
    return modulus, exponent


def _parse_ec_public_key(der: bytes) -> tuple[int, int]:
    # The EC public key is a raw uncompressed point (0x04 || X || Y),
    # not a DER value: it is the BIT STRING content of the
    # subjectPublicKeyInfo, with the unused-bits byte already stripped.
    if not der or der[0] != 0x04:
        raise TimestampError("EC public key is not uncompressed.")
    size = (len(der) - 1) // 2
    if 1 + 2 * size != len(der):
        raise TimestampError("EC public key has an odd length.")
    x = int.from_bytes(der[1 : 1 + size], "big")
    y = int.from_bytes(der[1 + size :], "big")
    return x, y


# ---------------------------------------------------------------------------
# Signature verification (pure Python)
# ---------------------------------------------------------------------------


def _rsa_verify_pkcs1_v15(
    modulus: int, exponent: int, signature: bytes, digest: bytes, hash_name: str
) -> bool:
    key_bytes = (modulus.bit_length() + 7) // 8
    if len(signature) != key_bytes:
        return False
    em = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(key_bytes, "big")
    prefix = _DIGEST_INFO_PREFIX[hash_name]
    expected = b"\x00\x01" + b"\xff" * (key_bytes - len(prefix) - len(digest) - 3) + b"\x00"
    expected += prefix + digest
    return em == expected


def _ec_point_add(
    p1: tuple[int, int] | None, p2: tuple[int, int] | None, curve: dict[str, int]
) -> tuple[int, int] | None:
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


def _ec_scalar_mult(
    k: int, point: tuple[int, int], curve: dict[str, int]
) -> tuple[int, int] | None:
    result: tuple[int, int] | None = None
    addend: tuple[int, int] | None = point
    while k:
        if k & 1:
            result = _ec_point_add(result, addend, curve)
        addend = _ec_point_add(addend, addend, curve)
        k >>= 1
    return result


def _ecdsa_verify(
    curve_name: str,
    public_point: tuple[int, int],
    signature_der: bytes,
    digest: bytes,
) -> bool:
    curve = _EC_CURVES[curve_name]
    root = _parse_all(signature_der)
    if root.tag != 0x30:
        return False
    fields = _children(root)
    if len(fields) != 2:
        return False
    r = int.from_bytes(fields[0].content, "big")
    s = int.from_bytes(fields[1].content, "big")
    n = curve["n"]
    if not 1 <= r < n or not 1 <= s < n:
        return False
    z = int.from_bytes(digest[: (n.bit_length() + 7) // 8], "big")
    w = pow(s, -1, n)
    u1 = (z * w) % n
    u2 = (r * w) % n
    point = _ec_point_add(
        _ec_scalar_mult(u1, (curve["gx"], curve["gy"]), curve),
        _ec_scalar_mult(u2, public_point, curve),
        curve,
    )
    if point is None:
        return False
    return point[0] % n == r


def parse_timestamp_token(token_der: bytes) -> dict[str, Any]:
    """Parse a TimeStampToken (CMS ContentInfo) into its fields.

    Raises :class:`TimestampError` on any structural problem.
    """
    if len(token_der) > MAX_TIMESTAMP_RESPONSE_BYTES:
        raise TimestampError("Time-stamp token exceeds the size cap.")
    content_type, content = _parse_content_info(token_der)
    if content_type != OID_SIGNED_DATA:
        raise TimestampError(f"TimeStampToken content type is {content_type}, not id-signedData.")
    signed = _parse_signed_data(content)
    if signed["econtent_type"] != OID_TST_INFO:
        raise TimestampError(
            f"SignedData eContentType is {signed['econtent_type']}, not id-ct-TSTInfo."
        )
    if signed["econtent"] is None:
        raise TimestampError("SignedData has no encapsulated TSTInfo.")
    tst_info = _parse_tst_info(signed["econtent"])
    signer_infos = [_parse_signer_info(node) for node in signed["signer_infos"]]
    certificates = []
    for cert_der in signed["certificates"]:
        try:
            certificates.append(_parse_certificate(cert_der))
        except TimestampError:
            continue
    return {
        "tst_info": tst_info,
        "econtent": signed["econtent"],
        "digest_algorithms": signed["digest_algorithms"],
        "signer_infos": signer_infos,
        "certificates": certificates,
        "certificate_count": len(signed["certificates"]),
    }


def verify_timestamp_token(
    token_der: bytes,
    *,
    expected_digest: bytes,
    expected_hash_algorithm: str = "sha256",
    expected_nonce: int | None = None,
) -> dict[str, Any]:
    """Verify a time-stamp token against an expected digest.

    Returns a report dict with ``valid``, ``errors``, ``gen_time``,
    ``policy``, ``serial_number``, ``signer_cert_fingerprint``,
    ``signature_algorithm`` and the ``qualified`` flag (always
    ``"unknown"`` offline — see the module docstring).  The report
    never raises on a malformed token; structural failures are errors.
    """
    errors: list[str] = []
    info: dict[str, Any] = {
        "valid": False,
        "errors": errors,
        "gen_time": None,
        "gen_time_utc": None,
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
        "qualification_label": TIMESTAMP_QUALIFICATION_LABEL,
        "note": (
            "A time-stamp token proves the digest existed at genTime; "
            "it does not prove receipt, authorship, or what the file "
            "looked like before."
        ),
    }
    try:
        parsed = parse_timestamp_token(token_der)
    except TimestampError as exc:
        errors.append(f"token_unparseable:{exc}")
        return info
    tst = parsed["tst_info"]
    info["gen_time"] = tst["gen_time"]
    info["gen_time_utc"] = tst["gen_time_utc"]
    info["policy"] = tst["policy"]
    info["serial_number"] = tst["serial_number"]
    info["nonce"] = tst["nonce"]
    info["certificate_count"] = parsed["certificate_count"]
    if tst["hash_algorithm"] != expected_hash_algorithm:
        errors.append(f"imprint_hash_algorithm_mismatch:{tst['hash_algorithm']}")
    if tst["hashed_message"] != expected_digest:
        errors.append("message_imprint_mismatch")
    if expected_nonce is not None and tst["nonce"] != expected_nonce:
        errors.append("nonce_mismatch")
    if len(parsed["signer_infos"]) != 1:
        errors.append(f"signer_info_count:{len(parsed['signer_infos'])} (expected exactly 1)")
        return info
    signer = parsed["signer_infos"][0]
    sig_oid = signer["signature_algorithm_oid"]
    info["signature_algorithm"] = sig_oid
    if signer["signed_attrs_raw"] is None:
        errors.append("signed_attrs_absent")
        return info
    message_digest_values = signer["attributes"].get(OID_MESSAGE_DIGEST, [])
    if len(message_digest_values) != 1:
        errors.append("message_digest_attribute_missing_or_ambiguous")
        return info
    try:
        digest_node = _parse_all(message_digest_values[0])
    except TimestampError as exc:
        errors.append(f"message_digest_attribute_unparseable:{exc}")
        return info
    if digest_node.tag != 0x04:
        errors.append("message_digest_attribute_not_octet_string")
        return info
    hash_name = signer["digest_algorithm"]
    if hash_name is None:
        errors.append(f"signer_digest_algorithm_unknown:{signer['digest_algorithm_oid']}")
        return info
    expected_econtent_digest = hashlib.new(hash_name, parsed["econtent"]).digest()
    if digest_node.content != expected_econtent_digest:
        errors.append("message_digest_mismatch")
        return info
    signed_data = hashlib.new(hash_name, signer["signed_attrs_raw"]).digest()
    # The signer certificate: match by issuer + serial when the sid
    # carries them; otherwise fall back to the first certificate.
    signer_cert: dict[str, Any] | None = None
    try:
        sid = _parse_all(signer["sid_raw"])
        sid_fields = _children(sid)
        if len(sid_fields) == 2:
            issuer_raw = sid_fields[0].raw
            serial = _parse_integer(sid_fields[1])
            for cert in parsed["certificates"]:
                if cert["issuer_raw"] == issuer_raw and cert["serial_number"] == serial:
                    signer_cert = cert
                    break
    except TimestampError:
        signer_cert = None
    if signer_cert is None and parsed["certificates"]:
        signer_cert = parsed["certificates"][0]
    if signer_cert is None:
        errors.append("signer_certificate_not_found")
        return info
    info["signer_cert_fingerprint"] = signer_cert["fingerprint_sha256"]
    verified = False
    key_oid = signer_cert["key_algorithm_oid"]
    if sig_oid in _RSA_SIGNATURE_OIDS and key_oid == OID_RSA_ENCRYPTION:
        if _RSA_SIGNATURE_OIDS[sig_oid] != hash_name:
            errors.append(f"signature_hash_mismatch:{_RSA_SIGNATURE_OIDS[sig_oid]} != {hash_name}")
            return info
        try:
            modulus, exponent = _parse_rsa_public_key(signer_cert["key_der"])
            verified = _rsa_verify_pkcs1_v15(
                modulus,
                exponent,
                signer["signature"],
                signed_data,
                _RSA_SIGNATURE_OIDS[sig_oid],
            )
        except TimestampError as exc:
            errors.append(f"rsa_key_unparseable:{exc}")
            return info
    elif sig_oid in _ECDSA_SIGNATURE_OIDS and key_oid == OID_EC_PUBLIC_KEY:
        hash_name_sig, curve_name = _ECDSA_SIGNATURE_OIDS[sig_oid]
        if hash_name_sig != hash_name:
            errors.append(f"signature_hash_mismatch:{hash_name_sig} != {hash_name}")
            return info
        curve_oid = signer_cert["key_params_oid"]
        expected_curve_oid = OID_PRIME256V1 if curve_name == "P-256" else OID_SECP384R1
        if curve_oid != expected_curve_oid:
            errors.append(f"ec_curve_mismatch:{curve_oid}")
            return info
        try:
            point = _parse_ec_public_key(signer_cert["key_der"])
            verified = _ecdsa_verify(curve_name, point, signer["signature"], signed_data)
        except TimestampError as exc:
            errors.append(f"ec_key_unparseable:{exc}")
            return info
    else:
        errors.append(f"unsupported_signature_algorithm:{sig_oid} with key {key_oid}")
        return info
    if not verified:
        errors.append("signature_verification_failed")
        return info
    info["valid"] = not errors
    return info
