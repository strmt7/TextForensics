"""DSSE (Dead Simple Signing Envelope) for sealed case files.

Implements the DSSE envelope format as specified at
https://github.com/secure-systems-lab/dsse (``DSSEv1`` pre-authentication
encoding, JSON envelope with ``payloadType``, base64 ``payload`` and a
``signatures`` list).  This module invents no custom signature format:
the only signature scheme used is standard Ed25519 (RFC 8032) from
:mod:`textforensics.ed25519`, and the key identifier is the SHA-256
fingerprint of the Ed25519 public key.

Stdlib only: ``base64`` and ``json``-free (envelopes are plain dicts).
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping
from typing import Any

from .ed25519 import fingerprint, public_key_from_seed, sign, verify

PAYLOAD_TYPE_CASE_FILE = "textforensics.case-file/v3"
PAYLOAD_TYPE_SEALED_BUNDLE_MANIFEST = "textforensics.sealed-bundle-manifest/v1"

_ENVELOPE_FIELDS = frozenset({"payloadType", "payload", "signatures"})
_SIGNATURE_FIELDS = frozenset({"keyid", "sig"})


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE pre-authentication encoding (``DSSEv1``).

    ``DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>``,
    where the lengths are decimal ASCII byte counts.
    """
    if not isinstance(payload_type, str):
        raise ValueError("payload_type must be a string")
    if not isinstance(payload, (bytes, bytearray)):
        raise ValueError("payload must be bytes")
    payload_type_bytes = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(payload_type_bytes)).encode("ascii")
        + b" "
        + payload_type_bytes
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + bytes(payload)
    )


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode_strict(value: Any) -> bytes | None:
    """Decode strict base64; None when the value is not canonical base64."""
    if not isinstance(value, str):
        return None
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        return None
    # Reject malleable encodings: the bytes must re-encode identically.
    if _b64encode(decoded) != value:
        return None
    return decoded


def sign_envelope(payload_type: str, payload: bytes, seed: bytes) -> dict[str, Any]:
    """Sign ``payload`` under ``payload_type``; return a DSSE envelope dict.

    The single signature's ``keyid`` is the Ed25519 public-key fingerprint
    (hex SHA-256 of the public key) of the key derived from ``seed``.
    """
    if not isinstance(payload_type, str) or not payload_type:
        raise ValueError("payload_type must be a non-empty string")
    if not isinstance(payload, (bytes, bytearray)):
        raise ValueError("payload must be bytes")
    public_key = public_key_from_seed(seed)
    signature = sign(seed, pae(payload_type, bytes(payload)))
    return {
        "payloadType": payload_type,
        "payload": _b64encode(bytes(payload)),
        "signatures": [
            {"keyid": fingerprint(public_key), "sig": _b64encode(signature)},
        ],
    }


def verify_envelope(
    envelope: Any,
    public_key: bytes,
    *,
    expected_payload_type: str | None = None,
) -> dict[str, Any]:
    """Verify a DSSE envelope against ``public_key``.

    Never raises for a malformed envelope: every problem is reported in
    ``errors`` and ``valid`` is False.  Returns ``{"valid", "errors",
    "payload", "keyid"}``; ``payload`` is the decoded payload bytes only
    when the envelope fully verifies, otherwise None.
    """
    errors: list[str] = []
    keyid: str | None = None

    def _fail(message: str) -> dict[str, Any]:
        errors.append(message)
        return {"valid": False, "errors": errors, "payload": None, "keyid": keyid}

    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        return _fail("public key must be exactly 32 bytes")
    expected_keyid = fingerprint(bytes(public_key))

    if not isinstance(envelope, Mapping):
        return _fail("envelope must be a mapping")
    if set(envelope.keys()) != _ENVELOPE_FIELDS:
        return _fail("envelope must have exactly the fields payloadType, payload and signatures")

    payload_type = envelope["payloadType"]
    if not isinstance(payload_type, str) or not payload_type:
        return _fail("payloadType must be a non-empty string")
    if expected_payload_type is not None and payload_type != expected_payload_type:
        return _fail(
            f"payloadType {payload_type!r} does not match expected {expected_payload_type!r}"
        )

    payload = _b64decode_strict(envelope["payload"])
    if payload is None:
        return _fail("payload is not canonical base64")

    signatures = envelope["signatures"]
    if not isinstance(signatures, list) or len(signatures) != 1:
        return _fail("envelope must contain exactly one signature")
    signature_entry = signatures[0]
    if not isinstance(signature_entry, Mapping):
        return _fail("signature entry must be a mapping")
    if set(signature_entry.keys()) != _SIGNATURE_FIELDS:
        return _fail("signature entry must have exactly the fields keyid and sig")
    if not isinstance(signature_entry["keyid"], str):
        return _fail("signature keyid must be a string")
    keyid = signature_entry["keyid"]
    if keyid != expected_keyid:
        return _fail("signature keyid does not match the supplied public key")

    signature = _b64decode_strict(signature_entry["sig"])
    if signature is None:
        return _fail("signature is not canonical base64")
    if len(signature) != 64:
        return _fail("signature must be exactly 64 bytes")

    if not verify(bytes(public_key), pae(payload_type, payload), signature):
        return _fail("Ed25519 signature does not verify over the PAE")

    return {"valid": True, "errors": [], "payload": payload, "keyid": keyid}
