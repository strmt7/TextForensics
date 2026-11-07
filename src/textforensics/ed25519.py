"""Pure-stdlib Ed25519 (RFC 8032), for sealed case files.

This is a from-RFC implementation of the standard Ed25519 signature
scheme defined in RFC 8032 (Edwards-curve Digital Signature Algorithm,
instantiated on the edwards25519 curve with SHA-512).  It is NOT a custom
curve and NOT a custom signature scheme: the parameters, clamping,
deterministic nonce derivation and verification equation are exactly
those of RFC 8032 section 5.1.  Only the Python standard library is used
(``hashlib`` and ``secrets``), so the forensic core stays dependency-free;
the ``cryptography`` package is an optional extra and is never imported
here.

Security notes:

* This is a straightforward reference implementation, not a
  constant-time one.  It is suitable for signing case files on a local
  machine, but it is not hardened against timing side channels the way
  a vetted C implementation is.
* Private seeds must be kept out of logs, case files and portable
  outputs.  Only the public key (and its fingerprint) is ever published.
"""

from __future__ import annotations

import hashlib
import secrets

# --- RFC 8032 section 5.1.1: modular arithmetic over GF(2**255 - 19). ---

_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
# d = -121665 / 121666 mod q (the Edwards curve parameter).
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
# sqrt(-1) mod q.
_I = pow(2, (_Q - 1) // 4, _Q)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _clamp(digest: bytes) -> int:
    """Clamp the first 32 bytes of a SHA-512 digest (RFC 8032 5.1.5)."""
    clamped = bytearray(digest[:32])
    clamped[0] &= 248
    clamped[31] &= 127
    clamped[31] |= 64
    return int.from_bytes(clamped, "little")


def _x_recover(y: int) -> int:
    """Recover the x-coordinate for a given y (RFC 8032 5.1.3)."""
    xx = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


# Base point B: y = 4/5, x recovered with the even-parity convention.
_BY = (4 * pow(5, _Q - 2, _Q)) % _Q
_BX = _x_recover(_BY)
_BASE_POINT = (_BX, _BY)


def _point_add(point_p: tuple[int, int], point_q: tuple[int, int]) -> tuple[int, int]:
    """Edwards point addition (RFC 8032 5.1.4, complete addition formula)."""
    x1, y1 = point_p
    x2, y2 = point_q
    denom_x = pow(1 + _D * x1 * x2 * y1 * y2, _Q - 2, _Q)
    denom_y = pow(1 - _D * x1 * x2 * y1 * y2, _Q - 2, _Q)
    x3 = (x1 * y2 + x2 * y1) * denom_x % _Q
    # The curve has a = -1, so the y-coordinate numerator is y1*y2 + x1*x2
    # (RFC 8032 section 5.1.4); the minus form belongs to the a = +1 curve.
    y3 = (y1 * y2 + x1 * x2) * denom_y % _Q
    return (x3, y3)


def _scalar_mult(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    """Scalar multiplication by double-and-add (most significant bit first)."""
    result = (0, 1)  # Identity point.
    addend = point
    for bit in bin(scalar)[2:]:
        result = _point_add(result, result)
        if bit == "1":
            result = _point_add(result, addend)
    return result


def _encode_point(point: tuple[int, int]) -> bytes:
    x, y = point
    encoded = y | ((x & 1) << 255)
    return encoded.to_bytes(32, "little")


def _decode_point(encoded: bytes) -> tuple[int, int] | None:
    """Decode a 32-byte compressed point; None when it is not on the curve."""
    if len(encoded) != 32:
        return None
    y = int.from_bytes(encoded, "little") & ((1 << 255) - 1)
    if y >= _Q:
        return None
    x = _x_recover(y)
    if x & 1 != (encoded[31] >> 7):
        x = _Q - x
    if (_y_on_curve(x, y)) is False:
        return None
    return (x, y)


def _y_on_curve(x: int, y: int) -> bool:
    # Curve equation: -x^2 + y^2 = 1 + d*x^2*y^2 (mod q).
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _Q == 0


def _decode_scalar(encoded: bytes) -> int | None:
    """Decode a 32-byte little-endian scalar; None when out of range."""
    if len(encoded) != 32:
        return None
    scalar = int.from_bytes(encoded, "little")
    if scalar >= _L:
        return None
    return scalar


def public_key_from_seed(seed: bytes) -> bytes:
    """Derive the 32-byte Ed25519 public key from a 32-byte seed.

    Raises ``ValueError`` when the seed is not exactly 32 bytes.
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes")
    digest = _sha512(bytes(seed))
    secret_scalar = _clamp(digest)
    return _encode_point(_scalar_mult(_BASE_POINT, secret_scalar))


def sign(seed: bytes, message: bytes) -> bytes:
    """Deterministic RFC 8032 signature (64 bytes) for ``message``.

    Raises ``ValueError`` when the seed is not exactly 32 bytes.
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes")
    if not isinstance(message, (bytes, bytearray)):
        raise ValueError("Ed25519 message must be bytes")
    message = bytes(message)
    digest = _sha512(bytes(seed))
    secret_scalar = _clamp(digest)
    prefix = digest[32:]
    public_key = _encode_point(_scalar_mult(_BASE_POINT, secret_scalar))
    nonce = int.from_bytes(_sha512(prefix + message), "little") % _L
    commitment = _encode_point(_scalar_mult(_BASE_POINT, nonce))
    challenge = int.from_bytes(_sha512(commitment + public_key + message), "little") % _L
    signature_scalar = (nonce + challenge * secret_scalar) % _L
    return commitment + signature_scalar.to_bytes(32, "little")


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature.

    Returns ``False`` (never raises) for any malformed or wrong-length
    input, for a signature that does not verify, and for a public key
    that is not a valid curve point.
    """
    try:
        if (
            not isinstance(public_key, (bytes, bytearray))
            or not isinstance(message, (bytes, bytearray))
            or not isinstance(signature, (bytes, bytearray))
        ):
            return False
        if len(public_key) != 32 or len(signature) != 64:
            return False
        point_a = _decode_point(bytes(public_key))
        if point_a is None:
            return False
        commitment = _decode_point(bytes(signature[:32]))
        if commitment is None:
            return False
        scalar_s = _decode_scalar(bytes(signature[32:]))
        if scalar_s is None:
            return False
        challenge = (
            int.from_bytes(
                _sha512(bytes(signature[:32]) + bytes(public_key) + bytes(message)),
                "little",
            )
            % _L
        )
        left = _scalar_mult(_BASE_POINT, scalar_s)
        right = _point_add(commitment, _scalar_mult(point_a, challenge))
        return left == right
    except Exception:
        return False


def keygen() -> tuple[bytes, bytes]:
    """Generate a fresh (seed, public_key) pair from OS randomness."""
    seed = secrets.token_bytes(32)
    return seed, public_key_from_seed(seed)


def fingerprint(public_key: bytes) -> str:
    """Lowercase hex SHA-256 of the public key bytes (the DSSE keyid)."""
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        raise ValueError("Ed25519 public key must be exactly 32 bytes")
    return hashlib.sha256(bytes(public_key)).hexdigest()
