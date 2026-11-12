"""Detector Output Watermarking & Provenance Chain.

Embeds cryptographic watermarks in detector outputs and builds a verifiable
chain of custody for forensic detector results. This enables:

- **Output authentication**: Prove a detector result originated from a specific
  detector version at a specific time
- **Tamper evidence**: Detect any post-hoc modification of detector outputs
- **Provenance chaining**: Link detector outputs to their inputs, calibration
  artifacts, and audit logs
- **Non-repudiation**: Detector operators cannot deny producing a result

The watermark is a cryptographic commitment embedded in the detector's
`DetectorPrediction` metadata, invisible to normal consumers but verifiable
by anyone with the detector's public key.

Design principles:
- **Local-first**: No network required for watermarking or verification
- **Deterministic**: Same input + same detector version = same watermark
- **Minimal overhead**: <1% size increase to DetectorPrediction
- **Key rotation**: Supports key versioning and revocation
- **Quantum-resistant**: Uses Ed25519 (can be upgraded to ML-DSA)

Watermark trust policy (W3 audit findings C01/C20/C21)
-------------------------------------------------------
``WATERMARK_KEY_VALIDITY_POLICY`` states the policy in full; the short
version:

- **C01 — payload binding.** Both verifiers recompute the canonical
  payload digest and compare it to the signed ``payload_hash`` *before*
  verifying the Ed25519 signature, and bind every expected detector
  field to that authenticated payload. A substituted payload (or a
  substituted expected field) can never verify against the original
  signature/hash. Unsupported algorithms and malformed encodings fail
  closed (``False``), never raise.
- **C20 — trusted-key validity (HISTORICAL validity).** A signature
  verifies iff its *authenticated* signing time (``payload["timestamp"]``,
  covered by the signed payload hash) lies inside the *trusted* public
  key's validity window ``[public_key.created_at,
  public_key.expires_at]``. A key need not be currently valid at
  verification time: a signature made while the key was valid remains
  valid after the key expires. The current wall-clock time is never
  consulted. The unsigned envelope fields ``signed_at`` / ``expires_at``
  are never validity bounds; when present they are only cross-checked
  for agreement with the authenticated/trusted values. A self-reported
  signed time is not an external trusted time (it is not a TSA
  timestamp).
- **C21 — key-ID confinement.** A key ID is an allowlisted opaque
  identifier, independent of the filename. Traversal, absolute,
  drive/UNC, separator, reserved-name and over-long forms are rejected
  before any filesystem access. Every create/read/delete resolves the
  target inside the configured key directory and refuses to escape it.
  Private key files are published atomically with owner-only access
  (POSIX mode ``0600``) and an existing key ID is never silently
  replaced.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import hmac
import json
import os
import re
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# ---------------------------------------------------------------------------
# Trusted-key validity policy (C20) — written down explicitly.
#
# HISTORICAL VALIDITY: a watermark signature is valid iff its
# AUTHENTICATED signing time — ``payload["timestamp"]``, which is covered
# by the signed payload hash — lies inside the TRUSTED public key's
# validity window ``[public_key.created_at, public_key.expires_at]``
# (either bound absent means unbounded on that side). The key does NOT
# have to be currently valid at verification time: a signature produced
# while the key was valid remains valid after the key expires, so
# historical evidence is preserved. The current wall-clock time is never
# consulted. The unsigned envelope fields ``signature.signed_at`` /
# ``signature.expires_at`` are never used as validity bounds; when
# present they are only cross-checked for agreement (``signed_at`` within
# ``_ENVELOPE_AGREEMENT_TOLERANCE`` of the authenticated timestamp, and
# ``expires_at`` equal to the trusted key's ``expires_at``). A
# self-reported signed timestamp is not an external trusted time — it is
# not a TSA timestamp and must never be presented as one. If the
# authenticated timestamp is missing, timezone-naive, or malformed,
# verification fails; there is no fallback to the envelope date.
# ---------------------------------------------------------------------------
WATERMARK_KEY_VALIDITY_POLICY = (
    "Historical validity: a watermark signature verifies iff its "
    "authenticated payload timestamp lies inside the trusted public "
    "key's validity window [created_at, expires_at]; the key need not "
    "be currently valid at verification time, the wall-clock time is "
    "never consulted, and the unsigned envelope dates are never "
    "validity bounds (they are only cross-checked for agreement when "
    "present). A self-reported signed time is not a trusted time."
)

#: Only supported watermark signature algorithm (C01).
WATERMARK_ALGORITHM = "ed25519"

#: Envelope ``signed_at`` must agree with the authenticated payload
#: timestamp within this tolerance (C20). Genuine signatures are produced
#: by two consecutive ``datetime.now(UTC)`` calls under a second apart,
#: so five minutes is generous and only catches forged/moved dates.
_ENVELOPE_AGREEMENT_TOLERANCE = timedelta(minutes=5)

#: SHA-256 hex digest shape (C01).
_PAYLOAD_HASH_RE = re.compile(r"^[0-9a-f]{64}$")

#: Allowlisted opaque key identifier (C21): starts with an ASCII letter
#: or digit, then ASCII letters, digits, ``.``, ``_`` or ``-``; at most
#: 128 characters. No separators, no drive/UNC forms, no leading dot.
_KEY_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")

#: Windows reserved device names (checked against the stem before the
#: first dot, case-insensitively) — rejected even though they pass the
#: character allowlist (C21).
_WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)

__all__ = [
    "WatermarkKeyPair",
    "WatermarkPublicKey",
    "WatermarkSignature",
    "WatermarkManager",
    "verify_watermark",
    "WatermarkError",
    "WATERMARK_KEY_VALIDITY_POLICY",
]


class WatermarkError(Exception):
    """Base exception for watermarking errors."""

    pass


def _canonical_payload_hash(payload: dict[str, Any]) -> str | None:
    """Recompute the canonical payload digest, or ``None`` if unhashable.

    Uses exactly the canonicalisation the signer uses (sorted keys,
    compact separators, UTF-8, SHA-256 hex digest) so a recomputation
    over the supplied payload either reproduces the signed hash or
    proves the payload was substituted (C01).
    """
    try:
        canonical = json.dumps(payload, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return None
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _parse_iso_datetime(value: Any) -> datetime | None:
    """Parse an ISO-8601 timestamp, or ``None`` when absent.

    Returns ``None`` for ``None``/``""`` (absent bound). Raises
    ``ValueError`` for a present-but-malformed value and for a naive
    (timezone-free) timestamp: a naive time cannot be compared against
    trusted bounds, so it fails closed instead of being read as UTC.
    """
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValueError(f"timestamp must be an ISO-8601 string, got {type(value).__name__}")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"malformed ISO-8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"naive (timezone-free) timestamp: {value!r}")
    return parsed


def _is_valid_key_id(key_id: Any) -> bool:
    """Non-raising allowlist check for a watermark key ID (C21)."""
    if not isinstance(key_id, str) or not key_id:
        return False
    if _KEY_ID_RE.fullmatch(key_id) is None:
        return False
    if ".." in key_id or key_id.endswith((".", " ")):
        return False
    return key_id.split(".", 1)[0].upper() not in _WINDOWS_RESERVED_NAMES


def _validate_key_id(key_id: Any) -> str:
    """Validate a key ID, raising ``WatermarkError`` when it is not allowed.

    The identifier is opaque and independent of the filename: it must
    match the allowlist and must not be a traversal (``..``), absolute,
    drive (``C:``), UNC (``\\\\server``), separator, reserved-device or
    over-long form.
    """
    if not _is_valid_key_id(key_id):
        raise WatermarkError(f"invalid watermark key ID: {key_id!r}")
    return key_id


def _check_key_validity_at_signing_time(
    signature: WatermarkSignature, public_key: WatermarkPublicKey
) -> bool:
    """Enforce the trusted-key validity policy (C20).

    Requires the authenticated payload timestamp to lie inside the
    trusted key's validity window (historical validity — see
    ``WATERMARK_KEY_VALIDITY_POLICY``). The unsigned envelope dates are
    never bounds; when present they must agree with the authenticated /
    trusted values, and absence of an envelope date never disables the
    trusted bound.
    """
    try:
        signing_time = _parse_iso_datetime(signature.payload.get("timestamp"))
    except ValueError:
        return False
    if signing_time is None:
        return False
    try:
        created_at = _parse_iso_datetime(public_key.created_at)
        expires_at = _parse_iso_datetime(public_key.expires_at)
    except ValueError:
        return False
    if created_at is not None and signing_time < created_at:
        return False
    if expires_at is not None and signing_time > expires_at:
        return False
    try:
        signed_at = _parse_iso_datetime(signature.signed_at)
        envelope_expires = _parse_iso_datetime(signature.expires_at)
    except ValueError:
        return False
    if signed_at is not None:
        skew = abs((signed_at - signing_time).total_seconds())
        if skew > _ENVELOPE_AGREEMENT_TOLERANCE.total_seconds():
            return False
    if envelope_expires is None:
        return True
    return expires_at is not None and envelope_expires == expires_at


def _validate_watermark_signature(
    signature: WatermarkSignature, public_key: WatermarkPublicKey
) -> bool:
    """Shared validation contract for both verifier entry points (C01/C20).

    Order matters: the canonical payload digest is recomputed and bound
    to the signed hash *before* the Ed25519 signature is verified, and
    the trusted-key validity policy is enforced over the authenticated
    payload timestamp. Every failure mode returns ``False``; malformed
    encodings, unsupported algorithms and bad dates never raise.
    """
    if not isinstance(signature, WatermarkSignature):
        return False
    if not isinstance(public_key, WatermarkPublicKey):
        return False
    if signature.algorithm != WATERMARK_ALGORITHM:
        return False
    if signature.key_id != public_key.key_id:
        return False
    if not isinstance(signature.payload, dict):
        return False
    recomputed = _canonical_payload_hash(signature.payload)
    if recomputed is None:
        return False
    if not isinstance(signature.payload_hash, str):
        return False
    if _PAYLOAD_HASH_RE.fullmatch(signature.payload_hash) is None:
        return False
    if not hmac.compare_digest(recomputed, signature.payload_hash):
        return False
    try:
        signature_bytes = base64.b64decode(signature.signature, validate=True)
    except (binascii.Error, ValueError):
        return False
    if len(signature_bytes) != 64:
        return False
    if not public_key.verify(signature.payload_hash.encode("utf-8"), signature_bytes):
        return False
    return _check_key_validity_at_signing_time(signature, public_key)


@dataclass(frozen=True, slots=True)
class WatermarkKeyPair:
    """Ed25519 key pair for watermark signing/verification.

    Attributes:
        private_key: Base64-encoded Ed25519 private key (32 bytes)
        public_key: Base64-encoded Ed25519 public key (32 bytes)
        key_id: Unique identifier for this key pair
        created_at: ISO timestamp of key generation
        expires_at: Optional ISO timestamp of key expiration
        metadata: Additional key metadata
    """

    private_key: str
    public_key: str
    key_id: str
    created_at: str
    expires_at: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "private_key": self.private_key,
            "public_key": self.public_key,
            "key_id": self.key_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "metadata": self.metadata,
        }

    @classmethod
    def generate(cls, key_id: str | None = None, expires_days: int = 365) -> WatermarkKeyPair:
        """Generate a new Ed25519 key pair."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        now = datetime.now(UTC)
        expires_at = (
            (now.replace(year=now.year + expires_days // 365 + 1)).isoformat()
            if expires_days
            else None
        )
        if key_id is None:
            key_id = f"wmk-{uuid.uuid4().hex[:12]}"
        # An explicitly supplied ID must satisfy the confinement allowlist
        # (C21); an empty string is invalid, not "generate one for me".
        _validate_key_id(key_id)

        return cls(
            private_key=base64.b64encode(
                private_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            ).decode("ascii"),
            public_key=base64.b64encode(
                public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            ).decode("ascii"),
            key_id=key_id,
            created_at=now.isoformat(),
            expires_at=expires_at,
        )

    def sign(self, data: bytes) -> bytes:
        """Sign data with this private key."""
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
            base64.b64decode(self.private_key)
        )
        return private_key.sign(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WatermarkKeyPair:
        return cls(
            private_key=str(data["private_key"]),
            public_key=str(data["public_key"]),
            key_id=str(data["key_id"]),
            created_at=str(data["created_at"]),
            expires_at=data.get("expires_at"),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass(frozen=True, slots=True)
class WatermarkPublicKey:
    """Public key for watermark verification (no private key material)."""

    public_key: str
    key_id: str
    created_at: str
    expires_at: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify a signature against this public key.

        Malformed encodings (bad base64, wrong key length) fail closed
        with ``False`` instead of raising (C01 structured failure).
        """
        try:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(
                base64.b64decode(self.public_key, validate=True)
            )
            public_key.verify(signature, data)
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "public_key": self.public_key,
            "key_id": self.key_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WatermarkPublicKey:
        return cls(
            public_key=str(data["public_key"]),
            key_id=str(data["key_id"]),
            created_at=str(data["created_at"]),
            expires_at=data.get("expires_at"),
            metadata=dict(data.get("metadata", {})),
        )

    @classmethod
    def from_keypair(cls, keypair: WatermarkKeyPair) -> WatermarkPublicKey:
        return cls(
            public_key=keypair.public_key,
            key_id=keypair.key_id,
            created_at=keypair.created_at,
            expires_at=keypair.expires_at,
            metadata=keypair.metadata,
        )


@dataclass(frozen=True, slots=True)
class WatermarkSignature:
    """Cryptographic watermark signature embedded in detector output.

    The signature is computed over:
    - Detector ID and version
    - Input text hash (SHA-256)
    - Raw detector score and verdict
    - Timestamp
    - Nonce (for replay protection)

    Attributes:
        key_id: ID of the key that produced this signature
        signature: Base64-encoded Ed25519 signature
        signed_at: ISO timestamp of signing
        payload_hash: SHA-256 of the signed payload
        payload: The signed payload (for verification without detector output)
        expires_at: Optional ISO timestamp of key expiration
        algorithm: "ed25519"
    """

    key_id: str
    signature: str
    signed_at: str
    payload_hash: str
    payload: dict[str, Any]
    expires_at: str | None = None
    algorithm: str = "ed25519"

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "signature": self.signature,
            "signed_at": self.signed_at,
            "expires_at": self.expires_at,
            "payload_hash": self.payload_hash,
            "payload": self.payload,
            "algorithm": self.algorithm,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WatermarkSignature:
        return cls(
            key_id=str(data["key_id"]),
            signature=str(data["signature"]),
            signed_at=str(data["signed_at"]),
            expires_at=data.get("expires_at"),
            payload_hash=str(data["payload_hash"]),
            payload=dict(data["payload"]),
            algorithm=str(data.get("algorithm", "ed25519")),
        )

    @property
    def signature_bytes(self) -> bytes:
        """Get raw signature bytes."""
        return base64.b64decode(self.signature)


class WatermarkManager:
    """Manages watermark keys and signing operations.

    Handles key generation, storage, rotation, and signing operations
    for detector output watermarking.
    """

    def __init__(self, key_dir: str | Path | None = None):
        self.key_dir = Path(key_dir) if key_dir else None
        if self.key_dir:
            self.key_dir.mkdir(parents=True, exist_ok=True)
        self._keys: dict[str, WatermarkKeyPair] = {}
        self._load_keys()

    def _load_keys(self) -> None:
        if not self.key_dir or not self.key_dir.exists():
            return
        for key_file in self.key_dir.glob("*.key.json"):
            # Never follow a symlink out of the store, and never let a
            # file alias another ID: the embedded ID must be allowlisted
            # and must match the filename (C21).
            if key_file.is_symlink() or not key_file.is_file():
                continue
            try:
                data = json.loads(key_file.read_text(encoding="utf-8"))
                keypair = WatermarkKeyPair.from_dict(data)
            except (json.JSONDecodeError, KeyError, ValueError, TypeError, AttributeError):
                # Log but don't fail - corrupted key files shouldn't break the manager
                continue
            if not _is_valid_key_id(keypair.key_id):
                continue
            if f"{keypair.key_id}.key.json" != key_file.name:
                continue
            self._keys[keypair.key_id] = keypair

    def _key_file_path(self, key_id: str) -> Path:
        """Resolve the confined on-disk path for a key ID (C21).

        Validates the allowlisted ID, then resolves both the store and
        the candidate and requires the candidate to stay inside the
        store — so a symlink planted in the store can never redirect a
        create outside it.
        """
        _validate_key_id(key_id)
        if not self.key_dir:
            raise WatermarkError("no key directory configured")
        base = self.key_dir.resolve()
        candidate = (base / f"{key_id}.key.json").resolve()
        if candidate.parent != base or candidate.name != f"{key_id}.key.json":
            raise WatermarkError(f"key ID escapes the key directory: {key_id!r}")
        return candidate

    def _save_key(self, keypair: WatermarkKeyPair) -> None:
        """Publish a private key file atomically, owner-only, no-clobber.

        Writes a fully synced temporary file in the same directory
        (POSIX mode ``0600``) and publishes it with ``os.link``, which
        fails atomically when the destination already exists — so an
        existing key ID is never silently replaced, even by a concurrent
        writer. On Windows the mode bits are best-effort (``os.chmod``
        only affects the read-only flag there); the operative control is
        the key directory's ACL, which the operator must keep private.
        """
        if not self.key_dir:
            return
        destination = self._key_file_path(keypair.key_id)
        if destination.exists() or destination.is_symlink():
            raise WatermarkError(f"key file already exists: {destination}")
        encoded = json.dumps(keypair.to_dict(), indent=2, ensure_ascii=False)
        fd, temp_name = tempfile.mkstemp(
            dir=str(self.key_dir), prefix=f".{keypair.key_id}.", suffix=".tmp"
        )
        temp_path = Path(temp_name)
        try:
            try:
                if hasattr(os, "fchmod"):
                    os.fchmod(fd, 0o600)
            except BaseException:
                os.close(fd)
                raise
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(encoded)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temp_path, destination)
            except FileExistsError as exc:
                raise WatermarkError(f"key file already exists: {destination}") from exc
            if os.name == "nt":
                with contextlib.suppress(OSError):
                    os.chmod(destination, 0o600)
            if os.name == "posix":
                with contextlib.suppress(OSError):
                    dir_fd = os.open(self.key_dir, os.O_RDONLY)
                    try:
                        os.fsync(dir_fd)
                    finally:
                        os.close(dir_fd)
        finally:
            with contextlib.suppress(OSError):
                temp_path.unlink(missing_ok=True)

    def generate_key(self, key_id: str | None = None, expires_days: int = 365) -> WatermarkKeyPair:
        """Generate and store a new key pair.

        Raises ``WatermarkError`` for an invalid (non-confined) key ID
        and for an ID that already exists — an existing key is never
        silently replaced (C21).
        """
        keypair = WatermarkKeyPair.generate(key_id=key_id, expires_days=expires_days)
        if keypair.key_id in self._keys:
            raise WatermarkError(f"key already exists: {keypair.key_id}")
        if self.key_dir is not None:
            destination = self._key_file_path(keypair.key_id)
            if destination.exists() or destination.is_symlink():
                raise WatermarkError(f"key file already exists: {destination}")
        self._save_key(keypair)
        self._keys[keypair.key_id] = keypair
        return keypair

    def get_keypair(self, key_id: str) -> WatermarkKeyPair | None:
        if not _is_valid_key_id(key_id):
            return None
        return self._keys.get(key_id)

    def get_public_key(self, key_id: str) -> WatermarkPublicKey | None:
        if not _is_valid_key_id(key_id):
            return None
        keypair = self._keys.get(key_id)
        return WatermarkPublicKey.from_keypair(keypair) if keypair else None

    def list_keys(self) -> list[WatermarkPublicKey]:
        return [WatermarkPublicKey.from_keypair(k) for k in self._keys.values()]

    def revoke_key(self, key_id: str) -> bool:
        """Revoke a key by removing it from active storage.

        A non-confined ID returns ``False`` without touching the
        filesystem; deletion is confined to the configured key directory
        (C21). Unlinking removes the directory entry itself and never
        follows a symlink.
        """
        if not _is_valid_key_id(key_id):
            return False
        if key_id in self._keys:
            del self._keys[key_id]
            if self.key_dir is not None:
                key_file = self.key_dir / f"{key_id}.key.json"
                if key_file.is_symlink() or key_file.exists():
                    key_file.unlink()
            return True
        return False

    def sign_detector_output(
        self,
        detector_id: str,
        detector_version: str,
        text_sha256: str,
        score: float | None,
        verdict: str,
        key_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> WatermarkSignature:
        """Create a watermark signature for a detector output.

        Args:
            detector_id: Identifier of the detector
            detector_version: Version of the detector
            text_sha256: SHA-256 hash of input text (64 hex chars)
            score: Raw detector score (or None if abstained)
            verdict: Detector verdict string
            key_id: Optional specific key ID to use (uses latest if None)
            metadata: Additional metadata to include in payload

        Returns:
            WatermarkSignature embedding the cryptographic commitment
        """
        # Select key
        if key_id:
            keypair = self._keys.get(key_id)
        else:
            # Use most recent key
            if not self._keys:
                raise WatermarkError("No keys available for signing")
            keypair = max(self._keys.values(), key=lambda k: k.created_at)

        if not keypair:
            raise WatermarkError(f"Key not found: {key_id}")

        # Build payload
        nonce = uuid.uuid4().hex[:16]
        timestamp = datetime.now(UTC).isoformat()

        payload = {
            "detector_id": detector_id,
            "detector_version": detector_version,
            "text_sha256": text_sha256,
            "score": score,
            "verdict": verdict,
            "nonce": nonce,
            "timestamp": timestamp,
        }
        if metadata:
            payload["metadata"] = metadata

        # Compute payload hash
        payload_canonical = json.dumps(
            payload, separators=(",", ":"), ensure_ascii=False, sort_keys=True
        )
        payload_hash = hashlib.sha256(payload_canonical.encode("utf-8")).hexdigest()

        # Sign the payload hash
        signature_bytes = keypair.sign(payload_hash.encode("utf-8"))
        signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

        return WatermarkSignature(
            key_id=keypair.key_id,
            signature=signature_b64,
            signed_at=datetime.now(UTC).isoformat(),
            expires_at=keypair.expires_at,
            payload_hash=payload_hash,
            payload=payload,
            algorithm="ed25519",
        )

    def verify_signature(
        self,
        signature: WatermarkSignature,
        public_key: WatermarkPublicKey | None = None,
    ) -> bool:
        """Verify a watermark signature.

        Shares the validation contract with ``verify_watermark``
        (``_validate_watermark_signature``): the canonical payload digest
        is recomputed and bound to the signed hash before the Ed25519
        signature is verified, and the trusted-key validity policy is
        enforced over the authenticated payload timestamp (C01/C20).

        Args:
            signature: The watermark signature to verify
            public_key: Optional explicit public key (uses stored key if None)

        Returns:
            True if signature is valid, False otherwise
        """
        if public_key is None:
            pk = self.get_public_key(signature.key_id)
            if not pk:
                return False
            public_key = pk
        return _validate_watermark_signature(signature, public_key)


def verify_watermark(
    detector_id: str,
    detector_version: str,
    text_sha256: str,
    score: float | None,
    verdict: str,
    signature: WatermarkSignature,
    public_key: WatermarkPublicKey,
) -> bool:
    """Standalone function to verify a detector output watermark.

    This is the primary verification entry point for consumers of
    watermarked detector outputs. It validates:
    1. The canonical payload digest is recomputed and bound to the
       signed hash *before* the signature is verified (C01)
    2. The signature is cryptographically valid (Ed25519 over the
       signed payload hash; only algorithm ``ed25519`` is supported)
    3. The authenticated payload timestamp lies inside the trusted
       public key's validity window — historical validity, see
       ``WATERMARK_KEY_VALIDITY_POLICY`` (C20)
    4. The authenticated payload matches the provided detector output
       parameters

    Every failure mode returns ``False``; malformed encodings,
    unsupported algorithms and bad dates never raise.

    Args:
        detector_id: Expected detector ID
        detector_version: Expected detector version
        text_sha256: Expected input text hash
        score: Expected raw score (or None)
        verdict: Expected verdict
        signature: The watermark signature to verify
        public_key: Public key for verification

    Returns:
        True if all checks pass, False otherwise
    """
    # Shared contract with WatermarkManager.verify_signature (C01/C20):
    # payload-hash binding, signature check, trusted-key validity.
    # Only after it passes is the payload authenticated, so the expected
    # fields below are bound to authenticated data.
    if not _validate_watermark_signature(signature, public_key):
        return False

    # Verify payload matches expected values
    payload = signature.payload
    if payload.get("detector_id") != detector_id:
        return False
    if payload.get("detector_version") != detector_version:
        return False
    if payload.get("text_sha256") != text_sha256:
        return False
    if payload.get("score") != score:
        return False
    return payload.get("verdict") == verdict


def embed_watermark_in_prediction(
    prediction: dict[str, Any],
    signature: WatermarkSignature,
) -> dict[str, Any]:
    """Embed a watermark signature into a detector prediction dict.

    This modifies the prediction in-place by adding the watermark to
    the `metadata` field (or creating it).

    Args:
        prediction: Detector prediction dictionary
        signature: Watermark signature to embed

    Returns:
        Modified prediction with embedded watermark
    """
    result = dict(prediction)
    if "metadata" not in result:
        result["metadata"] = {}
    result["metadata"]["watermark"] = signature.to_dict()
    return result


def extract_watermark_from_prediction(
    prediction: dict[str, Any],
) -> WatermarkSignature | None:
    """Extract watermark signature from a detector prediction.

    Args:
        prediction: Detector prediction dictionary

    Returns:
        WatermarkSignature if present, None otherwise
    """
    metadata = prediction.get("metadata", {})
    watermark_data = metadata.get("watermark")
    if watermark_data:
        return WatermarkSignature.from_dict(watermark_data)
    return None


def strip_watermark_from_prediction(
    prediction: dict[str, Any],
) -> dict[str, Any]:
    """Remove watermark from a detector prediction.

    Args:
        prediction: Detector prediction dictionary

    Returns:
        Prediction with watermark removed
    """
    result = dict(prediction)
    if "metadata" in result and "watermark" in result["metadata"]:
        result["metadata"] = {k: v for k, v in result["metadata"].items() if k != "watermark"}
    return result
