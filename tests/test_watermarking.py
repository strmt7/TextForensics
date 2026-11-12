"""Tests for Detector Output Watermarking & Provenance Chain."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import tempfile
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from textforensics.watermarking import (
    WatermarkError,
    WatermarkKeyPair,
    WatermarkManager,
    WatermarkPublicKey,
    WatermarkSignature,
    embed_watermark_in_prediction,
    extract_watermark_from_prediction,
    strip_watermark_from_prediction,
    verify_watermark,
)


class TestWatermarkKeyPair:
    def test_key_generation(self):
        """Key pair generation should produce valid Ed25519 keys."""
        keypair = WatermarkKeyPair.generate()
        assert len(keypair.key_id) > 0
        assert keypair.private_key
        assert keypair.public_key
        # Verify keys are valid base64
        assert base64.b64decode(keypair.private_key)
        assert base64.b64decode(keypair.public_key)
        assert len(base64.b64decode(keypair.private_key)) == 32
        assert len(base64.b64decode(keypair.public_key)) == 32

    def test_key_with_custom_id(self):
        """Key generation with custom ID."""
        keypair = WatermarkKeyPair.generate(key_id="my-custom-key")
        assert keypair.key_id == "my-custom-key"

    def test_key_with_expiration(self):
        """Key generation with custom expiration."""
        keypair = WatermarkKeyPair.generate(expires_days=30)
        assert keypair.expires_at is not None

    def test_sign_and_verify(self):
        """Signing and verification should work correctly."""
        keypair = WatermarkKeyPair.generate()
        data = b"test data to sign"
        signature = keypair.sign(data)

        pk = WatermarkPublicKey.from_keypair(keypair)
        assert pk.verify(data, signature)

        # Wrong data should fail
        assert not pk.verify(b"wrong data", signature)

    def test_key_roundtrip(self):
        """Key serialization/deserialization should preserve data."""
        keypair = WatermarkKeyPair.generate(key_id="test-key")
        d = keypair.to_dict()
        keypair2 = WatermarkKeyPair.from_dict(d)

        assert keypair2.key_id == keypair.key_id
        assert keypair2.private_key == keypair.private_key
        assert keypair2.public_key == keypair.public_key

    def test_public_key_from_keypair(self):
        """Public key derived from keypair should verify signatures."""
        keypair = WatermarkKeyPair.generate()
        pk = WatermarkPublicKey.from_keypair(keypair)

        data = b"test"
        sig = keypair.sign(data)
        assert pk.verify(data, sig)


class TestWatermarkPublicKey:
    def test_public_key_roundtrip(self):
        """Public key serialization should preserve data."""
        pk = WatermarkPublicKey(
            public_key="a" * 44,  # 32 bytes base64 = 44 chars
            key_id="test-key",
            created_at="2024-01-01T00:00:00+00:00",
            expires_at="2025-01-01T00:00:00+00:00",
        )
        d = pk.to_dict()
        pk2 = WatermarkPublicKey.from_dict(d)
        assert pk2.public_key == pk.public_key
        assert pk2.key_id == pk.key_id

    def test_verify_invalid_signature(self):
        """Invalid signature should be rejected."""
        keypair = WatermarkKeyPair.generate()
        pk = WatermarkPublicKey.from_keypair(keypair)
        assert not pk.verify(b"data", b"invalid signature")


class TestWatermarkSignature:
    def test_signature_creation(self):
        """Watermark signature creation should work."""
        payload = {"detector_id": "test", "score": 0.8}
        payload_hash = "a" * 64
        sig = WatermarkSignature(
            key_id="test-key",
            signature="a" * 88,  # 64 bytes base64 = 88 chars
            signed_at="2024-01-01T00:00:00+00:00",
            payload_hash=payload_hash,
            payload=payload,
        )
        assert sig.signature_bytes  # Should decode without error

    def test_signature_roundtrip(self):
        """Signature serialization should preserve data."""
        sig = WatermarkSignature(
            key_id="test-key",
            signature="a" * 88,
            signed_at="2024-01-01T00:00:00+00:00",
            payload_hash="a" * 64,
            payload={"detector_id": "test"},
        )
        d = sig.to_dict()
        sig2 = WatermarkSignature.from_dict(d)
        assert sig2.key_id == sig.key_id
        assert sig2.signature == sig.signature
        assert sig2.payload == sig.payload


class TestWatermarkManager:
    def test_manager_creation(self):
        """Manager creation should work."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))
            assert len(manager._keys) == 0

    def test_key_generation_and_persistence(self):
        """Keys should persist across manager instances."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            mgr1 = WatermarkManager(path)
            keypair = mgr1.generate_key(key_id="test-key")

            mgr2 = WatermarkManager(path)
            loaded = mgr2.get_keypair("test-key")
            assert loaded is not None
            assert loaded.key_id == keypair.key_id
            assert loaded.private_key == keypair.private_key

    def test_generate_key(self):
        """Key generation should work."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))
            keypair = manager.generate_key(key_id="test", expires_days=30)
            assert keypair.key_id == "test"
            assert keypair.expires_at is not None

    def test_sign_detector_output(self):
        """Signing detector output should work."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))
            manager.generate_key(key_id="test-key")

            signature = manager.sign_detector_output(
                detector_id="test/detector",
                detector_version="1.0",
                text_sha256="a" * 64,
                score=0.8,
                verdict="ai_like",
            )

            assert signature.key_id == "test-key"
            assert signature.payload["detector_id"] == "test/detector"
            assert signature.payload["score"] == 0.8
            assert signature.payload["verdict"] == "ai_like"
            assert signature.payload["nonce"]
            assert len(signature.signature) > 0

    def test_sign_with_metadata(self):
        """Signing with metadata should include it in payload."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))
            manager.generate_key(key_id="test-key")

            signature = manager.sign_detector_output(
                detector_id="test/detector",
                detector_version="1.0",
                text_sha256="a" * 64,
                score=0.8,
                verdict="ai_like",
                metadata={"model": "v1", "threshold": 0.5},
            )

            assert "metadata" in signature.payload
            assert signature.payload["metadata"]["model"] == "v1"

    def test_verify_signature(self):
        """Signature verification should work."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))
            manager.generate_key(key_id="test-key")

            signature = manager.sign_detector_output(
                detector_id="test/detector",
                detector_version="1.0",
                text_sha256="a" * 64,
                score=0.8,
                verdict="ai_like",
            )

            pk = manager.get_public_key("test-key")
            assert manager.verify_signature(signature, pk)

    def test_verify_wrong_key_fails(self):
        """Verification with wrong key should fail."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))
            manager.generate_key(key_id="key1")
            manager.generate_key(key_id="key2")

            signature = manager.sign_detector_output(
                detector_id="test/detector",
                detector_version="1.0",
                text_sha256="a" * 64,
                score=0.8,
                verdict="ai_like",
                key_id="key1",
            )

            pk_wrong = manager.get_public_key("key2")
            assert not manager.verify_signature(signature, pk_wrong)

    def test_verify_payload_mismatch(self):
        """Verification should fail if payload doesn't match."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))
            manager.generate_key(key_id="test-key")

            signature = manager.sign_detector_output(
                detector_id="test/detector",
                detector_version="1.0",
                text_sha256="a" * 64,
                score=0.8,
                verdict="ai_like",
            )

            # Tamper with payload
            signature.payload["score"] = 0.9

            pk = manager.get_public_key("test-key")
            assert not manager.verify_signature(signature, pk)

    def test_verify_signature_tampering(self):
        """Tampered signature should fail verification."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))
            manager.generate_key(key_id="test-key")

            signature = manager.sign_detector_output(
                detector_id="test/detector",
                detector_version="1.0",
                text_sha256="a" * 64,
                score=0.8,
                verdict="ai_like",
            )

            # Tamper with signature
            sig_bytes = base64.b64decode(signature.signature)
            tampered = base64.b64encode(sig_bytes[:-1] + b"x").decode("ascii")
            tampered_signature = WatermarkSignature(
                key_id=signature.key_id,
                signature=tampered,
                signed_at=signature.signed_at,
                expires_at=signature.expires_at,
                payload_hash=signature.payload_hash,
                payload=signature.payload,
                algorithm=signature.algorithm,
            )

            pk = manager.get_public_key("test-key")
            assert not manager.verify_signature(tampered_signature, pk)

    def test_key_revocation(self):
        """Key revocation should work."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))
            manager.generate_key(key_id="test-key")

            assert manager.revoke_key("test-key") is True
            assert manager.get_keypair("test-key") is None
            assert manager.get_public_key("test-key") is None

    def test_revoke_nonexistent_key(self):
        """Revoking nonexistent key should return False."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))
            assert manager.revoke_key("nonexistent") is False


class TestStandaloneVerification:
    def test_verify_watermark_valid(self):
        """Standalone verification should work for valid watermarks."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))
            manager.generate_key(key_id="test-key")

            signature = manager.sign_detector_output(
                detector_id="test/detector",
                detector_version="1.0",
                text_sha256="a" * 64,
                score=0.8,
                verdict="ai_like",
            )

            pk = manager.get_public_key("test-key")
            assert verify_watermark(
                detector_id="test/detector",
                detector_version="1.0",
                text_sha256="a" * 64,
                score=0.8,
                verdict="ai_like",
                signature=signature,
                public_key=pk,
            )

    def test_verify_watermark_wrong_detector(self):
        """Verification should fail for wrong detector ID."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))
            manager.generate_key(key_id="test-key")

            signature = manager.sign_detector_output(
                detector_id="test/detector",
                detector_version="1.0",
                text_sha256="a" * 64,
                score=0.8,
                verdict="ai_like",
            )

            pk = manager.get_public_key("test-key")
            assert not verify_watermark(
                detector_id="other/detector",  # Wrong detector
                detector_version="1.0",
                text_sha256="a" * 64,
                score=0.8,
                verdict="ai_like",
                signature=signature,
                public_key=pk,
            )

    def test_verify_watermark_wrong_score(self):
        """Verification should fail for wrong score."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))
            manager.generate_key(key_id="test-key")

            signature = manager.sign_detector_output(
                detector_id="test/detector",
                detector_version="1.0",
                text_sha256="a" * 64,
                score=0.8,
                verdict="ai_like",
            )

            pk = manager.get_public_key("test-key")
            assert not verify_watermark(
                detector_id="test/detector",
                detector_version="1.0",
                text_sha256="a" * 64,
                score=0.5,  # Wrong score
                verdict="ai_like",
                signature=signature,
                public_key=pk,
            )

    def test_verify_watermark_wrong_verdict(self):
        """Verification should fail for wrong verdict."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))
            manager.generate_key(key_id="test-key")

            signature = manager.sign_detector_output(
                detector_id="test/detector",
                detector_version="1.0",
                text_sha256="a" * 64,
                score=0.8,
                verdict="ai_like",
            )

            pk = manager.get_public_key("test-key")
            assert not verify_watermark(
                detector_id="test/detector",
                detector_version="1.0",
                text_sha256="a" * 64,
                score=0.8,
                verdict="human_like",  # Wrong verdict
                signature=signature,
                public_key=pk,
            )

    def test_verify_watermark_wrong_hash(self):
        """Verification should fail for wrong text hash."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))
            manager.generate_key(key_id="test-key")

            signature = manager.sign_detector_output(
                detector_id="test/detector",
                detector_version="1.0",
                text_sha256="a" * 64,
                score=0.8,
                verdict="ai_like",
            )

            pk = manager.get_public_key("test-key")
            assert not verify_watermark(
                detector_id="test/detector",
                detector_version="1.0",
                text_sha256="b" * 64,  # Wrong hash
                score=0.8,
                verdict="ai_like",
                signature=signature,
                public_key=pk,
            )


class TestWatermarkEmbedding:
    def test_embed_watermark(self):
        """Embedding watermark in prediction should work."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))
            manager.generate_key(key_id="test-key")

            signature = manager.sign_detector_output(
                detector_id="test/detector",
                detector_version="1.0",
                text_sha256="a" * 64,
                score=0.8,
                verdict="ai_like",
            )

            prediction = {
                "schema": "textforensics.detector-result/v1",
                "detector_id": "test/detector",
                "score": 0.8,
                "verdict": "ai_like",
            }

            embedded = embed_watermark_in_prediction(prediction, signature)

            assert "metadata" in embedded
            assert "watermark" in embedded["metadata"]
            assert embedded["metadata"]["watermark"]["key_id"] == "test-key"

    def test_extract_watermark(self):
        """Extracting watermark from prediction should work."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))
            manager.generate_key(key_id="test-key")

            signature = manager.sign_detector_output(
                detector_id="test/detector",
                detector_version="1.0",
                text_sha256="a" * 64,
                score=0.8,
                verdict="ai_like",
            )

            prediction = {
                "schema": "textforensics.detector-result/v1",
                "detector_id": "test/detector",
                "score": 0.8,
                "verdict": "ai_like",
                "metadata": {"watermark": signature.to_dict()},
            }

            extracted = extract_watermark_from_prediction(prediction)
            assert extracted is not None
            assert extracted.key_id == "test-key"
            assert extracted.signature == signature.signature

    def test_extract_nonexistent(self):
        """Extracting from prediction without watermark should return None."""
        prediction = {"score": 0.8, "verdict": "ai_like"}
        extracted = extract_watermark_from_prediction(prediction)
        assert extracted is None

    def test_strip_watermark(self):
        """Stripping watermark should remove it."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))
            manager.generate_key(key_id="test-key")

            signature = manager.sign_detector_output(
                detector_id="test/detector",
                detector_version="1.0",
                text_sha256="a" * 64,
                score=0.8,
                verdict="ai_like",
            )

            prediction = {
                "score": 0.8,
                "verdict": "ai_like",
                "metadata": {"watermark": signature.to_dict(), "other": "data"},
            }

            stripped = strip_watermark_from_prediction(prediction)

            assert "watermark" not in stripped.get("metadata", {})
            assert stripped["metadata"]["other"] == "data"

    def test_strip_nonexistent(self):
        """Stripping from prediction without watermark should work."""
        prediction = {"score": 0.8}
        stripped = strip_watermark_from_prediction(prediction)
        assert stripped == prediction


class TestWatermarkKeyPairPersistence:
    def test_key_persistence_across_managers(self):
        """Keys should persist when reloading manager."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)

            mgr1 = WatermarkManager(path)
            kp1 = mgr1.generate_key(key_id="persist-key")

            mgr2 = WatermarkManager(path)
            kp2 = mgr2.get_keypair("persist-key")

            assert kp2 is not None
            assert kp2.key_id == kp1.key_id
            assert kp2.private_key == kp1.private_key
            assert kp2.public_key == kp1.public_key

    def test_multiple_keys(self):
        """Manager should handle multiple keys."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))

            manager.generate_key(key_id="key1")
            manager.generate_key(key_id="key2")

            assert len(manager._keys) == 2
            keys = manager.list_keys()
            assert len(keys) == 2
            assert {k.key_id for k in keys} == {"key1", "key2"}

    def test_key_expiration_not_loaded(self):
        """Expired keys should still load but can be checked."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            mgr1 = WatermarkManager(path)
            mgr1.generate_key(key_id="expired-key", expires_days=-1)  # Expired yesterday

            mgr2 = WatermarkManager(path)
            keypair = mgr2.get_keypair("expired-key")

            assert keypair is not None
            assert keypair.expires_at is not None


def _make_manager_and_signature(tmp, *, score=0.2, verdict="human_like", metadata=None):
    """Build a manager, a genuine signature and its public key (synthetic)."""
    manager = WatermarkManager(Path(tmp))
    manager.generate_key(key_id="test-key")
    signature = manager.sign_detector_output(
        detector_id="test/detector",
        detector_version="1.0",
        text_sha256="a" * 64,
        score=score,
        verdict=verdict,
        metadata=metadata,
    )
    return manager, signature, manager.get_public_key("test-key")


def _verify_both(
    manager,
    signature,
    pk,
    *,
    detector_id="test/detector",
    detector_version="1.0",
    text_sha256="a" * 64,
    score=0.2,
    verdict="human_like",
):
    """Run both public verifier entry points with the given expected fields."""
    primary = verify_watermark(
        detector_id=detector_id,
        detector_version=detector_version,
        text_sha256=text_sha256,
        score=score,
        verdict=verdict,
        signature=signature,
        public_key=pk,
    )
    manager_result = manager.verify_signature(signature, pk)
    return primary, manager_result


def _handcraft_signature(
    keypair,
    *,
    timestamp,
    signed_at=None,
    expires_at=None,
    algorithm="ed25519",
    key_id=None,
    payload_overrides=None,
):
    """Build a genuine Ed25519 signature over a caller-chosen payload.

    Unlike ``sign_detector_output`` (which always stamps ``now``), this
    lets tests place the authenticated payload timestamp in the past so
    the historical-validity policy can be exercised honestly.
    """
    payload = {
        "detector_id": "test/detector",
        "detector_version": "1.0",
        "text_sha256": "a" * 64,
        "score": 0.2,
        "verdict": "human_like",
        "nonce": "0123456789abcdef",
        "timestamp": timestamp,
    }
    if payload_overrides:
        payload.update(payload_overrides)
    canonical = json.dumps(payload, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
    payload_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    signature_bytes = keypair.sign(payload_hash.encode("utf-8"))
    return WatermarkSignature(
        key_id=key_id if key_id is not None else keypair.key_id,
        signature=base64.b64encode(signature_bytes).decode("ascii"),
        signed_at=signed_at if signed_at is not None else timestamp,
        expires_at=expires_at,
        payload_hash=payload_hash,
        payload=payload,
        algorithm=algorithm,
    )


def _public_key_with_bounds(pk, *, created_at, expires_at):
    return WatermarkPublicKey(
        public_key=pk.public_key,
        key_id=pk.key_id,
        created_at=created_at,
        expires_at=expires_at,
        metadata=dict(pk.metadata),
    )


class TestWatermarkPayloadBinding:
    """C01: the signed payload digest must bind the displayed payload.

    The primary verifier used to check the signature over the supplied
    ``payload_hash`` and then compare expected fields against the supplied
    ``payload`` without ever establishing that the payload hashes to the
    signed hash. Mutating the payload (and the expected fields together)
    while preserving the original signature/hash must reject in BOTH
    verifiers; the untouched control must succeed in both.
    """

    def test_primary_rejects_substituted_payload_with_matching_expected_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager, signature, pk = _make_manager_and_signature(tmp)
            tampered = replace(
                signature,
                payload={**signature.payload, "score": 0.99, "verdict": "ai_like"},
            )
            primary, manager_result = _verify_both(
                manager, tampered, pk, score=0.99, verdict="ai_like"
            )
            assert primary is False
            assert manager_result is False

    @pytest.mark.parametrize(
        "field,value",
        [
            ("detector_id", "other/detector"),
            ("detector_version", "2.0"),
            ("text_sha256", "b" * 64),
            ("score", 0.99),
            ("verdict", "ai_like"),
        ],
    )
    def test_mutated_authenticated_field_rejected_by_both(self, field, value):
        with tempfile.TemporaryDirectory() as tmp:
            manager, signature, pk = _make_manager_and_signature(tmp)
            tampered = replace(signature, payload={**signature.payload, field: value})
            expected = {"score": 0.2, "verdict": "human_like"}
            expected[field] = value
            primary, manager_result = _verify_both(manager, tampered, pk, **expected)
            assert primary is False
            assert manager_result is False

    def test_metadata_mutation_rejected_by_both(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager, signature, pk = _make_manager_and_signature(tmp, metadata={"model": "v1"})
            tampered = replace(
                signature,
                payload={**signature.payload, "metadata": {"model": "v2"}},
            )
            primary, manager_result = _verify_both(manager, tampered, pk)
            assert primary is False
            assert manager_result is False

    def test_added_metadata_rejected_by_both(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager, signature, pk = _make_manager_and_signature(tmp)
            assert "metadata" not in signature.payload
            tampered = replace(
                signature,
                payload={**signature.payload, "metadata": {"model": "v1"}},
            )
            primary, manager_result = _verify_both(manager, tampered, pk)
            assert primary is False
            assert manager_result is False

    def test_recomputed_hash_with_original_signature_rejected_by_both(self):
        """Re-hashing a tampered payload does not rescue the old signature."""
        with tempfile.TemporaryDirectory() as tmp:
            manager, signature, pk = _make_manager_and_signature(tmp)
            tampered_payload = {**signature.payload, "score": 0.99, "verdict": "ai_like"}
            canonical = json.dumps(
                tampered_payload, separators=(",", ":"), ensure_ascii=False, sort_keys=True
            )
            new_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            tampered = replace(signature, payload=tampered_payload, payload_hash=new_hash)
            primary, manager_result = _verify_both(
                manager, tampered, pk, score=0.99, verdict="ai_like"
            )
            assert primary is False
            assert manager_result is False

    @pytest.mark.parametrize("bad_hash", ["not-hex", "a" * 63, "a" * 65, "A" * 64, ""])
    def test_malformed_payload_hash_rejected_by_both(self, bad_hash):
        with tempfile.TemporaryDirectory() as tmp:
            manager, signature, pk = _make_manager_and_signature(tmp)
            tampered = replace(signature, payload_hash=bad_hash)
            primary, manager_result = _verify_both(manager, tampered, pk)
            assert primary is False
            assert manager_result is False

    @pytest.mark.parametrize("bad_signature", ["not-base64!!!", "a" * 88, ""])
    def test_malformed_signature_encoding_rejected_by_both(self, bad_signature):
        with tempfile.TemporaryDirectory() as tmp:
            manager, signature, pk = _make_manager_and_signature(tmp)
            tampered = replace(signature, signature=bad_signature)
            primary, manager_result = _verify_both(manager, tampered, pk)
            assert primary is False
            assert manager_result is False

    @pytest.mark.parametrize("algorithm", ["ed448", "rsa", "Ed25519", ""])
    def test_unsupported_algorithm_rejected_by_both(self, algorithm):
        with tempfile.TemporaryDirectory() as tmp:
            manager, signature, pk = _make_manager_and_signature(tmp)
            tampered = replace(signature, algorithm=algorithm)
            primary, manager_result = _verify_both(manager, tampered, pk)
            assert primary is False
            assert manager_result is False

    def test_key_id_mismatch_rejected_by_both(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager, signature, pk = _make_manager_and_signature(tmp)
            mismatched_pk = replace(pk, key_id="other-key")
            primary, manager_result = _verify_both(manager, signature, mismatched_pk)
            assert primary is False
            assert manager_result is False

    def test_malformed_public_key_rejected_by_both(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager, signature, pk = _make_manager_and_signature(tmp)
            bad_pk = replace(pk, public_key="not-base64!!!")
            primary, manager_result = _verify_both(manager, signature, bad_pk)
            assert primary is False
            assert manager_result is False

    def test_untouched_control_accepted_by_both(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager, signature, pk = _make_manager_and_signature(tmp)
            primary, manager_result = _verify_both(manager, signature, pk)
            assert primary is True
            assert manager_result is True


class TestWatermarkKeyValidityPolicy:
    """C20: expiry must be enforced from the trusted key + authenticated time.

    Policy under test (see ``watermarking.WATERMARK_KEY_VALIDITY_POLICY``):
    historical validity — a signature verifies iff its authenticated
    payload timestamp lies inside the trusted public key's validity
    window; the unsigned envelope dates are never validity bounds, only
    cross-checked for agreement.
    """

    def test_trusted_key_expired_before_signing_time_rejected_by_both(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager, signature, pk = _make_manager_and_signature(tmp)
            signing_time = datetime.fromisoformat(signature.payload["timestamp"])
            expired_pk = _public_key_with_bounds(
                pk,
                created_at=(signing_time - timedelta(days=365)).isoformat(),
                expires_at=(signing_time - timedelta(days=1)).isoformat(),
            )
            primary, manager_result = _verify_both(manager, signature, expired_pk)
            assert primary is False
            assert manager_result is False

    def test_historical_signature_valid_after_key_expiry_accepted_by_both(self):
        """A signature made while the key was valid stays valid afterwards."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))
            keypair = manager.generate_key(key_id="test-key")
            signing_time = "2025-01-15T12:00:00+00:00"
            signature = _handcraft_signature(
                keypair, timestamp=signing_time, expires_at="2025-06-01T00:00:00+00:00"
            )
            pk = _public_key_with_bounds(
                manager.get_public_key("test-key"),
                created_at="2025-01-01T00:00:00+00:00",
                expires_at="2025-06-01T00:00:00+00:00",
            )
            # The key expired 2025-06-01, long before "now" (2026-11); the
            # signature was made 2025-01-15, inside the validity window.
            assert datetime.now(UTC) > datetime.fromisoformat("2025-06-01T00:00:00+00:00")
            primary, manager_result = _verify_both(manager, signature, pk)
            assert primary is True
            assert manager_result is True

    def test_key_not_yet_valid_at_signing_time_rejected_by_both(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))
            keypair = manager.generate_key(key_id="test-key")
            signature = _handcraft_signature(
                keypair,
                timestamp="2025-01-15T12:00:00+00:00",
                expires_at="2025-06-01T00:00:00+00:00",
            )
            pk = _public_key_with_bounds(
                manager.get_public_key("test-key"),
                created_at="2025-02-01T00:00:00+00:00",
                expires_at="2025-06-01T00:00:00+00:00",
            )
            primary, manager_result = _verify_both(manager, signature, pk)
            assert primary is False
            assert manager_result is False

    def test_forged_envelope_dates_with_expired_trusted_key_rejected_by_both(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager, signature, pk = _make_manager_and_signature(tmp)
            signing_time = datetime.fromisoformat(signature.payload["timestamp"])
            expired_pk = _public_key_with_bounds(
                pk,
                created_at=(signing_time - timedelta(days=365)).isoformat(),
                expires_at=(signing_time - timedelta(days=1)).isoformat(),
            )
            # Only the unsigned envelope dates are moved into a plausible window.
            forged = replace(
                signature,
                signed_at=(signing_time - timedelta(days=10)).isoformat(),
                expires_at=(signing_time + timedelta(days=365)).isoformat(),
            )
            primary, manager_result = _verify_both(manager, forged, expired_pk)
            assert primary is False
            assert manager_result is False

    def test_forged_envelope_signed_at_with_valid_trusted_key_rejected_by_both(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager, signature, pk = _make_manager_and_signature(tmp)
            signing_time = datetime.fromisoformat(signature.payload["timestamp"])
            forged = replace(
                signature,
                signed_at=(signing_time + timedelta(days=30)).isoformat(),
            )
            primary, manager_result = _verify_both(manager, forged, pk)
            assert primary is False
            assert manager_result is False

    def test_forged_envelope_expires_at_with_valid_trusted_key_rejected_by_both(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager, signature, pk = _make_manager_and_signature(tmp)
            forged = replace(signature, expires_at="2099-01-01T00:00:00+00:00")
            primary, manager_result = _verify_both(manager, forged, pk)
            assert primary is False
            assert manager_result is False

    def test_missing_payload_timestamp_rejected_by_both(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))
            keypair = manager.generate_key(key_id="test-key")
            payload = {
                "detector_id": "test/detector",
                "detector_version": "1.0",
                "text_sha256": "a" * 64,
                "score": 0.2,
                "verdict": "human_like",
                "nonce": "0123456789abcdef",
            }
            canonical = json.dumps(
                payload, separators=(",", ":"), ensure_ascii=False, sort_keys=True
            )
            payload_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            signature = WatermarkSignature(
                key_id=keypair.key_id,
                signature=base64.b64encode(keypair.sign(payload_hash.encode("utf-8"))).decode(
                    "ascii"
                ),
                signed_at="2025-01-15T12:00:00+00:00",
                expires_at=None,
                payload_hash=payload_hash,
                payload=payload,
            )
            pk = manager.get_public_key("test-key")
            primary, manager_result = _verify_both(manager, signature, pk)
            assert primary is False
            assert manager_result is False

    @pytest.mark.parametrize(
        "bad_timestamp", ["2025-01-15T12:00:00", "not-a-date", "", 12345, None]
    )
    def test_naive_or_malformed_payload_timestamp_rejected_by_both(self, bad_timestamp):
        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))
            keypair = manager.generate_key(key_id="test-key")
            signature = _handcraft_signature(
                keypair,
                timestamp="2025-01-15T12:00:00+00:00",
                expires_at="2025-06-01T00:00:00+00:00",
                payload_overrides={"timestamp": bad_timestamp},
            )
            pk = _public_key_with_bounds(
                manager.get_public_key("test-key"),
                created_at="2025-01-01T00:00:00+00:00",
                expires_at="2025-06-01T00:00:00+00:00",
            )
            primary, manager_result = _verify_both(manager, signature, pk)
            assert primary is False
            assert manager_result is False

    @pytest.mark.parametrize("field", ["expires_at", "created_at"])
    def test_malformed_trusted_key_date_rejected_by_both(self, field):
        with tempfile.TemporaryDirectory() as tmp:
            manager, signature, pk = _make_manager_and_signature(tmp)
            kwargs = {
                "created_at": pk.created_at,
                "expires_at": pk.expires_at,
            }
            kwargs[field] = "not-a-date"
            bad_pk = _public_key_with_bounds(pk, **kwargs)
            primary, manager_result = _verify_both(manager, signature, bad_pk)
            assert primary is False
            assert manager_result is False

    def test_malformed_envelope_signed_at_rejected_by_both(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager, signature, pk = _make_manager_and_signature(tmp)
            forged = replace(signature, signed_at="not-a-date")
            primary, manager_result = _verify_both(manager, forged, pk)
            assert primary is False
            assert manager_result is False

    def test_absent_envelope_expiry_still_enforces_trusted_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager, signature, pk = _make_manager_and_signature(tmp)
            signing_time = datetime.fromisoformat(signature.payload["timestamp"])
            expired_pk = _public_key_with_bounds(
                pk,
                created_at=(signing_time - timedelta(days=365)).isoformat(),
                expires_at=(signing_time - timedelta(days=1)).isoformat(),
            )
            no_envelope_expiry = replace(signature, expires_at=None)
            primary, manager_result = _verify_both(manager, no_envelope_expiry, expired_pk)
            assert primary is False
            assert manager_result is False
            # And the same envelope-absent signature verifies with a valid key.
            primary, manager_result = _verify_both(manager, no_envelope_expiry, pk)
            assert primary is True
            assert manager_result is True

    def test_key_without_expiry_accepted_by_both(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager, signature, pk = _make_manager_and_signature(tmp)
            never_expires = _public_key_with_bounds(pk, created_at=pk.created_at, expires_at=None)
            no_envelope_expiry = replace(signature, expires_at=None)
            primary, manager_result = _verify_both(manager, no_envelope_expiry, never_expires)
            assert primary is True
            assert manager_result is True


class TestWatermarkKeyIdConfinement:
    """C21: key IDs must stay inside the configured key directory."""

    INVALID_KEY_IDS = [
        "../synthetic-outside",
        "..\\synthetic-outside",
        "/abs/path",
        "C:\\evil",
        "C:/evil",
        "\\\\server\\share",
        "//server/share",
        "a/b",
        "a\\b",
        "..",
        ".",
        "",
        "CON",
        "NUL",
        "COM1",
        "aux",
        "LPT9",
        "key id",
        "a" * 129,
        ".hidden",
        "trailing.",
        "a..b",
        "key:id",
        "key*id",
    ]

    @pytest.mark.parametrize("bad_id", INVALID_KEY_IDS)
    def test_generate_key_rejects_confined_id(self, bad_id):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            key_dir = base / "keys"
            manager = WatermarkManager(key_dir)
            before = {p for p in base.rglob("*")}
            with pytest.raises(WatermarkError):
                manager.generate_key(key_id=bad_id)
            after = {p for p in base.rglob("*")}
            assert after == before
            assert not (base / "synthetic-outside.key.json").exists()

    @pytest.mark.parametrize("good_id", ["test-key", "wmk-abc123", "key_1.2", "A" * 128])
    def test_valid_key_ids_accepted(self, good_id):
        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))
            keypair = manager.generate_key(key_id=good_id)
            assert keypair.key_id == good_id
            assert (Path(tmp) / f"{good_id}.key.json").exists()

    def test_generate_key_collision_rejected_without_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))
            manager.generate_key(key_id="test-key")
            key_file = Path(tmp) / "test-key.key.json"
            original_bytes = key_file.read_bytes()
            with pytest.raises(WatermarkError):
                manager.generate_key(key_id="test-key")
            assert key_file.read_bytes() == original_bytes

    def test_existing_key_file_not_silently_replaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            key_file = Path(tmp) / "test-key.key.json"
            key_file.write_text('{"sentinel": true}', encoding="utf-8")
            manager = WatermarkManager(Path(tmp))
            assert manager.get_keypair("test-key") is None
            with pytest.raises(WatermarkError):
                manager.generate_key(key_id="test-key")
            assert key_file.read_text(encoding="utf-8") == '{"sentinel": true}'

    def test_revoke_key_confined(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            key_dir = base / "keys"
            sentinel = base / "victim.key.json"
            sentinel.write_text('{"sentinel": true}', encoding="utf-8")
            manager = WatermarkManager(key_dir)
            manager.generate_key(key_id="victim")
            assert manager.revoke_key("../victim") is False
            assert sentinel.read_text(encoding="utf-8") == '{"sentinel": true}'
            assert manager.revoke_key("victim") is True
            assert not (key_dir / "victim.key.json").exists()
            assert manager.revoke_key("victim") is False

    def test_revoke_key_confined_for_aliased_key_file(self):
        """A key file whose embedded ID escapes the store must not alias out.

        Craft a file inside the key dir whose embedded ``key_id`` is
        ``../victim``: on unfixed code the manager loads it under that ID
        and ``revoke_key("../victim")`` deletes the sentinel OUTSIDE the
        store. The fix must refuse to load the aliased entry at all.
        """
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            key_dir = base / "keys"
            key_dir.mkdir(parents=True)
            sentinel = base / "victim.key.json"
            sentinel.write_text('{"sentinel": true}', encoding="utf-8")
            keypair = WatermarkKeyPair.generate(key_id="victim")
            aliased = dict(keypair.to_dict())
            aliased["key_id"] = "../victim"
            (key_dir / "victim.key.json").write_text(json.dumps(aliased), encoding="utf-8")
            manager = WatermarkManager(key_dir)
            assert manager.get_keypair("../victim") is None
            assert manager.revoke_key("../victim") is False
            assert sentinel.read_text(encoding="utf-8") == '{"sentinel": true}'
            assert (key_dir / "victim.key.json").exists()

    def test_get_keypair_and_public_key_reject_confined_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))
            manager.generate_key(key_id="test-key")
            assert manager.get_keypair("../test-key") is None
            assert manager.get_public_key("../test-key") is None
            assert manager.get_keypair("/abs/path") is None

    @pytest.mark.skipif(os.name == "nt", reason="POSIX owner-only mode check")
    def test_key_file_owner_private_mode_posix(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))
            manager.generate_key(key_id="test-key")
            key_file = Path(tmp) / "test-key.key.json"
            mode = stat.S_IMODE(key_file.stat().st_mode)
            assert mode == 0o600, f"key file mode is {mode:03o}, expected 0600"
            leftovers = [p for p in Path(tmp).iterdir() if p.suffix == ".tmp"]
            assert leftovers == []

    @pytest.mark.skipif(os.name != "nt", reason="Windows ACL check only")
    def test_key_file_acl_windows(self):
        """On Windows the key file's DACL must grant nothing to Everyone.

        Not executed on POSIX (this VM): Windows CI runs it. Skipped
        (not passed) when the DACL cannot be read.
        """
        import ctypes
        from ctypes import wintypes

        with tempfile.TemporaryDirectory() as tmp:
            manager = WatermarkManager(Path(tmp))
            manager.generate_key(key_id="test-key")
            key_file = Path(tmp) / "test-key.key.json"
            advapi32 = ctypes.windll.advapi32
            owner_sid = (ctypes.c_void_p * 1)()
            group_sid = (ctypes.c_void_p * 1)()
            dacl = (ctypes.c_void_p * 1)()
            sacl = (ctypes.c_void_p * 1)()
            descriptor = (ctypes.c_void_p * 1)()
            result = advapi32.GetNamedSecurityInfoW(
                str(key_file),
                1,  # SE_FILE_OBJECT
                4,  # DACL_SECURITY_INFORMATION
                ctypes.byref(owner_sid),
                ctypes.byref(group_sid),
                ctypes.byref(dacl),
                ctypes.byref(sacl),
                ctypes.byref(descriptor),
            )
            if result != 0:
                pytest.skip(f"GetNamedSecurityInfoW failed: {result}")
            try:
                everyone = ctypes.create_string_buffer(68)
                size = wintypes.DWORD(68)
                if not advapi32.CreateWellKnownSid(1, None, everyone, ctypes.byref(size)):
                    pytest.skip("CreateWellKnownSid(WinWorldSid) failed")
                # Walk the DACL; no ACE may grant access to Everyone.
                acl = dacl[0]
                if not acl:
                    pytest.skip("no DACL present")
                ace_count = ctypes.cast(acl, ctypes.POINTER(wintypes.WORD))[
                    2
                ]  # AclSize(0), AceCount(2)
                for index in range(ace_count):
                    ace = ctypes.c_void_p()
                    if not advapi32.GetAce(acl, index, ctypes.byref(ace)):
                        continue
                    ace_header = ctypes.cast(ace, ctypes.POINTER(ctypes.c_ubyte * 8)).contents
                    ace_type = ace_header[0]
                    if ace_type not in (0, 1):  # ACCESS_ALLOWED / ACCESS_DENIED
                        continue
                    # ACE layout: ACE_HEADER (4 bytes) + ACCESS_MASK
                    # (4 bytes), then the SID itself. The SID starts at
                    # offset 8; pass its address straight to EqualSid.
                    sid_address = ctypes.addressof(ace) + 8
                    if advapi32.EqualSid(ctypes.c_void_p(sid_address), everyone):
                        assert ace_type == 1, "Everyone is granted access to the key file"
            finally:
                if descriptor[0]:
                    ctypes.windll.kernel32.LocalFree(descriptor[0])


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
