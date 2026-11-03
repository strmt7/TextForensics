"""Tests for Detector Output Watermarking & Provenance Chain."""

from __future__ import annotations

import base64
import tempfile
from pathlib import Path

import pytest

from textforensics.watermarking import (
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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
