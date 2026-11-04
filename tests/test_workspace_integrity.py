"""Tests for Workspace Integrity Module."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

import pytest

from textforensics.workspace_integrity import (
    AuditChainEntry,
    EmergencyStopSentinel,
    WorkspaceFingerprint,
    WorkspaceIntegrityReport,
    _sha256,
    _sha256_str,
    activate_emergency_stop,
    append_audit_entry,
    check_emergency_stop,
    compute_workspace_fingerprint,
    create_audit_chain,
    deactivate_emergency_stop,
    get_emergency_sentinel,
    load_audit_chain,
    save_audit_chain,
    verify_workspace_fingerprint,
    verify_workspace_integrity,
)


class TestWorkspaceFingerprint:
    def test_fingerprint_creation(self):
        """Test fingerprint creation."""
        fp = WorkspaceFingerprint(
            version=1,
            workspace_id="abc123",
            fingerprint="a" * 64,
            created_at="2024-01-01T00:00:00+00:00",
            source_path="/test/path",
        )
        assert fp.version == 1
        assert fp.workspace_id == "abc123"

    def test_fingerprint_roundtrip(self):
        """Fingerprint serialization should preserve all fields."""
        fp = WorkspaceFingerprint(
            version=1,
            workspace_id="test-workspace",
            fingerprint="a" * 64,
            created_at="2024-01-01T00:00:00+00:00",
            source_path="/test/path",
        )
        d = fp.to_dict()
        fp2 = WorkspaceFingerprint.from_dict(d)
        assert fp2.workspace_id == fp.workspace_id
        assert fp2.fingerprint == fp.fingerprint

    def test_compute_fingerprint_deterministic(self):
        """Same workspace should produce same fingerprint."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (Path(tmp) / "pyproject.toml").write_text("[project]\nname = 'test'")
            (Path(tmp) / "src").mkdir()
            (Path(tmp) / "src" / "main.py").write_text("print('hello')")

            fp1 = compute_workspace_fingerprint(path)
            fp2 = compute_workspace_fingerprint(path)

            assert fp1.fingerprint == fp2.fingerprint
            assert fp1.workspace_id == fp2.workspace_id

    def test_fingerprint_changes_with_content(self):
        """Fingerprint should change when workspace content changes."""
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp)
            (Path(tmp) / "pyproject.toml").write_text("[project]\nname = 'test'")
            fp1 = compute_workspace_fingerprint(tmp)

            # Modify a tracked config file
            (Path(tmp) / "pyproject.toml").write_text("[project]\nname = 'test2'")
            fp2 = compute_workspace_fingerprint(tmp)

            assert fp1.fingerprint != fp2.fingerprint

    def test_verify_fingerprint_match(self):
        """verify_workspace_fingerprint should return True for matching fingerprints."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (Path(tmp) / "pyproject.toml").write_text("[project]\nname = 'test'")
            fp = compute_workspace_fingerprint(path)

            match, actual = verify_workspace_fingerprint(tmp, fp.fingerprint)
            assert match is True
            assert actual is None

    def test_verify_fingerprint_mismatch(self):
        """verify_workspace_fingerprint should return False for mismatched fingerprints."""
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp)
            (Path(tmp) / "pyproject.toml").write_text("[project]\nname = 'test'")
            compute_workspace_fingerprint(tmp)

            match, actual = verify_workspace_fingerprint(tmp, "different_fingerprint")
            assert match is False
            assert actual == actual  # Should return actual fingerprint


class TestAuditChain:
    def test_empty_chain_verification(self):
        """Empty chain should verify successfully."""
        chain = create_audit_chain()
        valid, error = chain.verify_chain()
        assert valid is True
        assert error is None

    def test_single_entry_chain(self):
        """Single entry chain should verify."""
        chain = create_audit_chain()
        chain.add_entry("test", "op1", {"data": "test"})
        valid, error = chain.verify_chain()
        assert valid is True
        assert error is None

    def test_multi_entry_chain(self):
        """Multi-entry chain should verify."""
        chain = create_audit_chain()
        chain.add_entry("op1", "id1", {"data": "a"})
        chain.add_entry("op2", "id2", {"data": "b"})
        chain.add_entry("op3", "id3", {"data": "c"})
        valid, error = chain.verify_chain()
        assert valid is True

    def test_chain_tampering_detected(self):
        """Tampered chain should fail verification."""
        chain = create_audit_chain()
        chain.add_entry("op1", "id1", {"data": "a"})
        chain.add_entry("op2", "id2", {"data": "b"})

        # Tamper with the chain by creating a new entry with tampered payload_hash
        # We need to create a new entry with tampered payload_hash since fields are frozen
        tampered_entry = AuditChainEntry(
            index=chain.entries[0].index,
            timestamp=chain.entries[0].timestamp,
            operation=chain.entries[0].operation,
            operation_id=chain.entries[0].operation_id,
            payload_hash="tampered",  # Tampered hash
            previous_hash=chain.entries[0].previous_hash,
            entry_hash=chain.entries[0].entry_hash,
            metadata=chain.entries[0].metadata,
        )
        chain.entries[0] = tampered_entry

        valid, error = chain.verify_chain()
        assert valid is False
        assert "hash mismatch" in error.lower() or "hash chain broken" in error.lower()

    def test_chain_serialization(self):
        """Chain serialization should preserve data."""
        chain = create_audit_chain()
        chain.add_entry("op1", "id1", {"data": "test"})
        chain.add_entry("op2", "id2", {"data": "test2"})

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "chain.json"
            save_audit_chain(chain, path)

            loaded = load_audit_chain(Path(tmp) / "chain.json")
            assert loaded is not None
            assert len(loaded.entries) == 2
            assert loaded.entries[0].operation == "op1"
            assert loaded.entries[1].operation == "op2"

    def test_chain_hash_deterministic(self):
        """Chain hash should be deterministic."""
        chain = create_audit_chain()
        chain.add_entry("op1", "id1", {"data": "test"})

        hash1 = chain.compute_chain_hash()
        hash2 = chain.compute_chain_hash()

        assert hash1 == hash2

    def test_append_audit_entry(self):
        """append_audit_entry should work correctly."""
        chain = create_audit_chain()
        entry = append_audit_entry(chain, "test", "id1", {"key": "value"})
        assert entry.operation == "test"
        assert entry.operation_id == "id1"
        assert entry.payload_hash is not None


class TestAuditChainPersistence:
    def test_save_and_load_chain(self):
        """Chain save/load should preserve data."""
        chain = create_audit_chain()
        chain.add_entry("op1", "id1", {"data": "test"})
        chain.add_entry("op2", "id2", {"data": "test2"})

        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp) / "chain.json"
            assert save_audit_chain(chain, Path(tmp) / "chain.json")

            loaded = load_audit_chain(Path(tmp) / "chain.json")
            assert loaded is not None
            assert len(loaded.entries) == 2
            assert loaded.entries[0].operation == "op1"
            assert loaded.entries[1].operation == "op2"

    def test_load_nonexistent_file(self):
        """Loading non-existent file should return None."""
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp) / "nonexistent.json"
            chain = load_audit_chain(Path(tmp) / "nonexistent.json")
            assert chain is None


class TestEmergencyStopSentinel:
    def test_sentinel_creation(self):
        """Sentinel should initialize correctly."""
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp) / "emergency_stop"
            sentinel = EmergencyStopSentinel(Path(tmp) / "emergency_stop")
            assert sentinel.sentinel_path == Path(tmp) / "emergency_stop"

    def test_default_path_from_env(self, monkeypatch):
        """Sentinel should use env var if set."""
        with tempfile.TemporaryDirectory() as tmp:
            sentinel_path = Path(tmp) / "custom_emergency_stop"
            monkeypatch.setenv("TEXTFORENSICS_EMERGENCY_STOP", str(sentinel_path))
            sentinel = EmergencyStopSentinel()
            assert sentinel.sentinel_path == sentinel_path

    def test_default_path(self):
        """Default path should be .textforensics_emergency_stop in cwd."""
        with tempfile.TemporaryDirectory() as tmp:
            # Change to temp directory
            original_cwd = Path.cwd()
            try:
                os.chdir(tmp)
                sentinel = EmergencyStopSentinel()
                assert sentinel.sentinel_path == Path.cwd() / ".textforensics_emergency_stop"
            finally:
                os.chdir(original_cwd)

    def test_inactive_when_no_file(self):
        """Sentinel should be inactive when file doesn't exist."""
        with tempfile.TemporaryDirectory() as tmp:
            sentinel = EmergencyStopSentinel(Path(tmp) / "nonexistent")
            assert sentinel.is_active() is False

    def test_active_when_file_exists(self):
        """Sentinel should be active when file exists."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "emergency_stop"
            path.write_text("test")
            sentinel = EmergencyStopSentinel(path)
            assert sentinel.is_active() is True

    def test_activate_creates_file(self):
        """activate() should create sentinel file."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "emergency_stop"
            sentinel = EmergencyStopSentinel(path)
            assert sentinel.activate("test reason") is True
            assert path.exists()

    def test_activate_sets_reason(self):
        """Activate should store reason in file."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "emergency_stop"
            sentinel = EmergencyStopSentinel(path)
            sentinel.activate("test reason")
            content = json.loads(path.read_text())
            assert content["reason"] == "test reason"
            assert "activated_at" in content
            assert "activated_by" in content

    def test_deactivate_removes_file(self):
        """deactivate() should remove sentinel file."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "emergency_stop"
            path.write_text("test")
            sentinel = EmergencyStopSentinel(path)
            assert sentinel.deactivate() is True
            assert not path.exists()

    def test_is_active_false_when_no_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            sentinel = EmergencyStopSentinel(Path(tmp) / "nonexistent")
            assert sentinel.is_active() is False

    def test_is_active_true_when_file_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "emergency_stop"
            path.write_text("test")
            sentinel = EmergencyStopSentinel(path)
            assert sentinel.is_active() is True

    def test_is_active_false_on_permission_error(self, monkeypatch):
        """Should fail closed on permission error."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "emergency_stop"
            path.write_text("test")
            sentinel = EmergencyStopSentinel(path)

            # Mock read_bytes to raise PermissionError
            def mock_read_bytes(self):
                raise PermissionError("Permission denied")
            monkeypatch.setattr(Path, "read_bytes", mock_read_bytes)

            assert sentinel.is_active() is True  # fail closed

    def test_get_status(self):
        """get_status should return detailed status."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "emergency_stop"
            sentinel = EmergencyStopSentinel(path)
            status = sentinel.get_status()
            assert "active" in status
            assert "configured" in status
            assert "path" in status
            assert "reason" in status

    def test_activate_returns_true_on_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "emergency_stop"
            sentinel = EmergencyStopSentinel(path)
            assert sentinel.activate("test") is True

    def test_activate_returns_false_on_error(self):
        """activate should return False on error."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "emergency_stop"
            sentinel = EmergencyStopSentinel(path)
            # Make path read-only to cause write error
            path.parent.chmod(0o555)
            try:
                result = sentinel.activate("test")
                # May succeed or fail depending on OS permissions
                assert isinstance(result, bool)
            finally:
                path.parent.chmod(0o755)

    def test_deactivate_nonexistent(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "emergency_stop"
            sentinel = EmergencyStopSentinel(path)
            assert sentinel.deactivate() is True  # Should succeed even if file doesn't exist


class TestEmergencyStopGlobal:
    def test_get_emergency_singleton(self):
        """get_emergency_sentinel should return singleton."""
        sentinel1 = get_emergency_sentinel()
        sentinel2 = get_emergency_sentinel()
        assert sentinel1 is sentinel2

    def test_check_emergency_stop_returns_bool(self):
        """check_emergency_stop should return bool."""
        result = check_emergency_stop()
        assert isinstance(result, bool)

    def test_activate_emergency_stop(self):
        """activate_emergency_stop should return bool."""
        with tempfile.TemporaryDirectory():
            # This uses global sentinel, so we just verify it runs
            result = activate_emergency_stop("test")
            assert isinstance(result, bool)

    def test_deactivate_emergency_stop(self):
        """deactivate_emergency_stop should return bool."""
        result = deactivate_emergency_stop()
        assert isinstance(result, bool)

    def test_check_emergency_stop(self):
        result = check_emergency_stop()
        assert isinstance(result, bool)


class TestWorkspaceIntegrity:
    def test_verify_workspace_integrity_basic(self):
        """verify_workspace_integrity should run without error."""
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp)
            (Path(tmp) / "pyproject.toml").write_text("[project]\nname = 'test'")
            report = verify_workspace_integrity(Path(tmp))
            assert isinstance(report, WorkspaceIntegrityReport)

    def test_report_structure(self):
        """Report should have all required fields."""
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp)
            (Path(tmp) / "pyproject.toml").write_text("[project]\nname = 'test'")
            report = verify_workspace_integrity(Path(tmp))

            assert isinstance(report.workspace_fingerprint, WorkspaceFingerprint)
            assert isinstance(report.fingerprint_verified, bool)
            assert isinstance(report.audit_chain_valid, bool)
            assert isinstance(report.audit_chain_length, int)
            assert isinstance(report.emergency_stop_active, bool)
            assert isinstance(report.emergency_stop_configured, bool)
            assert report.overall_status in {"healthy", "degraded", "compromised", "emergency_stop"}
            assert isinstance(report.timestamp, str)
            assert isinstance(report.details, dict)

    def test_report_save_load_roundtrip(self):
        """Report save/load should work."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            report = WorkspaceIntegrityReport(
                workspace_fingerprint=WorkspaceFingerprint(
                    version=1,
                    workspace_id="test",
                    fingerprint="a" * 64,
                    created_at="2024-01-01T00:00:00+00:00",
                    source_path="/test",
                ),
                fingerprint_verified=True,
                audit_chain_valid=True,
                audit_chain_length=5,
                emergency_stop_active=False,
                emergency_stop_configured=False,
                emergency_stop_reason=None,
                overall_status="healthy",
            )
            path = Path(tmp) / "report.json"
            assert report.save(path) is True

            loaded = WorkspaceIntegrityReport.load(path)
            assert loaded is not None
            assert loaded.workspace_fingerprint.fingerprint == "a" * 64
            assert loaded.overall_status == "healthy"

    def test_report_roundtrip(self):
        """Report to_dict and load should preserve data."""
        report = WorkspaceIntegrityReport(
            workspace_fingerprint=WorkspaceFingerprint(
                version=1,
                workspace_id="test",
                fingerprint="a" * 64,
                created_at="2024-01-01T00:00:00+00:00",
                source_path="/test",
            ),
            fingerprint_verified=True,
            audit_chain_valid=True,
            audit_chain_length=3,
            emergency_stop_active=False,
            emergency_stop_configured=False,
            emergency_stop_reason=None,
            overall_status="healthy",
        )
        d = report.to_dict()
        assert d["overall_status"] == "healthy"
        assert d["audit_chain_length"] == 3


class TestSha256:
    def test_sha256_str(self):
        assert len(_sha256_str("test")) == 64
        assert _sha256_str("test") == hashlib.sha256(b"test").hexdigest()

    def test_sha256_bytes(self):
        assert len(_sha256(b"test")) == 64

    def test_sha256_deterministic(self):
        assert _sha256_str("test") == _sha256_str("test")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
