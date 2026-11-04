"""Tests for workspace_integrity.py — comprehensive coverage.

This module was previously at 66% coverage. These tests exercise:
- WorkspaceFingerprint: serialization, fingerprint computation
- AuditChainEntry: serialization, hash chaining
- AuditChain: add_entry, verify_chain, serialization
- EmergencyStopSentinel: is_active, activate, deactivate, get_status
- WorkspaceIntegrityReport: verification, save/load
- Functions: compute/verify fingerprint, audit chain ops, emergency stop
- Edge cases: missing files, corrupted chains, fail-closed behavior
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from textforensics.workspace_integrity import (
    AuditChain,
    AuditChainEntry,
    EmergencyStopSentinel,
    WorkspaceFingerprint,
    WorkspaceIntegrityReport,
    activate_emergency_stop,
    append_audit_entry,
    check_emergency_stop,
    compute_workspace_fingerprint,
    create_audit_chain,
    deactivate_emergency_stop,
    get_emergency_sentinel,
    load_audit_chain,
    save_audit_chain,
    verify_audit_chain,
    verify_workspace_fingerprint,
    verify_workspace_integrity,
)


class TestWorkspaceFingerprint:
    """Tests for WorkspaceFingerprint dataclass."""

    def test_to_dict_and_from_dict(self):
        fp = WorkspaceFingerprint(
            version=1,
            workspace_id="abc123",
            fingerprint="hash123",
            created_at="2024-01-01T00:00:00Z",
            source_path="/tmp/workspace",
        )
        d = fp.to_dict()
        restored = WorkspaceFingerprint.from_dict(d)
        assert restored.version == 1
        assert restored.workspace_id == "abc123"
        assert restored.fingerprint == "hash123"
        assert restored.source_path == "/tmp/workspace"

    def test_from_dict_with_missing_fields(self):
        fp = WorkspaceFingerprint.from_dict({})
        assert fp.version == 1
        assert fp.workspace_id == ""
        assert fp.fingerprint == ""


class TestAuditChainEntry:
    """Tests for AuditChainEntry dataclass."""

    def test_to_dict_and_from_dict(self):
        entry = AuditChainEntry(
            index=0,
            timestamp="2024-01-01T00:00:00Z",
            operation="test",
            operation_id="op1",
            payload_hash="payload123",
            previous_hash="0" * 64,
            entry_hash="entry123",
            metadata={"key": "value"},
        )
        d = entry.to_dict()
        restored = AuditChainEntry.from_dict(d)
        assert restored.index == 0
        assert restored.operation == "test"
        assert restored.operation_id == "op1"
        assert restored.payload_hash == "payload123"
        assert restored.previous_hash == "0" * 64
        assert restored.entry_hash == "entry123"
        assert restored.metadata == {"key": "value"}


class TestAuditChain:
    """Tests for AuditChain class."""

    def test_empty_chain(self):
        chain = AuditChain()
        assert len(chain.entries) == 0
        assert chain.last_entry_hash == "0" * 64
        assert chain.compute_chain_hash() == "0" * 64

    def test_add_entry(self):
        chain = AuditChain()
        entry = chain.add_entry("test_op", "op1", {"data": "value"})
        assert len(chain.entries) == 1
        assert entry.index == 0
        assert entry.operation == "test_op"
        assert entry.operation_id == "op1"
        assert entry.payload_hash != ""
        assert entry.previous_hash == "0" * 64
        assert entry.entry_hash != ""

    def test_add_multiple_entries_chained(self):
        chain = AuditChain()
        e1 = chain.add_entry("op1", "id1", {"a": 1})
        e2 = chain.add_entry("op2", "id2", {"b": 2})
        e3 = chain.add_entry("op3", "id3", {"c": 3})
        assert len(chain.entries) == 3
        assert e1.previous_hash == "0" * 64
        assert e2.previous_hash == e1.entry_hash
        assert e3.previous_hash == e2.entry_hash

    def test_verify_chain_valid(self):
        chain = AuditChain()
        chain.add_entry("op1", "id1", {"a": 1})
        chain.add_entry("op2", "id2", {"b": 2})
        valid, error = chain.verify_chain()
        assert valid is True
        assert error is None

    def test_verify_chain_broken_previous_hash(self):
        chain = AuditChain()
        chain.add_entry("op1", "id1", {"a": 1})
        e2 = chain.add_entry("op2", "id2", {"b": 2})
        # Corrupt the chain by creating a new entry with wrong previous_hash
        corrupted_entry = AuditChainEntry(
            index=e2.index,
            timestamp=e2.timestamp,
            operation=e2.operation,
            operation_id=e2.operation_id,
            payload_hash=e2.payload_hash,
            previous_hash="corrupted",
            entry_hash=e2.entry_hash,
            metadata=e2.metadata,
        )
        chain.entries[1] = corrupted_entry
        valid, error = chain.verify_chain()
        assert valid is False
        assert "hash chain broken" in error.lower()

    def test_verify_chain_broken_entry_hash(self):
        chain = AuditChain()
        chain.add_entry("op1", "id1", {"a": 1})
        e1 = chain.entries[0]
        # Corrupt the entry hash
        corrupted_entry = AuditChainEntry(
            index=e1.index,
            timestamp=e1.timestamp,
            operation=e1.operation,
            operation_id=e1.operation_id,
            payload_hash=e1.payload_hash,
            previous_hash=e1.previous_hash,
            entry_hash="corrupted",
            metadata=e1.metadata,
        )
        chain.entries[0] = corrupted_entry
        valid, error = chain.verify_chain()
        assert valid is False
        assert "entry hash mismatch" in error.lower()

    def test_to_dict_and_from_dict(self):
        chain = AuditChain()
        chain.add_entry("op1", "id1", {"a": 1})
        chain.add_entry("op2", "id2", {"b": 2})
        d = chain.to_dict()
        restored = AuditChain.from_dict(d)
        assert len(restored.entries) == 2
        assert restored.entries[0].operation == "op1"
        assert restored.entries[1].operation == "op2"
        # Verify chain still valid after round-trip
        valid, _ = restored.verify_chain()
        assert valid is True


class TestEmergencyStopSentinel:
    """Tests for EmergencyStopSentinel."""

    def test_is_active_when_file_exists(self):
        with tempfile.TemporaryDirectory() as td:
            sentinel_path = Path(td) / "emergency_stop"
            sentinel_path.write_text(json.dumps({"reason": "test"}))
            sentinel = EmergencyStopSentinel(sentinel_path)
            assert sentinel.is_active() is True

    def test_is_active_when_file_missing(self):
        with tempfile.TemporaryDirectory() as td:
            sentinel_path = Path(td) / "nonexistent"
            sentinel = EmergencyStopSentinel(sentinel_path)
            assert sentinel.is_active() is False

    def test_is_active_fail_closed_on_directory(self):
        with tempfile.TemporaryDirectory() as td:
            sentinel_path = Path(td) / "emergency_stop"
            sentinel_path.mkdir()  # It's a directory, not a file
            sentinel = EmergencyStopSentinel(sentinel_path)
            # Fail closed - directory instead of file -> active
            assert sentinel.is_active() is True

    def test_get_status(self):
        with tempfile.TemporaryDirectory() as td:
            sentinel_path = Path(td) / "emergency_stop"
            sentinel = EmergencyStopSentinel(sentinel_path)
            status = sentinel.get_status()
            assert status["active"] is False
            assert status["configured"] is False
            assert status["reason"] == "none"
            sentinel_path.write_text(json.dumps({"reason": "test"}))
            status = sentinel.get_status()
            assert status["active"] is True
            assert status["configured"] is True
            assert status["reason"] == "manual"

    def test_activate(self):
        with tempfile.TemporaryDirectory() as td:
            sentinel_path = Path(td) / "emergency_stop"
            sentinel = EmergencyStopSentinel(sentinel_path)
            assert sentinel.activate("test_reason") is True
            assert sentinel_path.exists()
            content = json.loads(sentinel_path.read_text())
            assert content["reason"] == "test_reason"
            assert "activated_at" in content

    def test_deactivate(self):
        with tempfile.TemporaryDirectory() as td:
            sentinel_path = Path(td) / "emergency_stop"
            sentinel = EmergencyStopSentinel(sentinel_path)
            sentinel.activate("test")
            assert sentinel.deactivate() is True
            assert not sentinel_path.exists()
            assert sentinel.is_active() is False

    def test_deactivate_when_missing(self):
        with tempfile.TemporaryDirectory() as td:
            sentinel_path = Path(td) / "emergency_stop"
            sentinel = EmergencyStopSentinel(sentinel_path)
            # Deactivating when not active should still return True
            assert sentinel.deactivate() is True

    def test_activate_creates_parent_dirs(self):
        with tempfile.TemporaryDirectory() as td:
            sentinel_path = Path(td) / "nested" / "dir" / "emergency_stop"
            sentinel = EmergencyStopSentinel(sentinel_path)
            assert sentinel.activate("test") is True
            assert sentinel_path.exists()


class TestComputeWorkspaceFingerprint:
    """Tests for compute_workspace_fingerprint and verify_workspace_fingerprint."""

    def test_compute_fingerprint_basic(self):
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            # Create a config file
            (workspace / "pyproject.toml").write_text("[tool.poetry]\nname = 'test'\n")
            fp = compute_workspace_fingerprint(workspace)
            assert isinstance(fp, WorkspaceFingerprint)
            assert fp.fingerprint != ""
            assert fp.workspace_id != ""
            assert fp.version == 1

    def test_compute_fingerprint_with_git(self):
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            # Initialize git repo
            os.system(f"cd '{workspace}' && git init -q && git config user.email 'test@test.com' && git config user.name 'Test' && echo 'test' > README.md && git add . && git commit -q -m 'init'")
            fp = compute_workspace_fingerprint(workspace)
            # Should include git commit in fingerprint
            assert fp.fingerprint != ""

    def test_verify_fingerprint_match(self):
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            (workspace / "pyproject.toml").write_text("name = 'test'")
            fp = compute_workspace_fingerprint(workspace)
            match, actual = verify_workspace_fingerprint(workspace, fp.fingerprint)
            assert match is True
            assert actual is None

    def test_verify_fingerprint_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            (workspace / "pyproject.toml").write_text("name = 'test'")
            match, actual = verify_workspace_fingerprint(workspace, "wrong_hash")
            assert match is False
            assert actual is not None


class TestAuditChainFunctions:
    """Tests for module-level audit chain functions."""

    def test_create_audit_chain(self):
        chain = create_audit_chain()
        assert isinstance(chain, AuditChain)
        assert len(chain.entries) == 0

    def test_load_save_audit_chain(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "chain.json"
            chain = create_audit_chain()
            chain.add_entry("op1", "id1", {"a": 1})
            assert save_audit_chain(chain, path) is True
            loaded = load_audit_chain(path)
            assert loaded is not None
            assert len(loaded.entries) == 1
            assert loaded.entries[0].operation == "op1"

    def test_load_nonexistent_chain(self):
        assert load_audit_chain(Path("/nonexistent/path/chain.json")) is None

    def test_load_corrupt_chain(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "bad.json"
            path.write_text("not json")
            assert load_audit_chain(path) is None

    def test_verify_audit_chain(self):
        chain = create_audit_chain()
        chain.add_entry("op1", "id1", {"a": 1})
        valid, error = verify_audit_chain(chain)
        assert valid is True
        assert error is None

    def test_append_audit_entry(self):
        chain = create_audit_chain()
        entry = append_audit_entry(chain, "test_op", "op1", {"data": "value"})
        assert len(chain.entries) == 1
        assert entry.operation == "test_op"
        assert entry.operation_id == "op1"


class TestEmergencyStopFunctions:
    """Tests for module-level emergency stop functions."""

    def test_check_emergency_stop_inactive(self):
        with tempfile.TemporaryDirectory() as td:
            sentinel_path = Path(td) / "emergency_stop"
            # Need to reset the global singleton
            import textforensics.workspace_integrity as wi
            wi._emergency_sentinel = None
            sentinel = get_emergency_sentinel(sentinel_path)
            assert check_emergency_stop() is False

    def test_activate_deactivate_emergency_stop(self):
        with tempfile.TemporaryDirectory() as td:
            sentinel_path = Path(td) / "emergency_stop"
            import textforensics.workspace_integrity as wi
            wi._emergency_sentinel = None
            assert activate_emergency_stop("test") is True
            assert check_emergency_stop() is True
            assert deactivate_emergency_stop() is True
            assert check_emergency_stop() is False

    def test_get_emergency_singleton(self):
        import textforensics.workspace_integrity as wi
        wi._emergency_sentinel = None
        sentinel1 = get_emergency_sentinel()
        sentinel2 = get_emergency_sentinel()
        assert sentinel1 is sentinel2


class TestWorkspaceIntegrityReport:
    """Tests for WorkspaceIntegrityReport."""

    def test_to_dict_and_load(self):
        with tempfile.TemporaryDirectory() as td:
            fp = WorkspaceFingerprint(
                version=1,
                workspace_id="ws1",
                fingerprint="hash123",
                created_at="2024-01-01T00:00:00Z",
                source_path="/tmp",
            )
            report = WorkspaceIntegrityReport(
                workspace_fingerprint=fp,
                fingerprint_verified=True,
                audit_chain_valid=True,
                audit_chain_length=5,
                emergency_stop_active=False,
                emergency_stop_configured=False,
                emergency_stop_reason=None,
                overall_status="healthy",
            )
            path = Path(td) / "report.json"
            assert report.save(path) is True
            loaded = WorkspaceIntegrityReport.load(path)
            assert loaded is not None
            assert loaded.fingerprint_verified is True
            assert loaded.audit_chain_valid is True
            assert loaded.audit_chain_length == 5
            assert loaded.overall_status == "healthy"

    def test_load_corrupt_report(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "bad.json"
            path.write_text("not json")
            assert WorkspaceIntegrityReport.load(path) is None


class TestVerifyWorkspaceIntegrity:
    """Tests for verify_workspace_integrity function."""

    def test_verify_healthy(self):
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            (workspace / "pyproject.toml").write_text("name = 'test'")
            report = verify_workspace_integrity(workspace)
            assert report.fingerprint_verified is True
            assert report.audit_chain_valid is True
            assert report.emergency_stop_active is False
            assert report.overall_status == "healthy"

    def test_verify_with_expected_fingerprint(self):
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            (workspace / "pyproject.toml").write_text("name = 'test'")
            fp = compute_workspace_fingerprint(workspace)
            report = verify_workspace_integrity(workspace, expected_fingerprint=fp.fingerprint)
            assert report.fingerprint_verified is True
            report2 = verify_workspace_integrity(workspace, expected_fingerprint="wrong")
            assert report2.fingerprint_verified is False
            assert report2.overall_status == "compromised"

    def test_verify_with_audit_chain(self):
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            (workspace / "pyproject.toml").write_text("name = 'test'")
            chain = create_audit_chain()
            chain.add_entry("op1", "id1", {"a": 1})
            chain_path = workspace / "audit_chain.json"
            save_audit_chain(chain, chain_path)
            report = verify_workspace_integrity(workspace, audit_chain_path=chain_path)
            assert report.audit_chain_valid is True
            assert report.audit_chain_length == 1

    def test_verify_corrupt_audit_chain(self):
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            (workspace / "pyproject.toml").write_text("name = 'test'")
            chain = create_audit_chain()
            chain.add_entry("op1", "id1", {"a": 1})
            e1 = chain.entries[0]
            corrupted_entry = AuditChainEntry(
                index=e1.index,
                timestamp=e1.timestamp,
                operation=e1.operation,
                operation_id=e1.operation_id,
                payload_hash=e1.payload_hash,
                previous_hash=e1.previous_hash,
                entry_hash="corrupted",
                metadata=e1.metadata,
            )
            chain.entries[0] = corrupted_entry
            chain_path = workspace / "audit_chain.json"
            save_audit_chain(chain, chain_path)
            report = verify_workspace_integrity(workspace, audit_chain_path=chain_path)
            assert report.audit_chain_valid is False
            assert report.overall_status == "compromised"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])