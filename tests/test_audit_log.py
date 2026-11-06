"""Tests for tamper-evident audit log."""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

import pytest

from textforensics.audit_log import (
    AuditLog,
    AuditLogEntry,
    AuditLogError,
    verify_audit_log,
)


class TestAuditLogEntry:
    def test_entry_roundtrip(self):
        """Entry serialization/deserialization should preserve data."""
        entry = AuditLogEntry(
            index=0,
            timestamp="2024-01-01T00:00:00+00:00",
            operation="scan",
            actor="user1",
            input_hash="a" * 64,
            output_hash="b" * 64,
            metadata={"key": "value"},
            prev_hash="0" * 64,
            entry_hash="c" * 64,
        )

        d = entry.to_dict()
        entry2 = AuditLogEntry.from_dict(d)

        assert entry2.index == entry.index
        assert entry2.timestamp == entry.timestamp
        assert entry2.operation == entry.operation
        assert entry2.actor == entry.actor
        assert entry2.input_hash == entry.input_hash
        assert entry2.output_hash == entry.output_hash
        assert entry2.metadata == entry.metadata
        assert entry2.prev_hash == entry.prev_hash
        assert entry2.entry_hash == entry.entry_hash

    def test_entry_json_line(self):
        """Entry JSON line should be valid JSON."""
        entry = AuditLogEntry(
            index=0,
            timestamp="2024-01-01T00:00:00+00:00",
            operation="scan",
            actor="user1",
            input_hash="a" * 64,
            output_hash="b" * 64,
            metadata={"key": "value"},
            prev_hash="0" * 64,
            entry_hash="c" * 64,
        )

        line = entry.to_json_line()
        data = json.loads(line)
        assert data["index"] == 0
        assert data["operation"] == "scan"


class TestAuditLog:
    def test_empty_log(self):
        """Empty log should be valid."""
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.log"
            log = AuditLog(log_path)
            assert len(log) == 0
            assert log.verify_chain() is True

    def test_append_first_entry(self):
        """First entry should have prev_hash of zeros."""
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.log"
            log = AuditLog(log_path)

            entry = log.append(
                operation="scan",
                actor="user1",
                input_data={"text": "test"},
                output_data={"verdict": "ai_like"},
                metadata={"model": "v1"},
            )

            assert entry.index == 0
            assert entry.prev_hash == "0" * 64
            assert entry.operation == "scan"
            assert entry.actor == "user1"
            assert entry.input_hash is not None
            assert entry.output_hash is not None
            assert entry.metadata == {"model": "v1"}
            assert len(log) == 1

    def test_append_chains_entries(self):
        """Subsequent entries should chain to previous."""
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.log"
            log = AuditLog(log_path)

            entry1 = log.append("scan", input_data={"text": "test1"})
            entry2 = log.append("report", input_data={"text": "test2"})
            entry3 = log.append("verify", input_data={"text": "test3"})

            assert entry1.prev_hash == "0" * 64
            assert entry2.prev_hash == entry1.entry_hash
            assert entry3.prev_hash == entry2.entry_hash

    def test_input_output_hashes(self):
        """Input and output hashes should be computed correctly."""
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.log"
            log = AuditLog(log_path)

            entry = log.append(
                operation="scan",
                input_data={"text": "hello world"},
                output_data={"verdict": "human_like", "score": 0.2},
            )

            # Verify input hash
            expected_input = json.dumps(
                {"text": "hello world"}, separators=(",", ":"), sort_keys=True
            )
            expected_input_hash = hashlib.sha256(expected_input.encode("utf-8")).hexdigest()

            assert entry.input_hash is not None
            assert len(entry.input_hash) == 64
            assert entry.input_hash == expected_input_hash

            assert entry.input_hash is not None
            assert len(entry.input_hash) == 64

    def test_persists_to_disk(self):
        """Entries should persist to disk and load correctly."""
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.log"
            log1 = AuditLog(log_path)
            log1.append("scan", input_data={"text": "test1"})
            log1.append("report", input_data={"text": "test2"})

            # Load from disk
            log2 = AuditLog(log_path)
            assert len(log2) == 2
            assert log2._entries[0].operation == "scan"
            assert log2._entries[1].operation == "report"

    def test_verify_chain(self):
        """Chain verification should pass for valid log."""
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.log"
            log = AuditLog(log_path)
            log.append("scan", input_data={"text": "test1"})
            log.append("report", input_data={"text": "test2"})
            log.append("verify", input_data={"text": "test3"})

            assert log.verify_chain() is True

    def test_tampering_detected(self):
        """Tampered log should fail verification."""
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.log"
            log = AuditLog(log_path)
            log.append("scan", input_data={"text": "test1"})
            log.append("report", input_data={"text": "test2"})

            # Tamper with the file directly
            with log_path.open("r+", encoding="utf-8") as f:
                lines = f.readlines()
                # Modify the operation in the first entry
                data = json.loads(lines[0])
                data["operation"] = "tampered"
                lines[0] = json.dumps(data, separators=(",", ":"), sort_keys=True) + "\n"
                f.seek(0)
                f.writelines(lines)
                f.truncate()

            # Loading should fail
            with pytest.raises(AuditLogError):
                AuditLog(log_path)

    def test_verify_audit_log_function(self):
        """verify_audit_log function should return correct results."""
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.log"
            log = AuditLog(log_path)
            log.append("scan", input_data={"text": "test1"})
            log.append("report", input_data={"text": "test2"})

            result = verify_audit_log(log_path)
            assert result["valid"] is True
            assert result["entry_count"] == 2
            assert result["first_entry_hash"] == log._entries[0].entry_hash
            assert result["last_entry_hash"] == log._entries[-1].entry_hash
            assert result["errors"] == []

    def test_verify_empty_log(self):
        """Empty log should be valid."""
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.log"
            # Create empty file
            log_path.touch()

            result = verify_audit_log(log_path)
            assert result["valid"] is True
            assert result["entry_count"] == 0
            assert result["first_entry_hash"] is None
            assert result["last_entry_hash"] is None

    def test_get_entry(self):
        """Getting entry by index should work."""
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.log"
            log = AuditLog(log_path)
            log.append("scan", input_data={"text": "test1"})
            log.append("report", input_data={"text": "test2"})

            entry = log.get_entry(0)
            assert entry is not None
            assert entry.operation == "scan"

            entry = log.get_entry(1)
            assert entry is not None
            assert entry.operation == "report"

            entry = log.get_entry(10)
            assert entry is None

    def test_get_entries_range(self):
        """Getting range of entries should work."""
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.log"
            log = AuditLog(log_path)
            for i in range(5):
                log.append(f"op{i}", input_data={"i": i})

            entries = log.get_entries(1, 4)
            assert len(entries) == 3
            assert entries[0].operation == "op1"
            assert entries[2].operation == "op3"

    def test_metadata_stored(self):
        """Metadata should be stored with entry."""
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.log"
            log = AuditLog(log_path)

            entry = log.append(
                operation="scan",
                metadata={"model": "v1.0", "threshold": 0.5},
            )

            assert entry.metadata == {"model": "v1.0", "threshold": 0.5}

    def test_no_actor(self):
        """Entry without actor should work."""
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.log"
            log = AuditLog(log_path)

            entry = log.append("scan", input_data={"text": "test"})
            assert entry.actor is None

    def test_none_input_output(self):
        """None input/output should not produce hashes."""
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.log"
            log = AuditLog(log_path)

            entry = log.append("init", input_data=None, output_data=None)
            assert entry.input_hash is None
            assert entry.output_hash is None


class TestAuditLogError:
    def test_audit_log_error_exception(self):
        """AuditLogError should be raised on corruption."""
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.log"
            # Create invalid JSON
            log_path.write_text("not valid json\n")

            with pytest.raises(AuditLogError):
                AuditLog(log_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
