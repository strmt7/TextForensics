"""Tests for tamper-evident audit log."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from textforensics.ledger import (
    AuditLog,
    AuditLogEntry,
    AuditLogError,
    _compute_entry_hash,
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


class TestVerifyAuditLogGenesisC07:
    """C07: the public wrapper must not discard a detected missing genesis
    or a non-contiguous index.

    The class-level ``verify_chain()`` already detects a non-genesis first
    entry (its predecessor loop starts from the zero genesis hash), but
    ``verify_audit_log`` collected that failure and returned valid anyway.
    These tests compare the class decision with the wrapper decision for
    every mutation: they must agree, and both must reject.
    """

    @staticmethod
    def _two_record_log(log_path: Path) -> AuditLog:
        log = AuditLog(log_path)
        log.append("scan", input_data={"text": "test1"})
        log.append("report", input_data={"text": "test2"})
        return log

    @staticmethod
    def _rewrite_line(log_path: Path, line_no: int, mutate) -> None:
        lines = log_path.read_text(encoding="utf-8").splitlines()
        data = json.loads(lines[line_no])
        mutate(data)
        # Recompute the entry hash over the mutated content so that only
        # the targeted structural property (genesis / index) is under
        # test, not a stale entry hash. ``prev_hash`` is excluded from
        # the entry hash, so mutating it needs no recomputation.
        data["entry_hash"] = _compute_entry_hash(data)
        lines[line_no] = json.dumps(data, separators=(",", ":"), sort_keys=True)
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_prefix_deletion_load_rejects_non_genesis(self, tmp_path: Path):
        """Deleting the first line leaves a first entry that is not genesis."""
        log_path = tmp_path / "audit.log"
        self._two_record_log(log_path)
        lines = log_path.read_text(encoding="utf-8").splitlines(keepends=True)
        log_path.write_text("".join(lines[1:]), encoding="utf-8")

        with pytest.raises(AuditLogError, match="genesis"):
            AuditLog(log_path)

    def test_prefix_deletion_wrapper_reports_invalid(self, tmp_path: Path):
        """The wrapper must report the prefix-deleted log invalid, with errors."""
        log_path = tmp_path / "audit.log"
        self._two_record_log(log_path)
        lines = log_path.read_text(encoding="utf-8").splitlines(keepends=True)
        log_path.write_text("".join(lines[1:]), encoding="utf-8")

        result = verify_audit_log(log_path)
        assert result["valid"] is False
        assert result["entry_count"] == 0
        assert result["errors"]
        assert any("genesis" in error.lower() for error in result["errors"])

    def test_replaced_first_predecessor_rejected(self, tmp_path: Path):
        """First entry whose prev_hash is not the zero genesis hash rejects."""
        log_path = tmp_path / "audit.log"
        self._two_record_log(log_path)
        self._rewrite_line(log_path, 0, lambda data: data.update(prev_hash="f" * 64))

        with pytest.raises(AuditLogError, match="genesis"):
            AuditLog(log_path)

        result = verify_audit_log(log_path)
        assert result["valid"] is False
        assert result["errors"]
        assert any("genesis" in error.lower() for error in result["errors"])

    def test_altered_starting_index_single_entry_rejected(self, tmp_path: Path):
        """A single-entry log whose first index is not 0 rejects."""
        log_path = tmp_path / "audit.log"
        log = AuditLog(log_path)
        log.append("scan", input_data={"text": "test1"})
        self._rewrite_line(log_path, 0, lambda data: data.update(index=1))

        with pytest.raises(AuditLogError, match="index"):
            AuditLog(log_path)

        result = verify_audit_log(log_path)
        assert result["valid"] is False
        assert result["errors"]
        assert any("index" in error.lower() for error in result["errors"])

    def test_index_gap_in_second_entry_rejected(self, tmp_path: Path):
        """Indices must be contiguous: 0, 1 -- a second entry numbered 5 rejects."""
        log_path = tmp_path / "audit.log"
        self._two_record_log(log_path)
        self._rewrite_line(log_path, 1, lambda data: data.update(index=5))

        with pytest.raises(AuditLogError, match="index"):
            AuditLog(log_path)

        result = verify_audit_log(log_path)
        assert result["valid"] is False
        assert result["errors"]
        assert any("index" in error.lower() for error in result["errors"])

    def test_verify_chain_detects_genesis_and_index_gap_in_memory(self, tmp_path: Path):
        """verify_chain itself must fail on a non-genesis predecessor and on
        a non-contiguous index, not only on broken links / bad entry hashes.
        The index mutation recomputes the entry hash, so only the index
        -- not a stale hash -- is under test."""
        log_path = tmp_path / "audit.log"
        log = self._two_record_log(log_path)
        assert log.verify_chain() is True

        mutated = replace(log._entries[0], prev_hash="f" * 64)
        log._entries[0] = mutated
        assert log.verify_chain() is False

        log2 = self._two_record_log(tmp_path / "audit2.log")
        assert log2.verify_chain() is True
        renumbered = replace(log2._entries[1], index=7)
        renumbered = replace(renumbered, entry_hash=_compute_entry_hash(renumbered.to_dict()))
        log2._entries[1] = renumbered
        assert log2.verify_chain() is False

    def test_missing_file_is_invalid_not_empty(self, tmp_path: Path):
        """Missing-file vs intentionally empty-log semantics: verifying a
        log file that does not exist is invalid (fail closed); an existing
        empty file is a valid empty log. Creating a new log from a missing
        path still works -- that is the AuditLog constructor's job, not
        the verifier's."""
        missing = tmp_path / "no-such-audit.log"

        result = verify_audit_log(missing)
        assert result["valid"] is False
        assert result["entry_count"] == 0
        assert result["first_entry_hash"] is None
        assert result["last_entry_hash"] is None
        assert result["errors"]
        assert any("not exist" in error or "missing" in error.lower() for error in result["errors"])

        # Construction semantics are unchanged: a missing path is a new log.
        assert len(AuditLog(missing)) == 0

    def test_empty_file_is_valid_empty_log(self, tmp_path: Path):
        """An existing but empty log file is a valid empty log."""
        log_path = tmp_path / "audit.log"
        log_path.touch()

        result = verify_audit_log(log_path)
        assert result["valid"] is True
        assert result["entry_count"] == 0
        assert result["first_entry_hash"] is None
        assert result["last_entry_hash"] is None
        assert result["errors"] == []

    def test_intact_multirecord_control(self, tmp_path: Path):
        """Intact control: class and wrapper agree the log is valid."""
        log_path = tmp_path / "audit.log"
        log = AuditLog(log_path)
        log.append("scan", input_data={"text": "test1"})
        log.append("report", input_data={"text": "test2"})
        log.append("verify", input_data={"text": "test3"})

        assert log.verify_chain() is True

        result = verify_audit_log(log_path)
        assert result["valid"] is True
        assert result["entry_count"] == 3
        assert result["first_entry_hash"] == log._entries[0].entry_hash
        assert result["last_entry_hash"] == log._entries[-1].entry_hash
        assert result["errors"] == []


class TestAuditLogTransactionsC15:
    """C15: appends are lock reload/check/advance/persist transactions.

    Reproduction (pre-W4): two instances created before either appends
    stored indices [0, 0]; an append whose disk write failed still
    advanced the in-memory head, so the next successful append stored
    index 2 after index 0 and the reloaded chain failed verification.
    """

    def test_two_stale_instances_append_serially(self, tmp_path: Path):
        """Two instances created before either appends must store
        contiguous indices: the second append reloads under the file
        lock and derives its index from the durable head, not its
        stale cache."""
        log_path = tmp_path / "audit.log"
        first = AuditLog(log_path)
        second = AuditLog(log_path)
        entry1 = first.append("op-a", input_data={"x": 1})
        entry2 = second.append("op-b", input_data={"x": 2})

        assert (entry1.index, entry2.index) == (0, 1)
        assert entry2.prev_hash == entry1.entry_hash
        lines = [json.loads(line) for line in log_path.read_text().splitlines()]
        assert [entry["index"] for entry in lines] == [0, 1]
        assert AuditLog(log_path).verify_chain() is True
        result = verify_audit_log(log_path)
        assert result["valid"] is True
        assert result["entry_count"] == 2

    def test_failed_append_does_not_advance_head(self, tmp_path: Path, monkeypatch):
        """An append whose disk write raises must not advance the
        in-memory head: the next append re-derives index 1 from disk
        and the reloaded chain stays contiguous."""
        log_path = tmp_path / "audit.log"
        log = AuditLog(log_path)
        log.append("op-0", input_data={"x": 0})
        assert len(log) == 1
        head_hash = log._entries[-1].entry_hash

        def _boom(entry):
            raise OSError("injected disk failure")

        monkeypatch.setattr(log, "_append_to_file", _boom)
        with pytest.raises(OSError, match="injected disk failure"):
            log.append("op-1", input_data={"x": 1})
        # The failed write left the in-memory head untouched and
        # persisted nothing.
        assert len(log) == 1
        assert log._entries[-1].entry_hash == head_hash
        assert len(log_path.read_text().splitlines()) == 1

        monkeypatch.undo()
        entry = log.append("op-1-retry", input_data={"x": 1})
        assert entry.index == 1
        assert entry.prev_hash == head_hash
        reloaded = AuditLog(log_path)
        assert len(reloaded) == 2
        assert reloaded.verify_chain() is True
        assert verify_audit_log(log_path)["valid"] is True

    def test_failed_fsync_leaves_prior_state_recoverable(self, tmp_path: Path, monkeypatch):
        """A write that lands on disk but whose fsync fails is not
        acknowledged (the in-memory head does not advance), yet the
        next append reloads the durable state and continues from it
        instead of reusing the unacknowledged index."""
        log_path = tmp_path / "audit.log"
        log = AuditLog(log_path)
        log.append("op-0", input_data={"x": 0})

        def _boom_fsync(_fd):
            raise OSError("injected fsync failure")

        monkeypatch.setattr(os, "fsync", _boom_fsync)
        with pytest.raises(OSError, match="injected fsync failure"):
            log.append("op-1", input_data={"x": 1})
        assert len(log) == 1
        monkeypatch.undo()

        entry = log.append("op-2", input_data={"x": 2})
        assert entry.index == 2
        lines = [json.loads(line) for line in log_path.read_text().splitlines()]
        assert [entry["index"] for entry in lines] == [0, 1, 2]
        assert AuditLog(log_path).verify_chain() is True

    def test_append_to_corrupt_log_refuses_and_keeps_head(self, tmp_path: Path):
        """Appending to a log that became corrupt on disk refuses
        (fail closed) instead of appending onto corruption, and the
        prior in-memory state is untouched."""
        log_path = tmp_path / "audit.log"
        log = AuditLog(log_path)
        log.append("op-0", input_data={"x": 0})

        lines = log_path.read_text().splitlines()
        data = json.loads(lines[0])
        data["operation"] = "tampered"
        lines[0] = json.dumps(data, separators=(",", ":"), sort_keys=True)
        log_path.write_text("\n".join(lines) + "\n")

        with pytest.raises(AuditLogError):
            log.append("op-1", input_data={"x": 1})
        assert len(log) == 1

    def test_concurrent_instances_append_contiguously(self, tmp_path: Path):
        """Bounded cross-thread test: 4 instances x 10 appends each.
        The outcome (contiguous 0..39, verifiable chain) must hold for
        any interleaving; no timing assertions are made."""
        log_path = tmp_path / "audit.log"
        errors: list[BaseException] = []

        def _worker(instance_no: int) -> None:
            try:
                log = AuditLog(log_path)
                for i in range(10):
                    log.append(f"op-{instance_no}-{i}", input_data={"n": i})
            except BaseException as exc:  # noqa: BLE001 -- collected, re-raised below
                errors.append(exc)

        threads = [threading.Thread(target=_worker, args=(n,)) for n in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert errors == []
        lines = [json.loads(line) for line in log_path.read_text().splitlines()]
        assert [entry["index"] for entry in lines] == list(range(40))
        assert AuditLog(log_path).verify_chain() is True
        assert verify_audit_log(log_path)["valid"] is True


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
