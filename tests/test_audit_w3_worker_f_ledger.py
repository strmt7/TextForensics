"""W3 Worker F (recovery) kill tests for ledger (audit-w3-f).

Each test kills one proof survivor from the W3 re-proof
(hidden_files/audit-w3-f2-survivors-ledger.json): the test asserts
the original behaviour on a distinguishing input, so the mutant
fails it. The distinguishing inputs are reversed-order values for
the ``!=`` -> ``<`` / ``>`` mutants (a lesser value kills ``>``, a
greater value kills ``<``), distinct-object values for the ``is`` /
``is not`` mutants, and exact line numbers for the ``enumerate``
mutants. See hidden_files/audit-w3-worker-f.md §5 for the
per-mutant kill evidence (mutate_code re-proof) and §6 for the
proven-equivalent survivors (the 11 postponed-evaluation
``str | Path`` annotation entries).
"""

import json
from dataclasses import replace
from pathlib import Path

import pytest

from textforensics.ledger import (
    AuditLog,
    AuditLogError,
    _compute_entry_hash,
)


def _two_record_log(log_path: Path) -> AuditLog:
    log = AuditLog(log_path)
    log.append("scan", input_data={"text": "test1"})
    log.append("report", input_data={"text": "test2"})
    return log


def _rewrite_line(log_path: Path, line_no: int, mutate) -> None:
    """Rewrite one JSON line, recomputing its entry hash so only the
    targeted structural property is under test."""
    lines = log_path.read_text(encoding="utf-8").splitlines()
    data = json.loads(lines[line_no])
    mutate(data)
    data["entry_hash"] = _compute_entry_hash(data)
    lines[line_no] = json.dumps(data, separators=(",", ":"), sort_keys=True)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _hex_inc(value: str) -> str:
    return format(int(value, 16) + 1, "064x")


def _hex_dec(value: str) -> str:
    return format(int(value, 16) - 1, "064x")


class TestWorkerFLedgerLoadKill:
    """Kill the _load survivors (line-ordered distinguishing inputs)."""

    def test_load_rejects_lesser_genesis_predecessor(self, tmp_path: Path):
        """NotEq_Gt [376,61]: a first entry whose prev_hash is
        lexicographically LESS than the all-zero genesis hash must
        still reject. The mutant (``>``) only rejects greater values,
        so it loads the log."""
        log_path = tmp_path / "audit.log"
        _two_record_log(log_path)
        # "/" (0x2f) sorts below "0" (0x30): strictly less, not equal.
        _rewrite_line(log_path, 0, lambda d: d.update(prev_hash="/" * 64))
        with pytest.raises(AuditLogError, match="genesis"):
            AuditLog(log_path)

    def test_load_rejects_lesser_second_index(self, tmp_path: Path):
        """NotEq_Gt [383,35]: a second entry numbered below the
        expected contiguous index must reject. The mutant (``>``)
        only rejects greater indices, so it loads the log."""
        log_path = tmp_path / "audit.log"
        _two_record_log(log_path)
        _rewrite_line(log_path, 1, lambda d: d.update(index=0))
        with pytest.raises(AuditLogError, match="index"):
            AuditLog(log_path)

    def test_load_rejects_greater_prev_hash(self, tmp_path: Path):
        """NotEq_Lt [389,57] and NotEq_Is [389,57]: a second entry
        whose prev_hash is lexicographically GREATER than the first
        entry's hash must reject. The ``<`` mutant only rejects
        lesser values; the ``is`` mutant never rejects distinct
        strings — both load the log."""
        log_path = tmp_path / "audit.log"
        log = _two_record_log(log_path)
        last = log._entries[0].entry_hash
        _rewrite_line(log_path, 1, lambda d: d.update(prev_hash=_hex_inc(last)))
        with pytest.raises(AuditLogError, match="chain broken"):
            AuditLog(log_path)

    def test_load_rejects_lesser_prev_hash(self, tmp_path: Path):
        """NotEq_Gt [389,57]: a second entry whose prev_hash is
        lexicographically LESS than the first entry's hash must
        reject. The mutant (``>``) only rejects greater values, so
        it loads the log."""
        log_path = tmp_path / "audit.log"
        log = _two_record_log(log_path)
        last = log._entries[0].entry_hash
        _rewrite_line(log_path, 1, lambda d: d.update(prev_hash=_hex_dec(last)))
        with pytest.raises(AuditLogError, match="chain broken"):
            AuditLog(log_path)

    def test_load_blank_line_then_valid_entry(self, tmp_path: Path):
        """ReplaceContinueWithBreak [371,20]: a blank line must be
        skipped, not end the load. The mutant breaks the loop, so
        the following valid entry is never loaded."""
        log_path = tmp_path / "audit.log"
        log = AuditLog(log_path)
        log.append("scan", input_data={"text": "test1"})
        lines = log_path.read_text(encoding="utf-8").splitlines()
        log_path.write_text("\n" + "\n".join(lines) + "\n", encoding="utf-8")
        assert len(AuditLog(log_path)) == 1

    def test_load_error_reports_exact_line_number(self, tmp_path: Path):
        """NumberReplacer [368,47] occ 20/21 (``enumerate(f, 1)``):
        the malformed line is line 3, and the error must say so.
        The ``1`` -> ``2`` mutant reports line 4; ``1`` -> ``0``
        reports line 2."""
        log_path = tmp_path / "audit.log"
        _two_record_log(log_path)
        with log_path.open("a", encoding="utf-8") as f:
            f.write("not valid json\n")
        with pytest.raises(AuditLogError) as excinfo:
            AuditLog(log_path)
        assert "line 3" in str(excinfo.value)

    def test_load_large_equal_index_is_not_identity(self, tmp_path: Path):
        """NotEq_IsNot [383,35]: indices are compared by VALUE, not
        identity. At index 300 the JSON-parsed int and ``len()`` are
        distinct objects (small-int caching ends at 256), so the
        ``is not`` mutant raises on a perfectly valid 301-entry log
        while the original loads it."""
        log_path = tmp_path / "audit.log"
        log = AuditLog(log_path)
        for i in range(301):
            log.append("scan", input_data={"text": f"test{i}"})
        assert len(AuditLog(log_path)) == 301


class TestWorkerFLedgerVerifyChainKill:
    """Kill the verify_chain survivors (in-memory tampered entries)."""

    def test_verify_chain_large_equal_index_is_not_identity(self, tmp_path: Path):
        """NotEq_IsNot [514,27]: in-memory indices are compared by
        VALUE, not identity. At index 300 the stored int and
        ``enumerate``'s int are distinct objects (small-int caching
        ends at 256), so the ``is not`` mutant rejects a perfectly
        valid 301-entry log while the original verifies it."""
        log_path = tmp_path / "audit.log"
        log = AuditLog(log_path)
        for i in range(301):
            log.append("scan", input_data={"text": f"test{i}"})
        assert log.verify_chain() is True

    def test_verify_chain_rejects_lesser_second_index(self, tmp_path: Path):
        """NotEq_Gt [514,27]: a second entry numbered below its
        expected index must fail verification. The mutant (``>``)
        only rejects greater indices, so it verifies."""
        log = _two_record_log(tmp_path / "audit.log")
        renumbered = replace(log._entries[1], index=0)
        renumbered = replace(renumbered, entry_hash=_compute_entry_hash(renumbered.to_dict()))
        log._entries[1] = renumbered
        assert log.verify_chain() is False

    def test_verify_chain_rejects_zero_predecessor(self, tmp_path: Path):
        """NotEq_Gt [516,31]: a second entry whose prev_hash is the
        all-zero genesis hash (lexicographically less than the first
        entry's hash) must fail verification. The mutant (``>``)
        only rejects greater predecessors, so it verifies."""
        log = _two_record_log(tmp_path / "audit.log")
        relinked = replace(log._entries[1], prev_hash="0" * 64)
        relinked = replace(relinked, entry_hash=_compute_entry_hash(relinked.to_dict()))
        log._entries[1] = relinked
        assert log.verify_chain() is False

    def test_verify_chain_rejects_greater_entry_hash(self, tmp_path: Path):
        """NotEq_Lt [518,32], NotEq_Is [518,32] and
        ReplaceFalseWithTrue [519,23]: a second entry whose
        entry_hash is lexicographically GREATER than its recomputed
        hash must fail verification. The ``<`` mutant only rejects
        lesser hashes, the ``is`` mutant never rejects distinct
        strings, and the ``return False`` -> ``True`` mutant returns
        True — all three verify the tampered chain."""
        log = _two_record_log(tmp_path / "audit.log")
        real = _compute_entry_hash(log._entries[1].to_dict())
        tampered = replace(log._entries[1], entry_hash=_hex_inc(real))
        log._entries[1] = tampered
        assert log.verify_chain() is False

    def test_verify_chain_rejects_lesser_entry_hash(self, tmp_path: Path):
        """NotEq_Gt [518,32]: a second entry whose entry_hash is
        lexicographically LESS than its recomputed hash must fail
        verification. The mutant (``>``) only rejects greater
        hashes, so it verifies."""
        log = _two_record_log(tmp_path / "audit.log")
        real = _compute_entry_hash(log._entries[1].to_dict())
        tampered = replace(log._entries[1], entry_hash=_hex_dec(real))
        log._entries[1] = tampered
        assert log.verify_chain() is False
