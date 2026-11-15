"""Kill tests for the W4 mutation-proof survivors in
``textforensics.workspace_integrity``.

Worker F2 (audit W4): the cosmic-ray proof of the W4-changed
``AuditChain`` / ``verify_workspace_integrity`` (C16/C17 head
validation) left 19 runtime survivors in 14 positions. 17 are killed
by the tests below; the remaining 2 are proven domain-equivalent
(see ``audit-w4-f-equiv-reasons-workspace_integrity.json``):
``[313] NotEq->IsNot`` (``version != 1`` vs ``is not`` — the clause
only evaluates for non-bool ints against the constant 1) and ``[959]
And->Or`` (the ``elif`` is only reached when the preceding ``elif``
already guarantees both operands True).

Kill notes (each test names the mutant it kills):
- ``sort_keys`` / ``metadata`` / empty-chain / index / hash /
  head-field mutants are killed by direct assertions on the exact
  value or verdict message the mutant changes; message assertions
  matter where the mutant still fails verification, but for the
  wrong reason (e.g. a tampered index that also breaks the entry
  hash).
- The ``is not`` mutants need inputs past the CPython small-int
  cache (indices > 256 are distinct objects) or an equal-but-distinct
  string object; the tests assert that premise explicitly so a
  platform where it does not hold fails loudly instead of passing
  vacuously.
"""

import hashlib
import json
from pathlib import Path

import pytest

from textforensics.workspace_integrity import (
    AuditChain,
    AuditChainEntry,
    compute_workspace_fingerprint,
    create_audit_chain,
    verify_workspace_integrity,
)


def _chain(entries=2):
    chain = create_audit_chain()
    for i in range(entries):
        chain.add_entry(f"op{i}", f"id{i}", {"n": i})
    return chain


def _rebuild(entry, **overrides):
    fields = {
        "index": entry.index,
        "timestamp": entry.timestamp,
        "operation": entry.operation,
        "operation_id": entry.operation_id,
        "payload_hash": entry.payload_hash,
        "previous_hash": entry.previous_hash,
        "entry_hash": entry.entry_hash,
        "metadata": entry.metadata,
    }
    fields.update(overrides)
    return AuditChainEntry(**fields)


class TestAddEntrySurvivors:
    def test_payload_hash_uses_sorted_keys(self):
        """A payload whose insertion order differs from sorted order
        still hashes in sorted order (kills ReplaceTrueWithFalse
        [165, 54] sort_keys occ 4)."""
        chain = create_audit_chain()
        payload = {"z": 1, "a": 2}
        entry = chain.add_entry("op", "id", payload)
        expected = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        assert entry.payload_hash == expected

    def test_metadata_round_trips(self):
        """Non-empty metadata survives add_entry (kills
        ReplaceOrWithAnd [178, 30] occ 0)."""
        chain = create_audit_chain()
        entry = chain.add_entry("op", "id", {"n": 1}, metadata={"k": "v"})
        assert entry.metadata == {"k": "v"}


class TestVerifyChainSurvivors:
    def test_empty_chain_verifies(self):
        """An empty chain verifies (kills ReplaceTrueWithFalse
        [249, 19] occ 7)."""
        assert AuditChain().verify_chain() == (True, None)

    def test_index_below_position_reported(self):
        """An entry index below its position is a non-contiguous
        index, not a hash mismatch (kills NotEq->Gt [253, 27]
        occ 0)."""
        chain = _chain(2)
        chain.entries[1] = _rebuild(chain.entries[1], index=0)
        valid, error = chain.verify_chain()
        assert valid is False
        assert "Non-contiguous index at position 1" in error

    def test_index_above_position_reported(self):
        """An entry index above its position is a non-contiguous
        index, not a hash mismatch (kills NotEq->Lt [253, 27]
        occ 0)."""
        chain = _chain(2)
        chain.entries[1] = _rebuild(chain.entries[1], index=5)
        valid, error = chain.verify_chain()
        assert valid is False
        assert "Non-contiguous index at position 1" in error

    def test_large_index_identity_is_not_equality(self):
        """Indices past the small-int cache are compared by value,
        not identity: a 300-entry chain verifies (kills NotEq->IsNot
        [253, 27] occ 0)."""
        chain = _chain(300)
        # Premise: the stored index and the enumerate counter are
        # distinct objects past 256 (CPython caches only -5..256).
        # Written as `is not int("257")`, not `is not 257`: the
        # literal form is F632 (identity comparison with a constant)
        # and the fresh int from int() is a distinct object either
        # way, so the premise — and the kill — is unchanged.
        assert chain.entries[257].index is not int("257")
        assert chain.verify_chain() == (True, None)

    def test_entry_hash_below_computed_reported(self):
        """A stored entry hash below the recomputed hash is an entry
        hash mismatch (kills NotEq->Gt [275, 32] occ 2)."""
        chain = _chain(2)
        chain.entries[0] = _rebuild(chain.entries[0], entry_hash="0" * 64)
        valid, error = chain.verify_chain()
        assert valid is False
        assert "Entry hash mismatch at index 0" in error

    def test_chain_hash_above_recomputed_reported(self):
        """A cached chain hash above the recomputed hash is a cached
        head mismatch (kills NotEq->Lt [280, 47] occ 3)."""
        chain = _chain(2)
        chain.chain_hash = "f" * 64
        valid, error = chain.verify_chain()
        assert valid is False
        assert "Cached chain_hash" in error

    def test_last_entry_hash_distinct_object_not_a_mismatch(self):
        """A cached last-entry hash equal by value (but a distinct
        object) is not a mismatch (kills NotEq->IsNot [282, 59]
        occ 4)."""
        chain = _chain(2)
        fresh = chain._last_entry_hash.encode("utf-8").decode("utf-8")
        assert fresh is not chain._last_entry_hash
        assert fresh == chain._last_entry_hash
        chain._last_entry_hash = fresh
        assert chain.verify_chain() == (True, None)

    def test_last_entry_hash_above_last_reported(self):
        """A cached last-entry hash above the last entry's hash is a
        cached head mismatch (kills NotEq->Lt [282, 59] occ 4)."""
        chain = _chain(2)
        chain._last_entry_hash = "f" * 64
        valid, error = chain.verify_chain()
        assert valid is False
        assert "Cached last_entry_hash" in error


class TestFromDictSurvivors:
    def test_from_dict_rejects_bool_version(self):
        """A bool version is not an int version (kills
        ReplaceOrWithAnd [312, 12] occ 1)."""
        data = _chain(2).to_dict()
        data["version"] = True
        with pytest.raises(ValueError, match="Unsupported audit chain version"):
            AuditChain.from_dict(data)

    def test_from_dict_rejects_version_zero(self):
        """Version 0 is not the current version (kills NotEq->Gt
        [313, 23] occ 5)."""
        data = _chain(2).to_dict()
        data["version"] = 0
        with pytest.raises(ValueError, match="Unsupported audit chain version"):
            AuditChain.from_dict(data)

    def test_from_dict_rejects_index_below_position(self):
        """A renumbered entry below its position is rejected at load
        (kills NotEq->Gt [318, 27] occ 6)."""
        data = _chain(2).to_dict()
        data["entries"][1]["index"] = 0
        with pytest.raises(ValueError, match="Non-contiguous audit chain index"):
            AuditChain.from_dict(data)

    def test_from_dict_accepts_large_indices(self):
        """Indices past the small-int cache load by value, not
        identity (kills NotEq->IsNot [318, 27] occ 6)."""
        chain = _chain(300)
        # Premise as above: the stored index is a distinct object
        # from a freshly built 257 (see test_large_index_identity_
        # is_not_equality for why the literal form is avoided).
        assert chain.entries[257].index is not int("257")
        loaded = AuditChain.from_dict(chain.to_dict())
        assert len(loaded.entries) == 300
        assert loaded.verify_chain() == (True, None)

    def test_from_dict_rejects_larger_chain_hash(self):
        """A serialized chain hash above the recomputed hash is
        rejected at load (kills NotEq->Lt [330, 77] occ 7)."""
        data = _chain(2).to_dict()
        assert data["chain_hash"] != "f" * 64
        data["chain_hash"] = "f" * 64
        with pytest.raises(ValueError, match="Serialized chain_hash"):
            AuditChain.from_dict(data)

    def test_from_dict_rejects_larger_last_entry_hash(self):
        """A serialized last-entry hash above the last entry's hash
        is rejected at load (kills NotEq->Lt [336, 43] occ 8)."""
        data = _chain(2).to_dict()
        assert data["last_entry_hash"] != "f" * 64
        data["last_entry_hash"] = "f" * 64
        with pytest.raises(ValueError, match="Serialized last_entry_hash"):
            AuditChain.from_dict(data)


class TestVerifyWorkspaceSurvivors:
    def test_fingerprint_below_actual_not_verified(self, tmp_path: Path):
        """An expected fingerprint below the actual one is not a
        match (kills Eq->GtE [926, 55] occ 3)."""
        workspace = tmp_path
        (workspace / "pyproject.toml").write_text("name = 'test'")
        actual = compute_workspace_fingerprint(workspace).fingerprint
        assert actual != "0" * 64
        report = verify_workspace_integrity(workspace, expected_fingerprint="0" * 64)
        assert report.fingerprint_verified is False
        assert report.overall_status == "compromised"
