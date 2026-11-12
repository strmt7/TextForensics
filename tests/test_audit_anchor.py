"""Tests for the audit anchor system (rollback detection)."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from textforensics.constants import EXIT_ERROR
from textforensics.ledger import (
    SCHEMA_VERSION,
    AuditAnchor,
    CalibrationChain,
    RollbackError,
    _hash_directory,
    export_audit_anchor,
    verify_audit_anchor,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_file(path: Path, content: str = "x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """Create a fake workspace with calibrations/ and benchmarks/ directories."""
    base = tmp_path / "workspace"
    (base / "calibrations").mkdir(parents=True)
    (base / "benchmarks").mkdir(parents=True)
    _make_file(base / "calibrations" / "det-a.json", '{"threshold": 0.5}')
    _make_file(base / "benchmarks" / "run1.json", '{"auroc": 0.9}')
    return base


# ---------------------------------------------------------------------------
# AuditAnchor serialization
# ---------------------------------------------------------------------------


class TestAuditAnchor:
    def test_to_dict_roundtrip(self):
        anchor = AuditAnchor(
            calibration_artifacts_sha256="a" * 64,
            benchmark_results_sha256="b" * 64,
            detector_versions={"alpha": "1.0"},
            calibration_chain=["c" * 64],
            exported_at="2026-01-01T00:00:00+00:00",
            schema_version=SCHEMA_VERSION,
        )
        data = anchor.to_dict()
        restored = AuditAnchor.from_dict(data)
        assert restored == anchor

    def test_from_dict_defaults(self):
        anchor = AuditAnchor.from_dict(
            {
                "calibration_artifacts_sha256": "a" * 64,
                "benchmark_results_sha256": "b" * 64,
            }
        )
        assert anchor.detector_versions == {}
        assert anchor.calibration_chain == []
        assert anchor.schema_version == SCHEMA_VERSION


# ---------------------------------------------------------------------------
# export_audit_anchor
# ---------------------------------------------------------------------------


class TestExportAuditAnchor:
    def test_export_computes_hashes(self, workspace: Path):
        anchor = export_audit_anchor(base_dir=workspace, detector_versions={})
        assert anchor.calibration_artifacts_sha256 != ""
        assert anchor.benchmark_results_sha256 != ""
        assert anchor.schema_version == SCHEMA_VERSION
        assert anchor.exported_at  # ISO timestamp set

    def test_export_is_deterministic(self, workspace: Path):
        a1 = export_audit_anchor(base_dir=workspace, detector_versions={})
        a2 = export_audit_anchor(base_dir=workspace, detector_versions={})
        assert a1.calibration_artifacts_sha256 == a2.calibration_artifacts_sha256
        assert a1.benchmark_results_sha256 == a2.benchmark_results_sha256

    def test_export_changes_when_content_changes(self, workspace: Path):
        a1 = export_audit_anchor(base_dir=workspace, detector_versions={})
        _make_file(workspace / "calibrations" / "det-a.json", '{"threshold": 0.6}')
        a2 = export_audit_anchor(base_dir=workspace, detector_versions={})
        assert a1.calibration_artifacts_sha256 != a2.calibration_artifacts_sha256

    def test_export_changes_when_file_renamed(self, workspace: Path):
        a1 = export_audit_anchor(base_dir=workspace, detector_versions={})
        _make_file(workspace / "calibrations" / "det-b.json", '{"threshold": 0.5}')
        a2 = export_audit_anchor(base_dir=workspace, detector_versions={})
        assert a1.calibration_artifacts_sha256 != a2.calibration_artifacts_sha256

    def test_export_empty_directories(self, tmp_path: Path):
        base = tmp_path / "empty"
        base.mkdir()
        anchor = export_audit_anchor(base_dir=base, detector_versions={})
        assert anchor.calibration_artifacts_sha256 == ""
        assert anchor.benchmark_results_sha256 == ""

    def test_export_missing_directories(self, tmp_path: Path):
        anchor = export_audit_anchor(base_dir=tmp_path / "nope", detector_versions={})
        assert anchor.calibration_artifacts_sha256 == ""
        assert anchor.benchmark_results_sha256 == ""

    def test_export_with_chain(self, workspace: Path):
        chain = CalibrationChain()
        chain.append("c" * 64)
        anchor = export_audit_anchor(
            base_dir=workspace,
            detector_versions={},
            calibration_chain=chain.hashes,
        )
        assert anchor.calibration_chain == ["c" * 64]

    def test_export_auto_detects_detectors(self, workspace: Path):
        anchor = export_audit_anchor(base_dir=workspace)
        # Auto-detection must produce a dict (possibly empty on failure)
        assert isinstance(anchor.detector_versions, dict)


# ---------------------------------------------------------------------------
# _hash_directory
# ---------------------------------------------------------------------------


class TestHashDirectory:
    def test_missing_directory_returns_empty_string(self, tmp_path: Path):
        assert _hash_directory(tmp_path / "does-not-exist") == ""

    def test_empty_directory_returns_sha256_of_empty_input(self, tmp_path: Path):
        empty = tmp_path / "empty"
        empty.mkdir()
        assert _hash_directory(empty) == hashlib.sha256(b"").hexdigest()
        assert _hash_directory(empty) == (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_missing_and_empty_directories_are_distinct(self, tmp_path: Path):
        empty = tmp_path / "empty"
        empty.mkdir()
        assert _hash_directory(tmp_path / "does-not-exist") != _hash_directory(empty)

    def test_directory_with_file_returns_stable_distinct_hash(self, tmp_path: Path):
        populated = tmp_path / "populated"
        populated.mkdir()
        _make_file(populated / "a.json", '{"threshold": 0.5}')
        first = _hash_directory(populated)
        assert first == _hash_directory(populated)
        assert first != ""
        assert first != hashlib.sha256(b"").hexdigest()

    def test_large_file_hashed_in_chunks(self, tmp_path: Path):
        # File larger than the 1 MiB read chunk: chunked reading must
        # produce the identical digest to hashing the same bytes directly.
        from textforensics.ledger import _HASH_CHUNK_SIZE

        content = (b"0123456789abcdef" * 163840) + b"tail"  # 2.5 MiB + 4 B
        assert len(content) > _HASH_CHUNK_SIZE
        large = tmp_path / "large"
        large.mkdir()
        (large / "big.bin").write_bytes(content)

        expected = hashlib.sha256()
        expected.update(b"big.bin")
        expected.update(b"\x00")
        for offset in range(0, len(content), _HASH_CHUNK_SIZE):
            expected.update(content[offset : offset + _HASH_CHUNK_SIZE])
        expected.update(b"\n")

        assert _hash_directory(large) == expected.hexdigest()

        # Same digest again when the whole content is fed in one update,
        # proving chunk boundaries do not change the result.
        whole = hashlib.sha256()
        whole.update(b"big.bin")
        whole.update(b"\x00")
        whole.update(content)
        whole.update(b"\n")
        assert _hash_directory(large) == whole.hexdigest()


# ---------------------------------------------------------------------------
# C09 RED corpus (W4 acceptance) -- DO NOT "fix" by editing these tests.
# ---------------------------------------------------------------------------


class TestHashDirectoryFramingC09Red:
    """C09 (W3 side: RED tests only -- NOT closed in W3).

    The tree preimage is concatenated ``relative_path || NUL ||
    raw_content || LF`` records with no length framing and no per-file
    hashes, so raw file content can contain the next record's
    delimiter/path bytes. This is a framing defect, NOT a collision in
    SHA-256, and it does NOT provide a second preimage for an arbitrary
    pre-existing honest directory: the attacker must control crafted
    artifact content/layout.

    These tests FAIL on the current code for that reason. They are the
    W4 acceptance corpus: W4 turns them green with the versioned framing
    (canonical manifest or length-prefixed records) + the migration
    decision (changing the algorithm invalidates existing anchors -- a
    parent/integrator decision, not W3's). The green controls below pin
    the behavior W4 must preserve (portable separators, empty/missing
    distinction, deterministic ordering).
    """

    def test_two_trees_with_same_preimage_have_different_digests(self, tmp_path: Path):
        """The audit's two-tree construction: Tree A holds one file whose
        content embeds the next record's delimiter/path bytes; Tree B
        holds two files. Both serialize to the exact specified preimage
        ``b"a.bin\\x00x\\nb.bin\\x00y\\n"`` today -- they must not share
        a digest once framing is fixed."""
        tree_a = tmp_path / "a"
        tree_b = tmp_path / "b"
        tree_a.mkdir()
        tree_b.mkdir()
        (tree_a / "a.bin").write_bytes(b"x\nb.bin\x00y")
        (tree_b / "a.bin").write_bytes(b"x")
        (tree_b / "b.bin").write_bytes(b"y")

        expected_preimage = b"a.bin\x00x\nb.bin\x00y\n"
        expected_digest = hashlib.sha256(expected_preimage).hexdigest()
        # Mechanism pin (true today, documents WHY the digests collide):
        # both trees currently hash exactly the specified preimage.
        assert _hash_directory(tree_a) == expected_digest
        assert _hash_directory(tree_b) == expected_digest
        # The requirement: different file maps/counts, different digests.
        assert _hash_directory(tree_a) != _hash_directory(tree_b)

    def test_nested_path_collision_has_different_digests(self, tmp_path: Path):
        """Same framing hole through a nested path: a one-file tree
        ``a/b.bin`` whose content embeds ``c.bin`` must not collide with
        the two-file tree ``a/b.bin`` + ``c.bin``."""
        tree_a = tmp_path / "a"
        tree_b = tmp_path / "b"
        (tree_a / "a").mkdir(parents=True)
        (tree_b / "a").mkdir(parents=True)
        (tree_a / "a" / "b.bin").write_bytes(b"x\nc.bin\x00y")
        (tree_b / "a" / "b.bin").write_bytes(b"x")
        (tree_b / "c.bin").write_bytes(b"y")

        expected_preimage = b"a/b.bin\x00x\nc.bin\x00y\n"
        expected_digest = hashlib.sha256(expected_preimage).hexdigest()
        assert _hash_directory(tree_a) == expected_digest
        assert _hash_directory(tree_b) == expected_digest
        assert _hash_directory(tree_a) != _hash_directory(tree_b)

    def test_binary_contents_with_delimiters_have_different_digests(self, tmp_path: Path):
        """Binary contents (NUL / LF / non-UTF-8 bytes) must not smuggle
        record boundaries either."""
        tree_a = tmp_path / "a"
        tree_b = tmp_path / "b"
        tree_a.mkdir()
        tree_b.mkdir()
        (tree_a / "a.bin").write_bytes(b"x\nb.bin\x00y\xff\x00")
        (tree_b / "a.bin").write_bytes(b"x")
        (tree_b / "b.bin").write_bytes(b"y\xff\x00")

        expected_preimage = b"a.bin\x00x\nb.bin\x00y\xff\x00\n"
        expected_digest = hashlib.sha256(expected_preimage).hexdigest()
        assert _hash_directory(tree_a) == expected_digest
        assert _hash_directory(tree_b) == expected_digest
        assert _hash_directory(tree_a) != _hash_directory(tree_b)

    def test_nested_paths_use_portable_separators(self, tmp_path: Path):
        """CONTROL (green now, must stay green after W4): a nested tree's
        digest is built from forward-slash relative paths, so the same
        tree hashes identically on POSIX and Windows."""
        tree = tmp_path / "tree"
        (tree / "a").mkdir(parents=True)
        (tree / "a" / "b.bin").write_bytes(b"x")
        (tree / "c.bin").write_bytes(b"y")
        expected = hashlib.sha256(b"a/b.bin\x00x\nc.bin\x00y\n").hexdigest()
        assert _hash_directory(tree) == expected

    def test_empty_file_missing_file_and_empty_directory_are_distinct(self, tmp_path: Path):
        """CONTROL (green now, must stay green after W4): a directory
        holding one empty file, an empty directory, and a missing
        directory all hash differently -- emptiness is never confused
        with absence, at either level."""
        with_empty_file = tmp_path / "with-empty-file"
        with_empty_file.mkdir()
        (with_empty_file / "a.bin").write_bytes(b"")
        empty = tmp_path / "empty"
        empty.mkdir()
        digests = {
            _hash_directory(with_empty_file),
            _hash_directory(empty),
            _hash_directory(tmp_path / "does-not-exist"),
        }
        assert len(digests) == 3
        assert _hash_directory(empty) == hashlib.sha256(b"").hexdigest()
        assert _hash_directory(tmp_path / "does-not-exist") == ""

    def test_deterministic_ordering(self, tmp_path: Path):
        """CONTROL (green now, must stay green after W4): the digest
        depends on the sorted file set, not on creation order."""
        first = tmp_path / "first"
        second = tmp_path / "second"
        first.mkdir()
        second.mkdir()
        for name in ("a.json", "b.json", "c.json"):
            _make_file(first / name, '{"v": 1}')
        for name in ("c.json", "a.json", "b.json"):
            _make_file(second / name, '{"v": 1}')
        assert _hash_directory(first) == _hash_directory(second)


# ---------------------------------------------------------------------------
# verify_audit_anchor
# ---------------------------------------------------------------------------


class TestVerifyAuditAnchor:
    def test_no_changes(self, workspace: Path):
        anchor = export_audit_anchor(base_dir=workspace, detector_versions={})
        status = verify_audit_anchor(anchor, base_dir=workspace)
        assert status == "no_changes"

    def test_calibration_rollback_raises(self, workspace: Path):
        anchor = export_audit_anchor(base_dir=workspace, detector_versions={})
        _make_file(workspace / "calibrations" / "det-a.json", '{"threshold": 0.1}')
        with pytest.raises(RollbackError, match="Calibration artifacts rolled back"):
            verify_audit_anchor(anchor, base_dir=workspace)

    def test_benchmark_rollback_raises(self, workspace: Path):
        anchor = export_audit_anchor(base_dir=workspace, detector_versions={})
        _make_file(workspace / "benchmarks" / "run1.json", '{"auroc": 0.5}')
        with pytest.raises(RollbackError, match="Benchmark results rolled back"):
            verify_audit_anchor(anchor, base_dir=workspace)

    def test_both_rollback_raises(self, workspace: Path):
        anchor = export_audit_anchor(base_dir=workspace, detector_versions={})
        _make_file(workspace / "calibrations" / "det-a.json", "changed")
        _make_file(workspace / "benchmarks" / "run1.json", "changed")
        with pytest.raises(RollbackError) as exc_info:
            verify_audit_anchor(anchor, base_dir=workspace)
        msg = str(exc_info.value)
        assert "Calibration artifacts rolled back" in msg
        assert "Benchmark results rolled back" in msg

    def test_chain_valid_when_chain_extends(self, workspace: Path):
        anchor_chain = CalibrationChain()
        anchor_chain.append("c" * 64)
        anchor = export_audit_anchor(
            base_dir=workspace,
            detector_versions={},
            calibration_chain=anchor_chain.hashes,
        )
        # Now change calibration state (hash mismatch) but current chain extends
        _make_file(workspace / "calibrations" / "det-a.json", '{"threshold": 0.7}')
        current_chain = CalibrationChain()
        current_chain.append("c" * 64)
        current_chain.append("d" * 64)
        status = verify_audit_anchor(anchor, current_chain=current_chain, base_dir=workspace)
        assert status == "chain_valid"

    def test_chain_too_short_rollback(self, workspace: Path):
        anchor_chain = CalibrationChain()
        anchor_chain.append("c" * 64)
        anchor_chain.append("d" * 64)
        anchor = export_audit_anchor(
            base_dir=workspace,
            detector_versions={},
            calibration_chain=anchor_chain.hashes,
        )
        _make_file(workspace / "calibrations" / "det-a.json", "changed")
        current_chain = CalibrationChain()
        current_chain.append("c" * 64)
        with pytest.raises(RollbackError, match="Calibration artifacts rolled back"):
            verify_audit_anchor(anchor, current_chain=current_chain, base_dir=workspace)

    def test_chain_prefix_mismatch_rollback(self, workspace: Path):
        anchor_chain = CalibrationChain()
        anchor_chain.append("c" * 64)
        anchor = export_audit_anchor(
            base_dir=workspace,
            detector_versions={},
            calibration_chain=anchor_chain.hashes,
        )
        _make_file(workspace / "calibrations" / "det-a.json", "changed")
        # Current chain has wrong prefix
        current_chain = CalibrationChain()
        current_chain.append("e" * 64)
        current_chain.append("c" * 64)
        with pytest.raises(RollbackError):
            verify_audit_anchor(anchor, current_chain=current_chain, base_dir=workspace)

    def test_no_changes_takes_precedence_over_chain(self, workspace: Path):
        anchor = export_audit_anchor(base_dir=workspace, detector_versions={})
        chain = CalibrationChain()
        chain.append("c" * 64)
        status = verify_audit_anchor(anchor, current_chain=chain, base_dir=workspace)
        assert status == "no_changes"


# ---------------------------------------------------------------------------
# C08 RED corpus (W4 acceptance) -- DO NOT "fix" by editing these tests.
# ---------------------------------------------------------------------------


class TestVerifyAuditAnchorC08Red:
    """C08 (W3 side: RED tests only -- NOT closed in W3).

    An unchanged calibration chain must never authorize changed artifact
    roots. Today ``verify_audit_anchor`` accepts any hash mismatch when
    ``current_chain.extends_anchor`` is true, and that predicate checks
    only list-prefix equality: it does not bind the chain to either
    current directory root, it does not bind detector versions at all,
    and a calibration-only list authorizes benchmark changes.

    These tests FAIL on the current code for that reason. They are the
    W4 acceptance corpus: W4 turns them green with the versioned
    state-transition redesign (binding calibration root + benchmark root
    + detector-version state; validating loaded chain entries and state
    lineage, not just hash syntax/prefix).

    NOTE: the pre-existing ``test_chain_valid_when_chain_extends`` above
    asserts the defective acceptance (an arbitrary appended digest
    authorizes a calibration change). W4 must update that test when the
    redesign lands; it directly contradicts
    ``test_arbitrary_appended_digest_does_not_authorize_change`` here.
    """

    @staticmethod
    def _anchored_workspace(workspace: Path) -> AuditAnchor:
        chain = CalibrationChain()
        chain.append("c" * 64)
        return export_audit_anchor(
            base_dir=workspace,
            detector_versions={},
            calibration_chain=chain.hashes,
        )

    @staticmethod
    def _copied_chain() -> CalibrationChain:
        chain = CalibrationChain()
        chain.append("c" * 64)
        return chain

    def test_benchmark_change_with_unchanged_chain_rejected(self, workspace: Path):
        """Changed benchmark file + the exact anchor chain must reject:
        a calibration-only list cannot authorize benchmark tampering."""
        anchor = self._anchored_workspace(workspace)
        _make_file(workspace / "benchmarks" / "run1.json", '{"auroc": 0.5}')
        with pytest.raises(RollbackError, match="Benchmark results rolled back"):
            verify_audit_anchor(anchor, current_chain=self._copied_chain(), base_dir=workspace)

    def test_calibration_rollback_with_copied_chain_rejected(self, workspace: Path):
        """Changed calibration file + a verbatim copy of the anchor chain
        (an equal, non-extended chain) must reject."""
        anchor = self._anchored_workspace(workspace)
        _make_file(workspace / "calibrations" / "det-a.json", '{"threshold": 0.1}')
        with pytest.raises(RollbackError, match="Calibration artifacts rolled back"):
            verify_audit_anchor(anchor, current_chain=self._copied_chain(), base_dir=workspace)

    def test_arbitrary_appended_digest_does_not_authorize_change(self, workspace: Path):
        """An arbitrary appended digest -- a well-formed hash bound to no
        artifact -- must not authorize a calibration change."""
        anchor = self._anchored_workspace(workspace)
        _make_file(workspace / "calibrations" / "det-a.json", '{"threshold": 0.7}')
        current_chain = CalibrationChain()
        current_chain.append("c" * 64)
        current_chain.append("f" * 64)
        with pytest.raises(RollbackError, match="Calibration artifacts rolled back"):
            verify_audit_anchor(anchor, current_chain=current_chain, base_dir=workspace)

    def test_changed_detector_versions_rejected(self, workspace: Path, monkeypatch):
        """A changed detector version must reject even when both directory
        roots are unchanged: the anchor binds detector-version state too.

        The current state is expressed through the same auto-detection
        ``export_audit_anchor`` uses (patched here to report a new
        version); the premise export proves the patched detection is
        really observed. W4 may wire the current versions through a new
        explicit parameter instead -- if so, adapt this call when the
        redesign lands; the requirement (version change rejects) stands.
        """
        anchor = export_audit_anchor(
            base_dir=workspace,
            detector_versions={"textforensics/builtin-heuristic": "0.1.0"},
            calibration_chain=["c" * 64],
        )
        monkeypatch.setattr(
            "textforensics.detectors.list_detector_metadata",
            lambda: [
                {
                    "detector_id": "textforensics/builtin-heuristic",
                    "detector_version": "9.9.9",
                }
            ],
        )
        current = export_audit_anchor(base_dir=workspace)
        assert current.detector_versions == {"textforensics/builtin-heuristic": "9.9.9"}
        with pytest.raises(RollbackError):
            verify_audit_anchor(anchor, base_dir=workspace)

    def test_missing_calibration_root_with_copied_chain_rejected(self, workspace: Path):
        """Deleting the whole calibrations directory + presenting the
        unchanged chain must reject: a missing root is not an extension."""
        anchor = self._anchored_workspace(workspace)
        shutil.rmtree(workspace / "calibrations")
        with pytest.raises(RollbackError, match="Calibration artifacts rolled back"):
            verify_audit_anchor(anchor, current_chain=self._copied_chain(), base_dir=workspace)

    def test_empty_root_anchor_does_not_authorize_new_artifacts(self, tmp_path: Path):
        """An anchor exported from missing roots (both hashes empty, empty
        chain) must not authorize artifacts appearing from nowhere just
        because a non-empty chain is presented."""
        base = tmp_path / "empty-base"
        base.mkdir()
        anchor = export_audit_anchor(base_dir=base, detector_versions={})
        assert anchor.calibration_artifacts_sha256 == ""
        assert anchor.benchmark_results_sha256 == ""
        assert anchor.calibration_chain == []

        (base / "calibrations").mkdir()
        _make_file(base / "calibrations" / "det-a.json", '{"threshold": 0.5}')
        current_chain = CalibrationChain()
        current_chain.append("c" * 64)
        with pytest.raises(RollbackError):
            verify_audit_anchor(anchor, current_chain=current_chain, base_dir=base)

    def test_legitimate_transition_still_valid(self, workspace: Path):
        """CONTROL (green now, must stay green after W4): a real
        transition -- calibration content changes AND the new chain entry
        is the hash of the new calibration root -- still verifies. This
        pins what W4 must accept while it rejects the cases above."""
        anchor = self._anchored_workspace(workspace)
        _make_file(workspace / "calibrations" / "det-a.json", '{"threshold": 0.7}')
        current_chain = CalibrationChain()
        current_chain.append("c" * 64)
        current_chain.append(_hash_directory(workspace / "calibrations"))
        status = verify_audit_anchor(anchor, current_chain=current_chain, base_dir=workspace)
        assert status == "chain_valid"


# ---------------------------------------------------------------------------
# CalibrationChain
# ---------------------------------------------------------------------------


class TestCalibrationChain:
    def test_append_and_hashes(self):
        chain = CalibrationChain()
        chain.append("a" * 64)
        chain.append("b" * 64)
        assert chain.hashes == ["a" * 64, "b" * 64]
        assert chain.length == 2

    def test_hashes_returns_copy(self):
        chain = CalibrationChain()
        chain.append("a" * 64)
        h = chain.hashes
        h.append("mutated")
        assert chain.hashes == ["a" * 64]

    def test_serialization_roundtrip(self):
        chain = CalibrationChain()
        chain.append("a" * 64)
        chain.append("b" * 64)
        data = chain.to_dict()
        restored = CalibrationChain.from_dict(data)
        assert restored.hashes == chain.hashes

    def test_verify_integrity_ok(self):
        chain = CalibrationChain()
        chain.append(hashlib.sha256(b"one").hexdigest())
        chain.append(hashlib.sha256(b"two").hexdigest())
        assert chain.verify_integrity() == []

    def test_verify_integrity_bad_length(self):
        # Malformed entries can no longer be added via append() (it
        # validates), so build the chain through the lenient load path
        # that verify_integrity() exists to guard.
        chain = CalibrationChain.from_dict({"chain": ["short"], "length": 1})
        errors = chain.verify_integrity()
        assert any("length" in e for e in errors)

    def test_verify_integrity_bad_hex(self):
        chain = CalibrationChain.from_dict({"chain": ["z" * 64], "length": 1})
        errors = chain.verify_integrity()
        assert len(errors) == 1
        assert "hex" in errors[0]

    def test_append_rejects_short_entry(self):
        """Test that append fails loudly on a too-short hash."""
        chain = CalibrationChain()
        with pytest.raises(ValueError, match="64-character"):
            chain.append("short")
        assert chain.hashes == []

    def test_append_rejects_non_hex_entry(self):
        """Test that append fails loudly on a tampered non-hex hash."""
        chain = CalibrationChain()
        with pytest.raises(ValueError, match="hexadecimal"):
            chain.append("z" * 64)
        assert chain.hashes == []

    def test_append_rejects_empty_and_non_string_entries(self):
        """Test that append fails loudly on empty/non-string entries."""
        chain = CalibrationChain()
        with pytest.raises(ValueError, match="64-character"):
            chain.append("")
        with pytest.raises(ValueError, match="64-character"):
            chain.append(123)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="64-character"):
            chain.append(None)  # type: ignore[arg-type]
        assert chain.hashes == []

    def test_append_rejected_entry_leaves_chain_unchanged(self):
        """Test that a rejected append does not disturb valid entries."""
        chain = CalibrationChain()
        chain.append("a" * 64)
        with pytest.raises(ValueError, match="64-character"):
            chain.append("tampered")
        assert chain.hashes == ["a" * 64]
        assert chain.verify_integrity() == []

    def test_append_accepts_uppercase_hex(self):
        """Test that uppercase hex digests are valid entries."""
        chain = CalibrationChain()
        chain.append("A" * 64)
        assert chain.hashes == ["A" * 64]
        assert chain.verify_integrity() == []

    def test_extends_anchor_same_chain(self):
        chain = CalibrationChain()
        chain.append("a" * 64)
        anchor = AuditAnchor(
            calibration_artifacts_sha256="",
            benchmark_results_sha256="",
            detector_versions={},
            calibration_chain=["a" * 64],
        )
        assert chain.extends_anchor(anchor) is True

    def test_extends_anchor_extended(self):
        chain = CalibrationChain()
        chain.append("a" * 64)
        chain.append("b" * 64)
        anchor = AuditAnchor(
            calibration_artifacts_sha256="",
            benchmark_results_sha256="",
            detector_versions={},
            calibration_chain=["a" * 64],
        )
        assert chain.extends_anchor(anchor) is True

    def test_not_extends_shorter_chain(self):
        chain = CalibrationChain()
        chain.append("a" * 64)
        anchor = AuditAnchor(
            calibration_artifacts_sha256="",
            benchmark_results_sha256="",
            detector_versions={},
            calibration_chain=["a" * 64, "b" * 64],
        )
        assert chain.extends_anchor(anchor) is False

    def test_extends_anchor_empty_anchor_chain(self):
        chain = CalibrationChain()
        chain.append("a" * 64)
        anchor = AuditAnchor(
            calibration_artifacts_sha256="",
            benchmark_results_sha256="",
            detector_versions={},
            calibration_chain=[],
        )
        assert chain.extends_anchor(anchor) is True

    def test_extends_anchor_empty_current_chain(self):
        chain = CalibrationChain()
        anchor = AuditAnchor(
            calibration_artifacts_sha256="",
            benchmark_results_sha256="",
            detector_versions={},
            calibration_chain=[],
        )
        assert chain.extends_anchor(anchor) is False

    def test_save_and_load(self, tmp_path: Path):
        path = tmp_path / "chain.json"
        chain = CalibrationChain()
        chain.append("a" * 64)
        chain.save_to_file(path)
        assert path.exists()
        loaded = CalibrationChain()
        loaded.load_from_file(path)
        assert loaded.hashes == ["a" * 64]

    def test_load_missing_file(self, tmp_path: Path):
        chain = CalibrationChain()
        chain.load_from_file(tmp_path / "missing.json")
        assert chain.hashes == []


# ---------------------------------------------------------------------------
# RollbackError
# ---------------------------------------------------------------------------


class TestRollbackError:
    def test_is_exception(self):
        assert issubclass(RollbackError, Exception)

    def test_message_preserved(self):
        exc = RollbackError("Calibration artifacts rolled back")
        assert "rolled back" in str(exc)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestAuditAnchorCli:
    """CLI integration tests for `textforensics audit export/verify`."""

    def _run_main(self, argv: list[str]) -> tuple[int, str, str]:
        import io
        import sys

        from textforensics.cli import main

        old_argv = sys.argv
        old_stdin = sys.stdin
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        try:
            sys.argv = ["textforensics", *argv]
            sys.stdin = io.StringIO("")
            sys.stdout = io.StringIO()
            sys.stderr = io.StringIO()
            exit_code = main()
            return exit_code, sys.stdout.getvalue(), sys.stderr.getvalue()
        except SystemExit as e:
            code = e.code
            if isinstance(code, str):
                code = int(code) if code.isdigit() else 1
            return code or 0, sys.stdout.getvalue(), sys.stderr.getvalue()
        finally:
            sys.argv = old_argv
            sys.stdin = old_stdin
            sys.stdout = old_stdout
            sys.stderr = old_stderr

    def test_cli_export_and_verify(self, workspace: Path, capsys=None):
        anchor_path = workspace.parent / "anchor.json"
        code, out, err = self._run_main(
            [
                "audit",
                "export",
                str(anchor_path),
                "--base-dir",
                str(workspace),
            ]
        )
        assert code == 0, err
        assert anchor_path.exists()
        data = json.loads(anchor_path.read_text(encoding="utf-8"))
        assert data["schema_version"] == 1
        assert "calibration_artifacts_sha256" in data
        assert "benchmark_results_sha256" in data

        # Verify with no changes
        code, out, err = self._run_main(
            [
                "audit",
                "verify",
                str(anchor_path),
                "--base-dir",
                str(workspace),
            ]
        )
        assert code == 0, err
        payload = json.loads(out)
        assert payload["valid"] is True
        assert payload["status"] == "no_changes"

    def test_cli_verify_detects_rollback(self, workspace: Path):
        anchor_path = workspace.parent / "anchor.json"
        code, out, err = self._run_main(
            ["audit", "export", str(anchor_path), "--base-dir", str(workspace)]
        )
        assert code == 0, err

        # Modify calibrations (rollback simulation)
        _make_file(workspace / "calibrations" / "det-a.json", '{"threshold": 0.05}')

        code, out, err = self._run_main(
            ["audit", "verify", str(anchor_path), "--base-dir", str(workspace)]
        )
        assert code == EXIT_ERROR
        assert "rollback" in err.lower()
        payload = json.loads(out)
        assert payload["valid"] is False
        assert "rolled back" in payload["error"]

    def test_cli_verify_with_chain(self, workspace: Path):
        chain_path = workspace.parent / "chain.json"
        chain = CalibrationChain()
        chain.append("c" * 64)
        chain.save_to_file(chain_path)

        anchor_path = workspace.parent / "anchor.json"
        code, out, err = self._run_main(
            [
                "audit",
                "export",
                str(anchor_path),
                "--base-dir",
                str(workspace),
                "--chain",
                str(chain_path),
            ]
        )
        assert code == 0, err
        data = json.loads(anchor_path.read_text(encoding="utf-8"))
        assert data["calibration_chain"] == ["c" * 64]

    def test_cli_verify_missing_anchor_file(self, tmp_path: Path):
        code, out, err = self._run_main(["audit", "verify", str(tmp_path / "missing.json")])
        assert code == EXIT_ERROR
        assert "failed to read anchor file" in err

    def test_cli_export_without_output(self, workspace: Path):
        code, out, err = self._run_main(["audit", "export", "--base-dir", str(workspace)])
        assert code == EXIT_ERROR
        assert "requires an output path" in err

    def test_cli_verify_without_anchor(self, workspace: Path):
        code, out, err = self._run_main(["audit", "verify", "--base-dir", str(workspace)])
        assert code == EXIT_ERROR
        assert "requires an anchor file path" in err

    def test_cli_legacy_naturalness_still_works(self):
        # Backward compatibility: `audit` without subcommand = naturalness audit
        import io
        import sys

        from textforensics.cli import main

        old_argv = sys.argv
        old_stdin = sys.stdin
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        try:
            sys.argv = ["textforensics", "audit"]
            sys.stdin = io.StringIO(
                "Furthermore, it is important to note that this robust "
                "solution seamlessly unlocks the potential."
            )
            sys.stdout = io.StringIO()
            sys.stderr = io.StringIO()
            code = main()
            out = sys.stdout.getvalue()
        finally:
            sys.argv = old_argv
            sys.stdin = old_stdin
            sys.stdout = old_stdout
            sys.stderr = old_stderr

        assert code == 0
        issues = json.loads(out)
        assert isinstance(issues, list)
