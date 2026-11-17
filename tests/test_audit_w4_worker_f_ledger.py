"""W4 mutation kill tests: textforensics.ledger (Worker F2).

Each test kills one or more phase-1 survivors from the W4 proof set
(audit-w4-f-proofset.json / audit-w4-f-survivors.json). The tests pin the
specified behaviour of AuditLog canonicalisation, the v2 audit-anchor
verification (C08) and CalibrationChain transition authorisation -- not
incidental implementation detail. Equivalent ledger mutants (self-check
assert in _append_locked, schema-version identity, extends_anchor
non-negativity, the authorises LtE/Eq subsumption, the unread
DIRECTORY_HASH_VERSION constant) are documented in
audit-w4-f-equiv-reasons-ledger.json and must SURVIVE this file.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import patch

import pytest

from textforensics.ledger import (
    SCHEMA_VERSION,
    AuditAnchor,
    AuditLog,
    CalibrationChain,
    RollbackError,
    _detect_detector_versions,
    _hash_directory,
)

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _make_dirs(base: Path) -> tuple[Path, Path]:
    """Create calibrations/ + benchmarks/ dirs with one file each."""
    cal_dir = base / "calibrations"
    bench_dir = base / "benchmarks"
    cal_dir.mkdir(parents=True)
    bench_dir.mkdir(parents=True)
    (cal_dir / "artifact.txt").write_text("calibration artifact\n", encoding="utf-8")
    (bench_dir / "results.txt").write_text("benchmark results\n", encoding="utf-8")
    return cal_dir, bench_dir


def _authorizing_chain(anchor_chain: list[str], current_cal_hash: str) -> CalibrationChain:
    """A chain that strictly extends *anchor_chain* and binds the current cal root."""
    chain = CalibrationChain()
    for h in [*anchor_chain, current_cal_hash]:
        chain.append(h)
    return chain


# ---------------------------------------------------------------------------
# AuditLog._append_to_file / _append_locked
# ---------------------------------------------------------------------------


def test_append_creates_missing_parent_directories(tmp_path: Path) -> None:
    """mkdir(parents=True): appending to a log in missing nested dirs works."""
    log = AuditLog(tmp_path / "a" / "b" / "audit.log")
    entry = log.append("scan")
    assert entry.index == 0
    assert (tmp_path / "a" / "b" / "audit.log").exists()


def test_append_locked_creates_missing_parent_directories(tmp_path: Path) -> None:
    """mkdir(parents=True) in _append_to_file: called directly, appending
    to a log in missing nested dirs works. (Through append() the
    parents=False mutant is unobservable: _ledger_lock creates the
    parents first. The direct call is the only path that exercises
    _append_to_file's own mkdir.)
    """
    log = AuditLog(tmp_path / "a" / "b" / "audit.log")
    entry = log._append_locked(operation="scan")  # noqa: SLF001 - kill test
    assert entry.index == 0
    assert (tmp_path / "a" / "b" / "audit.log").exists()


def test_append_locked_operation_is_positional_or_keyword(tmp_path: Path) -> None:
    """The `*` in _append_locked keeps actor/input/output keyword-only and
    leaves `operation` positional-or-keyword: calling it with a keyword
    operation must work."""
    log = AuditLog(tmp_path / "audit.log")
    entry = log._append_locked(operation="scan")  # noqa: SLF001 - kill test
    assert entry.operation == "scan"


def test_input_hash_uses_sorted_keys(tmp_path: Path) -> None:
    """input canonical form is json.dumps(sort_keys=True): the stored
    input_hash is the SHA-256 of '{"a":2,"z":1}' for unsorted input."""
    log = AuditLog(tmp_path / "audit.log")
    entry = log.append("scan", input_data={"z": 1, "a": 2})
    assert entry.input_hash == _sha256_hex('{"a":2,"z":1}')


def test_input_hash_uses_raw_utf8(tmp_path: Path) -> None:
    """input canonical form is json.dumps(ensure_ascii=False): non-ASCII
    input is hashed as raw UTF-8, not \\u-escaped."""
    log = AuditLog(tmp_path / "audit.log")
    entry = log.append("scan", input_data={"k": "café"})
    assert entry.input_hash == _sha256_hex('{"k":"café"}')


def test_output_hash_uses_json_form_for_dicts(tmp_path: Path) -> None:
    """output canonical form for a dict is json.dumps (not str()): the
    stored output_hash is the SHA-256 of '{"a":2,"z":1}'."""
    log = AuditLog(tmp_path / "audit.log")
    entry = log.append("scan", output_data={"z": 1, "a": 2})
    assert entry.output_hash == _sha256_hex('{"a":2,"z":1}')


def test_output_hash_uses_raw_utf8(tmp_path: Path) -> None:
    """output canonical form is json.dumps(ensure_ascii=False)."""
    log = AuditLog(tmp_path / "audit.log")
    entry = log.append("scan", output_data={"k": "café"})
    assert entry.output_hash == _sha256_hex('{"k":"café"}')


# ---------------------------------------------------------------------------
# SCHEMA_VERSION / _detect_detector_versions
# ---------------------------------------------------------------------------


def test_schema_version_2_anchor_verifies(tmp_path: Path) -> None:
    """An anchor carrying the current schema version (2) verifies against
    matching state."""
    from textforensics.ledger import verify_audit_anchor

    cal_dir, bench_dir = _make_dirs(tmp_path)
    anchor = AuditAnchor(
        calibration_artifacts_sha256=_hash_directory(cal_dir),
        benchmark_results_sha256=_hash_directory(bench_dir),
        detector_versions={},
        schema_version=SCHEMA_VERSION,
    )
    assert SCHEMA_VERSION == 2
    assert verify_audit_anchor(anchor, base_dir=tmp_path, detector_versions={}) == "no_changes"


def test_detect_detector_versions_swallows_errors() -> None:
    """A detection failure yields {} rather than raising."""
    with patch(
        "textforensics.detectors.list_detector_metadata",
        side_effect=RuntimeError("boom"),
    ):
        assert _detect_detector_versions() == {}


# ---------------------------------------------------------------------------
# verify_audit_anchor: Check 1 identity vs equality
# ---------------------------------------------------------------------------


def test_verify_matching_hashes_no_changes_with_authorizing_chain(tmp_path: Path) -> None:
    """Check 1 (exact match) takes precedence over Check 2: matching cal
    and bench roots return "no_changes" even when a chain that would
    authorize a transition exists. The hashes are equal-valued but
    distinct string objects (two _hash_directory calls), so `==` must be
    value equality, not identity."""
    from textforensics.ledger import verify_audit_anchor

    cal_dir, bench_dir = _make_dirs(tmp_path)
    cal_current = _hash_directory(cal_dir)
    cal_anchor = _hash_directory(cal_dir)
    bench_current = _hash_directory(bench_dir)
    bench_anchor = _hash_directory(bench_dir)
    assert cal_current == cal_anchor and cal_current is not cal_anchor
    assert bench_current == bench_anchor and bench_current is not bench_anchor
    anchor = AuditAnchor(
        calibration_artifacts_sha256=cal_anchor,
        benchmark_results_sha256=bench_anchor,
        detector_versions={},
        calibration_chain=["a" * 64],
        schema_version=SCHEMA_VERSION,
    )
    chain = _authorizing_chain(["a" * 64], cal_current)
    assert (
        verify_audit_anchor(anchor, current_chain=chain, base_dir=tmp_path, detector_versions={})
        == "no_changes"
    )


def test_verify_bench_greater_than_anchor_rolls_back(tmp_path: Path) -> None:
    """A benchmark root greater than the anchor's is a rollback, not a
    match: verify raises RollbackError naming the benchmark results."""
    from textforensics.ledger import verify_audit_anchor

    cal_dir, bench_dir = _make_dirs(tmp_path)
    current_bench = _hash_directory(bench_dir)
    assert current_bench > "0" * 64
    anchor = AuditAnchor(
        calibration_artifacts_sha256=_hash_directory(cal_dir),
        benchmark_results_sha256="0" * 64,
        detector_versions={},
        schema_version=SCHEMA_VERSION,
    )
    with pytest.raises(RollbackError, match="Benchmark results"):
        verify_audit_anchor(anchor, base_dir=tmp_path, detector_versions={})


def test_verify_bench_changed_with_authorizing_chain_rolls_back(tmp_path: Path) -> None:
    """A calibration-only chain cannot authorize benchmark tampering: with
    the bench root changed and the cal root changed, an authorizing cal
    chain still yields RollbackError."""
    from textforensics.ledger import verify_audit_anchor

    cal_dir, bench_dir = _make_dirs(tmp_path)
    current_cal = _hash_directory(cal_dir)
    current_bench = _hash_directory(bench_dir)
    assert current_bench > "0" * 64
    anchor = AuditAnchor(
        calibration_artifacts_sha256="c" * 64,
        benchmark_results_sha256="0" * 64,
        detector_versions={},
        calibration_chain=["a" * 64],
        schema_version=SCHEMA_VERSION,
    )
    chain = _authorizing_chain(["a" * 64], current_cal)
    with pytest.raises(RollbackError, match="Benchmark results"):
        verify_audit_anchor(anchor, current_chain=chain, base_dir=tmp_path, detector_versions={})


def test_verify_bench_smaller_than_anchor_rolls_back(tmp_path: Path) -> None:
    """Same as above with the bench root smaller than the anchor's: the
    chain still cannot authorize it."""
    from textforensics.ledger import verify_audit_anchor

    cal_dir, bench_dir = _make_dirs(tmp_path)
    current_cal = _hash_directory(cal_dir)
    current_bench = _hash_directory(bench_dir)
    assert current_bench < "f" * 64
    anchor = AuditAnchor(
        calibration_artifacts_sha256="c" * 64,
        benchmark_results_sha256="f" * 64,
        detector_versions={},
        calibration_chain=["a" * 64],
        schema_version=SCHEMA_VERSION,
    )
    chain = _authorizing_chain(["a" * 64], current_cal)
    with pytest.raises(RollbackError, match="Benchmark results"):
        verify_audit_anchor(anchor, current_chain=chain, base_dir=tmp_path, detector_versions={})


def test_verify_cal_reason_not_spurious_for_equal_hashes(tmp_path: Path) -> None:
    """Equal-but-distinct calibration hashes are NOT a rollback: when only
    the bench root changed, the error names the benchmark results only."""
    from textforensics.ledger import verify_audit_anchor

    cal_dir, bench_dir = _make_dirs(tmp_path)
    cal_current = _hash_directory(cal_dir)
    cal_anchor = _hash_directory(cal_dir)
    assert cal_current == cal_anchor and cal_current is not cal_anchor
    anchor = AuditAnchor(
        calibration_artifacts_sha256=cal_anchor,
        benchmark_results_sha256="b" * 64,
        detector_versions={},
        schema_version=SCHEMA_VERSION,
    )
    with pytest.raises(RollbackError) as excinfo:
        verify_audit_anchor(anchor, base_dir=tmp_path, detector_versions={})
    assert "Calibration artifacts" not in str(excinfo.value)
    assert "Benchmark results" in str(excinfo.value)


def test_verify_bench_reason_not_spurious_for_equal_hashes(tmp_path: Path) -> None:
    """Equal-but-distinct benchmark hashes are NOT a rollback: when only
    the cal root changed, the error names the calibration artifacts only."""
    from textforensics.ledger import verify_audit_anchor

    cal_dir, bench_dir = _make_dirs(tmp_path)
    bench_current = _hash_directory(bench_dir)
    bench_anchor = _hash_directory(bench_dir)
    assert bench_current == bench_anchor and bench_current is not bench_anchor
    anchor = AuditAnchor(
        calibration_artifacts_sha256="a" * 64,
        benchmark_results_sha256=bench_anchor,
        detector_versions={},
        schema_version=SCHEMA_VERSION,
    )
    with pytest.raises(RollbackError) as excinfo:
        verify_audit_anchor(anchor, base_dir=tmp_path, detector_versions={})
    assert "Benchmark results" not in str(excinfo.value)
    assert "Calibration artifacts" in str(excinfo.value)


def test_verify_rollback_message_shows_exact_16_char_prefixes(tmp_path: Path) -> None:
    """Rollback reasons show exactly the first 16 hex chars of each hash
    (``[:16]``), for both the expected and the got digest."""
    from textforensics.ledger import verify_audit_anchor

    cal_dir, bench_dir = _make_dirs(tmp_path)
    current_cal = _hash_directory(cal_dir)
    current_bench = _hash_directory(bench_dir)
    anchor = AuditAnchor(
        calibration_artifacts_sha256="a" * 64,
        benchmark_results_sha256="b" * 64,
        detector_versions={},
        schema_version=SCHEMA_VERSION,
    )
    with pytest.raises(RollbackError) as excinfo:
        verify_audit_anchor(anchor, base_dir=tmp_path, detector_versions={})
    message = str(excinfo.value)
    assert f"expected {'a' * 16}..." in message
    assert f"got {current_cal[:16]}..." in message
    assert f"expected {'b' * 16}..." in message
    assert f"got {current_bench[:16]}..." in message


# ---------------------------------------------------------------------------
# CalibrationChain.extends_anchor
# ---------------------------------------------------------------------------


def test_extends_anchor_prefix_greater_is_not_extension() -> None:
    """A chain whose prefix is lexicographically greater than the anchor
    chain does not extend it."""
    chain = CalibrationChain()
    chain.append("f" * 64)
    anchor = AuditAnchor(
        calibration_artifacts_sha256="",
        benchmark_results_sha256="",
        detector_versions={},
        calibration_chain=["0" * 64],
    )
    assert chain.extends_anchor(anchor) is False


def test_extends_anchor_prefix_smaller_is_not_extension() -> None:
    """A chain whose prefix is lexicographically smaller than the anchor
    chain does not extend it."""
    chain = CalibrationChain()
    chain.append("0" * 64)
    anchor = AuditAnchor(
        calibration_artifacts_sha256="",
        benchmark_results_sha256="",
        detector_versions={},
        calibration_chain=["f" * 64],
    )
    assert chain.extends_anchor(anchor) is False


def test_extends_anchor_distinct_equal_length_lists_is_not_extension() -> None:
    """A chain holding a different hash than the anchor chain does not
    extend it, even though the two lists are distinct objects."""
    chain = CalibrationChain()
    chain.append("a" * 64)
    anchor = AuditAnchor(
        calibration_artifacts_sha256="",
        benchmark_results_sha256="",
        detector_versions={},
        calibration_chain=["b" * 64],
    )
    assert chain.extends_anchor(anchor) is False


# ---------------------------------------------------------------------------
# CalibrationChain.authorizes_transition
# ---------------------------------------------------------------------------


def test_authorizes_transition_anchor_is_positional_or_keyword() -> None:
    """The `*` in authorizes_transition keeps calibration_root keyword-only
    and leaves `anchor` positional-or-keyword: calling it with a keyword
    anchor must work."""
    chain = CalibrationChain()
    chain.append("a" * 64)
    anchor = AuditAnchor(
        calibration_artifacts_sha256="",
        benchmark_results_sha256="",
        detector_versions={},
        calibration_chain=["a" * 64],
    )
    assert chain.authorizes_transition(anchor=anchor, calibration_root="a" * 64) is False


def test_authorizes_transition_rejects_invalid_anchor_hash() -> None:
    """An anchor chain holding a malformed hash authorizes nothing."""
    chain = CalibrationChain()
    chain.append("a" * 64)
    anchor = AuditAnchor(
        calibration_artifacts_sha256="",
        benchmark_results_sha256="",
        detector_versions={},
        calibration_chain=["not-a-hash"],
    )
    assert chain.authorizes_transition(anchor, calibration_root="a" * 64) is False


def test_authorizes_transition_equal_lengths_is_not_extension() -> None:
    """An equal chain is not a strict extension, however short."""
    chain = CalibrationChain()
    chain.append("a" * 64)
    anchor = AuditAnchor(
        calibration_artifacts_sha256="",
        benchmark_results_sha256="",
        detector_versions={},
        calibration_chain=["a" * 64],
    )
    assert chain.authorizes_transition(anchor, calibration_root="a" * 64) is False


def test_authorizes_transition_large_equal_lengths_is_not_extension() -> None:
    """An equal chain is not a strict extension even at lengths where
    ``len(...) is len(...)`` is False (2000 is above the small-int
    cache on every supported Python: CPython cached -5..256 through
    3.14, and 3.15 raised the cache to -5..1024, so 300/257 — the
    values this test used before — are cached singletons on 3.15
    and the ``is not`` premise fails there)."""
    hashes = ["a" * 64] * 2000
    chain = CalibrationChain()
    for h in hashes:
        chain.append(h)
    anchor = AuditAnchor(
        calibration_artifacts_sha256="",
        benchmark_results_sha256="",
        detector_versions={},
        calibration_chain=list(hashes),
    )
    assert len(chain.hashes) is not len(anchor.calibration_chain)
    assert chain.authorizes_transition(anchor, calibration_root="a" * 64) is False


def test_authorizes_transition_prefix_smaller_authorizes_nothing() -> None:
    """A chain whose prefix is smaller than the anchor chain authorizes
    nothing, even when its last entry equals the calibration root."""
    chain = CalibrationChain()
    chain.append("0" * 64)
    chain.append("a" * 64)
    anchor = AuditAnchor(
        calibration_artifacts_sha256="",
        benchmark_results_sha256="",
        detector_versions={},
        calibration_chain=["f" * 64],
    )
    assert chain.authorizes_transition(anchor, calibration_root="a" * 64) is False


def test_authorizes_transition_prefix_greater_authorizes_nothing() -> None:
    """A chain whose prefix is greater than the anchor chain authorizes
    nothing, even when its last entry equals the calibration root."""
    chain = CalibrationChain()
    chain.append("f" * 64)
    chain.append("a" * 64)
    anchor = AuditAnchor(
        calibration_artifacts_sha256="",
        benchmark_results_sha256="",
        detector_versions={},
        calibration_chain=["0" * 64],
    )
    assert chain.authorizes_transition(anchor, calibration_root="a" * 64) is False


def test_authorizes_transition_distinct_prefix_authorizes_nothing() -> None:
    """A chain whose prefix differs from the anchor chain (distinct list
    objects) authorizes nothing, even when its last entry equals the
    calibration root."""
    chain = CalibrationChain()
    chain.append("a" * 64)
    chain.append("b" * 64)
    anchor = AuditAnchor(
        calibration_artifacts_sha256="",
        benchmark_results_sha256="",
        detector_versions={},
        calibration_chain=["c" * 64],
    )
    assert chain.authorizes_transition(anchor, calibration_root="b" * 64) is False


def test_authorizes_transition_last_hash_must_equal_root() -> None:
    """The final entry must equal the calibration root: a last entry
    merely smaller than the root authorizes nothing."""
    chain = CalibrationChain()
    chain.append("a" * 64)
    chain.append("b" * 64)
    anchor = AuditAnchor(
        calibration_artifacts_sha256="",
        benchmark_results_sha256="",
        detector_versions={},
        calibration_chain=["a" * 64],
    )
    assert chain.authorizes_transition(anchor, calibration_root="f" * 64) is False
