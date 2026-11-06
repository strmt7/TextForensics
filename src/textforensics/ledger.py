"""Tamper-evident stores for TextForensics: ledgers, graphs, and anchors.

This module is the single home for the project's append-only, hash-linked
record keeping. It merges the former ``provenance``, ``audit_log``,
``decision_ledger``, ``provenance_graph`` and ``audit_anchor`` modules;
their public names and on-disk formats are preserved exactly, so files
written by the old modules still verify here.

The stores differ in what they record, not in how they hash:

- :func:`snapshot_file` / :func:`verify_ledger` — hash-chained file
  snapshots (``textforensics-ledger/v1`` JSONL), with cross-process
  locking, fsync, and verify-before-append.
- :class:`AuditLog` — generic hash-chained operation log (JSONL, no
  schema field). No Merkle trees, no encryption: an earlier docstring
  claimed both, neither was implemented.
- :class:`DecisionLedger` — replayable detector-decision records
  (``textforensics.decision-record/v1`` JSONL). Deliberately unchained:
  integrity comes from replay, not from a hash chain. Raw text is never
  stored, only its SHA-256.
- :class:`ProvenanceGraph` — in-memory evidence DAG (cycle rejection,
  lineage, subgraphs), persisted as a single JSON document.
- :func:`export_audit_anchor` / :func:`verify_audit_anchor` and
  :class:`CalibrationChain` — external-anchor rollback detection over
  directory-tree hashes.

One canonical-JSON helper (:func:`_canonical_json_bytes`) serves all
hashing; each record type keeps its own exact byte spelling (excluded
keys, ``ensure_ascii``, ``allow_nan``), so existing files verify
unchanged.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from collections import defaultdict, deque
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

__all__ = [
    "AuditAnchor",
    "AuditLog",
    "AuditLogEntry",
    "AuditLogError",
    "CalibrationChain",
    "DecisionLedger",
    "DecisionLedgerError",
    "DecisionRecord",
    "LEDGER_SCHEMA",
    "ProvenanceEdge",
    "ProvenanceGraph",
    "ProvenanceGraphError",
    "ProvenanceNode",
    "ReplayResult",
    "RollbackError",
    "SCHEMA_VERSION",
    "create_evidence_node",
    "detect_drift",
    "export_audit_anchor",
    "load_graph",
    "load_ledger",
    "save_graph",
    "save_ledger",
    "sha256_bytes",
    "snapshot_file",
    "text_sha256",
    "verify_audit_anchor",
    "verify_audit_log",
    "verify_ledger",
]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json_bytes(
    data: dict[str, Any],
    *,
    exclude: frozenset[str] = frozenset(),
    ensure_ascii: bool = False,
    allow_nan: bool = True,
) -> bytes:
    """Canonical JSON bytes for hashing: sorted keys, compact separators.

    Each record type keeps its own exact byte spelling (``exclude``,
    ``ensure_ascii``, ``allow_nan``), so files written before the merge
    verify unchanged.
    """
    payload = {key: value for key, value in data.items() if key not in exclude}
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=ensure_ascii,
        allow_nan=allow_nan,
    ).encode("utf-8")


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


# ----------------------------------------------------------------------------
# File snapshots — hash-chained provenance ledger (was provenance.py)
# ----------------------------------------------------------------------------


def _canonical_record_payload(record: dict[str, Any]) -> bytes:
    """Canonical bytes of a provenance record, excluding its own hash.

    Kept as a named helper: tests and fuzz targets import it directly.
    Byte-identical to the former ``provenance._canonical_record_payload``.
    """
    return _canonical_json_bytes(record, exclude=frozenset({"record_sha256"}), allow_nan=False)


@contextmanager
def _ledger_lock(ledger_path: Path) -> Iterator[None]:
    """Serialize ledger reads/writes across local processes.

    A separate lock file avoids changing the ledger contents merely to lock it.
    The lock file intentionally persists; deleting lock files can introduce a
    race with another process that is waiting on the same inode/handle.
    """
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = Path(str(ledger_path) + ".lock")
    handle = lock_path.open("a+b")
    try:
        if os.name == "nt":
            import msvcrt

            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
                os.fsync(handle.fileno())
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)

        try:
            yield
        finally:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


def _verify_ledger_unlocked(ledger_path: Path) -> dict[str, Any]:
    if not ledger_path.exists():
        return {
            "valid": False,
            "records": 0,
            "errors": ["ledger_not_found"],
        }

    errors: list[str] = []
    previous = None
    records = 0
    with ledger_path.open("r", encoding="utf-8") as handle:
        for index, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            records += 1
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                errors.append(f"line_{index}:invalid_json")
                continue
            if not isinstance(record, dict):
                errors.append(f"line_{index}:record_not_object")
                continue

            expected = sha256_bytes(_canonical_record_payload(record))
            if record.get("record_sha256") != expected:
                errors.append(f"line_{index}:record_hash_mismatch")
            if record.get("previous_record_sha256") != previous:
                errors.append(f"line_{index}:chain_mismatch")
            previous = record.get("record_sha256")

    return {
        "valid": not errors,
        "records": records,
        "errors": errors,
        "warning": (
            "The ledger is tamper-evident but uses the local system clock; "
            "it is not an independent trusted timestamp."
        ),
    }


def verify_ledger(ledger_path: str | Path) -> dict[str, Any]:
    ledger = Path(ledger_path)
    with _ledger_lock(ledger):
        return _verify_ledger_unlocked(ledger)


def snapshot_file(
    file_path: str | Path,
    ledger_path: str | Path,
) -> dict[str, Any]:
    file_path = Path(file_path)
    ledger_path = Path(ledger_path)
    data = file_path.read_bytes()

    with _ledger_lock(ledger_path):
        previous_record_sha256 = None
        if ledger_path.exists():
            verification = _verify_ledger_unlocked(ledger_path)
            if not verification["valid"]:
                raise ValueError("Refusing to append to an invalid provenance ledger.")
            with ledger_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if line.strip():
                        previous_record_sha256 = json.loads(line)["record_sha256"]

        record: dict[str, Any] = {
            "schema": "textforensics-ledger/v1",
            "timestamp_utc": datetime.now(UTC).isoformat(),
            "file_name": file_path.name,
            "file_size": len(data),
            "file_sha256": sha256_bytes(data),
            "previous_record_sha256": previous_record_sha256,
        }
        record["record_sha256"] = sha256_bytes(_canonical_record_payload(record))

        ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with ledger_path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    record,
                    sort_keys=True,
                    ensure_ascii=False,
                    allow_nan=False,
                )
                + "\n"
            )
            handle.flush()
            os.fsync(handle.fileno())
        return record


# ----------------------------------------------------------------------------
# Generic operation log (was audit_log.py)
# ----------------------------------------------------------------------------


class AuditLogError(Exception):
    """Base exception for audit log errors."""

    pass


@dataclass(frozen=True, slots=True)
class AuditLogEntry:
    """A single audit log entry.

    Attributes:
        index: Monotonically increasing entry index (0-based).
        timestamp: ISO 8601 UTC timestamp.
        operation: Operation type (e.g., "scan", "report", "verify", "policy_evaluate").
        actor: Optional actor identity (user, service, API key).
        input_hash: SHA-256 of input data (for data integrity).
        output_hash: SHA-256 of output data (for data integrity).
        metadata: Additional operation-specific metadata.
        prev_hash: SHA-256 hash of the previous entry (chaining).
        entry_hash: SHA-256 hash of this entry's content (excluding prev_hash).
    """

    index: int
    timestamp: str
    operation: str
    actor: str | None
    input_hash: str | None
    output_hash: str | None
    metadata: dict[str, Any]
    prev_hash: str
    entry_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "operation": self.operation,
            "actor": self.actor,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "metadata": self.metadata,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditLogEntry:
        return cls(
            index=int(data["index"]),
            timestamp=str(data["timestamp"]),
            operation=str(data["operation"]),
            actor=data.get("actor"),
            input_hash=data.get("input_hash"),
            output_hash=data.get("output_hash"),
            metadata=dict(data.get("metadata", {})),
            prev_hash=str(data["prev_hash"]),
            entry_hash=str(data["entry_hash"]),
        )

    def to_json_line(self) -> str:
        """Serialize as a JSON line."""
        return json.dumps(self.to_dict(), separators=(",", ":"), ensure_ascii=False, sort_keys=True)


def _compute_entry_hash(entry_data: dict[str, Any]) -> str:
    """Compute SHA-256 hash of entry content (excluding prev_hash and entry_hash)."""
    return sha256_bytes(
        _canonical_json_bytes(entry_data, exclude=frozenset({"prev_hash", "entry_hash"}))
    )


class AuditLog:
    """Tamper-evident append-only audit log.

    The log maintains a hash chain where each entry includes the hash of the
    previous entry. This makes it computationally infeasible to modify,
    insert, or delete entries without detection.

    The log is stored as JSON Lines (one JSON object per line) for
    streaming compatibility and crash resilience.
    """

    def __init__(self, log_path: str | Path):
        self.log_path = Path(log_path)
        self._entries: list[AuditLogEntry] = []
        self._load()

    def _load(self) -> None:
        """Load existing log entries from disk."""
        if not self.log_path.exists():
            return

        with self.log_path.open("r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    entry = AuditLogEntry.from_dict(data)
                    # Verify chain integrity on load
                    if self._entries and entry.prev_hash != self._entries[-1].entry_hash:
                        raise AuditLogError(
                            f"Hash chain broken at entry {entry.index}: "
                            f"prev_hash mismatch (line {line_num})"
                        )
                    if entry.entry_hash != _compute_entry_hash(entry.to_dict()):
                        raise AuditLogError(
                            f"Entry hash mismatch at entry {entry.index} (line {line_num})"
                        )
                    self._entries.append(entry)
                except (json.JSONDecodeError, KeyError, ValueError) as exc:
                    raise AuditLogError(f"Invalid entry at line {line_num}: {exc}") from exc

    def _append_to_file(self, entry: AuditLogEntry) -> None:
        """Append a single entry to the log file."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(entry.to_json_line() + "\n")

    def append(
        self,
        operation: str,
        *,
        actor: str | None = None,
        input_data: Any | None = None,
        output_data: Any | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditLogEntry:
        """Append a new entry to the audit log.

        Args:
            operation: Operation type identifier.
            actor: Optional actor identity.
            input_data: Optional input data to hash.
            output_data: Optional output data to hash.
            metadata: Additional metadata.

        Returns:
            The created audit log entry.
        """
        index = len(self._entries)
        prev_hash = self._entries[-1].entry_hash if self._entries else "0" * 64

        # Compute hashes
        input_hash = None
        if input_data is not None:
            if isinstance(input_data, (dict, list)):
                input_canonical = json.dumps(
                    input_data, separators=(",", ":"), ensure_ascii=False, sort_keys=True
                )
            else:
                input_canonical = str(input_data)
            input_hash = hashlib.sha256(input_canonical.encode("utf-8")).hexdigest()

        output_hash = None
        if output_data is not None:
            if isinstance(output_data, (dict, list)):
                output_canonical = json.dumps(
                    output_data, separators=(",", ":"), ensure_ascii=False, sort_keys=True
                )
            else:
                output_canonical = str(output_data)
            output_hash = hashlib.sha256(output_canonical.encode("utf-8")).hexdigest()

        timestamp = _now_iso()

        # Build entry data (without hashes)
        entry_data = {
            "index": index,
            "timestamp": timestamp,
            "operation": operation,
            "actor": actor,
            "input_hash": input_hash,
            "output_hash": output_hash,
            "metadata": metadata or {},
            "prev_hash": prev_hash,
        }

        entry_hash = _compute_entry_hash(entry_data)

        entry = AuditLogEntry(
            index=index,
            timestamp=timestamp,
            operation=operation,
            actor=actor,
            input_hash=input_hash,
            output_hash=output_hash,
            metadata=metadata or {},
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )

        # Verify the hash
        assert entry.entry_hash == _compute_entry_hash(entry.to_dict())

        self._entries.append(entry)
        self._append_to_file(entry)

        return entry

    def get_entry(self, index: int) -> AuditLogEntry | None:
        """Get an entry by index."""
        if 0 <= index < len(self._entries):
            return self._entries[index]
        return None

    def get_entries(self, start: int = 0, end: int | None = None) -> list[AuditLogEntry]:
        """Get a range of entries."""
        return self._entries[start:end]

    def verify_chain(self) -> bool:
        """Verify the integrity of the entire hash chain.

        Returns:
            True if the chain is intact, False otherwise.
        """
        if not self._entries:
            return True

        prev_hash = "0" * 64
        for entry in self._entries:
            if entry.prev_hash != prev_hash:
                return False
            if entry.entry_hash != _compute_entry_hash(entry.to_dict()):
                return False
            prev_hash = entry.entry_hash
        return True

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self):
        return iter(self._entries)


def verify_audit_log(log_path: str | Path) -> dict[str, Any]:
    """Verify an audit log file and return verification results.

    Args:
        log_path: Path to the audit log file.

    Returns:
        Dictionary with verification results including:
        - valid: bool
        - entry_count: int
        - first_entry_hash: str
        - last_entry_hash: str
        - errors: list of error messages
    """
    errors: list[str] = []
    try:
        log = AuditLog(log_path)
        if not log.verify_chain():
            errors.append("Hash chain verification failed")
    except AuditLogError as exc:
        errors.append(str(exc))
        return {
            "valid": False,
            "entry_count": 0,
            "first_entry_hash": None,
            "last_entry_hash": None,
            "errors": errors,
        }

    if not log._entries:
        return {
            "valid": True,
            "entry_count": 0,
            "first_entry_hash": None,
            "last_entry_hash": None,
            "errors": [],
        }

    return {
        "valid": True,
        "entry_count": len(log._entries),
        "first_entry_hash": log._entries[0].entry_hash,
        "last_entry_hash": log._entries[-1].entry_hash,
        "errors": [],
    }


# ----------------------------------------------------------------------------
# Replayable detector-decision ledger (was decision_ledger.py)
# ----------------------------------------------------------------------------

LEDGER_SCHEMA = "textforensics.decision-record/v1"


class DecisionLedgerError(Exception):
    """Base exception for decision ledger errors."""

    pass


def _validate_sha256(value: str, field_name: str) -> None:
    if not isinstance(value, str) or len(value) != 64:
        raise DecisionLedgerError(f"{field_name} must be a 64-character hex digest.")
    if not all(c in "0123456789abcdef" for c in value.lower()):
        raise DecisionLedgerError(f"{field_name} must contain only hexadecimal characters.")


def _validate_nonempty_text(text: str) -> None:
    if not isinstance(text, str) or not text.strip():
        raise DecisionLedgerError("Text must be a non-empty string.")


def text_sha256(text: str) -> str:
    """Compute SHA-256 hash of text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class DecisionRecord:
    """A single detector decision record.

    NEVER stores raw text - only the SHA-256 hash of the text (per project rule 22).
    """

    record_id: str
    timestamp: str
    text_sha256: str
    detector_id: str
    detector_version: str
    raw_score: float | None
    verdict: str
    runtime_ms: float | None
    ledger_schema: str = LEDGER_SCHEMA

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DecisionRecord:
        """Deserialize from dictionary."""
        return cls(
            record_id=str(data["record_id"]),
            timestamp=str(data["timestamp"]),
            text_sha256=str(data["text_sha256"]),
            detector_id=str(data["detector_id"]),
            detector_version=str(data["detector_version"]),
            raw_score=data.get("raw_score"),
            verdict=str(data["verdict"]),
            runtime_ms=data.get("runtime_ms"),
            ledger_schema=str(data.get("ledger_schema", LEDGER_SCHEMA)),
        )

    def to_json_line(self) -> str:
        """Serialize as a JSON line."""
        return json.dumps(self.to_dict(), separators=(",", ":"), ensure_ascii=False, sort_keys=True)


@dataclass(frozen=True, slots=True)
class ReplayResult:
    """Result of verifying a recorded decision against a fresh detector run."""

    record_id: str
    matched: bool
    expected_score: float | None
    actual_score: float | None
    expected_verdict: str
    actual_verdict: str
    score_delta: float | None
    detail: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return asdict(self)


class DecisionLedger:
    """Replayable detector decision ledger with optional JSONL persistence."""

    def __init__(self, store_path: str | Path | None = None) -> None:
        self.store_path = Path(store_path) if store_path else None
        self._records: list[DecisionRecord] = []
        if self.store_path:
            self._load()

    def _load(self) -> None:
        """Load existing records from JSONL file."""
        if not self.store_path or not self.store_path.exists():
            return

        with self.store_path.open("r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    record = DecisionRecord.from_dict(data)
                    _validate_sha256(record.text_sha256, "text_sha256")
                    self._records.append(record)
                except (json.JSONDecodeError, KeyError, ValueError) as exc:
                    raise DecisionLedgerError(f"Corrupt JSONL at line {line_num}: {exc}") from exc

    def _append_to_file(self, record: DecisionRecord) -> None:
        """Append a single record to the JSONL file."""
        if not self.store_path:
            return
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        with self.store_path.open("a", encoding="utf-8") as f:
            f.write(record.to_json_line() + "\n")

    def _extract_prediction_fields(
        self, prediction: Any
    ) -> tuple[str, str, float | None, str, float | None]:
        """Extract fields from a DetectorPrediction-like object using duck typing."""
        detector_id = getattr(prediction, "detector_id", None)
        detector_version = getattr(prediction, "detector_version", None)
        raw_score = getattr(prediction, "score", None)
        verdict = getattr(prediction, "verdict", None)
        runtime_ms = getattr(prediction, "runtime_ms", None)

        if detector_id is None or detector_version is None or verdict is None:
            raise DecisionLedgerError("Prediction object missing required attributes")

        return (
            str(detector_id),
            str(detector_version),
            float(raw_score) if raw_score is not None else None,
            str(verdict),
            float(runtime_ms) if runtime_ms is not None else None,
        )

    def record(self, text: str, prediction: Any) -> DecisionRecord:
        """Record a single detector decision."""
        _validate_nonempty_text(text)

        text_hash = text_sha256(text)
        _validate_sha256(text_hash, "text_sha256")

        detector_id, detector_version, raw_score, verdict, runtime_ms = (
            self._extract_prediction_fields(prediction)
        )

        record = DecisionRecord(
            record_id=uuid.uuid4().hex,
            timestamp=_now_iso(),
            text_sha256=text_hash,
            detector_id=detector_id,
            detector_version=detector_version,
            raw_score=raw_score,
            verdict=verdict,
            runtime_ms=runtime_ms,
        )

        self._records.append(record)
        self._append_to_file(record)
        return record

    def record_all(self, text: str, predictions: Sequence[Any]) -> list[DecisionRecord]:
        """Record multiple detector decisions for the same text."""
        return [self.record(text, pred) for pred in predictions]

    def _find_last(
        self, detector_id: str, detector_version: str, text_sha256: str
    ) -> DecisionRecord | None:
        """Find the most recent record matching detector_id, detector_version, and text_sha256."""
        for record in reversed(self._records):
            if (
                record.detector_id == detector_id
                and record.detector_version == detector_version
                and record.text_sha256 == text_sha256
            ):
                return record
        return None

    def verify(
        self,
        text: str,
        prediction: Any,
        *,
        tolerance: float = 1e-9,
    ) -> ReplayResult:
        """Verify a single decision against the most recent matching record."""
        _validate_nonempty_text(text)

        text_hash = text_sha256(text)
        _validate_sha256(text_hash, "text_sha256")

        detector_id, detector_version, raw_score, verdict, runtime_ms = (
            self._extract_prediction_fields(prediction)
        )

        existing = self._find_last(detector_id, detector_version, text_hash)

        if existing is None:
            return ReplayResult(
                record_id="",
                matched=False,
                expected_score=None,
                actual_score=raw_score,
                expected_verdict="",
                actual_verdict=verdict,
                score_delta=None,
                detail="no matching record",
            )

        score_delta = None
        scores_match = False
        if existing.raw_score is None and raw_score is None:
            scores_match = True
        elif existing.raw_score is not None and raw_score is not None:
            score_delta = abs(existing.raw_score - raw_score)
            scores_match = score_delta <= tolerance
        else:
            scores_match = False

        verdicts_match = existing.verdict == verdict
        matched = scores_match and verdicts_match

        detail = "matched" if matched else "mismatch"
        if not scores_match:
            detail = "score mismatch"
        elif not verdicts_match:
            detail = "verdict mismatch"

        return ReplayResult(
            record_id=existing.record_id,
            matched=matched,
            expected_score=existing.raw_score,
            actual_score=raw_score,
            expected_verdict=existing.verdict,
            actual_verdict=verdict,
            score_delta=score_delta,
            detail=detail,
        )

    def verify_text(
        self,
        text: str,
        predictions: Sequence[Any],
        *,
        tolerance: float = 1e-9,
    ) -> list[ReplayResult]:
        """Verify all predictions for a text against the ledger."""
        return [self.verify(text, pred, tolerance=tolerance) for pred in predictions]

    def verify_determinism(
        self,
        text: str,
        run_function: Callable[[str], Sequence[Any]],
        *,
        tolerance: float = 1e-9,
    ) -> list[ReplayResult]:
        """Replay verification entry point: run detectors fresh and verify against ledger."""
        predictions = run_function(text)
        return self.verify_text(text, predictions, tolerance=tolerance)

    def records_for_text(self, text: str) -> list[DecisionRecord]:
        """Get all records for a given text (by hash)."""
        text_hash = text_sha256(text)
        return [r for r in self._records if r.text_sha256 == text_hash]

    def records_for_detector(self, detector_id: str) -> list[DecisionRecord]:
        """Get all records for a given detector."""
        return [r for r in self._records if r.detector_id == detector_id]

    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self):
        return iter(self._records)

    def to_list(self) -> list[dict[str, Any]]:
        """Export all records as list of dictionaries."""
        return [r.to_dict() for r in self._records]


def save_ledger(records: Sequence[DecisionRecord], path: str | Path) -> None:
    """Save records to JSONL file (one record per line)."""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(record.to_json_line() + "\n")


def load_ledger(path: str | Path) -> list[DecisionRecord]:
    """Load records from JSONL file."""
    records: list[DecisionRecord] = []
    input_path = Path(path)
    if not input_path.exists():
        return records

    with input_path.open("r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                record = DecisionRecord.from_dict(data)
                _validate_sha256(record.text_sha256, "text_sha256")
                records.append(record)
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                raise DecisionLedgerError(f"Corrupt JSONL at line {line_num}: {exc}") from exc
    return records


def detect_drift(
    records: Sequence[DecisionRecord],
    baseline: Sequence[DecisionRecord],
) -> list[dict[str, Any]]:
    """Compare two sets of records for detector drift.

    For each detector_id present in both sets, computes:
    - mean score delta (skipping None scores)
    - verdict flip count
    - drift_detected: True iff paired_count >= 1 and (abs(mean_score_delta) > 0.05 or verdict_flips > 0)
    """
    # Index by detector_id
    records_by_detector: dict[str, list[DecisionRecord]] = {}
    for r in records:
        records_by_detector.setdefault(r.detector_id, []).append(r)

    baseline_by_detector: dict[str, list[DecisionRecord]] = {}
    for r in baseline:
        baseline_by_detector.setdefault(r.detector_id, []).append(r)

    # Only compare detectors present in both
    common_detectors = sorted(set(records_by_detector) & set(baseline_by_detector))
    results: list[dict[str, Any]] = []

    for detector_id in common_detectors:
        current_list = records_by_detector[detector_id]
        base_list = baseline_by_detector[detector_id]

        # Index by text_sha256 to pair records
        current_by_hash = {r.text_sha256: r for r in current_list}
        base_by_hash = {r.text_sha256: r for r in base_list}

        common_hashes = sorted(set(current_by_hash) & set(base_by_hash))
        paired_count = len(common_hashes)

        if paired_count == 0:
            results.append(
                {
                    "detector_id": detector_id,
                    "paired_count": 0,
                    "mean_score_delta": None,
                    "verdict_flips": 0,
                    "drift_detected": False,
                }
            )
            continue

        score_deltas: list[float] = []
        verdict_flips = 0

        for h in common_hashes:
            current_rec = current_by_hash[h]
            base_rec = base_by_hash[h]

            # Score delta (skip None)
            if current_rec.raw_score is not None and base_rec.raw_score is not None:
                score_deltas.append(current_rec.raw_score - base_rec.raw_score)

            # Verdict flip
            if current_rec.verdict != base_rec.verdict:
                verdict_flips += 1

        mean_score_delta = sum(score_deltas) / len(score_deltas) if score_deltas else None

        drift_detected = False
        if paired_count >= 1:
            if mean_score_delta is not None and abs(mean_score_delta) > 0.05:
                drift_detected = True
            if verdict_flips > 0:
                drift_detected = True

        results.append(
            {
                "detector_id": detector_id,
                "paired_count": paired_count,
                "mean_score_delta": round(mean_score_delta, 6)
                if mean_score_delta is not None
                else None,
                "verdict_flips": verdict_flips,
                "drift_detected": drift_detected,
            }
        )

    return results


# ----------------------------------------------------------------------------
# Evidence provenance graph (was provenance_graph.py)
# ----------------------------------------------------------------------------


class ProvenanceGraphError(Exception):
    """Base exception for provenance graph errors."""

    pass


@dataclass(frozen=True, slots=True)
class ProvenanceNode:
    """A node in the provenance graph representing a piece of evidence.

    Attributes:
        node_id: Unique identifier for this node.
        node_type: Type of evidence (e.g., "detector_result", "calibration",
                   "threshold", "scan_input", "report", "verification").
        content_hash: SHA-256 hash of the node's content.
        timestamp: ISO 8601 UTC timestamp of creation.
        metadata: Additional type-specific metadata.
        operation: The operation that produced this node (e.g., "scan", "calibrate").
        actor: Optional actor identity.
    """

    node_id: str
    node_type: str
    content_hash: str
    timestamp: str
    metadata: dict[str, Any]
    operation: str
    actor: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "content_hash": self.content_hash,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
            "operation": self.operation,
            "actor": self.actor,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProvenanceNode:
        return cls(
            node_id=str(data["node_id"]),
            node_type=str(data["node_type"]),
            content_hash=str(data["content_hash"]),
            timestamp=str(data["timestamp"]),
            metadata=dict(data.get("metadata", {})),
            operation=str(data["operation"]),
            actor=data.get("actor"),
        )


@dataclass(frozen=True, slots=True)
class ProvenanceEdge:
    """A directed edge in the provenance graph representing a dependency.

    Attributes:
        source_id: ID of the source node (upstream dependency).
        target_id: ID of the target node (downstream derived).
        edge_type: Type of dependency (e.g., "derived_from", "calibrates",
                   "validates", "inputs_to").
        metadata: Additional edge-specific metadata.
    """

    source_id: str
    target_id: str
    edge_type: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProvenanceEdge:
        return cls(
            source_id=str(data["source_id"]),
            target_id=str(data["target_id"]),
            edge_type=str(data["edge_type"]),
            metadata=dict(data.get("metadata", {})),
        )


def _compute_content_hash(content: Any) -> str:
    """Compute SHA-256 hash of content."""
    if isinstance(content, (dict, list)):
        canonical = json.dumps(content, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
    else:
        canonical = str(content)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _generate_node_id(node_type: str, content_hash: str) -> str:
    """Generate a deterministic node ID from type and content hash."""
    return f"{node_type}:{content_hash[:16]}"


class ProvenanceGraph:
    """Directed acyclic graph for evidence provenance tracking.

    The graph maintains nodes representing pieces of evidence and directed
    edges representing derivation/dependency relationships. It enforces
    acyclicity and provides traversal methods for traceability analysis.
    """

    def __init__(self):
        self._nodes: dict[str, ProvenanceNode] = {}
        self._edges: list[ProvenanceEdge] = []
        self._adjacency: dict[str, set[str]] = defaultdict(set)  # source -> targets
        self._reverse_adjacency: dict[str, set[str]] = defaultdict(set)  # target -> sources

    def add_node(
        self,
        node_type: str,
        content: Any,
        operation: str,
        *,
        metadata: dict[str, Any] | None = None,
        actor: str | None = None,
        node_id: str | None = None,
    ) -> ProvenanceNode:
        """Add a node to the graph.

        Args:
            node_type: Type of evidence.
            content: The content to hash.
            operation: Operation that produced this node.
            metadata: Additional metadata.
            actor: Optional actor identity.
            node_id: Optional explicit node ID (generated if not provided).

        Returns:
            The created ProvenanceNode.
        """
        content_hash = _compute_content_hash(content)
        if node_id is None:
            node_id = _generate_node_id(node_type, content_hash)

        if node_id in self._nodes:
            # Check if content matches existing node
            existing = self._nodes[node_id]
            if existing.content_hash != content_hash:
                raise ProvenanceGraphError(
                    f"Node ID collision: {node_id} exists with different content"
                )
            return existing

        timestamp = _now_iso()
        node = ProvenanceNode(
            node_id=node_id,
            node_type=node_type,
            content_hash=content_hash,
            timestamp=timestamp,
            metadata=metadata or {},
            operation=operation,
            actor=actor,
        )

        self._nodes[node_id] = node
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: str,
        metadata: dict[str, Any] | None = None,
    ) -> ProvenanceEdge:
        """Add a directed edge between nodes.

        Args:
            source_id: Source node ID (upstream).
            target_id: Target node ID (downstream).
            edge_type: Type of dependency.
            metadata: Additional edge metadata.

        Returns:
            The created ProvenanceEdge.
        """
        if source_id not in self._nodes:
            raise ProvenanceGraphError(f"Source node not found: {source_id}")
        if target_id not in self._nodes:
            raise ProvenanceGraphError(f"Target node not found: {target_id}")

        # Check for cycles
        if self._would_create_cycle(source_id, target_id):
            raise ProvenanceGraphError(
                f"Adding edge {source_id} -> {target_id} would create a cycle"
            )

        edge = ProvenanceEdge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            metadata=metadata or {},
        )

        self._edges.append(edge)
        self._adjacency[source_id].add(target_id)
        self._reverse_adjacency[target_id].add(source_id)

        return edge

    def _would_create_cycle(self, source_id: str, target_id: str) -> bool:
        """Check if adding an edge would create a cycle using DFS."""
        # If target can reach source, adding source->target creates a cycle
        visited = set()
        stack = [target_id]
        while stack:
            current = stack.pop()
            if current == source_id:
                return True
            if current in visited:
                continue
            visited.add(current)
            stack.extend(self._adjacency.get(current, set()))
        return False

    def get_node(self, node_id: str) -> ProvenanceNode | None:
        """Get a node by ID."""
        return self._nodes.get(node_id)

    def get_parents(self, node_id: str) -> list[ProvenanceNode]:
        """Get all parent (upstream) nodes of a node."""
        parent_ids = self._reverse_adjacency.get(node_id, set())
        return [self._nodes[pid] for pid in parent_ids if pid in self._nodes]

    def get_children(self, node_id: str) -> list[ProvenanceNode]:
        """Get all child (downstream) nodes of a node."""
        child_ids = self._adjacency.get(node_id, set())
        return [self._nodes[cid] for cid in child_ids if cid in self._nodes]

    def get_ancestors(self, node_id: str) -> list[ProvenanceNode]:
        """Get all ancestors (transitive upstream) of a node."""
        ancestors = []
        visited = set()
        queue = deque(self._reverse_adjacency.get(node_id, set()))

        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            if current in self._nodes:
                ancestors.append(self._nodes[current])
                queue.extend(self._reverse_adjacency.get(current, set()))

        return ancestors

    def get_descendants(self, node_id: str) -> list[ProvenanceNode]:
        """Get all descendants (transitive downstream) of a node."""
        descendants = []
        visited = set()
        queue = deque(self._adjacency.get(node_id, set()))

        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            if current in self._nodes:
                descendants.append(self._nodes[current])
                queue.extend(self._adjacency.get(current, set()))

        return descendants

    def get_lineage(self, node_id: str) -> dict[str, Any]:
        """Get complete lineage (ancestors and descendants) of a node."""
        if node_id not in self._nodes:
            raise ProvenanceGraphError(f"Node not found: {node_id}")

        node = self._nodes[node_id]
        ancestors = self.get_ancestors(node_id)
        descendants = self.get_descendants(node_id)

        return {
            "node": node.to_dict(),
            "ancestors": [a.to_dict() for a in ancestors],
            "descendants": [d.to_dict() for d in descendants],
            "ancestor_count": len(ancestors),
            "descendant_count": len(descendants),
        }

    def get_subgraph(self, node_ids: set[str]) -> ProvenanceGraph:
        """Extract a subgraph containing only specified nodes and their connecting edges."""
        subgraph = ProvenanceGraph()
        for node_id in node_ids:
            if node_id in self._nodes:
                node = self._nodes[node_id]
                subgraph._nodes[node_id] = node

        for edge in self._edges:
            if edge.source_id in node_ids and edge.target_id in node_ids:
                subgraph._edges.append(edge)
                subgraph._adjacency[edge.source_id].add(edge.target_id)
                subgraph._reverse_adjacency[edge.target_id].add(edge.source_id)

        return subgraph

    def verify_integrity(self) -> bool:
        """Verify graph integrity (no cycles, all edges reference valid nodes)."""
        # Check all edges reference valid nodes
        for edge in self._edges:
            if edge.source_id not in self._nodes or edge.target_id not in self._nodes:
                return False

        # Check for cycles using Kahn's algorithm
        in_degree = defaultdict(int)
        for edge in self._edges:
            in_degree[edge.target_id] += 1

        queue = deque([nid for nid in self._nodes if in_degree[nid] == 0])
        processed = 0

        while queue:
            current = queue.popleft()
            processed += 1
            for target in self._adjacency.get(current, set()):
                in_degree[target] -= 1
                if in_degree[target] == 0:
                    queue.append(target)

        return processed == len(self._nodes)

    def to_dict(self) -> dict[str, Any]:
        """Serialize graph to dictionary."""
        return {
            "nodes": {nid: node.to_dict() for nid, node in self._nodes.items()},
            "edges": [edge.to_dict() for edge in self._edges],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProvenanceGraph:
        """Deserialize graph from dictionary."""
        graph = cls()
        for nid, node_data in data.get("nodes", {}).items():
            graph._nodes[nid] = ProvenanceNode.from_dict(node_data)
        for edge_data in data.get("edges", []):
            edge = ProvenanceEdge.from_dict(edge_data)
            graph._edges.append(edge)
            graph._adjacency[edge.source_id].add(edge.target_id)
            graph._reverse_adjacency[edge.target_id].add(edge.source_id)
        return graph

    def __len__(self) -> int:
        return len(self._nodes)

    def __contains__(self, node_id: str) -> bool:
        return node_id in self._nodes


def create_evidence_node(
    graph: ProvenanceGraph,
    evidence_type: str,
    content: Any,
    operation: str,
    *,
    parents: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
    actor: str | None = None,
) -> ProvenanceNode:
    """Convenience function to create a node and link it to parent nodes.

    Args:
        graph: ProvenanceGraph to add node to.
        evidence_type: Type of evidence.
        content: Content to hash.
        operation: Operation that produced this evidence.
        parents: Optional list of parent node IDs.
        metadata: Additional metadata.
        actor: Optional actor identity.

    Returns:
        The created ProvenanceNode.
    """
    node = graph.add_node(evidence_type, content, operation, metadata=metadata, actor=actor)

    if parents:
        for parent_id in parents:
            graph.add_edge(parent_id, node.node_id, "derived_from")

    return node


def save_graph(graph: ProvenanceGraph, path: str | Path) -> None:
    """Save graph to JSON file."""
    Path(path).write_text(
        json.dumps(graph.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def load_graph(path: str | Path) -> ProvenanceGraph:
    """Load graph from JSON file."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return ProvenanceGraph.from_dict(data)


# ----------------------------------------------------------------------------
# External-anchor rollback detection (was audit_anchor.py)
# ----------------------------------------------------------------------------

SCHEMA_VERSION = 1


class RollbackError(Exception):
    """Raised when a rollback of calibration or benchmark artifacts is detected.

    An anchor was previously exported (and stored externally), but the current
    state of calibration or benchmark artifacts does not match the anchor and
    does not extend the calibration chain. This indicates either:
    - A deliberate rollback of artifacts to an earlier state, or
    - Corruption or tampering of the artifact store.
    """

    pass


@dataclass(frozen=True, slots=True)
class AuditAnchor:
    """An exported audit point for rollback detection.

    Attributes:
        calibration_artifacts_sha256: SHA-256 of the calibrations directory tree.
        benchmark_results_sha256: SHA-256 of the benchmarks directory tree.
        detector_versions: Mapping of detector_id to version string.
        calibration_chain: Ordered list of calibration artifact hashes.
        exported_at: ISO 8601 timestamp of export.
        schema_version: Schema version for forward compatibility.
    """

    calibration_artifacts_sha256: str
    benchmark_results_sha256: str
    detector_versions: dict[str, str]
    calibration_chain: list[str] = field(default_factory=list)
    exported_at: str = ""
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "calibration_artifacts_sha256": self.calibration_artifacts_sha256,
            "benchmark_results_sha256": self.benchmark_results_sha256,
            "detector_versions": dict(self.detector_versions),
            "calibration_chain": list(self.calibration_chain),
            "exported_at": self.exported_at,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditAnchor:
        return cls(
            calibration_artifacts_sha256=str(data["calibration_artifacts_sha256"]),
            benchmark_results_sha256=str(data["benchmark_results_sha256"]),
            detector_versions=dict(data.get("detector_versions", {})),
            calibration_chain=list(data.get("calibration_chain", [])),
            exported_at=str(data.get("exported_at", "")),
            schema_version=int(data.get("schema_version", 1)),
        )


def _hash_directory(dir_path: Path) -> str:
    """Compute a deterministic SHA-256 hash of a directory tree.

    Files are sorted by relative path and hashed sequentially. Directories
    without files produce the empty-string hash. A missing directory also
    produces the empty-string hash.
    """
    if not dir_path.is_dir():
        return ""

    hasher = hashlib.sha256()
    for file_path in sorted(dir_path.rglob("*")):
        if file_path.is_file():
            # Include relative path in hash so renaming files changes the result
            rel = str(file_path.relative_to(dir_path))
            hasher.update(rel.encode("utf-8"))
            hasher.update(b"\x00")
            hasher.update(file_path.read_bytes())
            hasher.update(b"\n")
    return hasher.hexdigest()


def _resolve_base_dir() -> Path:
    """Resolve the project base directory (parent of src/textforensics)."""
    return Path(__file__).resolve().parent.parent.parent


def export_audit_anchor(
    base_dir: Path | None = None,
    detector_versions: dict[str, str] | None = None,
    calibration_chain: list[str] | None = None,
) -> AuditAnchor:
    """Export an audit anchor for rollback detection.

    The anchor captures the current state of calibration artifacts, benchmark
    results, and detector versions. Store the returned anchor externally (e.g.
    in a secure vault, a signed commit, or an out-of-band file) and use
    ``verify_audit_anchor`` to detect rollbacks.

    Args:
        base_dir: Override the project root (default: auto-detected).
        detector_versions: Override detector versions (default: auto-discovered).
        calibration_chain: Override the calibration chain (default: empty).

    Returns:
        An ``AuditAnchor`` with current hashes and metadata.
    """
    if base_dir is None:
        base_dir = _resolve_base_dir()

    cal_dir = base_dir / "calibrations"
    bench_dir = base_dir / "benchmarks"

    cal_hash = _hash_directory(cal_dir)
    bench_hash = _hash_directory(bench_dir)

    if detector_versions is None:
        try:
            from .detectors import list_detector_metadata

            detector_versions = {
                item["detector_id"]: item.get("detector_version", "unknown")
                for item in list_detector_metadata()
            }
        except Exception:
            detector_versions = {}

    if calibration_chain is None:
        calibration_chain = []

    return AuditAnchor(
        calibration_artifacts_sha256=cal_hash,
        benchmark_results_sha256=bench_hash,
        detector_versions=detector_versions,
        calibration_chain=calibration_chain,
        exported_at=datetime.now(UTC).isoformat(),
        schema_version=SCHEMA_VERSION,
    )


def verify_audit_anchor(
    anchor: AuditAnchor,
    current_chain: CalibrationChain | None = None,
    base_dir: Path | None = None,
) -> str:
    """Verify that the current state has not rolled back relative to *anchor*.

    Checks (in order of specificity):
    1. If calibration and benchmark hashes match the anchor exactly, return
       "no_changes".
    2. If a ``CalibrationChain`` is provided and the current chain extends the
       anchor's chain, return "chain_valid".
    3. Otherwise raise ``RollbackError``.

    Args:
        anchor: The previously exported audit anchor to verify against.
        current_chain: The current calibration chain for chain verification.
        base_dir: Override the project root (default: auto-detected).

    Returns:
        A status string: ``"no_changes"``, ``"chain_valid"``, or raises.

    Raises:
        RollbackError: When a rollback is detected.
    """
    if base_dir is None:
        base_dir = _resolve_base_dir()

    cal_dir = base_dir / "calibrations"
    bench_dir = base_dir / "benchmarks"

    current_cal_hash = _hash_directory(cal_dir)
    current_bench_hash = _hash_directory(bench_dir)

    # Check 1: Exact match – no changes since anchor
    if (
        current_cal_hash == anchor.calibration_artifacts_sha256
        and current_bench_hash == anchor.benchmark_results_sha256
    ):
        return "no_changes"

    # Check 2: Chain verification – current chain extends anchor chain
    if current_chain is not None and current_chain.extends_anchor(anchor):
        return "chain_valid"

    # Determine which artifact(s) changed
    reasons: list[str] = []
    if current_cal_hash != anchor.calibration_artifacts_sha256:
        reasons.append(
            f"Calibration artifacts rolled back "
            f"(expected {anchor.calibration_artifacts_sha256[:16]}..., "
            f"got {current_cal_hash[:16]}...)"
        )
    if current_bench_hash != anchor.benchmark_results_sha256:
        reasons.append(
            f"Benchmark results rolled back "
            f"(expected {anchor.benchmark_results_sha256[:16]}..., "
            f"got {current_bench_hash[:16]}...)"
        )

    if reasons:
        raise RollbackError("; ".join(reasons))

    # Edge case: both empty – nothing to verify
    return "no_changes"


class CalibrationChain:
    """Tracks a monotonic chain of calibration artifact hashes.

    Each new calibration artifact appends its SHA-256 hash to the chain.
    Verification ensures the chain is contiguous and extends from a known
    anchor point.

    The chain is external to the workspace by convention: it is stored and
    verified using externally managed checkpoints so that a whole-database
    rollback is detectable.
    """

    def __init__(self) -> None:
        self._hashes: list[str] = []

    @property
    def hashes(self) -> list[str]:
        """Return a copy of the current chain hashes."""
        return list(self._hashes)

    @property
    def length(self) -> int:
        return len(self._hashes)

    def append(self, artifact_hash: str) -> None:
        """Append a new calibration artifact hash to the chain."""
        self._hashes.append(artifact_hash)

    def to_dict(self) -> dict[str, Any]:
        return {"chain": list(self._hashes), "length": self.length}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CalibrationChain:
        chain = cls()
        chain._hashes = list(data.get("chain", []))
        return chain

    def verify_integrity(self) -> list[str]:
        """Verify that all chain hashes are valid SHA-256 hex strings.

        Returns a list of errors (empty if valid).
        """
        errors: list[str] = []
        for i, h in enumerate(self._hashes):
            if not h or len(h) != 64:
                errors.append(f"Entry {i}: hash length {len(h)} != 64")
            try:
                int(h, 16)
            except ValueError:
                errors.append(f"Entry {i}: not valid hex")
        return errors

    def extends_anchor(self, anchor: AuditAnchor) -> bool:
        """Check if the current chain extends the anchor's chain.

        The current chain must contain all hashes from the anchor's chain
        in the same order, followed by zero or more additional hashes.
        """
        anchor_chain = anchor.calibration_chain
        if not anchor_chain:
            # Empty anchor chain: any non-empty current chain extends it,
            # or if both are empty that means the artifacts themselves
            # changed (handled by the caller's hash check).
            return len(self._hashes) > 0

        # Current chain must be at least as long as anchor chain
        if len(self._hashes) < len(anchor_chain):
            return False

        # Check that the prefix matches
        return self._hashes[: len(anchor_chain)] == anchor_chain

    def load_from_file(self, path: Path) -> None:
        """Load a persisted chain from a JSON file."""
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            self._hashes = list(data.get("chain", []))

    def save_to_file(self, path: Path) -> None:
        """Persist the chain to a JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
