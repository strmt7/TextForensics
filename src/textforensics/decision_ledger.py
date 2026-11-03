"""Replayable Detector Decision Ledger for TextForensics.

This module provides a deterministic replay verification system for detector decisions.
It records every detector decision (input hash, detector ID/version, raw score, verdict)
and supports re-running the same detectors on the same inputs to confirm the recorded
decisions reproduce exactly.

Inspired by AiSOC's "replayable decision ledger" but adapted to AI-text detector auditing.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

__all__ = [
    "DecisionLedgerError",
    "DecisionRecord",
    "ReplayResult",
    "DecisionLedger",
    "save_ledger",
    "load_ledger",
    "detect_drift",
    "LEDGER_SCHEMA",
]

LEDGER_SCHEMA = "textforensics.decision-record/v1"


class DecisionLedgerError(Exception):
    """Base exception for decision ledger errors."""
    pass


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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

        detector_id, detector_version, raw_score, verdict, runtime_ms = self._extract_prediction_fields(
            prediction
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

    def _find_last(self, detector_id: str, detector_version: str, text_sha256: str) -> DecisionRecord | None:
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

        detector_id, detector_version, raw_score, verdict, runtime_ms = self._extract_prediction_fields(
            prediction
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
                "mean_score_delta": round(mean_score_delta, 6) if mean_score_delta is not None else None,
                "verdict_flips": verdict_flips,
                "drift_detected": drift_detected,
            }
        )

    return results