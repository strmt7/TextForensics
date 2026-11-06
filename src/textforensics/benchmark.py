"""JSONL benchmarking and dataset fingerprinting for TextForensics.

Benchmarking scores a JSONL dataset with the built-in heuristic detector,
selects operating thresholds at a target human false-positive rate, and
evaluates a fitted threshold on held-out data. Dataset fingerprinting
provides immutable per-dataset fingerprints and disjointness checks so
training, threshold selection, calibration, and final evaluation stay
disjoint (AGENTS.md rule 12).
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .detectors import BuiltinHeuristicDetector
from .engine import analyze_text

CALIBRATION_SCHEMA = "textforensics.calibration/v1"


class DatasetFormatError(ValueError):
    """Raised when benchmark JSONL is malformed or ambiguous."""


def dataset_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_scores(
    path: str | Path,
    *,
    strict: bool = True,
) -> tuple[list[tuple[str, float]], int]:
    rows: list[tuple[str, float]] = []
    skipped = 0
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                if strict:
                    raise DatasetFormatError(f"Line {line_number} is not valid JSON.") from exc
                skipped += 1
                continue
            if not isinstance(row, dict):
                if strict:
                    raise DatasetFormatError(f"Line {line_number} must be a JSON object.")
                skipped += 1
                continue

            label = str(row.get("label", "")).strip().lower()
            text = row.get("text")
            if label not in {"human", "ai"} or not isinstance(text, str) or not text.strip():
                if strict:
                    raise DatasetFormatError(
                        f"Line {line_number} requires label 'human'/'ai' and non-empty text."
                    )
                skipped += 1
                continue

            score = analyze_text(text, include_robustness=False).score
            rows.append((label, float(score)))
    return rows, skipped


def _metrics(
    rows: list[tuple[str, float]],
    threshold: float,
) -> dict[str, Any]:
    if not math.isfinite(threshold):
        raise ValueError("threshold must be finite.")

    tp = fp = tn = fn = 0
    for label, score in rows:
        pred = "ai" if score >= threshold else "human"
        if label == "ai" and pred == "ai":
            tp += 1
        elif label == "ai":
            fn += 1
        elif pred == "ai":
            fp += 1
        else:
            tn += 1

    total = len(rows)
    accuracy = (tp + tn) / total if total else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0

    return {
        "threshold": threshold,
        "evaluated": total,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "true_positive_rate": round(tpr, 4),
        "specificity": round(specificity, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
    }


def benchmark_jsonl(
    path: str | Path,
    threshold: float = 0.5,
    *,
    strict: bool = True,
) -> dict[str, Any]:
    rows, skipped = _load_scores(path, strict=strict)
    result = _metrics(rows, threshold)
    result.update(
        {
            "schema": "textforensics.benchmark-result/v1",
            "dataset_sha256": dataset_sha256(path),
            "skipped": skipped,
            "mode": "diagnostic_fixed_threshold",
            "warning": (
                "Built-in analyzers are heuristic baselines. This command does "
                "not make a production-performance claim."
            ),
        }
    )
    return result


def calibrate_threshold_jsonl(
    path: str | Path,
    target_fpr: float = 0.01,
    *,
    strict: bool = True,
) -> dict[str, Any]:
    if not 0 <= target_fpr <= 1:
        raise ValueError("target_fpr must be between 0 and 1.")

    rows, skipped = _load_scores(path, strict=strict)
    humans = [score for label, score in rows if label == "human"]
    ais = [score for label, score in rows if label == "ai"]
    if not humans or not ais:
        raise ValueError("Calibration requires at least one human and one AI sample.")

    max_score = max(score for _, score in rows)
    candidates = sorted(
        {
            *(score for _, score in rows),
            math.nextafter(max_score, math.inf),
        }
    )

    best: tuple[tuple[float, float, float], float, float, float] | None = None
    for threshold in candidates:
        fp = sum(score >= threshold for score in humans)
        tp = sum(score >= threshold for score in ais)
        fpr = fp / len(humans)
        tpr = tp / len(ais)
        if fpr <= target_fpr:
            candidate = (tpr, -fpr, -threshold)
            if best is None or candidate > best[0]:
                best = (candidate, threshold, fpr, tpr)

    if best is None:
        raise RuntimeError("No threshold satisfied the target false-positive rate.")

    _, threshold, fpr, tpr = best
    detector = BuiltinHeuristicDetector()
    return {
        "schema": CALIBRATION_SCHEMA,
        "created_at_utc": datetime.now(UTC).isoformat(),
        "detector_id": detector.detector_id,
        "detector_version": detector.detector_version,
        "score_semantics": "higher_means_more_machine_like; uncalibrated pattern score",
        "calibration_method": "threshold_at_target_human_fpr",
        "target_false_positive_rate": target_fpr,
        "recommended_threshold": float(threshold),
        "observed_false_positive_rate": round(float(fpr), 4),
        "observed_true_positive_rate": round(float(tpr), 4),
        "human_samples": len(humans),
        "ai_samples": len(ais),
        "skipped": skipped,
        "calibration_dataset_sha256": dataset_sha256(path),
        "classification_rule": "ai_like iff score >= recommended_threshold",
        "mode": "calibration_only_not_final_evaluation",
        "warning": (
            "This artifact is fitted to the supplied calibration corpus. "
            "Evaluate it on a separate held-out dataset before making claims."
        ),
    }


def validate_calibration_artifact(artifact: dict[str, Any]) -> None:
    required = {
        "schema",
        "detector_id",
        "detector_version",
        "recommended_threshold",
        "calibration_dataset_sha256",
    }
    missing = sorted(required - artifact.keys())
    if missing:
        raise ValueError(f"Calibration artifact is missing: {', '.join(missing)}")
    if artifact["schema"] != CALIBRATION_SCHEMA:
        raise ValueError("Unsupported calibration artifact schema.")

    detector = BuiltinHeuristicDetector()
    if artifact["detector_id"] != detector.detector_id:
        raise ValueError("Calibration artifact targets a different detector.")
    if artifact["detector_version"] != detector.detector_version:
        raise ValueError("Calibration artifact targets a different detector version.")

    threshold = artifact["recommended_threshold"]
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        raise ValueError("Calibration threshold must be numeric.")
    if not math.isfinite(float(threshold)):
        raise ValueError("Calibration threshold must be finite.")

    fingerprint = artifact["calibration_dataset_sha256"]
    if not isinstance(fingerprint, str) or len(fingerprint) != 64:
        raise ValueError("Invalid calibration dataset fingerprint.")
    if any(char not in "0123456789abcdef" for char in fingerprint):
        raise ValueError("Invalid calibration dataset fingerprint.")


def benchmark_with_calibration_jsonl(
    path: str | Path,
    calibration: dict[str, Any],
    *,
    strict: bool = True,
    allow_same_dataset: bool = False,
) -> dict[str, Any]:
    validate_calibration_artifact(calibration)
    evaluation_sha = dataset_sha256(path)
    if not allow_same_dataset and evaluation_sha == calibration["calibration_dataset_sha256"]:
        raise ValueError(
            "Evaluation dataset matches the calibration dataset. Use a separate "
            "held-out dataset for release-quality validation."
        )

    rows, skipped = _load_scores(path, strict=strict)
    result = _metrics(rows, float(calibration["recommended_threshold"]))
    result.update(
        {
            "schema": "textforensics.benchmark-result/v1",
            "dataset_sha256": evaluation_sha,
            "calibration_dataset_sha256": calibration["calibration_dataset_sha256"],
            "detector_id": calibration["detector_id"],
            "detector_version": calibration["detector_version"],
            "skipped": skipped,
            "mode": "held_out_evaluation",
        }
    )
    return result


def load_calibration_artifact(path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Calibration artifact must be a JSON object.")
    validate_calibration_artifact(payload)
    return payload


# ---------------------------------------------------------------------------
# Dataset fingerprinting and contamination prevention
# (merged from benchmark_fingerprint.py, Phase 2 wave e)
# ---------------------------------------------------------------------------
# Immutable fingerprints track dataset identity so training, threshold
# selection, calibration, and final evaluation stay disjoint (AGENTS.md
# rule 12). The per-sample hashes here are the canonical implementation
# used by the contamination gates.


@dataclass(frozen=True, slots=True)
class DatasetFingerprint:
    """Immutable fingerprint for a benchmark dataset.

    Tracks dataset identity, provenance, and content to ensure
    reproducibility and detect contamination.

    Attributes:
        name: Dataset identifier (e.g., "RAID", "DetectRL", "M4")
        version: Dataset version or release identifier
        split: Dataset split ("train", "calibration", "test", "evaluation")
        filters: Applied filters as a JSON-serializable dict
        sample_count: Number of samples in the dataset
        content_hashes: Per-sample content hashes for overlap detection
        dataset_hash: SHA256 hash of the entire dataset file
        created_at: UTC timestamp of fingerprint creation
    """

    name: str
    version: str
    split: str
    filters: dict[str, Any] = field(default_factory=dict)
    sample_count: int = 0
    content_hashes: tuple[str, ...] = field(default_factory=tuple)
    dataset_hash: str = ""
    created_at: str = ""

    def __post_init__(self) -> None:
        """Set creation timestamp if not provided."""
        if not self.created_at:
            object.__setattr__(self, "created_at", datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        """Serialize fingerprint to a dictionary."""
        return {
            "schema": "textforensics.dataset-fingerprint/v1",
            "name": self.name,
            "version": self.version,
            "split": self.split,
            "filters": self.filters,
            "sample_count": self.sample_count,
            "content_hashes": list(self.content_hashes),
            "dataset_hash": self.dataset_hash,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DatasetFingerprint:
        """Deserialize fingerprint from a dictionary."""
        required = {"name", "version", "split", "dataset_hash"}
        missing = required - set(data.keys())
        if missing:
            raise ValueError(f"Missing required fields: {', '.join(sorted(missing))}")

        return cls(
            name=data["name"],
            version=data["version"],
            split=data["split"],
            filters=data.get("filters", {}),
            sample_count=data.get("sample_count", 0),
            content_hashes=tuple(data.get("content_hashes", [])),
            dataset_hash=data["dataset_hash"],
            created_at=data.get("created_at", ""),
        )


def _compute_content_hash(text: str) -> str:
    """Compute a stable hash for text content."""
    # Use canonical form for stability
    canonical = json.dumps(
        {"text": text},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _iter_jsonl_samples(path: Path) -> Iterator[dict[str, Any]]:
    """Iterate over JSONL samples as dictionaries."""
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Line {line_number} is not valid JSON: {exc}") from exc


def _compute_sample_hashes(
    path: Path,
    *,
    strict: bool = True,
    include_text: bool = False,
) -> tuple[list[str], int]:
    """Compute hashes for samples in a JSONL file.

    Returns:
        Tuple of (list of content hashes, count of valid samples)

    Raises:
        ValueError: If strict mode and invalid JSON is encountered.
    """
    hashes: list[str] = []
    count = 0

    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                if strict:
                    raise ValueError(f"Line {line_number} is not valid JSON") from exc
                continue

            if not isinstance(row, dict):
                if strict:
                    raise ValueError(f"Line {line_number} must be a JSON object")
                continue

            text = row.get("text", "")
            if include_text and isinstance(text, str):
                # When including text, hash the full text content
                content = json.dumps(
                    {"label": str(row.get("label", "")), "text": text},
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
            elif "label" in row:
                # Otherwise just hash the text
                content = json.dumps(
                    {"text": text},
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
            else:
                continue

            hashes.append(hashlib.sha256(content.encode("utf-8")).hexdigest())
            count += 1

    return hashes, count


def fingerprint_dataset(
    path: str | Path,
    name: str,
    version: str = "1.0.0",
    split: str = "test",
    filters: dict[str, Any] | None = None,
    *,
    strict: bool = True,
    include_text: bool = False,
) -> DatasetFingerprint:
    """Create an immutable fingerprint for a dataset.

    Args:
        path: Path to the JSONL dataset file
        name: Dataset identifier (e.g., "RAID", "DetectRL")
        version: Dataset version string
        split: Dataset split type ("test", "calibration", "evaluation")
        filters: Applied filters as a dictionary
        strict: Whether to fail on invalid JSON lines
        include_text: Whether to include text in sample hashes

    Returns:
        DatasetFingerprint object

    Raises:
        ValueError: If the dataset cannot be read or parsed.
    """
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"Dataset file not found: {path}")

    data_hash = dataset_sha256(path)
    hashes, count = _compute_sample_hashes(path, strict=strict, include_text=include_text)

    fingerprint_args = {
        "name": name,
        "version": version,
        "split": split,
        "filters": filters or {},
        "sample_count": count,
        "content_hashes": tuple(sorted(hashes)),  # Sort for determinism
        "dataset_hash": data_hash,
    }

    return DatasetFingerprint(**fingerprint_args)


def verify_fingerprint(
    path: str | Path,
    fingerprint: DatasetFingerprint,
    *,
    strict: bool = True,
) -> dict[str, Any]:
    """Verify that a dataset matches its fingerprint.

    Returns a verification result dict with:
        - valid: bool indicating if dataset matches fingerprint
        - errors: list of error messages if not valid
        - details: additional verification details
    """
    path = Path(path)
    result: dict[str, Any] = {
        "valid": False,
        "errors": [],
        "details": {},
    }

    if not path.exists():
        result["errors"].append("Dataset file not found")
        return result

    # Check file hash
    try:
        current_hash = dataset_sha256(path)
    except Exception as exc:
        result["errors"].append(f"Failed to compute file hash: {exc}")
        return result

    if current_hash != fingerprint.dataset_hash:
        result["errors"].append(
            f"File hash mismatch. Expected: {fingerprint.dataset_hash[:16]}..., "
            f"Got: {current_hash[:16]}..."
        )

    # Check sample count
    try:
        _, count = _compute_sample_hashes(path, strict=strict)
    except Exception as exc:
        result["errors"].append(f"Failed to count samples: {exc}")
        return result

    if count != fingerprint.sample_count:
        result["errors"].append(
            f"Sample count mismatch. Expected: {fingerprint.sample_count}, Got: {count}"
        )

    result["valid"] = len(result["errors"]) == 0
    return result


def check_disjointness(
    path1: str | Path,
    fp1: DatasetFingerprint,
    path2: str | Path,
    fp2: DatasetFingerprint,
    *,
    strict: bool = True,
) -> dict[str, Any]:
    """Check if two datasets are disjoint (no overlap).

    This is critical for preventing benchmark contamination.

    Fail-closed: if the content hashes for either dataset cannot be
    computed, the check is unverifiable and the result must NOT claim
    disjointness. ``disjoint`` is False, ``verified`` is False, and the
    reason is recorded in ``errors`` (and ``warnings``). A caller that
    checks only ``disjoint`` therefore treats an unreadable dataset as
    contaminated, never as clean.

    Returns a result dict with:
        - disjoint: True if datasets have no overlapping samples
        - shared_samples: count of overlapping samples
        - shared_hashes: list of shared content hashes
        - warnings: list of potential issues
        - errors: list of failures that prevented verification
        - verified: True only if both datasets were hashed successfully
    """
    path1 = Path(path1)
    path2 = Path(path2)

    result: dict[str, Any] = {
        "disjoint": True,
        "shared_samples": 0,
        "shared_hashes": [],
        "warnings": [],
        "errors": [],
        "verified": True,
    }

    # Compute hashes for both datasets
    hashes1: set[str] = set()
    hashes2: set[str] = set()

    try:
        hashes1_raw, _ = _compute_sample_hashes(path1, strict=strict)
    except Exception as exc:
        message = f"Could not compute hashes for path1: {exc}"
        result["warnings"].append(message)
        result["errors"].append(message)
        result["disjoint"] = False
        result["verified"] = False
        return result

    try:
        hashes2_raw, _ = _compute_sample_hashes(path2, strict=strict)
    except Exception as exc:
        message = f"Could not compute hashes for path2: {exc}"
        result["warnings"].append(message)
        result["errors"].append(message)
        result["disjoint"] = False
        result["verified"] = False
        return result

    hashes1 = set(hashes1_raw)
    hashes2 = set(hashes2_raw)

    # Find overlap
    shared = hashes1 & hashes2

    if shared:
        result["disjoint"] = False
        result["shared_samples"] = len(shared)
        result["shared_hashes"] = sorted(shared)

    return result


def load_fingerprint(path: str | Path) -> DatasetFingerprint:
    """Load a fingerprint from a JSON file."""
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Fingerprint file must contain a JSON object")
    return DatasetFingerprint.from_dict(data)


def save_fingerprint(
    fingerprint: DatasetFingerprint,
    path: str | Path,
) -> Path:
    """Save a fingerprint to a JSON file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(fingerprint.to_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def validate_disjointness(
    calibration_path: str | Path,
    calibration_fp: DatasetFingerprint,
    evaluation_path: str | Path,
    evaluation_fp: DatasetFingerprint,
) -> None:
    """Validate that calibration and evaluation datasets are disjoint.

    Raises:
        ValueError: If datasets share samples (contamination detected),
            or if disjointness could not be verified (fail-closed: an
            unverifiable check is refused, never passed).
    """
    result = check_disjointness(
        calibration_path,
        calibration_fp,
        evaluation_path,
        evaluation_fp,
    )

    if result.get("errors"):
        raise ValueError(
            "Benchmark disjointness could not be verified: "
            + "; ".join(result["errors"])
            + ". Refusing to treat unverifiable datasets as disjoint."
        )

    if not result["disjoint"]:
        raise ValueError(
            f"Benchmark contamination detected: {result['shared_samples']} overlapping "
            f"samples between calibration and evaluation datasets. "
            f"Use disjoint datasets to prevent data leakage."
        )
