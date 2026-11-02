"""Benchmark dataset fingerprinting for contamination prevention.

This module provides immutable fingerprints for datasets to track their
identity and prevent benchmark contamination. Part of requirement #12
from AGENTS.md: "Prevent benchmark contamination. Training, threshold
selection, calibration, and final evaluation must be disjoint. Track
dataset fingerprints and model provenance."
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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
            object.__setattr__(self, "created_at", datetime.now(timezone.utc).isoformat())

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


def dataset_sha256(path: str | Path) -> str:
    """Compute SHA256 hash of entire dataset file.

    This is the same as the existing function in benchmark.py
    but included here for the fingerprint module's API.
    """
    digest = hashlib.sha256()
    path = Path(path)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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

    Returns a result dict with:
        - disjoint: True if datasets have no overlapping samples
        - shared_samples: count of overlapping samples
        - shared_hashes: list of shared content hashes
        - warnings: list of potential issues
    """
    path1 = Path(path1)
    path2 = Path(path2)

    result: dict[str, Any] = {
        "disjoint": True,
        "shared_samples": 0,
        "shared_hashes": [],
        "warnings": [],
    }

    # Compute hashes for both datasets
    hashes1: set[str] = set()
    hashes2: set[str] = set()

    try:
        hashes1_raw, _ = _compute_sample_hashes(path1, strict=strict)
    except Exception as exc:
        result["warnings"].append(f"Could not compute hashes for path1: {exc}")
        return result

    try:
        hashes2_raw, _ = _compute_sample_hashes(path2, strict=strict)
    except Exception as exc:
        result["warnings"].append(f"Could not compute hashes for path2: {exc}")
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
        ValueError: If datasets share samples (contamination detected).
    """
    result = check_disjointness(
        calibration_path,
        calibration_fp,
        evaluation_path,
        evaluation_fp,
    )

    if not result["disjoint"]:
        raise ValueError(
            f"Benchmark contamination detected: {result['shared_samples']} overlapping "
            f"samples between calibration and evaluation datasets. "
            f"Use disjoint datasets to prevent data leakage."
        )
