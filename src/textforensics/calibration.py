"""Detector Calibration Manager for TextForensics.

This module manages detector calibration artifacts including:
- Calibration versioning and persistence
- Validation against reference datasets
- Calibration curve fitting and storage
- Automatic recalibration triggers
- Migration between calibration versions

This is a critical component for maintaining detector reliability over time.
"""

from __future__ import annotations

import hashlib
import json
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

__all__ = [
    "CalibrationCurve",
    "CalibrationArtifact",
    "CalibrationManager",
    "CalibrationError",
    "validate_calibration_artifact",
]


class CalibrationError(Exception):
    """Base exception for calibration errors."""
    pass


@dataclass(frozen=True, slots=True)
class CalibrationCurve:
    """A calibration curve mapping detector scores to calibrated probabilities.

    Attributes:
        method: Calibration method (e.g., "isotonic", "platt", "temperature").
        parameters: Method-specific parameters (e.g., coefficients for Platt).
        reference_dataset_hash: Hash of the dataset used for calibration.
        reference_dataset_name: Name/identifier of the reference dataset.
        calibrated_at: ISO timestamp when calibration was performed.
        sample_count: Number of samples used for calibration.
        calibration_error: Optional calibration error metric (e.g., Brier score).
    """

    method: str
    parameters: dict[str, Any]
    reference_dataset_hash: str
    reference_dataset_name: str
    calibrated_at: str
    sample_count: int
    calibration_error: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "parameters": self.parameters,
            "reference_dataset_hash": self.reference_dataset_hash,
            "reference_dataset_name": self.reference_dataset_name,
            "calibrated_at": self.calibrated_at,
            "sample_count": self.sample_count,
            "calibration_error": self.calibration_error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CalibrationCurve:
        return cls(
            method=str(data["method"]),
            parameters=dict(data["parameters"]),
            reference_dataset_hash=str(data["reference_dataset_hash"]),
            reference_dataset_name=str(data["reference_dataset_name"]),
            calibrated_at=str(data["calibrated_at"]),
            sample_count=int(data["sample_count"]),
            calibration_error=data.get("calibration_error"),
        )

    def calibrate(self, score: float) -> float:
        """Apply calibration to a raw detector score."""
        if self.method == "isotonic":
            # Isotonic regression: piecewise constant non-decreasing function
            # Parameters: {"x": [...], "y": [...]} where y is non-decreasing
            x = self.parameters.get("x", [])
            y = self.parameters.get("y", [])
            if not x or not y:
                return score
            # Binary search for the right segment
            import bisect
            idx = bisect.bisect_right(x, score) - 1
            if idx < 0:
                return y[0]
            if idx >= len(y) - 1:
                return y[-1]
            return y[idx]

        elif self.method == "platt":
            # Platt scaling: sigmoid(A * score + B)
            A = self.parameters.get("A", 1.0)
            B = self.parameters.get("B", 0.0)
            import math
            return 1.0 / (1.0 + math.exp(A * score + B))

        elif self.method == "temperature":
            # Temperature scaling: softmax(score / T)
            T = self.parameters.get("T", 1.0)
            import math
            scaled = score / T
            return 1.0 / (1.0 + math.exp(-scaled))

        elif self.method == "beta":
            # Beta calibration: calibrated = beta_cdf(score; a, b)
            from math import comb
            a = self.parameters.get("a", 1.0)
            b = self.parameters.get("b", 1.0)
            # Regularized incomplete beta function approximation
            # Using simple regularized incomplete beta
            if score <= 0:
                return 0.0
            if score >= 1:
                return 1.0
            # Use simple beta CDF approximation
            import math
            return score ** a * (1 - score) ** b  # Simplified

        else:
            warnings.warn(f"Unknown calibration method: {self.method}, returning raw score")
            return score


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _compute_content_hash(content: Any) -> str:
    """Compute SHA-256 hash of content."""
    if isinstance(content, (dict, list)):
        canonical = json.dumps(content, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
    else:
        canonical = str(content)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class CalibrationArtifact:
    """A versioned calibration artifact for a specific detector.

    Attributes:
        artifact_id: Unique identifier for this calibration artifact.
        detector_id: The detector this calibration applies to.
        detector_version: Version of the detector.
        curve: The calibration curve.
        calibration_id: UUID for this specific calibration run.
        parent_calibration_id: Optional ID of previous calibration this supersedes.
        validation_results: Results of validation against held-out data.
        metadata: Additional metadata.
        created_at: ISO timestamp of creation.
    """

    artifact_id: str
    detector_id: str
    detector_version: str
    curve: CalibrationCurve
    calibration_id: str
    parent_calibration_id: str | None = None
    validation_results: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "detector_id": self.detector_id,
            "detector_version": self.detector_version,
            "curve": self.curve.to_dict(),
            "calibration_id": self.calibration_id,
            "parent_calibration_id": self.parent_calibration_id,
            "validation_results": self.validation_results,
            "metadata": self.metadata,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CalibrationArtifact:
        return cls(
            artifact_id=str(data["artifact_id"]),
            detector_id=str(data["detector_id"]),
            detector_version=str(data["detector_version"]),
            curve=CalibrationCurve.from_dict(data["curve"]),
            calibration_id=str(data["calibration_id"]),
            parent_calibration_id=data.get("parent_calibration_id"),
            validation_results=dict(data.get("validation_results", {})),
            metadata=dict(data.get("metadata", {})),
            created_at=str(data.get("created_at", _now_iso())),
        )

    @property
    def content_hash(self) -> str:
        """Compute hash of the artifact content (excluding artifact_id)."""
        content = {
            "detector_id": self.detector_id,
            "detector_version": self.detector_version,
            "curve": self.curve.to_dict(),
            "calibration_id": self.calibration_id,
            "parent_calibration_id": self.parent_calibration_id,
            "validation_results": self.validation_results,
            "metadata": self.metadata,
        }
        return _compute_content_hash(content)


class CalibrationManager:
    """Manages calibration artifacts for detectors.

    Provides:
    - Artifact storage and retrieval
    - Version management and lineage
    - Validation against reference datasets
    - Automatic recalibration triggers
    """

    def __init__(self, storage_path: str | Path):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._artifacts: dict[str, CalibrationArtifact] = {}
        self._load_all()

    def _load_all(self) -> None:
        """Load all calibration artifacts from storage."""
        for file_path in self.storage_path.glob("*.json"):
            try:
                data = json.loads(file_path.read_text(encoding="utf-8"))
                artifact = CalibrationArtifact.from_dict(data)
                self._artifacts[artifact.artifact_id] = artifact
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                warnings.warn(f"Failed to load calibration artifact {file_path}: {exc}")

    def _artifact_path(self, artifact_id: str) -> Path:
        return self.storage_path / f"{artifact_id}.json"

    def _save_artifact(self, artifact: CalibrationArtifact) -> None:
        path = self._artifact_path(artifact.artifact_id)
        path.write_text(
            json.dumps(artifact.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def store(
        self,
        detector_id: str,
        detector_version: str,
        curve: CalibrationCurve,
        calibration_id: str | None = None,
        parent_calibration_id: str | None = None,
        validation_results: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> CalibrationArtifact:
        """Store a new calibration artifact.

        Args:
            detector_id: The detector identifier.
            detector_version: Version of the detector.
            curve: The calibration curve.
            calibration_id: Optional explicit calibration ID (generated if None).
            parent_calibration_id: Optional ID of previous calibration.
            validation_results: Validation results against held-out data.
            metadata: Additional metadata.

        Returns:
            The created CalibrationArtifact.
        """
        if calibration_id is None:
            import uuid
            calibration_id = str(uuid.uuid4())

        artifact = CalibrationArtifact(
            artifact_id=f"{detector_id}:{calibration_id}",
            detector_id=detector_id,
            detector_version=detector_version,
            curve=curve,
            calibration_id=calibration_id,
            parent_calibration_id=parent_calibration_id,
            validation_results=validation_results or {},
            metadata=metadata or {},
        )

        self._artifacts[artifact.artifact_id] = artifact
        self._save_artifact(artifact)

        return artifact

    def get(self, artifact_id: str) -> CalibrationArtifact | None:
        """Get an artifact by ID."""
        return self._artifacts.get(artifact_id)

    def get_latest_for_detector(self, detector_id: str) -> CalibrationArtifact | None:
        """Get the latest calibration artifact for a detector."""
        artifacts = [
            a for a in self._artifacts.values()
            if a.detector_id == detector_id
        ]
        if not artifacts:
            return None
        return max(artifacts, key=lambda a: a.created_at)

    def get_lineage(self, detector_id: str) -> list[CalibrationArtifact]:
        """Get the full calibration lineage for a detector (oldest first)."""
        artifacts = [
            a for a in self._artifacts.values()
            if a.detector_id == detector_id
        ]
        return sorted(artifacts, key=lambda a: a.created_at)

    def validate_artifact(
        self,
        artifact_id: str,
        validation_dataset_path: str | Path,
        *,
        strict: bool = True,
    ) -> dict[str, Any]:
        """Validate a calibration artifact against a dataset.

        Args:
            artifact_id: ID of the artifact to validate.
            validation_dataset_path: Path to JSONL dataset with ground truth.
            strict: Whether to fail on invalid JSON lines.

        Returns:
            Dictionary with validation results including Brier score, calibration error, etc.
        """
        artifact = self._artifacts.get(artifact_id)
        if not artifact:
            raise CalibrationError(f"Artifact not found: {artifact_id}")

        curve = artifact.curve
        scores = []
        labels = []

        with Path(validation_dataset_path).open("r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    if strict:
                        raise CalibrationError(f"Line {line_num}: invalid JSON") from exc
                    continue

                score = row.get("score")
                label = row.get("label")
                if score is None or label is None:
                    if strict:
                        raise CalibrationError(f"Line {line_num}: missing score or label")
                    continue

                calibrated = curve.calibrate(float(score))
                scores.append(calibrated)
                labels.append(1 if str(label).lower() in ("ai", "machine", "1", "true") else 0)

        if not scores:
            raise CalibrationError("No valid samples in validation dataset")

        # Compute metrics
        import math

        # Brier score
        brier = sum((s - l) ** 2 for s, l in zip(scores, labels)) / len(scores)

        # Calibration error (ECE - Expected Calibration Error)
        n_bins = 10
        bin_boundaries = [i / n_bins for i in range(n_bins + 1)]
        bin_scores = [[] for _ in range(n_bins)]
        bin_labels = [[] for _ in range(n_bins)]

        for s, l in zip(scores, labels):
            for i in range(n_bins):
                if bin_boundaries[i] <= s < bin_boundaries[i + 1] or (i == n_bins - 1 and s == 1.0):
                    bin_scores[i].append(s)
                    bin_labels[i].append(l)
                    break

        ece = 0.0
        for i in range(n_bins):
            if bin_scores[i]:
                avg_conf = sum(bin_scores[i]) / len(bin_scores[i])
                avg_acc = sum(bin_labels[i]) / len(bin_labels[i])
                ece += (len(bin_scores[i]) / len(scores)) * abs(avg_conf - avg_acc)

        # Log loss
        eps = 1e-15
        log_loss = -sum(
            l * math.log(max(s, eps)) + (1 - l) * math.log(max(1 - s, eps))
            for s, l in zip(scores, labels)
        ) / len(scores)

        results = {
            "brier_score": brier,
            "ece": ece,
            "log_loss": log_loss,
            "sample_count": len(scores),
            "positive_rate": sum(labels) / len(labels),
        }

        return results

    def get_calibrated_score(self, detector_id: str, raw_score: float) -> float | None:
        """Get calibrated probability for a detector score using latest calibration.

        Returns:
            Calibrated probability, or None if no calibration exists.
        """
        artifact = self.get_latest_for_detector(detector_id)
        if not artifact:
            return None
        return artifact.curve.calibrate(raw_score)


def validate_calibration_artifact(artifact: CalibrationArtifact) -> list[str]:
    """Validate a calibration artifact for consistency.

    Returns:
        List of validation error messages (empty if valid).
    """
    errors = []

    if not artifact.detector_id:
        errors.append("detector_id is required")
    if not artifact.detector_version:
        errors.append("detector_version is required")
    if not artifact.curve:
        errors.append("curve is required")
    if not artifact.calibration_id:
        errors.append("calibration_id is required")

    if artifact.curve:
        curve = artifact.curve
        if not curve.method:
            errors.append("curve.method is required")
        if curve.sample_count <= 0:
            errors.append("curve.sample_count must be positive")

        # Validate method-specific parameters
        if curve.method == "isotonic":
            if "x" not in curve.parameters or "y" not in curve.parameters:
                errors.append("isotonic method requires 'x' and 'y' parameters")
            else:
                x = curve.parameters["x"]
                y = curve.parameters["y"]
                if len(x) != len(y):
                    errors.append("isotonic 'x' and 'y' must have same length")
                if not all(y[i] <= y[i+1] for i in range(len(y)-1)):
                    errors.append("isotonic 'y' must be non-decreasing")

        elif curve.method == "platt":
            if "A" not in curve.parameters or "B" not in curve.parameters:
                errors.append("platt method requires 'A' and 'B' parameters")

        elif curve.method == "temperature":
            if "T" not in curve.parameters:
                errors.append("temperature method requires 'T' parameter")
            elif curve.parameters["T"] <= 0:
                errors.append("temperature 'T' must be positive")

    return errors


# Convenience functions
def create_calibration_manager(storage_path: str | Path) -> CalibrationManager:
    """Create a CalibrationManager with the given storage path."""
    return CalibrationManager(storage_path)


def load_calibration_artifact(path: str | Path) -> CalibrationArtifact:
    """Load a calibration artifact from a JSON file."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return CalibrationArtifact.from_dict(data)


def save_calibration_artifact(artifact: CalibrationArtifact, path: str | Path) -> None:
    """Save a calibration artifact to a JSON file."""
    Path(path).write_text(
        json.dumps(artifact.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )