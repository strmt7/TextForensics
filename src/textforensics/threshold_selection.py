"""Threshold selection and evaluation for calibrated detectors.

This module provides separate functions for threshold selection (on
calibration data) and evaluation (on held-out test data) to prevent
benchmark contamination. Part of requirement #12 from AGENTS.md:
"Prevent benchmark contamination. Training, threshold selection,
calibration, and final evaluation must be disjoint."
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .benchmark import (
    CALIBRATION_SCHEMA,
    _load_scores,
    dataset_sha256,
)


@dataclass
class ThresholdSelectionResult:
    """Result of threshold selection on calibration data.

    Attributes:
        threshold: Selected operating threshold
        observed_fpr: Observed false positive rate at threshold
        observed_tpr: Observed true positive rate at threshold
        target_fpr: Target false positive rate
        human_samples: Number of human samples used
        ai_samples: Number of AI samples used
        detector_id: Detector identifier
        detector_version: Detector version
        calibration_dataset_hash: Hash of calibration dataset
        calibration_record_hash: Hash of this record for provenance
        selection_method: Method used for threshold selection
        warning: Optional warning message
    """

    threshold: float
    observed_fpr: float
    observed_tpr: float
    target_fpr: float
    human_samples: int
    ai_samples: int
    detector_id: str
    detector_version: str
    calibration_dataset_hash: str
    selection_method: str = "threshold_at_target_fpr"
    warning: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for artifact storage."""
        record = {
            "schema": "textforensics.threshold-selection/v1",
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "threshold": self.threshold,
            "observed_false_positive_rate": self.observed_fpr,
            "observed_true_positive_rate": self.observed_tpr,
            "target_false_positive_rate": self.target_fpr,
            "human_samples": self.human_samples,
            "ai_samples": self.ai_samples,
            "detector_id": self.detector_id,
            "detector_version": self.detector_version,
            "calibration_dataset_hash": self.calibration_dataset_hash,
            "selection_method": self.selection_method,
            "mode": "calibration_only",
            "warning": (
                "This artifact is fitted to the calibration corpus only. "
                "Do not use for evaluation on the same data."
            ),
        }
        if self.warning:
            record["warning"] = self.warning

        # Compute record hash for provenance
        canonical = json.dumps(
            {k: v for k, v in record.items() if k != "calibration_record_hash"},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        record["calibration_record_hash"] = hashlib.sha256(
            canonical.encode("utf-8")
        ).hexdigest()

        return record


@dataclass
class EvaluationResult:
    """Result of evaluating on held-out test data.

    Attributes:
        threshold: Threshold used for evaluation
        tp: True positives
        fp: False positives
        tn: True negatives
        fn: False negatives
        accuracy: Overall accuracy
        fpr: False positive rate
        fnr: False negative rate
        tpr: True positive rate
        specificity: Specificity (true negative rate)
        precision: Precision (positive predictive value)
        evaluated: Number of samples evaluated
        test_dataset_hash: Hash of test dataset
        calibration_dataset_hash: Hash of calibration dataset (for verification)
        evaluation_mode: "held_out" or "diagnostic"
        contamination_detected: Whether contamination was detected
    """

    threshold: float
    tp: int
    fp: int
    tn: int
    fn: int
    accuracy: float
    fpr: float
    fnr: float
    tpr: float
    specificity: float
    precision: float
    evaluated: int
    test_dataset_hash: str
    calibration_dataset_hash: str
    evaluation_mode: str = "held_out"
    contamination_detected: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "schema": "textforensics.evaluation-result/v1",
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "threshold": self.threshold,
            "evaluated": self.evaluated,
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "accuracy": round(self.accuracy, 4),
            "precision": round(self.precision, 4),
            "true_positive_rate": round(self.tpr, 4),
            "specificity": round(self.specificity, 4),
            "false_positive_rate": round(self.fpr, 4),
            "false_negative_rate": round(self.fnr, 4),
            "test_dataset_hash": self.test_dataset_hash,
            "calibration_dataset_hash": self.calibration_dataset_hash,
            "evaluation_mode": self.evaluation_mode,
            "contamination_detected": self.contamination_detected,
        }


def select_threshold(
    calibration_path: str | Path,
    *,
    target_fpr: float = 0.01,
    strict: bool = True,
    detector_id: str = "textforensics/builtin-heuristic",
    detector_version: str = "1.0.0",
) -> ThresholdSelectionResult:
    """Select an operating threshold on calibration data only.

    This function should only be called with calibration data that is
    completely separate from any evaluation data.

    Args:
        calibration_path: Path to calibration JSONL dataset
        target_fpr: Target false positive rate for threshold selection
        strict: Whether to fail on invalid JSON lines
        detector_id: Detector identifier for provenance
        detector_version: Detector version for provenance

    Returns:
        ThresholdSelectionResult with the selected threshold

    Raises:
        ValueError: If target_fpr is invalid or no valid threshold found
    """
    if not 0 <= target_fpr <= 1:
        raise ValueError("target_fpr must be between 0 and 1")

    calibration_path = Path(calibration_path)
    dataset_hash = dataset_sha256(calibration_path)

    rows, skipped = _load_scores(calibration_path, strict=strict)
    humans = [score for label, score in rows if label == "human"]
    ais = [score for label, score in rows if label == "ai"]

    if not humans or not ais:
        raise ValueError(
            "Calibration requires at least one human and one AI sample. "
            f"Found {len(humans)} human and {len(ais)} AI samples."
        )

    max_score = max(score for _, score in rows)
    candidates = sorted(
        {
            *(score for _, score in rows),
            math.nextafter(max_score, math.inf),
        }
    )

    best: ThresholdSelectionResult | None = None
    for threshold in candidates:
        fp = sum(score >= threshold for score in humans)
        tp = sum(score >= threshold for score in ais)
        fpr = fp / len(humans)
        tpr = tp / len(ais)

        if fpr <= target_fpr:
            # Prefer higher TPR (catch more AI) with same or lower FPR
            candidate = ThresholdSelectionResult(
                threshold=threshold,
                observed_fpr=fpr,
                observed_tpr=tpr,
                target_fpr=target_fpr,
                human_samples=len(humans),
                ai_samples=len(ais),
                detector_id=detector_id,
                detector_version=detector_version,
                calibration_dataset_hash=dataset_hash,
            )
            # Select best: higher TPR wins, or lower threshold (more inclusive) as tiebreaker
            if best is None or (candidate.observed_tpr > best.observed_tpr or
                                (candidate.observed_tpr == best.observed_tpr and
                                 candidate.threshold < best.threshold)):
                best = candidate

    if best is None:
        raise RuntimeError(
            f"No threshold satisfies target FPR={target_fpr}. "
            f"Best achievable FPR with this data: {max(sum(score >= t for score in humans) / len(humans) for t in candidates):.4f}"
        )

    return best


def evaluate_threshold(
    test_path: str | Path,
    threshold: float,
    *,
    calibration_dataset_hash: str | None = None,
    strict: bool = True,
    allow_same_dataset: bool = False,
) -> EvaluationResult:
    """Evaluate a threshold on held-out test data.

    This is the EVALUATION step that must use data separate from calibration.

    Args:
        test_path: Path to test/evaluation JSONL dataset
        threshold: Threshold to evaluate
        calibration_dataset_hash: Hash of calibration dataset (for verification)
        strict: Whether to fail on invalid JSON lines
        allow_same_dataset: Allow evaluation on same dataset as calibration (diagnostic only)

    Returns:
        EvaluationResult with metrics
    """
    test_path = Path(test_path)
    test_hash = dataset_sha256(test_path)

    if not allow_same_dataset and calibration_dataset_hash:
        if test_hash == calibration_dataset_hash:
            raise ValueError(
                "Evaluation dataset matches the calibration dataset. "
                "Use a separate held-out dataset for release-quality validation. "
                "Use allow_same_dataset=True only for diagnostics."
            )

    rows, skipped = _load_scores(test_path, strict=strict)

    # Compute metrics
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

    return EvaluationResult(
        threshold=threshold,
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        accuracy=accuracy,
        fpr=fpr,
        fnr=fnr,
        tpr=tpr,
        specificity=specificity,
        precision=precision,
        evaluated=total,
        test_dataset_hash=test_hash,
        calibration_dataset_hash=calibration_dataset_hash or "",
    )


def validate_no_contamination(
    calibration_path: str | Path,
    test_path: str | Path,
) -> dict[str, Any]:
    """Assert that calibration and test sets are disjoint.

    This is a critical validation step before any evaluation.
    It checks for sample overlap to detect contamination.

    Returns:
        Dict with 'contamination_detected' bool, 'shared_samples' count,
        and 'shared_hashes' list if overlap found.
    """
    calibration_path = Path(calibration_path)
    test_path = Path(test_path)

    cal_hash = dataset_sha256(calibration_path)
    test_hash = dataset_sha256(test_path)

    # Initialize result with valid=True (we'll set valid=False if contamination found)
    result: dict[str, Any] = {
        "valid": True,
        "contamination_detected": False,
        "calibration_hash": cal_hash,
        "test_hash": test_hash,
        "shared_samples": 0,
        "shared_hashes": [],
    }

    if cal_hash == test_hash:
        result["contamination_detected"] = True
        result["shared_samples"] = -1  # Identical files
        result["warning"] = "Files are identical; all samples overlap"
        result["valid"] = False
        return result

    # Compute sample-level overlap
    cal_samples: set[str] = set()
    test_samples: set[str] = set()

    try:
        rows, _ = _load_scores(calibration_path, strict=False)
        for label, text in rows:
            sample_hash = hashlib.sha256(
                json.dumps({"text": text}, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            cal_samples.add(sample_hash)
    except Exception as e:
        result["warning"] = f"Could not read calibration samples: {e}"
        result["valid"] = False
        return result

    try:
        rows = _get_test_samples(test_path)
        for text in rows:
            sample_hash = hashlib.sha256(
                json.dumps({"text": text}, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            test_samples.add(sample_hash)
    except Exception as e:
        result["warning"] = f"Could not read test samples: {e}"
        result["valid"] = False
        return result

    shared = cal_samples & test_samples
    if shared:
        result["contamination_detected"] = True
        result["shared_samples"] = len(shared)
        result["shared_hashes"] = sorted(shared)
        result["valid"] = False

    return result


def _get_test_samples(path: Path) -> list[str]:
    """Extract text samples from a JSONL file."""
    samples: list[str] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                if isinstance(row, dict) and "text" in row:
                    samples.append(str(row["text"]))
            except json.JSONDecodeError:
                continue
    return samples


def load_threshold_artifact(path: str | Path) -> dict[str, Any]:
    """Load a threshold selection artifact.

    Validates the artifact format and returns the dictionary.
    """
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise ValueError("Threshold artifact must be a JSON object")

    validation_errors = []

    if data.get("schema") not in ("textforensics.threshold-selection/v1", CALIBRATION_SCHEMA):
        validation_errors.append(f"Unsupported schema: {data.get('schema')}")

    if "threshold" not in data:
        validation_errors.append("Missing required field: threshold")
    elif not isinstance(data["threshold"], (int, float)):
        validation_errors.append("threshold must be numeric")
    elif not math.isfinite(data["threshold"]):
        validation_errors.append("threshold must be finite")

    if "calibration_dataset_hash" not in data:
        validation_errors.append("Missing required field: calibration_dataset_hash")

    if validation_errors:
        raise ValueError("; ".join(validation_errors))

    return data


def create_calibration_artifact(
    calibration_result: ThresholdSelectionResult,
    output_path: str | Path,
) -> Path:
    """Create a calibration artifact file from a threshold selection result.

    This creates a JSON file that can be used with evaluate_threshold().
    """
    output_path = Path(output_path)
    artifact = calibration_result.to_dict()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(artifact, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )
    return output_path


def run_calibration_evaluation(
    calibration_path: str | Path,
    evaluation_path: str | Path,
    *,
    target_fpr: float = 0.01,
    strict: bool = True,
) -> dict[str, Any]:
    """Run the full calibration + evaluation pipeline.

    This is a convenience function that:
    1. Selects threshold on calibration data
    2. Validates disjointness
    3. Evaluates on held-out test data
    4. Returns combined results

    Args:
        calibration_path: Path to calibration JSONL
        evaluation_path: Path to evaluation JSONL
        target_fpr: Target false positive rate
        strict: Whether to fail on invalid JSON

    Returns:
        Dict with calibration_result, evaluation_result, and validation
    """
    # Validate disjointness first
    validation = validate_no_contamination(calibration_path, evaluation_path)
    if validation["contamination_detected"]:
        raise ValueError(
            f"Contamination detected: {validation['shared_samples']} overlapping "
            f"samples. Calibration and evaluation datasets must be disjoint."
        )

    # Select threshold on calibration data
    calibration_result = select_threshold(
        calibration_path,
        target_fpr=target_fpr,
        strict=strict,
    )

    # Evaluate on held-out test data
    evaluation_result = evaluate_threshold(
        evaluation_path,
        calibration_result.threshold,
        calibration_dataset_hash=validation["calibration_hash"],
        strict=strict,
        allow_same_dataset=False,
    )
    evaluation_result.contamination_detected = validation["contamination_detected"]

    return {
        "calibration_result": calibration_result.to_dict(),
        "evaluation_result": evaluation_result.to_dict(),
        "validation": validation,
    }