from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .detectors import BuiltinHeuristicDetector
from .engine import analyze_text


CALIBRATION_SCHEMA = "textforensics.calibration/v1"


class DatasetFormatError(ValueError):
    """Raised when benchmark JSONL is malformed or ambiguous."""


def dataset_sha256(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _load_scores(
    path: str | Path,
    *,
    strict: bool = True,
) -> tuple[list[tuple[str, float]], int]:
    rows: list[tuple[str, float]] = []
    skipped = 0
    for line_number, line in enumerate(
        Path(path).read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            if strict:
                raise DatasetFormatError(
                    f"Line {line_number} is not valid JSON."
                ) from exc
            skipped += 1
            continue
        if not isinstance(row, dict):
            if strict:
                raise DatasetFormatError(
                    f"Line {line_number} must be a JSON object."
                )
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
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
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


def benchmark_with_calibration_jsonl(
    path: str | Path,
    calibration: dict[str, Any],
    *,
    strict: bool = True,
    allow_same_dataset: bool = False,
) -> dict[str, Any]:
    validate_calibration_artifact(calibration)
    evaluation_sha = dataset_sha256(path)
    if (
        not allow_same_dataset
        and evaluation_sha == calibration["calibration_dataset_sha256"]
    ):
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
            "calibration_dataset_sha256": calibration[
                "calibration_dataset_sha256"
            ],
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
