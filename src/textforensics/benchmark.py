from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .detectors import (
    BuiltinHeuristicDetector,
    Detector,
    execute_detector,
    get_known_detector_metadata,
    load_detector,
)


CALIBRATION_SCHEMA = "textforensics.calibration/v1"
_HIGHER_AI_PREFIX = "higher_means_more_machine_like"


class DatasetFormatError(ValueError):
    """Raised when benchmark JSONL or detector output is malformed."""


@dataclass(slots=True)
class ScoredDataset:
    rows: list[tuple[str, float]]
    skipped: int
    abstained: int
    detector_failures: int
    valid_samples: int
    score_semantics: str


def dataset_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _detector_or_default(detector: Detector | None) -> Detector:
    return detector if detector is not None else BuiltinHeuristicDetector()


def _load_scores(
    path: str | Path,
    *,
    detector: Detector | None = None,
    strict: bool = True,
) -> ScoredDataset:
    active = _detector_or_default(detector)
    rows: list[tuple[str, float]] = []
    skipped = 0
    abstained = 0
    failures = 0
    valid_samples = 0
    semantics: str | None = None

    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
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
            if (
                label not in {"human", "ai"}
                or not isinstance(text, str)
                or not text.strip()
            ):
                if strict:
                    raise DatasetFormatError(
                        f"Line {line_number} requires label 'human'/'ai' "
                        "and non-empty text."
                    )
                skipped += 1
                continue

            valid_samples += 1
            prediction, failure = execute_detector(active, text)
            if failure is not None:
                failures += 1
                if strict:
                    raise DatasetFormatError(
                        f"Detector failed on line {line_number} "
                        f"({failure.error_type})."
                    )
                continue
            assert prediction is not None

            if semantics is None:
                semantics = prediction.score_semantics
            elif semantics != prediction.score_semantics:
                raise DatasetFormatError(
                    "Detector changed score_semantics within one benchmark run."
                )

            if not prediction.score_semantics.startswith(_HIGHER_AI_PREFIX):
                raise DatasetFormatError(
                    "This benchmark/calibration path currently requires "
                    "higher_means_more_machine_like score semantics."
                )

            if prediction.score is None:
                abstained += 1
                continue
            rows.append((label, float(prediction.score)))

    return ScoredDataset(
        rows=rows,
        skipped=skipped,
        abstained=abstained,
        detector_failures=failures,
        valid_samples=valid_samples,
        score_semantics=semantics or "",
    )


def _roc_auc(rows: list[tuple[str, float]]) -> float | None:
    positives = sum(label == "ai" for label, _ in rows)
    negatives = sum(label == "human" for label, _ in rows)
    if positives == 0 or negatives == 0:
        return None

    ordered = sorted(rows, key=lambda item: item[1])
    rank = 1
    positive_rank_sum = 0.0
    index = 0
    while index < len(ordered):
        end = index + 1
        while end < len(ordered) and ordered[end][1] == ordered[index][1]:
            end += 1
        first_rank = rank
        last_rank = rank + (end - index) - 1
        average_rank = (first_rank + last_rank) / 2.0
        positive_rank_sum += average_rank * sum(
            ordered[pos][0] == "ai" for pos in range(index, end)
        )
        rank += end - index
        index = end

    auc = (
        positive_rank_sum - positives * (positives + 1) / 2.0
    ) / (positives * negatives)
    return float(auc)


def _average_precision(rows: list[tuple[str, float]]) -> float | None:
    positives = sum(label == "ai" for label, _ in rows)
    if positives == 0:
        return None

    ordered = sorted(rows, key=lambda item: item[1], reverse=True)
    tp = 0
    fp = 0
    previous_recall = 0.0
    area = 0.0
    index = 0
    while index < len(ordered):
        score = ordered[index][1]
        end = index
        group_tp = 0
        group_fp = 0
        while end < len(ordered) and ordered[end][1] == score:
            if ordered[end][0] == "ai":
                group_tp += 1
            else:
                group_fp += 1
            end += 1
        tp += group_tp
        fp += group_fp
        recall = tp / positives
        precision = tp / (tp + fp)
        area += (recall - previous_recall) * precision
        previous_recall = recall
        index = end
    return float(area)


def _metrics(
    scored: ScoredDataset,
    threshold: float,
) -> dict[str, Any]:
    if not math.isfinite(threshold):
        raise ValueError("threshold must be finite.")

    tp = fp = tn = fn = 0
    for label, score in scored.rows:
        pred = "ai" if score >= threshold else "human"
        if label == "ai" and pred == "ai":
            tp += 1
        elif label == "ai":
            fn += 1
        elif pred == "ai":
            fp += 1
        else:
            tn += 1

    evaluated = len(scored.rows)
    accuracy = (tp + tn) / evaluated if evaluated else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = (
        2 * precision * tpr / (precision + tpr)
        if precision + tpr
        else 0.0
    )
    balanced_accuracy = (tpr + specificity) / 2.0
    coverage = (
        evaluated / scored.valid_samples
        if scored.valid_samples
        else 0.0
    )
    auroc = _roc_auc(scored.rows)
    average_precision = _average_precision(scored.rows)

    return {
        "threshold": threshold,
        "valid_samples": scored.valid_samples,
        "evaluated": evaluated,
        "abstained": scored.abstained,
        "detector_failures": scored.detector_failures,
        "coverage": round(coverage, 4),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": round(accuracy, 4),
        "balanced_accuracy": round(balanced_accuracy, 4),
        "precision": round(precision, 4),
        "f1": round(f1, 4),
        "true_positive_rate": round(tpr, 4),
        "specificity": round(specificity, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "auroc": round(auroc, 4) if auroc is not None else None,
        "average_precision": (
            round(average_precision, 4)
            if average_precision is not None
            else None
        ),
    }


def benchmark_jsonl(
    path: str | Path,
    threshold: float = 0.5,
    *,
    detector: Detector | None = None,
    strict: bool = True,
) -> dict[str, Any]:
    active = _detector_or_default(detector)
    scored = _load_scores(path, detector=active, strict=strict)
    result = _metrics(scored, threshold)
    result.update(
        {
            "schema": "textforensics.benchmark-result/v1",
            "dataset_sha256": dataset_sha256(path),
            "detector_id": active.detector_id,
            "detector_version": active.detector_version,
            "score_semantics": scored.score_semantics,
            "skipped": scored.skipped,
            "mode": "diagnostic_fixed_threshold",
            "warning": (
                "A fixed-threshold benchmark is diagnostic unless the threshold "
                "was selected independently of this evaluation dataset."
            ),
        }
    )
    return result


def calibrate_threshold_jsonl(
    path: str | Path,
    target_fpr: float = 0.01,
    *,
    detector: Detector | None = None,
    strict: bool = True,
) -> dict[str, Any]:
    if not 0 <= target_fpr <= 1:
        raise ValueError("target_fpr must be between 0 and 1.")

    active = _detector_or_default(detector)
    scored = _load_scores(path, detector=active, strict=strict)
    humans = [score for label, score in scored.rows if label == "human"]
    ais = [score for label, score in scored.rows if label == "ai"]
    if not humans or not ais:
        raise ValueError(
            "Calibration requires at least one scored human and one scored AI sample."
        )

    max_score = max(score for _, score in scored.rows)
    candidates = sorted(
        {
            *(score for _, score in scored.rows),
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
    return {
        "schema": CALIBRATION_SCHEMA,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "detector_id": active.detector_id,
        "detector_version": active.detector_version,
        "score_semantics": scored.score_semantics,
        "calibration_method": "threshold_at_target_human_fpr",
        "target_false_positive_rate": target_fpr,
        "recommended_threshold": float(threshold),
        "observed_false_positive_rate": round(float(fpr), 4),
        "observed_true_positive_rate": round(float(tpr), 4),
        "human_samples": len(humans),
        "ai_samples": len(ais),
        "valid_samples": scored.valid_samples,
        "scored_samples": len(scored.rows),
        "abstained_samples": scored.abstained,
        "detector_failures": scored.detector_failures,
        "coverage": round(
            len(scored.rows) / scored.valid_samples
            if scored.valid_samples
            else 0.0,
            4,
        ),
        "skipped": scored.skipped,
        "calibration_dataset_sha256": dataset_sha256(path),
        "classification_rule": "ai_like iff score >= recommended_threshold",
        "mode": "calibration_only_not_final_evaluation",
        "warning": (
            "This artifact is fitted to the supplied calibration corpus. "
            "Evaluate it on a separate held-out dataset before making claims."
        ),
    }


def validate_calibration_artifact(
    artifact: dict[str, Any],
    *,
    detector: Detector | None = None,
) -> None:
    required = {
        "schema",
        "detector_id",
        "detector_version",
        "score_semantics",
        "recommended_threshold",
        "calibration_dataset_sha256",
    }
    missing = sorted(required - artifact.keys())
    if missing:
        raise ValueError(f"Calibration artifact is missing: {', '.join(missing)}")
    if artifact["schema"] != CALIBRATION_SCHEMA:
        raise ValueError("Unsupported calibration artifact schema.")

    if detector is not None:
        expected = {
            "detector_id": detector.detector_id,
            "detector_version": detector.detector_version,
        }
    else:
        expected = get_known_detector_metadata(str(artifact["detector_id"]))

    if expected is not None:
        if artifact["detector_id"] != expected["detector_id"]:
            raise ValueError("Calibration artifact targets a different detector.")
        if artifact["detector_version"] != expected["detector_version"]:
            raise ValueError(
                "Calibration artifact targets a different detector version."
            )

    semantics = artifact["score_semantics"]
    if not isinstance(semantics, str) or not semantics.startswith(_HIGHER_AI_PREFIX):
        raise ValueError("Unsupported calibration score semantics.")

    threshold = artifact["recommended_threshold"]
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        raise ValueError("Calibration threshold must be numeric.")
    if not math.isfinite(float(threshold)):
        raise ValueError("Calibration threshold must be finite.")

    fingerprint = artifact["calibration_dataset_sha256"]
    if (
        not isinstance(fingerprint, str)
        or len(fingerprint) != 64
        or any(char not in "0123456789abcdef" for char in fingerprint)
    ):
        raise ValueError("Invalid calibration dataset fingerprint.")


def benchmark_with_calibration_jsonl(
    path: str | Path,
    calibration: dict[str, Any],
    *,
    detector: Detector | None = None,
    strict: bool = True,
    allow_same_dataset: bool = False,
) -> dict[str, Any]:
    active = (
        detector
        if detector is not None
        else load_detector(str(calibration.get("detector_id", "")))
    )
    validate_calibration_artifact(calibration, detector=active)

    evaluation_sha = dataset_sha256(path)
    if (
        not allow_same_dataset
        and evaluation_sha == calibration["calibration_dataset_sha256"]
    ):
        raise ValueError(
            "Evaluation dataset matches the calibration dataset. Use a separate "
            "held-out dataset for release-quality validation."
        )

    scored = _load_scores(path, detector=active, strict=strict)
    if scored.score_semantics != calibration["score_semantics"]:
        raise ValueError(
            "Detector score semantics differ from the calibration artifact."
        )

    result = _metrics(scored, float(calibration["recommended_threshold"]))
    result.update(
        {
            "schema": "textforensics.benchmark-result/v1",
            "dataset_sha256": evaluation_sha,
            "calibration_dataset_sha256": calibration[
                "calibration_dataset_sha256"
            ],
            "detector_id": active.detector_id,
            "detector_version": active.detector_version,
            "score_semantics": scored.score_semantics,
            "skipped": scored.skipped,
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
