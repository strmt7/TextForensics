"""Detector observatory: longitudinal drift + live per-detector health.

Two time-scales, one module:

* Longitudinal reliability (from drift.py): snapshots of detector
  behaviour over a frozen probe corpus, pairwise snapshot comparison
  (score shift, verdict flips, threshold/calibration/human-FPR drift,
  provider-version changes), and post-hoc drift alerts. Snapshots store
  probe IDs/hashes, never raw probe text.
* Live operational health (from detector_health.py): per-detector
  latency / error-rate / score-distribution / throughput metrics with
  thresholded checks, health reports, and alert callbacks.

Deliberately NOT unified here: the two halves keep their own alert
types (DriftAlert vs HealthAlert) and state enums (drift report status
strings vs HealthState) because they measure different things — a
longitudinal reliability claim is not a live operational state, and
merging the taxonomies would let one be read as the other. Likewise
``detectors.list_detector_health`` (plugin/entry-point health) and
``diagnostics`` (process/host health) stay separate systems.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import statistics
import time
import uuid
from collections import defaultdict, deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from .detectors import (
    Detector,
    DetectorPrediction,
    execute_detector,
    is_remote_detector,
    text_sha256,
)
from .execution_policy import (
    CancellationToken,
    ExecutionPolicy,
    assert_execution_allowed,
)

__all__ = [
    # Longitudinal drift observatory (from drift.py)
    "DRIFT_CORPUS_SCHEMA",
    "DRIFT_SNAPSHOT_SCHEMA",
    "DRIFT_SNAPSHOT_STORE_SCHEMA",
    "DRIFT_REPORT_SCHEMA",
    "ProbeSample",
    "DriftObservatory",
    "DriftAlert",
    "generate_drift_alerts",
    "filter_alerts",
    "summarize_alerts",
    # Live per-detector health (from detector_health.py)
    "HealthState",
    "AlertSeverity",
    "HealthMetric",
    "HealthAlert",
    "DetectorHealthReport",
    "HealthCheck",
    "DetectorHealthMonitor",
    "create_health_monitor",
]

DRIFT_CORPUS_SCHEMA = "textforensics.drift-corpus/v1"
DRIFT_SNAPSHOT_SCHEMA = "textforensics.drift-snapshot/v1"
DRIFT_SNAPSHOT_STORE_SCHEMA = "textforensics.drift-snapshot-store/v1"
DRIFT_REPORT_SCHEMA = "textforensics.drift-report/v1"

VERDICTS = {"ai_like", "human_like", "abstain"}
EXECUTIONS = {"local", "remote"}

REPORT_LIMITATIONS = [
    "Drift metrics compare detector observations on a fixed probe corpus; they do not prove authorship for real-world documents.",
    "Uncalibrated detector scores are instrument outputs, not probabilities.",
    "Remote provider observations are not ground truth and may change without notice.",
    "A single probe sample cannot establish provider drift.",
    "Raw probe text is intentionally omitted from drift reports.",
]


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_hex64(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(char in "0123456789abcdef" for char in value.lower())


def _require_nonempty_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string.")
    return value


def _coerce_float(
    value: Any,
    field_name: str,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
    allow_none: bool = True,
) -> float | None:
    if value is None:
        if allow_none:
            return None
        raise ValueError(f"{field_name} must not be null.")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field_name} must be a finite number.")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"{field_name} must be finite.")
    if minimum is not None and number < minimum:
        raise ValueError(f"{field_name} must be >= {minimum}.")
    if maximum is not None and number > maximum:
        raise ValueError(f"{field_name} must be <= {maximum}.")
    return number


def _coerce_int_or_none(value: Any, field_name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer or null.")
    if value < 0:
        raise ValueError(f"{field_name} must be non-negative.")
    return value


def _round(value: float | None, digits: int = 6) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number):
        return None
    return round(number, digits)


def _percentile(sorted_values: Sequence[float], q: float) -> float | None:
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return sorted_values[0]
    position = (len(sorted_values) - 1) * q
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return sorted_values[lower]
    return sorted_values[lower] * (upper - position) + sorted_values[upper] * (position - lower)


def _distribution_summary(values: Iterable[float]) -> dict[str, Any]:
    clean: list[float] = []
    for value in values:
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        number = float(value)
        if not math.isfinite(number):
            continue
        clean.append(number)
    clean.sort()
    count = len(clean)
    if count == 0:
        return {
            "n": 0,
            "mean": None,
            "median": None,
            "stdev": None,
            "min": None,
            "max": None,
            "p10": None,
            "p90": None,
        }
    try:
        stdev = statistics.pstdev(clean) if count > 1 else 0.0
    except statistics.StatisticsError:
        stdev = 0.0
    return {
        "n": count,
        "mean": _round(sum(clean) / count),
        "median": _round(statistics.median(clean)),
        "stdev": _round(stdev),
        "min": _round(clean[0]),
        "max": _round(clean[-1]),
        "p10": _round(_percentile(clean, 0.10)),
        "p90": _round(_percentile(clean, 0.90)),
    }


def _sort_key(value: Any) -> tuple[int, float, str]:
    if value is None:
        return (0, 0.0, "")
    if isinstance(value, bool):
        return (3, 0.0, str(value))
    if isinstance(value, (int, float)):
        return (1, float(value), "")
    return (2, 0.0, str(value))


def _unique_scalars(values: Iterable[Any]) -> list[Any]:
    seen = list(dict.fromkeys(values))
    return sorted(seen, key=_sort_key)


def _finding(code: str, severity: str, detail: str, **extra: Any) -> dict[str, Any]:
    return {"code": code, "severity": severity, "detail": detail, **extra}


def _compute_corpus_sha256(samples: Iterable[ProbeSample]) -> str:
    payload = sorted(
        ({"sample_id": sample.sample_id, "text_sha256": sample.text_sha256} for sample in samples),
        key=lambda row: row["sample_id"],
    )
    return _sha256_hex(_canonical_bytes(payload))


def _is_human_sample(metadata: Mapping[str, Any]) -> bool:
    label = metadata.get("label", metadata.get("expected_label", metadata.get("ground_truth", "")))
    return str(label).strip().lower() in {"human", "true_human", "person"}


def _records_by_detector(snapshot: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for record in snapshot.get("records", []):
        detector_id = record.get("detector_id")
        if not isinstance(detector_id, str) or not detector_id:
            raise ValueError("Drift snapshot records require detector_id.")
        grouped.setdefault(detector_id, []).append(record)
    return grouped


def _index_by_sample(records: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for record in records:
        sample_id = record.get("sample_id")
        if not isinstance(sample_id, str) or not sample_id:
            raise ValueError("Drift snapshot records require sample_id.")
        if sample_id in indexed:
            raise ValueError(f"Duplicate drift record for sample {sample_id}.")
        indexed[sample_id] = dict(record)
    return indexed


def _compare_score_distribution(
    pairs: Sequence[tuple[dict[str, Any], dict[str, Any], str]],
    *,
    claim_allowed: bool,
    shift_threshold: float,
    min_samples: int,
) -> dict[str, Any]:
    baseline_values: list[float] = []
    current_values: list[float] = []
    deltas: list[float] = []
    for baseline, current, _ in pairs:
        baseline_score = _coerce_float(baseline.get("score"), "score")
        current_score = _coerce_float(current.get("score"), "score")
        if baseline_score is None or current_score is None:
            continue
        baseline_values.append(baseline_score)
        current_values.append(current_score)
        deltas.append(current_score - baseline_score)

    baseline_summary = _distribution_summary(baseline_values)
    current_summary = _distribution_summary(current_values)
    if not deltas:
        return {
            "n_paired": 0,
            "baseline": baseline_summary,
            "current": current_summary,
            "delta_mean": None,
            "mean_abs_delta": None,
            "max_abs_delta": None,
            "standardized_mean_difference": None,
            "shift_magnitude": None,
            "significant": False,
            "status": "no_paired_scores",
        }

    delta_mean = sum(deltas) / len(deltas)
    mean_abs_delta = sum(abs(delta) for delta in deltas) / len(deltas)
    max_abs_delta = max(abs(delta) for delta in deltas)
    sd_baseline = float(baseline_summary.get("stdev") or 0.0)
    sd_current = float(current_summary.get("stdev") or 0.0)
    pooled_sd = math.sqrt((sd_baseline * sd_baseline + sd_current * sd_current) / 2.0)
    standardized = delta_mean / pooled_sd if pooled_sd > 1e-12 else None
    shift_magnitude = abs(delta_mean)
    significant = bool(
        claim_allowed and len(deltas) >= min_samples and shift_magnitude >= shift_threshold
    )
    return {
        "n_paired": len(deltas),
        "baseline": baseline_summary,
        "current": current_summary,
        "delta_mean": _round(delta_mean),
        "mean_abs_delta": _round(mean_abs_delta),
        "max_abs_delta": _round(max_abs_delta),
        "standardized_mean_difference": _round(standardized),
        "shift_magnitude": _round(shift_magnitude),
        "significant": significant,
        "status": "score_distribution_shift" if significant else "stable",
    }


def _compare_verdict_flips(
    pairs: Sequence[tuple[dict[str, Any], dict[str, Any], str]],
    *,
    claim_allowed: bool,
    flip_rate_threshold: float,
    min_samples: int,
) -> dict[str, Any]:
    total = len(pairs)
    flip_count = 0
    severe_flip_count = 0
    transitions: dict[str, int] = {}
    for baseline, current, _ in pairs:
        baseline_verdict = baseline.get("verdict")
        current_verdict = current.get("verdict")
        if baseline_verdict == current_verdict:
            continue
        flip_count += 1
        key = f"{baseline_verdict}->{current_verdict}"
        transitions[key] = transitions.get(key, 0) + 1
        if {baseline_verdict, current_verdict} == {"ai_like", "human_like"}:
            severe_flip_count += 1

    flip_rate = flip_count / total if total else None
    significant = bool(
        claim_allowed
        and total >= min_samples
        and flip_rate is not None
        and flip_rate >= flip_rate_threshold
    )
    return {
        "n": total,
        "flip_count": flip_count,
        "severe_flip_count": severe_flip_count,
        "flip_rate": _round(flip_rate),
        "transitions": dict(sorted(transitions.items())),
        "significant": significant,
        "status": "verdict_flip_change" if significant else "stable",
    }


def _compare_thresholds(
    pairs: Sequence[tuple[dict[str, Any], dict[str, Any], str]],
    baseline_records: Sequence[Mapping[str, Any]],
    current_records: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    baseline_thresholds = _unique_scalars(record.get("threshold") for record in baseline_records)
    current_thresholds = _unique_scalars(record.get("threshold") for record in current_records)
    global_changed = baseline_thresholds != current_thresholds
    per_sample_changed = sum(
        1 for baseline, current, _ in pairs if baseline.get("threshold") != current.get("threshold")
    )
    threshold_changed = bool(global_changed or per_sample_changed)
    return {
        "baseline_thresholds": baseline_thresholds,
        "current_thresholds": current_thresholds,
        "global_threshold_changed": global_changed,
        "per_sample_threshold_changes": per_sample_changed,
        "threshold_changed": threshold_changed,
    }


def _compare_calibration(
    pairs: Sequence[tuple[dict[str, Any], dict[str, Any], str]],
    *,
    claim_allowed: bool,
    shift_threshold: float,
    min_samples: int,
) -> dict[str, Any]:
    baseline_values: list[float] = []
    current_values: list[float] = []
    deltas: list[float] = []
    id_changes: list[dict[str, Any]] = []
    baseline_ids: list[Any] = []
    current_ids: list[Any] = []

    for baseline, current, sample_id in pairs:
        baseline_id = baseline.get("calibration_id")
        current_id = current.get("calibration_id")
        baseline_ids.append(baseline_id)
        current_ids.append(current_id)
        if baseline_id != current_id:
            id_changes.append(
                {
                    "sample_id": sample_id,
                    "baseline_calibration_id": baseline_id,
                    "current_calibration_id": current_id,
                }
            )
        baseline_probability = _coerce_float(
            baseline.get("calibrated_ai_probability"),
            "calibrated_ai_probability",
            minimum=0.0,
            maximum=1.0,
        )
        current_probability = _coerce_float(
            current.get("calibrated_ai_probability"),
            "calibrated_ai_probability",
            minimum=0.0,
            maximum=1.0,
        )
        if baseline_probability is None or current_probability is None:
            continue
        baseline_values.append(baseline_probability)
        current_values.append(current_probability)
        deltas.append(current_probability - baseline_probability)

    baseline_summary = _distribution_summary(baseline_values)
    current_summary = _distribution_summary(current_values)
    mean_abs_delta = sum(abs(delta) for delta in deltas) / len(deltas) if deltas else None
    max_abs_delta = max(abs(delta) for delta in deltas) if deltas else None
    probability_shift_significant = bool(
        claim_allowed
        and len(deltas) >= min_samples
        and max_abs_delta is not None
        and max_abs_delta >= shift_threshold
    )
    calibration_id_changed = bool(id_changes)
    significant = bool(claim_allowed and (calibration_id_changed or probability_shift_significant))
    return {
        "n_paired_probabilities": len(deltas),
        "baseline": baseline_summary,
        "current": current_summary,
        "mean_abs_delta": _round(mean_abs_delta),
        "max_abs_delta": _round(max_abs_delta),
        "baseline_calibration_ids": _unique_scalars(baseline_ids),
        "current_calibration_ids": _unique_scalars(current_ids),
        "calibration_id_changed": calibration_id_changed,
        "calibration_id_change_count": len(id_changes),
        "calibration_id_change_examples": id_changes[:10],
        "probability_shift_significant": probability_shift_significant,
        "significant": significant,
        "status": (
            "calibration_drift"
            if significant
            else "no_calibrated_probabilities"
            if not deltas and not id_changes
            else "stable"
        ),
    }


def _compare_human_fpr(
    pairs: Sequence[tuple[dict[str, Any], dict[str, Any], str]],
    *,
    claim_allowed: bool,
    min_slice_samples: int,
    increase_threshold: float,
    samples: Mapping[str, ProbeSample],
) -> dict[str, Any]:
    human_ids = {
        sample_id for sample_id, sample in samples.items() if _is_human_sample(sample.metadata)
    }
    human_pairs = [pair for pair in pairs if pair[2] in human_ids]
    count = len(human_pairs)
    if count == 0:
        return {
            "human_sample_count": 0,
            "baseline_false_positives": 0,
            "current_false_positives": 0,
            "baseline_fpr": None,
            "current_fpr": None,
            "delta": None,
            "baseline_decided": 0,
            "current_decided": 0,
            "significant_increase": False,
            "status": "no_human_samples",
        }

    baseline_fp = sum(1 for baseline, _, _ in human_pairs if baseline.get("verdict") == "ai_like")
    current_fp = sum(1 for _, current, _ in human_pairs if current.get("verdict") == "ai_like")
    baseline_decided = sum(
        1 for baseline, _, _ in human_pairs if baseline.get("verdict") != "abstain"
    )
    current_decided = sum(1 for _, current, _ in human_pairs if current.get("verdict") != "abstain")
    baseline_fpr = baseline_fp / count
    current_fpr = current_fp / count
    delta = current_fpr - baseline_fpr
    slice_claim_allowed = bool(claim_allowed and count >= min_slice_samples)
    significant_increase = bool(slice_claim_allowed and delta > 0.0 and delta >= increase_threshold)
    return {
        "human_sample_count": count,
        "baseline_false_positives": baseline_fp,
        "current_false_positives": current_fp,
        "baseline_fpr": _round(baseline_fpr),
        "current_fpr": _round(current_fpr),
        "delta": _round(delta),
        "baseline_decided": baseline_decided,
        "current_decided": current_decided,
        "slice_claim_allowed": slice_claim_allowed,
        "significant_increase": significant_increase,
        "status": (
            "human_fpr_increase"
            if significant_increase
            else "insufficient_human_samples"
            if not slice_claim_allowed
            else "stable"
        ),
    }


def _compare_provider_metadata(
    baseline_records: Sequence[Mapping[str, Any]],
    current_records: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    baseline_provider = _unique_scalars(
        record.get("provider_version") for record in baseline_records
    )
    current_provider = _unique_scalars(record.get("provider_version") for record in current_records)
    baseline_detector_version = _unique_scalars(
        record.get("detector_version") for record in baseline_records
    )
    current_detector_version = _unique_scalars(
        record.get("detector_version") for record in current_records
    )
    baseline_execution = _unique_scalars(record.get("execution") for record in baseline_records)
    current_execution = _unique_scalars(record.get("execution") for record in current_records)

    missing_provider_version = any(
        record.get("execution") == "remote" and record.get("provider_version") is None
        for record in current_records
    )
    baseline_had_provider = any(value is not None for value in baseline_provider)
    current_missing_provider = any(value is None for value in current_provider)
    lost_provider_version = bool(baseline_had_provider and current_missing_provider)
    changed_provider_version = baseline_provider != current_provider
    changed_detector_version = baseline_detector_version != current_detector_version
    execution_changed = baseline_execution != current_execution
    provider_metadata_changed = bool(
        changed_provider_version
        or changed_detector_version
        or execution_changed
        or missing_provider_version
        or lost_provider_version
    )
    return {
        "baseline_provider_versions": baseline_provider,
        "current_provider_versions": current_provider,
        "baseline_detector_versions": baseline_detector_version,
        "current_detector_versions": current_detector_version,
        "baseline_executions": baseline_execution,
        "current_executions": current_execution,
        "missing_provider_version": missing_provider_version,
        "lost_provider_version": lost_provider_version,
        "changed_provider_version": changed_provider_version,
        "changed_detector_version": changed_detector_version,
        "execution_changed": execution_changed,
        "provider_metadata_changed": provider_metadata_changed,
    }


def _compare_supported_regime(
    baseline_records: Sequence[Mapping[str, Any]],
    current_records: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    baseline_languages = sorted(
        {
            language
            for record in baseline_records
            for language in record.get("supported_languages", [])
            if isinstance(language, str) and language
        }
    )
    current_languages = sorted(
        {
            language
            for record in current_records
            for language in record.get("supported_languages", [])
            if isinstance(language, str) and language
        }
    )
    baseline_min_words = _unique_scalars(record.get("min_words") for record in baseline_records)
    current_min_words = _unique_scalars(record.get("min_words") for record in current_records)
    language_changed = baseline_languages != current_languages
    min_words_changed = baseline_min_words != current_min_words
    return {
        "baseline_supported_languages": baseline_languages,
        "current_supported_languages": current_languages,
        "added_languages": sorted(set(current_languages) - set(baseline_languages)),
        "removed_languages": sorted(set(baseline_languages) - set(current_languages)),
        "baseline_min_words": baseline_min_words,
        "current_min_words": current_min_words,
        "language_changed": language_changed,
        "min_words_changed": min_words_changed,
        "supported_regime_changed": bool(language_changed or min_words_changed),
    }


def _overall_summary(reports: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    compared = len(reports)
    drift_detected = sum(1 for report in reports if report.get("status") == "drift_detected")
    insufficient = sum(1 for report in reports if report.get("status") == "insufficient_evidence")
    missing = sum(
        1
        for report in reports
        if report.get("status") in {"missing_in_baseline", "missing_in_current"}
    )
    stable = sum(1 for report in reports if report.get("status") == "stable")

    if compared == 0:
        status = "no_detectors_compared"
    elif drift_detected:
        status = "drift_detected"
    elif missing == compared:
        status = "no_comparable_detectors"
    elif insufficient == compared:
        status = "insufficient_evidence"
    elif stable and (insufficient or missing):
        status = "stable_with_coverage_gaps"
    elif stable:
        status = "stable"
    else:
        status = "mixed"

    return {
        "status": status,
        "detectors_compared": compared,
        "detectors_with_drift": drift_detected,
        "detectors_insufficient": insufficient,
        "detectors_missing": missing,
        "detectors_stable": stable,
    }


@dataclass(slots=True)
class ProbeSample:
    sample_id: str
    text_sha256: str
    text: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class DriftObservatory:
    """Longitudinal detector reliability tracking over a stable probe corpus."""

    def __init__(
        self,
        corpus_path: str | Path | None = None,
        corpus: Mapping[str, Any] | Sequence[Mapping[str, Any]] | None = None,
        *,
        min_samples_for_drift_claim: int = 2,
        min_slice_samples: int = 2,
        score_shift_threshold: float = 0.05,
        verdict_flip_rate_threshold: float = 0.10,
        calibration_shift_threshold: float = 0.05,
        human_fpr_increase_threshold: float = 0.05,
    ) -> None:
        if corpus_path is not None and corpus is not None:
            raise ValueError("Provide either corpus_path or corpus, not both.")
        if min_samples_for_drift_claim < 1:
            raise ValueError("min_samples_for_drift_claim must be at least 1.")
        if min_slice_samples < 1:
            raise ValueError("min_slice_samples must be at least 1.")

        self.samples: dict[str, ProbeSample] = {}
        if corpus is not None:
            self._load_corpus(corpus)
        elif corpus_path is not None:
            self._load_corpus_path(corpus_path)

        self.corpus_sha256 = _compute_corpus_sha256(self.samples.values())
        self.snapshots: list[dict[str, Any]] = []
        self.min_samples_for_drift_claim = int(min_samples_for_drift_claim)
        self.min_slice_samples = int(min_slice_samples)
        self.score_shift_threshold = float(score_shift_threshold)
        self.verdict_flip_rate_threshold = float(verdict_flip_rate_threshold)
        self.calibration_shift_threshold = float(calibration_shift_threshold)
        self.human_fpr_increase_threshold = float(human_fpr_increase_threshold)

    def _load_corpus_path(self, corpus_path: str | Path) -> None:
        path = Path(corpus_path)
        data = json.loads(path.read_text(encoding="utf-8"))
        self._load_corpus(data)

    def _load_corpus(self, corpus: Mapping[str, Any] | Sequence[Mapping[str, Any]]) -> None:
        if isinstance(corpus, Mapping):
            schema = corpus.get("schema")
            if schema is not None and schema != DRIFT_CORPUS_SCHEMA:
                raise ValueError(f"Unsupported drift corpus schema: {schema}")
            raw_samples = corpus.get("samples")
            if raw_samples is None:
                raise ValueError("Drift corpus must contain a samples list.")
            if not isinstance(raw_samples, (list, tuple)):
                raise ValueError("Drift corpus samples must be a list.")
        elif isinstance(corpus, (list, tuple)):
            raw_samples = corpus
        else:
            raise ValueError("Drift corpus must be a list or an object with samples.")

        for raw_sample in raw_samples:
            self._add_sample(raw_sample)

    def _add_sample(self, raw_sample: Any) -> None:
        if not isinstance(raw_sample, Mapping):
            raise ValueError("Drift corpus samples must be objects.")
        sample_id = raw_sample.get("id", raw_sample.get("sample_id"))
        _require_nonempty_string(sample_id, "sample id")
        sample_id = str(sample_id)
        if sample_id in self.samples:
            raise ValueError(f"Duplicate drift corpus sample id: {sample_id}")

        text = raw_sample.get("text")
        if text is not None and (not isinstance(text, str) or not text.strip()):
            raise ValueError(f"Sample {sample_id}: text must be a non-empty string when present.")

        text_sha = raw_sample.get("text_sha256")
        if text_sha is None:
            if text is None:
                raise ValueError(f"Sample {sample_id}: requires text_sha256 or text.")
            text_sha = text_sha256(text)
        if not _is_hex64(text_sha):
            raise ValueError(f"Sample {sample_id}: text_sha256 must be a 64-character hex digest.")
        if text is not None and text_sha256(text) != text_sha:
            raise ValueError(f"Sample {sample_id}: text_sha256 does not match text.")

        metadata = raw_sample.get("metadata") or {}
        if not isinstance(metadata, Mapping):
            raise ValueError(f"Sample {sample_id}: metadata must be an object.")
        self.samples[sample_id] = ProbeSample(
            sample_id=sample_id,
            text_sha256=str(text_sha),
            text=text,
            metadata=dict(metadata),
        )

    def _settings_dict(self) -> dict[str, Any]:
        return {
            "min_samples_for_drift_claim": self.min_samples_for_drift_claim,
            "min_slice_samples": self.min_slice_samples,
            "score_shift_threshold": _round(self.score_shift_threshold),
            "verdict_flip_rate_threshold": _round(self.verdict_flip_rate_threshold),
            "calibration_shift_threshold": _round(self.calibration_shift_threshold),
            "human_fpr_increase_threshold": _round(self.human_fpr_increase_threshold),
        }

    def _normalize_observation(self, observation: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(observation, Mapping):
            raise ValueError("Drift observations must be objects.")
        data = dict(observation)

        sample_id = _require_nonempty_string(data.get("sample_id"), "sample_id")
        sample = self.samples.get(sample_id)
        if sample is None:
            raise ValueError(f"Unknown probe sample: {sample_id}")

        text_sha = data.get("text_sha256", sample.text_sha256)
        if not _is_hex64(text_sha):
            raise ValueError(f"Sample {sample_id}: text_sha256 must be a 64-character hex digest.")
        if text_sha != sample.text_sha256:
            raise ValueError(f"Sample {sample_id}: text_sha256 does not match the probe corpus.")

        detector_id = _require_nonempty_string(data.get("detector_id"), "detector_id")
        detector_version = _require_nonempty_string(
            data.get("detector_version"), "detector_version"
        )
        detector_family = _require_nonempty_string(data.get("detector_family"), "detector_family")
        execution = _require_nonempty_string(data.get("execution"), "execution")
        if execution not in EXECUTIONS:
            raise ValueError("execution must be 'local' or 'remote'.")
        verdict = _require_nonempty_string(data.get("verdict"), "verdict")
        if verdict not in VERDICTS:
            raise ValueError("verdict must be 'ai_like', 'human_like', or 'abstain'.")

        score = _coerce_float(data.get("score"), "score")
        threshold = _coerce_float(data.get("threshold"), "threshold")
        calibrated = _coerce_float(
            data.get("calibrated_ai_probability"),
            "calibrated_ai_probability",
            minimum=0.0,
            maximum=1.0,
        )
        calibration_id = data.get("calibration_id")
        if calibrated is not None:
            _require_nonempty_string(calibration_id, "calibration_id")
        elif calibration_id is not None:
            raise ValueError("calibration_id cannot be set without calibrated_ai_probability.")
        reliability = _coerce_float(
            data.get("reliability"), "reliability", minimum=0.0, maximum=1.0
        )
        min_words = _coerce_int_or_none(data.get("min_words"), "min_words")

        supported_languages = data.get("supported_languages") or []
        if not isinstance(supported_languages, (list, tuple)):
            raise ValueError("supported_languages must be a list of strings.")
        normalized_languages: list[str] = []
        for language in supported_languages:
            normalized_languages.append(
                _require_nonempty_string(language, "supported_languages item")
            )

        provider_version = data.get("provider_version")
        if provider_version is not None:
            provider_version = _require_nonempty_string(provider_version, "provider_version")

        score_semantics = data.get("score_semantics") or "unspecified"
        _require_nonempty_string(score_semantics, "score_semantics")

        return {
            "sample_id": sample_id,
            "text_sha256": str(text_sha),
            "detector_id": detector_id,
            "detector_version": detector_version,
            "detector_family": detector_family,
            "execution": execution,
            "observed_at": data.get("observed_at") or _now_iso(),
            "score": score,
            "score_semantics": score_semantics,
            "verdict": verdict,
            "threshold": threshold,
            "calibrated_ai_probability": calibrated,
            "calibration_id": calibration_id,
            "reliability": reliability,
            "supported_languages": normalized_languages,
            "min_words": min_words,
            "provider_version": provider_version,
        }

    def _normalize_failure(self, failure: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(failure, Mapping):
            raise ValueError("Drift failures must be objects.")
        data = dict(failure)
        sample_id = data.get("sample_id")
        text_sha = data.get("text_sha256")
        if sample_id is not None:
            sample_id = _require_nonempty_string(sample_id, "sample_id")
            sample = self.samples.get(sample_id)
            if sample is None:
                raise ValueError(f"Unknown probe sample in failure: {sample_id}")
            if text_sha is None:
                text_sha = sample.text_sha256
            if text_sha != sample.text_sha256:
                raise ValueError(f"Sample {sample_id}: failure text_sha256 does not match corpus.")
        if text_sha is not None and not _is_hex64(text_sha):
            raise ValueError("Failure text_sha256 must be a 64-character hex digest.")
        return {
            "sample_id": sample_id,
            "text_sha256": text_sha,
            "detector_id": data.get("detector_id"),
            "detector_version": data.get("detector_version"),
            "detector_family": data.get("detector_family"),
            "error_type": data.get("error_type"),
            "observed_at": data.get("observed_at") or _now_iso(),
        }

    def _observation_from_prediction(
        self,
        sample: ProbeSample,
        detector: Detector,
        prediction: DetectorPrediction,
    ) -> dict[str, Any]:
        return {
            "sample_id": sample.sample_id,
            "text_sha256": sample.text_sha256,
            "detector_id": prediction.detector_id,
            "detector_version": prediction.detector_version,
            "detector_family": prediction.detector_family,
            "execution": prediction.execution,
            "observed_at": _now_iso(),
            "score": prediction.score,
            "score_semantics": prediction.score_semantics,
            "verdict": prediction.verdict,
            "threshold": prediction.threshold,
            "calibrated_ai_probability": prediction.calibrated_ai_probability,
            "calibration_id": prediction.calibration_id,
            "reliability": prediction.reliability,
            "supported_languages": list(prediction.supported_languages),
            "min_words": prediction.min_words,
            "provider_version": getattr(detector, "provider_version", None),
        }

    def snapshot_from_observations(
        self,
        observations: Iterable[Mapping[str, Any]],
        *,
        failures: Iterable[Mapping[str, Any]] | None = None,
        taken_at: str | None = None,
        snapshot_id: str | None = None,
        label: str | None = None,
        detector_ids: Sequence[str] | None = None,
    ) -> dict[str, Any]:
        records = [self._normalize_observation(observation) for observation in observations]
        normalized_failures = [self._normalize_failure(failure) for failure in (failures or [])]
        snapshot_detector_ids = (
            sorted({record["detector_id"] for record in records})
            if detector_ids is None
            else sorted(set(detector_ids))
        )
        snapshot: dict[str, Any] = {
            "schema": DRIFT_SNAPSHOT_SCHEMA,
            "snapshot_id": snapshot_id or uuid.uuid4().hex,
            "taken_at": taken_at or _now_iso(),
            "corpus_sha256": self.corpus_sha256,
            "label": label,
            "detector_ids": snapshot_detector_ids,
            "record_count": len(records),
            "failure_count": len(normalized_failures),
            "records": records,
            "failures": normalized_failures,
            "limitations": [
                "Snapshots store detector observations and probe IDs, not raw probe text.",
                "Remote provider observations are not ground truth.",
            ],
        }
        self.snapshots.append(snapshot)
        return snapshot

    def take_snapshot(
        self,
        *,
        detectors: Sequence[Detector] | None = None,
        detector_ids: Sequence[str] | None = None,
        allow_remote: bool = False,
        taken_at: str | None = None,
        snapshot_id: str | None = None,
        label: str | None = None,
        execution_policy: ExecutionPolicy | None = None,
        cancellation: CancellationToken | None = None,
    ) -> dict[str, Any]:
        # S08 / IF-03: the canonical stop gate runs before any execution
        # and between sample/detector operations. A stop raises
        # EmergencyStopError — an explicit terminal/incomplete condition,
        # never a stored observation and never an ordinary suppressed
        # detector failure. Cancellation is cooperative: a detector
        # already running is not forcibly terminated, but no further
        # sample/detector operation starts after it is requested.
        policy_supplied = execution_policy is not None
        effective_policy = execution_policy or ExecutionPolicy.default_local_only()
        assert_execution_allowed(effective_policy, cancellation=cancellation)

        if not self.samples:
            snapshot = self.snapshot_from_observations(
                [],
                taken_at=taken_at,
                snapshot_id=snapshot_id,
                label=label,
                detector_ids=detector_ids or [],
            )
            snapshot["skipped_detectors"] = []
            return snapshot

        if detectors is None:
            # Resolved at call time (W1: same convention as api/mcp/cli/
            # report): a module-level import binds at import time, so
            # patching the canonical name would have no effect.
            from .detectors import discover_detector_registry

            registry = discover_detector_registry()
            selected_detectors: list[Detector] = list(registry.detectors.values())
        else:
            selected_detectors = list(detectors)

        if detector_ids is not None:
            wanted = set(detector_ids)
            selected_detectors = [
                detector for detector in selected_detectors if detector.detector_id in wanted
            ]

        # Legacy caller opt-in: when no explicit policy was supplied,
        # allow_remote=True consents to exactly the remote detectors
        # selected for this snapshot. An explicit policy always wins.
        if not policy_supplied and allow_remote:
            effective_policy = ExecutionPolicy.with_remote_consent(
                [
                    detector.detector_id
                    for detector in selected_detectors
                    if is_remote_detector(detector)
                ]
            )

        records: list[dict[str, Any]] = []
        failures: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []

        for detector in selected_detectors:
            assert_execution_allowed(effective_policy, cancellation=cancellation)
            if is_remote_detector(detector) and not effective_policy.allows_remote(
                detector.detector_id
            ):
                skipped.append(
                    {
                        "detector_id": detector.detector_id,
                        "reason": "remote_not_allowed",
                    }
                )
                continue
            for sample in self.samples.values():
                assert_execution_allowed(effective_policy, cancellation=cancellation)
                if sample.text is None:
                    raise ValueError(
                        f"Sample {sample.sample_id} has no text; cannot execute detectors."
                    )
                prediction, failure = execute_detector(
                    detector,
                    sample.text,
                    policy=effective_policy,
                    cancellation=cancellation,
                )
                if failure is not None:
                    failures.append(
                        {
                            "sample_id": sample.sample_id,
                            "text_sha256": sample.text_sha256,
                            "detector_id": failure.detector_id,
                            "detector_version": failure.detector_version,
                            "detector_family": failure.detector_family,
                            "error_type": failure.error_type,
                            "observed_at": _now_iso(),
                        }
                    )
                elif prediction is not None:
                    records.append(self._observation_from_prediction(sample, detector, prediction))

        snapshot = self.snapshot_from_observations(
            records,
            failures=failures,
            taken_at=taken_at,
            snapshot_id=snapshot_id,
            label=label,
            detector_ids=detector_ids,
        )
        snapshot["skipped_detectors"] = skipped
        return snapshot

    def add_snapshot(self, snapshot: Mapping[str, Any]) -> dict[str, Any]:
        self._validate_snapshot_schema(snapshot)
        stored = dict(snapshot)
        self.snapshots.append(stored)
        return stored

    def save_snapshots(self, path: str | Path) -> None:
        payload = {
            "schema": DRIFT_SNAPSHOT_STORE_SCHEMA,
            "snapshots": self.snapshots,
        }
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
            encoding="utf-8",
        )

    def load_snapshots(
        self,
        path: str | Path,
        *,
        replace: bool = True,
        expected_corpus_sha256: str | None = None,
    ) -> list[dict[str, Any]]:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if data.get("schema") == DRIFT_SNAPSHOT_STORE_SCHEMA:
            snapshots = data.get("snapshots", [])
        elif data.get("schema") == DRIFT_SNAPSHOT_SCHEMA:
            snapshots = [data]
        else:
            raise ValueError("Unrecognized drift snapshot store schema.")
        if not isinstance(snapshots, list):
            raise ValueError("Drift snapshot store snapshots must be a list.")

        loaded: list[dict[str, Any]] = []
        for snapshot in snapshots:
            self._validate_snapshot_schema(snapshot)
            if (
                expected_corpus_sha256 is not None
                and snapshot.get("corpus_sha256") != expected_corpus_sha256
            ):
                raise ValueError(
                    "Drift snapshot corpus hash does not match the loaded probe corpus."
                )
            loaded.append(dict(snapshot))

        if replace:
            self.snapshots = loaded
        else:
            self.snapshots.extend(loaded)
        return self.snapshots

    @staticmethod
    def read_snapshot_file(path: str | Path) -> dict[str, Any]:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if data.get("schema") == DRIFT_SNAPSHOT_STORE_SCHEMA:
            snapshots = data.get("snapshots", [])
            if len(snapshots) != 1:
                raise ValueError(
                    "Snapshot file must contain exactly one snapshot; use drift report for stores."
                )
            snapshot = snapshots[0]
        elif data.get("schema") == DRIFT_SNAPSHOT_SCHEMA:
            snapshot = data
        else:
            raise ValueError("Unrecognized drift snapshot schema.")
        if not isinstance(snapshot, dict) or snapshot.get("schema") != DRIFT_SNAPSHOT_SCHEMA:
            raise ValueError("Unrecognized drift snapshot schema.")
        return snapshot

    def _validate_snapshot_schema(self, snapshot: Mapping[str, Any]) -> None:
        if not isinstance(snapshot, Mapping) or snapshot.get("schema") != DRIFT_SNAPSHOT_SCHEMA:
            raise ValueError("Unrecognized drift snapshot schema.")
        if not isinstance(snapshot.get("records", []), list):
            raise ValueError("Drift snapshot records must be a list.")
        if not isinstance(snapshot.get("failures", []), list):
            raise ValueError("Drift snapshot failures must be a list.")

    def compare_snapshots(
        self, baseline: Mapping[str, Any], current: Mapping[str, Any]
    ) -> dict[str, Any]:
        self._validate_snapshot_schema(baseline)
        self._validate_snapshot_schema(current)
        baseline_dict = dict(baseline)
        current_dict = dict(current)
        generated_at = _now_iso()
        baseline_corpus = baseline_dict.get("corpus_sha256")
        current_corpus = current_dict.get("corpus_sha256")

        if baseline_corpus != current_corpus or baseline_corpus != self.corpus_sha256:
            return {
                "schema": DRIFT_REPORT_SCHEMA,
                "generated_at": generated_at,
                "baseline_snapshot_id": baseline_dict.get("snapshot_id"),
                "current_snapshot_id": current_dict.get("snapshot_id"),
                "corpus_sha256": {
                    "baseline": baseline_corpus,
                    "current": current_corpus,
                    "observatory": self.corpus_sha256,
                },
                "settings": self._settings_dict(),
                "detectors": [],
                "overall": {
                    "status": "corpus_mismatch",
                    "detectors_compared": 0,
                    "detectors_with_drift": 0,
                    "detectors_insufficient": 0,
                    "detectors_missing": 0,
                    "detectors_stable": 0,
                },
                "limitations": [
                    "Snapshots must refer to the same probe corpus and the observatory's loaded corpus.",
                    *REPORT_LIMITATIONS,
                ],
            }

        baseline_by_detector = _records_by_detector(baseline_dict)
        current_by_detector = _records_by_detector(current_dict)
        detector_ids = sorted(set(baseline_by_detector) | set(current_by_detector))
        detector_reports = [
            self._compare_detector(
                detector_id,
                baseline_by_detector.get(detector_id, []),
                current_by_detector.get(detector_id, []),
            )
            for detector_id in detector_ids
        ]

        return {
            "schema": DRIFT_REPORT_SCHEMA,
            "generated_at": generated_at,
            "baseline_snapshot_id": baseline_dict.get("snapshot_id"),
            "current_snapshot_id": current_dict.get("snapshot_id"),
            "baseline_taken_at": baseline_dict.get("taken_at"),
            "current_taken_at": current_dict.get("taken_at"),
            "corpus_sha256": self.corpus_sha256,
            "settings": self._settings_dict(),
            "detectors": detector_reports,
            "overall": _overall_summary(detector_reports),
            "limitations": REPORT_LIMITATIONS,
        }

    def _compare_detector(
        self,
        detector_id: str,
        baseline_records: Sequence[Mapping[str, Any]],
        current_records: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        if not baseline_records or not current_records:
            status = "missing_in_baseline" if not baseline_records else "missing_in_current"
            score = _compare_score_distribution(
                [],
                claim_allowed=False,
                shift_threshold=self.score_shift_threshold,
                min_samples=self.min_samples_for_drift_claim,
            )
            verdict = _compare_verdict_flips(
                [],
                claim_allowed=False,
                flip_rate_threshold=self.verdict_flip_rate_threshold,
                min_samples=self.min_samples_for_drift_claim,
            )
            threshold = _compare_thresholds([], baseline_records, current_records)
            calibration = _compare_calibration(
                [],
                claim_allowed=False,
                shift_threshold=self.calibration_shift_threshold,
                min_samples=self.min_samples_for_drift_claim,
            )
            human = _compare_human_fpr(
                [],
                claim_allowed=False,
                min_slice_samples=self.min_slice_samples,
                increase_threshold=self.human_fpr_increase_threshold,
                samples=self.samples,
            )
            provider = _compare_provider_metadata(baseline_records, current_records)
            regime = _compare_supported_regime(baseline_records, current_records)
            return {
                "detector_id": detector_id,
                "comparable_samples": 0,
                "drift_claim_allowed": False,
                "status": status,
                "drift_detected": False,
                "behavioral_drift_detected": False,
                "configuration_drift_detected": False,
                "score_distribution": score,
                "verdict_flips": verdict,
                "threshold_changes": threshold,
                "calibration_drift": calibration,
                "human_slice_fpr": human,
                "provider_metadata": provider,
                "supported_regime": regime,
                "findings": [
                    _finding(
                        status,
                        "warning",
                        f"Detector {detector_id} is missing from one snapshot.",
                    )
                ],
            }

        baseline_index = _index_by_sample(baseline_records)
        current_index = _index_by_sample(current_records)
        common_ids = sorted(set(baseline_index) & set(current_index))
        comparable = len(common_ids)
        claim_allowed = comparable >= self.min_samples_for_drift_claim
        pairs = [
            (baseline_index[sample_id], current_index[sample_id], sample_id)
            for sample_id in common_ids
        ]

        score = _compare_score_distribution(
            pairs,
            claim_allowed=claim_allowed,
            shift_threshold=self.score_shift_threshold,
            min_samples=self.min_samples_for_drift_claim,
        )
        verdict = _compare_verdict_flips(
            pairs,
            claim_allowed=claim_allowed,
            flip_rate_threshold=self.verdict_flip_rate_threshold,
            min_samples=self.min_samples_for_drift_claim,
        )
        threshold = _compare_thresholds(pairs, baseline_records, current_records)
        calibration = _compare_calibration(
            pairs,
            claim_allowed=claim_allowed,
            shift_threshold=self.calibration_shift_threshold,
            min_samples=self.min_samples_for_drift_claim,
        )
        human = _compare_human_fpr(
            pairs,
            claim_allowed=claim_allowed,
            min_slice_samples=self.min_slice_samples,
            increase_threshold=self.human_fpr_increase_threshold,
            samples=self.samples,
        )
        provider = _compare_provider_metadata(baseline_records, current_records)
        regime = _compare_supported_regime(baseline_records, current_records)

        findings: list[dict[str, Any]] = []
        if not claim_allowed:
            findings.append(
                _finding(
                    "insufficient_sample_count",
                    "info",
                    f"Only {comparable} comparable probe samples; drift claims require at least {self.min_samples_for_drift_claim}.",
                    comparable_samples=comparable,
                )
            )
        if score["significant"]:
            findings.append(
                _finding(
                    "score_distribution_shift",
                    "warning",
                    f"Mean score shifted by {score['delta_mean']} across {score['n_paired']} paired samples.",
                    shift_magnitude=score["shift_magnitude"],
                )
            )
        if verdict["significant"]:
            findings.append(
                _finding(
                    "verdict_flip_change",
                    "critical" if verdict["severe_flip_count"] else "warning",
                    f"{verdict['flip_count']} of {verdict['n']} verdicts changed; {verdict['severe_flip_count']} severe AI/human flips.",
                    flip_rate=verdict["flip_rate"],
                )
            )
        if threshold["threshold_changed"]:
            findings.append(
                _finding(
                    "threshold_changed",
                    "warning",
                    f"Detector threshold changed from {threshold['baseline_thresholds']} to {threshold['current_thresholds']}.",
                )
            )
        if calibration["calibration_id_changed"]:
            findings.append(
                _finding(
                    "calibration_artifact_changed",
                    "warning",
                    f"Calibration artifact changed on {calibration['calibration_id_change_count']} samples.",
                )
            )
        if calibration["probability_shift_significant"]:
            findings.append(
                _finding(
                    "calibrated_probability_shift",
                    "warning",
                    f"Maximum calibrated probability delta was {calibration['max_abs_delta']}.",
                )
            )
        if human["significant_increase"]:
            findings.append(
                _finding(
                    "human_false_positive_rate_increase",
                    "critical",
                    f"Human-slice false-positive rate changed from {human['baseline_fpr']} to {human['current_fpr']} across {human['human_sample_count']} samples.",
                    delta=human["delta"],
                )
            )
        if provider["missing_provider_version"]:
            findings.append(
                _finding(
                    "missing_provider_version",
                    "warning",
                    "Remote provider version metadata is missing in the current snapshot.",
                )
            )
        if provider["lost_provider_version"]:
            findings.append(
                _finding(
                    "lost_provider_version",
                    "warning",
                    "Provider version metadata present in the baseline snapshot is missing in the current snapshot.",
                )
            )
        if provider["changed_provider_version"]:
            findings.append(
                _finding(
                    "changed_provider_version",
                    "warning",
                    f"Provider version metadata changed from {provider['baseline_provider_versions']} to {provider['current_provider_versions']}.",
                )
            )
        if provider["changed_detector_version"]:
            findings.append(
                _finding(
                    "changed_detector_version",
                    "warning",
                    f"Detector version changed from {provider['baseline_detector_versions']} to {provider['current_detector_versions']}.",
                )
            )
        if provider["execution_changed"]:
            findings.append(
                _finding(
                    "execution_mode_changed",
                    "warning",
                    f"Detector execution mode changed from {provider['baseline_executions']} to {provider['current_executions']}.",
                )
            )
        if regime["language_changed"]:
            findings.append(
                _finding(
                    "supported_language_change",
                    "warning",
                    f"Supported languages changed; added={regime['added_languages']}, removed={regime['removed_languages']}.",
                )
            )
        if regime["min_words_changed"]:
            findings.append(
                _finding(
                    "min_words_change",
                    "warning",
                    f"Declared minimum word count changed from {regime['baseline_min_words']} to {regime['current_min_words']}.",
                )
            )

        behavioral = bool(
            claim_allowed
            and (
                score["significant"]
                or verdict["significant"]
                or calibration["probability_shift_significant"]
                or human["significant_increase"]
            )
        )
        configuration = bool(
            threshold["threshold_changed"]
            or calibration["calibration_id_changed"]
            or provider["provider_metadata_changed"]
            or regime["supported_regime_changed"]
        )
        configuration_drift = bool(configuration and claim_allowed)
        drift_detected = bool(behavioral or configuration_drift)

        if not claim_allowed:
            status = "insufficient_evidence"
        elif drift_detected:
            status = "drift_detected"
        else:
            status = "stable"

        return {
            "detector_id": detector_id,
            "comparable_samples": comparable,
            "drift_claim_allowed": claim_allowed,
            "status": status,
            "drift_detected": drift_detected,
            "behavioral_drift_detected": behavioral,
            "configuration_drift_detected": configuration_drift,
            "score_distribution": score,
            "verdict_flips": verdict,
            "threshold_changes": threshold,
            "calibration_drift": calibration,
            "human_slice_fpr": human,
            "provider_metadata": provider,
            "supported_regime": regime,
            "findings": findings,
        }


def _is_remote_detector(detector: Detector) -> bool:
    # Kept for internal callers; delegates to the shared classifier in
    # detectors.py (the execution-policy boundary).
    return is_remote_detector(detector)


# ---------------------------------------------------------------------------
# Drift alerting
# ---------------------------------------------------------------------------


@dataclass
class DriftAlert:
    """A detected drift alert with severity and recommended action."""

    detector_id: str
    severity: str  # "critical", "warning", "info"
    category: str  # "behavioral", "configuration", "calibration", "human_fpr"
    message: str
    recommended_action: str
    snapshot_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector_id": self.detector_id,
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
            "recommended_action": self.recommended_action,
            "snapshot_id": self.snapshot_id,
        }


def generate_drift_alerts(
    reports: Sequence[Mapping[str, Any]],
    *,
    critical_severity: str = "critical",
) -> list[DriftAlert]:
    """Generate drift alerts from drift comparison reports.

    Alerts are generated based on:
    - Behavioral drift (score shifts, verdict flips)
    - Configuration drift (threshold changes, calibration ID changes)
    - Human FPR increases
    - Provider metadata changes
    """
    alerts: list[DriftAlert] = []

    for report in reports:
        detector_id = str(report.get("detector_id", "unknown"))
        status = str(report.get("status", "unknown"))

        if status == "drift_detected":
            score = report.get("score_distribution", {})
            if score.get("significant"):
                alerts.append(
                    DriftAlert(
                        detector_id=detector_id,
                        severity="warning",
                        category="behavioral",
                        message=f"Score distribution shift detected for {detector_id}",
                        recommended_action="Review detector performance on recent data.",
                        snapshot_id=report.get("snapshot_id"),
                    )
                )

            verdict = report.get("verdict_flips", {})
            if verdict.get("significant"):
                alerts.append(
                    DriftAlert(
                        detector_id=detector_id,
                        severity="warning",
                        category="behavioral",
                        message=f"Verdict flip rate increased for {detector_id}",
                        recommended_action="Investigate changes in verdict consistency.",
                        snapshot_id=report.get("snapshot_id"),
                    )
                )

            calibration = report.get("calibration_drift", {})
            if calibration.get("probability_shift_significant"):
                alerts.append(
                    DriftAlert(
                        detector_id=detector_id,
                        severity="critical",
                        category="calibration",
                        message=f"Calibration probability shift detected for {detector_id}",
                        recommended_action="Re-calibrate detector immediately.",
                        snapshot_id=report.get("snapshot_id"),
                    )
                )

            human = report.get("human_slice_fpr", {})
            if human.get("significant_increase"):
                alerts.append(
                    DriftAlert(
                        detector_id=detector_id,
                        severity="critical",
                        category="human_fpr",
                        message=f"Human false positive rate increased for {detector_id}",
                        recommended_action="Investigate false positive triggers.",
                        snapshot_id=report.get("snapshot_id"),
                    )
                )

            threshold = report.get("threshold_changes", {})
            if threshold.get("threshold_changed"):
                alerts.append(
                    DriftAlert(
                        detector_id=detector_id,
                        severity="info",
                        category="configuration",
                        message=f"Threshold changed for {detector_id}",
                        recommended_action="Verify threshold change was intentional.",
                        snapshot_id=report.get("snapshot_id"),
                    )
                )

            provider = report.get("provider_metadata", {})
            if provider.get("provider_metadata_changed"):
                alerts.append(
                    DriftAlert(
                        detector_id=detector_id,
                        severity="info",
                        category="configuration",
                        message=f"Provider metadata changed for {detector_id}",
                        recommended_action="Verify provider version is correct.",
                        snapshot_id=report.get("snapshot_id"),
                    )
                )

    return alerts


def filter_alerts(
    alerts: Sequence[DriftAlert],
    *,
    severity: str | None = None,
    category: str | None = None,
    detector_id: str | None = None,
) -> list[DriftAlert]:
    """Filter drift alerts by severity, category, or detector ID."""
    filtered = list(alerts)

    if severity is not None:
        filtered = [a for a in filtered if a.severity == severity]

    if category is not None:
        filtered = [a for a in filtered if a.category == category]

    if detector_id is not None:
        filtered = [a for a in filtered if a.detector_id == detector_id]

    return filtered


def summarize_alerts(alerts: Sequence[DriftAlert]) -> dict[str, Any]:
    """Summarize drift alerts by severity and category."""
    summary: dict[str, Any] = {
        "total": len(alerts),
        "by_severity": {},
        "by_category": {},
        "critical_count": 0,
        "warning_count": 0,
        "info_count": 0,
    }

    for alert in alerts:
        severity = alert.severity
        category = alert.category

        summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1
        summary["by_category"][category] = summary["by_category"].get(category, 0) + 1

        if severity == "critical":
            summary["critical_count"] += 1
        elif severity == "warning":
            summary["warning_count"] += 1
        elif severity == "info":
            summary["info_count"] += 1

    return summary


# ---------------------------------------------------------------------------
# Live per-detector operational health (merged from detector_health.py,
# Phase 2 wave e)
# ---------------------------------------------------------------------------
# NOTE: numpy is an optional import below (np=None fallback to a manual
# histogram); psutil-style process health lives in diagnostics.py, not here.


class HealthState(StrEnum):
    """Overall health state of a detector."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    UNKNOWN = "unknown"
    OFFLINE = "offline"


class AlertSeverity(StrEnum):
    """Severity level of health alerts."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class HealthMetric:
    """A single health metric measurement."""

    name: str
    value: float
    unit: str
    timestamp: str
    detector_id: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "unit": self.unit,
            "timestamp": self.timestamp,
            "detector_id": self.detector_id,
            "metadata": self.metadata,
        }


@dataclass(frozen=True, slots=True)
class HealthAlert:
    """A health alert triggered by anomaly detection."""

    alert_id: str
    detector_id: str
    severity: AlertSeverity
    message: str
    metric_name: str
    metric_value: float
    threshold: float
    timestamp: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "detector_id": self.detector_id,
            "severity": self.severity.value,
            "message": self.message,
            "metric_name": self.metric_name,
            "metric_value": self.metric_value,
            "threshold": self.threshold,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


@dataclass
class DetectorHealthReport:
    """Comprehensive health report for a detector."""

    detector_id: str
    overall_state: HealthState
    health_score: float  # 0.0 - 1.0
    metrics: dict[str, list[HealthMetric]] = field(default_factory=dict)
    alerts: list[HealthAlert] = field(default_factory=list)
    last_updated: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector_id": self.detector_id,
            "overall_state": self.overall_state.value,
            "health_score": self.health_score,
            "metrics": {k: [m.to_dict() for m in v] for k, v in self.metrics.items()},
            "alerts": [a.to_dict() for a in self.alerts],
            "last_updated": self.last_updated,
            "metadata": self.metadata,
        }

    def save(self, path: Path) -> bool:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            return True
        except Exception:
            return False

    @classmethod
    def load(cls, path: Path) -> DetectorHealthReport | None:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return cls(
                detector_id=data["detector_id"],
                overall_state=HealthState(data["overall_state"]),
                health_score=data["health_score"],
                metrics={
                    k: [HealthMetric(**m) for m in v] for k, v in data.get("metrics", {}).items()
                },
                alerts=[HealthAlert(**a) for a in data.get("alerts", [])],
                last_updated=data.get("last_updated", datetime.now(UTC).isoformat()),
                metadata=data.get("metadata", {}),
            )
        except Exception:
            return None


class HealthCheck:
    """A single health check definition."""

    def __init__(
        self,
        name: str,
        metric_name: str,
        check_fn: Callable[[list[float]], tuple[bool, float]],
        warning_threshold: float,
        critical_threshold: float,
        severity: AlertSeverity = AlertSeverity.WARNING,
        description: str = "",
        source_metric: str | None = None,
        inverted: bool = False,
    ):
        self.name = name
        self.metric_name = metric_name
        self.check_fn = check_fn
        self.warning_threshold = warning_threshold
        self.critical_threshold = critical_threshold
        self.severity = severity
        self.description = description
        # The raw per-event series this check reads. Defaults to metric_name
        # when the check consumes the same series it reports on.
        self.source_metric = source_metric or metric_name
        # If True, LOWER values are worse (e.g., entropy ratio).
        # If False (default), HIGHER values are worse (e.g., error rate, latency).
        self.inverted = inverted

    def evaluate(self, values: list[float], detector_id: str = "") -> HealthAlert | None:
        """Evaluate the health check against a series of values."""
        if not values:
            return None

        passed, value = self.check_fn(values)
        if passed:
            return None

        # For inverted checks (e.g., entropy), LOWER value is worse
        if self.inverted:
            if value <= self.critical_threshold:
                severity = AlertSeverity.CRITICAL
            elif value <= self.warning_threshold:
                severity = AlertSeverity.WARNING
            else:
                return None
            cmp_word = "below"
        else:
            # Normal: HIGHER value is worse
            if value >= self.critical_threshold:
                severity = AlertSeverity.CRITICAL
            elif value >= self.warning_threshold:
                severity = AlertSeverity.WARNING
            else:
                return None
            cmp_word = "exceeds"

        return HealthAlert(
            alert_id=f"alert-{hashlib.sha256(f'{self.name}{time.time()}'.encode()).hexdigest()[:8]}",
            detector_id=detector_id,
            severity=severity,
            message=f"{self.name}: {value} {cmp_word} {self.critical_threshold if severity == AlertSeverity.CRITICAL else self.warning_threshold}",
            metric_name=self.metric_name,
            metric_value=value,
            threshold=self.critical_threshold
            if severity == AlertSeverity.CRITICAL
            else self.warning_threshold,
            timestamp=datetime.now(UTC).isoformat(),
        )


# Built-in health checks
def _create_latency_check() -> HealthCheck:
    def check(values: list[float]) -> tuple[bool, float]:
        p95 = statistics.quantiles(values, n=20)[18] if len(values) >= 20 else max(values)
        return p95 < 5000.0, p95  # 5 second p95 threshold

    return HealthCheck(
        name="latency_p95",
        metric_name="latency_ms",
        check_fn=check,
        warning_threshold=3000.0,
        critical_threshold=10000.0,
        severity=AlertSeverity.WARNING,
        description="P95 latency exceeds threshold",
    )


def _create_error_rate_check() -> HealthCheck:
    def check(values: list[float]) -> tuple[bool, float]:
        error_rate = sum(1 for v in values if v > 0) / len(values)
        return error_rate < 0.05, error_rate  # 5% error rate threshold

    return HealthCheck(
        name="error_rate",
        metric_name="error_rate",
        check_fn=check,
        warning_threshold=0.05,
        critical_threshold=0.10,
        severity=AlertSeverity.CRITICAL,
        description="Error rate exceeds threshold",
        source_metric="error",
    )


def _create_score_distribution_check() -> HealthCheck:
    def check(values: list[float]) -> tuple[bool, float]:
        # Check for suspicious score distributions (too uniform = low entropy)
        # Returns (passed, entropy_ratio) where passed=True means healthy (high entropy)
        if len(values) < 10:
            return True, 1.0
        # Calculate entropy of score distribution
        bins = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
        if np is not None:
            hist, _ = np.histogram(values, bins=bins)
        else:
            # Manual histogram (numpy is an optional dependency)
            hist = [0] * 10
            for v in values:
                idx = min(int(v * 10), 9)
                hist[idx] += 1
        total = sum(hist)
        if total == 0:
            return True, 1.0
        probs = [h / total for h in hist if h > 0]
        entropy = -sum(p * math.log2(p) for p in probs)
        max_entropy = math.log2(len([h for h in hist if h > 0]))
        entropy_ratio = entropy / max_entropy if max_entropy > 0 else 0.0
        # Healthy if entropy_ratio > 0.3 (not too uniform)
        return entropy_ratio > 0.3, entropy_ratio

    return HealthCheck(
        name="score_distribution_entropy",
        metric_name="score_entropy_ratio",
        check_fn=check,
        warning_threshold=0.5,
        critical_threshold=0.3,
        severity=AlertSeverity.WARNING,
        description="Score distribution entropy too low (suspiciously uniform)",
        source_metric="score",
        inverted=True,
    )


def _create_throughput_check() -> HealthCheck:
    def check(values: list[float]) -> tuple[bool, float]:
        # values are timestamps of requests
        if len(values) < 2:
            return True, 0.0
        # Calculate requests per second over last window
        now = time.time()
        recent = [v for v in values if now - v < 60]  # Last minute
        throughput = len(recent) / 60.0  # req/s
        return throughput >= 0.1, throughput  # At least 0.1 req/s

    return HealthCheck(
        name="throughput",
        metric_name="throughput_rps",
        check_fn=check,
        warning_threshold=0.5,
        critical_threshold=0.1,
        severity=AlertSeverity.WARNING,
        source_metric="request_timestamp",
        description="Throughput below threshold",
    )


# Import json and hashlib at module level
try:
    import numpy as np
except ImportError:
    np = None


class DetectorHealthMonitor:
    """Monitors detector health with anomaly detection and alerting."""

    def __init__(
        self,
        max_history: int = 10000,
        alert_callback: Callable[[HealthAlert], None] | None = None,
    ):
        self.max_history = max_history
        self.alert_callback = alert_callback
        self._metrics: dict[str, dict[str, deque]] = defaultdict(lambda: defaultdict(deque))
        self._health_checks: dict[str, list[HealthCheck]] = defaultdict(list)
        self._reports: dict[str, DetectorHealthReport] = {}
        self._alerts: list[HealthAlert] = []
        self._lock = asyncio.Lock()

        # Register default health checks
        self._register_default_checks()

    def _register_default_checks(self) -> None:
        """Register default health checks for all detectors."""
        # These will be added per-detector when first metric is recorded
        pass

    def _ensure_detector_checks(self, detector_id: str) -> None:
        if detector_id not in self._health_checks:
            self._health_checks[detector_id] = [
                _create_latency_check(),
                _create_error_rate_check(),
                _create_score_distribution_check(),
                _create_throughput_check(),
            ]

    def record_metric(
        self,
        detector_id: str,
        metric_name: str,
        value: float,
        unit: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Record a metric value for a detector."""
        metric = HealthMetric(
            name=metric_name,
            value=value,
            unit=unit,
            timestamp=datetime.now(UTC).isoformat(),
            detector_id=detector_id,
            metadata=metadata or {},
        )

        self._metrics[detector_id][metric_name].append(metric)
        if len(self._metrics[detector_id][metric_name]) > self.max_history:
            self._metrics[detector_id][metric_name].popleft()

        # Run health checks
        self._evaluate_health_checks(detector_id)

    def record_latency(self, detector_id: str, latency_ms: float) -> None:
        self.record_metric(detector_id, "latency_ms", latency_ms, "ms")

    def record_error(self, detector_id: str, is_error: bool) -> None:
        # Record the per-event error flag. The error_rate health check reads
        # this series and derives its rate, so every event must be recorded —
        # recording only on failure would make the series all-1.0.
        self.record_metric(detector_id, "error", 1.0 if is_error else 0.0, "count")

    def record_score(self, detector_id: str, score: float) -> None:
        self.record_metric(detector_id, "score", score, "ratio")

    def record_request(self, detector_id: str) -> None:
        self.record_metric(detector_id, "request_timestamp", time.time(), "timestamp")

    def _evaluate_health_checks(self, detector_id: str) -> None:
        self._ensure_detector_checks(detector_id)

        for check in self._health_checks[detector_id]:
            values = [m.value for m in self._metrics[detector_id].get(check.source_metric, [])]
            if not values:
                continue

            alert = check.evaluate(values, detector_id=detector_id)
            if alert:
                self._alerts.append(alert)
                if self.alert_callback:
                    self.alert_callback(alert)

    def get_report(self, detector_id: str) -> DetectorHealthReport:
        """Generate a health report for a detector."""
        if detector_id not in self._reports:
            self._reports[detector_id] = DetectorHealthReport(
                detector_id=detector_id,
                overall_state=HealthState.UNKNOWN,
                health_score=0.0,
            )

        report = self._reports[detector_id]
        report.metrics = {k: list(v) for k, v in self._metrics.get(detector_id, {}).items()}
        report.alerts = [a for a in self._alerts if a.detector_id == detector_id]
        report.last_updated = datetime.now(UTC).isoformat()
        report.overall_state, report.health_score = self._compute_overall_health(detector_id)

        return report

    def _compute_overall_health(self, detector_id: str) -> tuple[HealthState, float]:
        """Compute overall health state and score.

        Evaluates the checks for state/scoring only — it must not append to
        ``self._alerts``. ``_evaluate_health_checks`` is the single place that
        records alerts; re-firing here on every report call would duplicate
        them indefinitely.
        """
        checks = self._health_checks.get(detector_id, [])
        if not checks:
            return HealthState.UNKNOWN, 0.0

        critical_count = 0
        warning_count = 0
        total_checks = 0

        for check in checks:
            values = [m.value for m in self._metrics[detector_id].get(check.source_metric, [])]
            if not values:
                continue
            total_checks += 1
            alert = check.evaluate(values, detector_id=detector_id)
            if alert:
                if alert.severity == AlertSeverity.CRITICAL:
                    critical_count += 1
                elif alert.severity == AlertSeverity.WARNING:
                    warning_count += 1

        if total_checks == 0:
            return HealthState.UNKNOWN, 0.0

        if critical_count > 0:
            return HealthState.CRITICAL, max(0.0, 1.0 - (critical_count / total_checks) * 0.8)
        elif warning_count > 0:
            return HealthState.DEGRADED, max(0.5, 1.0 - (warning_count / total_checks) * 0.5)
        else:
            return HealthState.HEALTHY, 1.0

    def get_all_alerts(self, since: datetime | None = None) -> list[HealthAlert]:
        if since is None:
            return list(self._alerts)
        cutoff = since.isoformat()
        return [a for a in self._alerts if a.timestamp >= cutoff]

    def clear_alerts(self, detector_id: str | None = None) -> int:
        if detector_id:
            before = len(self._alerts)
            self._alerts = [a for a in self._alerts if a.detector_id != detector_id]
            return before - len(self._alerts)
        else:
            count = len(self._alerts)
            self._alerts.clear()
            return count


class HighLevelDetectorHealthMonitor:
    """High-level detector health monitor with orchestration integration."""

    def __init__(
        self,
        max_history: int = 10000,
        alert_callback: Callable[[HealthAlert], None] | None = None,
    ):
        self.monitor = DetectorHealthMonitor(max_history, alert_callback)

    def record_detector_result(
        self,
        detector_id: str,
        latency_ms: float,
        score: float | None = None,
        verdict: str | None = None,
        is_error: bool = False,
    ) -> None:
        self.monitor.record_latency(detector_id, latency_ms)
        if score is not None:
            self.monitor.record_score(detector_id, score)
        # Always record the per-event error flag: the error-rate health check
        # derives its rate from this series, and recording only on failure
        # would leave the series all-1.0 (100% error rate forever).
        self.monitor.record_error(detector_id, is_error)
        self.monitor.record_request(detector_id)

    def get_detector_health(self, detector_id: str) -> DetectorHealthReport:
        return self.monitor.get_report(detector_id)

    def get_all_health(self) -> dict[str, DetectorHealthReport]:
        all_ids = set(self.monitor._metrics.keys()) | set(self.monitor._health_checks.keys())
        return {d: self.monitor.get_report(d) for d in all_ids}

    def get_alerts(self, since: datetime | None = None) -> list[HealthAlert]:
        return self.monitor.get_all_alerts(since)

    def check_detector_health(self, detector_id: str) -> tuple[HealthState, float]:
        report = self.get_detector_health(detector_id)
        return report.overall_state, report.health_score


def create_health_monitor(
    max_history: int = 10000,
    alert_callback: Callable[[HealthAlert], None] | None = None,
) -> DetectorHealthMonitor:
    """Create a detector health monitor."""
    return DetectorHealthMonitor(max_history=max_history, alert_callback=alert_callback)


def create_detector_health_monitor(
    max_history: int = 10000,
    alert_callback: Callable[[HealthAlert], None] | None = None,
) -> HighLevelDetectorHealthMonitor:
    """Create a high-level detector health monitor."""
    return HighLevelDetectorHealthMonitor(max_history=max_history, alert_callback=alert_callback)
