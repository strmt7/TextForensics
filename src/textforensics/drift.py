from __future__ import annotations

import hashlib
import json
import math
import statistics
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .detectors import (
    Detector,
    DetectorPrediction,
    discover_detector_registry,
    execute_detector,
    text_sha256,
)

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
    return datetime.now(timezone.utc).isoformat()


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
    ) -> dict[str, Any]:
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
            registry = discover_detector_registry()
            selected_detectors: list[Detector] = list(registry.detectors.values())
        else:
            selected_detectors = list(detectors)

        if detector_ids is not None:
            wanted = set(detector_ids)
            selected_detectors = [
                detector for detector in selected_detectors if detector.detector_id in wanted
            ]

        records: list[dict[str, Any]] = []
        failures: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []

        for detector in selected_detectors:
            if _is_remote_detector(detector) and not allow_remote:
                skipped.append(
                    {
                        "detector_id": detector.detector_id,
                        "reason": "remote_not_allowed",
                    }
                )
                continue
            for sample in self.samples.values():
                if sample.text is None:
                    raise ValueError(
                        f"Sample {sample.sample_id} has no text; cannot execute detectors."
                    )
                prediction, failure = execute_detector(detector, sample.text)
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
    return getattr(detector, "execution", None) == "remote" or bool(
        getattr(detector, "remote", False)
    )
