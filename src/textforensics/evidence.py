"""Versioned validation-evidence registry and input-conditioned coverage.

This module is the heart of the TextForensics audit layer. It answers a
different question from a detector: *which validation evidence covers this
exact input regime, for this exact detector version?*

Design rules
------------
* Evidence is immutable-by-ID and carries a reproducible artifact reference.
* A missing or stale artifact is never silently upgraded to ``supported``.
* Sample-size thresholds and confidence intervals are required for
  ``supported`` states. Aggregate accuracy alone is not enough.
* Input conditions that cannot be observed (editing regime, generator,
  human population) are ``unknown`` unless declared.
* The registry is untrusted input. Loading verifies the registry hash and
  all field invariants before use.

The module has no third-party dependencies.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from .conditions import InputConditions

EVIDENCE_SCHEMA = "textforensics.validation-evidence/v1"
REGISTRY_SCHEMA = "textforensics.evidence-registry/v1"

TRUST_STATES = ("supported", "partial", "unknown", "out_of_scope")
_STATE_RANK = {"out_of_scope": 0, "unknown": 1, "partial": 2, "supported": 3}

MIN_HUMAN_SAMPLES = 100
MIN_AI_SAMPLES = 100
DEFAULT_MAX_AGE_DAYS = 365
DEFAULT_FPR_CEILING = 0.05

ALLOWED_METRICS = frozenset(
    {
        "accuracy",
        "auprc",
        "auroc",
        "brier",
        "ece",
        "fpr",
        "precision",
        "specificity",
        "tpr",
    }
)

ALLOWED_EDITING_REGIMES = frozenset(
    {
        "human_only",
        "machine_only",
        "machine_then_human_edited",
        "machine_then_machine_paraphrased",
        "mixed",
        "*",
    }
)

ALLOWED_GENERATOR_SCOPES = frozenset({"single", "multi", "representative", "unknown"})


class EvidenceError(ValueError):
    """Raised when evidence or registry data violates the public contract."""


# ---------------------------------------------------------------------------
# Primitive helpers
# ---------------------------------------------------------------------------


def _require_nonempty_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceError(f"{field_name} must be a non-empty string.")
    return value.strip()


def _require_hex(value: Any, field_name: str, *, lengths: tuple[int, ...] = (64,)) -> str:
    text = _require_nonempty_string(value, field_name)
    if len(text) not in lengths or any(char not in "0123456789abcdef" for char in text):
        expected = " or ".join(str(length) for length in lengths)
        raise EvidenceError(f"{field_name} must be {expected} lowercase hex characters.")
    return text


def _require_number(value: Any, field_name: str, *, minimum: float | None = None) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvidenceError(f"{field_name} must be a finite number.")
    number = float(value)
    if not math.isfinite(number):
        raise EvidenceError(f"{field_name} must be finite.")
    if minimum is not None and number < minimum:
        raise EvidenceError(f"{field_name} must be >= {minimum}.")
    return number


def _require_int(value: Any, field_name: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EvidenceError(f"{field_name} must be an integer.")
    if value < minimum:
        raise EvidenceError(f"{field_name} must be >= {minimum}.")
    return value


def _parse_iso8601(value: Any, field_name: str) -> datetime:
    text = _require_nonempty_string(value, field_name)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError(f"{field_name} must be an ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _coerce_now(now: datetime | str | None) -> datetime:
    if now is None:
        return _now_utc()
    if isinstance(now, str):
        return _parse_iso8601(now, "now")
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


def _safe_relative_path(value: Any, field_name: str) -> str:
    text = _require_nonempty_string(value, field_name).replace("\\", "/")
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or (len(path.parts) > 0 and ":" in path.parts[0]):
        raise EvidenceError(f"{field_name} must be a portable relative path.")
    return path.as_posix()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256_payload(payload: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


# ---------------------------------------------------------------------------
# Metrics and slices
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MetricEstimate:
    """A bounded metric with an optional confidence interval."""

    value: float
    n: int
    ci_lower: float | None = None
    ci_upper: float | None = None
    method: str | None = None

    def __post_init__(self) -> None:
        value = _require_number(self.value, "metric.value")
        if not 0.0 <= value <= 1.0:
            raise EvidenceError("metric.value must be between 0 and 1.")
        _require_int(self.n, "metric.n", minimum=1)
        if self.ci_lower is not None:
            _require_number(self.ci_lower, "metric.ci_lower")
            if not 0.0 <= self.ci_lower <= 1.0:
                raise EvidenceError("metric.ci_lower must be between 0 and 1.")
        if self.ci_upper is not None:
            _require_number(self.ci_upper, "metric.ci_upper")
            if not 0.0 <= self.ci_upper <= 1.0:
                raise EvidenceError("metric.ci_upper must be between 0 and 1.")
        if (self.ci_lower is None) != (self.ci_upper is None):
            raise EvidenceError("metric confidence interval requires both bounds.")
        if self.ci_lower is not None and self.ci_upper is not None:
            if self.ci_lower > self.ci_upper:
                raise EvidenceError("metric.ci_lower must not exceed metric.ci_upper.")
            if not self.ci_lower <= value <= self.ci_upper:
                raise EvidenceError("metric value must lie inside its confidence interval.")
        if self.method is not None and (not isinstance(self.method, str) or not self.method.strip()):
            raise EvidenceError("metric.method must be a non-empty string or null.")

    @property
    def has_ci(self) -> bool:
        return self.ci_lower is not None and self.ci_upper is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "n": self.n,
            "ci_lower": self.ci_lower,
            "ci_upper": self.ci_upper,
            "method": self.method,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> MetricEstimate:
        if not isinstance(payload, Mapping):
            raise EvidenceError("metric must be an object.")
        return cls(
            value=payload["value"],
            n=payload["n"],
            ci_lower=payload.get("ci_lower"),
            ci_upper=payload.get("ci_upper"),
            method=payload.get("method"),
        )


@dataclass(frozen=True, slots=True)
class SliceMatch:
    """The result of matching an input condition against a slice."""

    language: str
    length: str
    domain: str
    editing: str
    applicable: bool
    reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "language": self.language,
            "length": self.length,
            "domain": self.domain,
            "editing": self.editing,
            "applicable": self.applicable,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True, slots=True)
class SliceConditions:
    """The conditions under which one validation slice applies."""

    languages: tuple[str, ...]
    domains: tuple[str, ...]
    editing_regimes: tuple[str, ...]
    min_words: int | None = None
    max_words: int | None = None
    generators: tuple[str, ...] = ()
    generator_scope: str = "unknown"
    human_populations: tuple[str, ...] = ()
    notes: str | None = None

    def __post_init__(self) -> None:
        if not self.languages:
            raise EvidenceError("slice conditions require at least one language.")
        if not self.domains:
            raise EvidenceError("slice conditions require at least one domain.")
        if not self.editing_regimes:
            raise EvidenceError("slice conditions require at least one editing regime.")
        for language in self.languages:
            _require_nonempty_string(language, "slice language")
        for domain in self.domains:
            _require_nonempty_string(domain, "slice domain")
        for regime in self.editing_regimes:
            if regime not in ALLOWED_EDITING_REGIMES:
                raise EvidenceError(f"Unsupported editing regime: {regime!r}.")
        if self.min_words is not None:
            _require_int(self.min_words, "slice min_words")
        if self.max_words is not None:
            _require_int(self.max_words, "slice max_words")
        if (
            self.min_words is not None
            and self.max_words is not None
            and self.min_words > self.max_words
        ):
            raise EvidenceError("slice min_words must not exceed max_words.")
        for generator in self.generators:
            _require_nonempty_string(generator, "slice generator")
        if self.generator_scope not in ALLOWED_GENERATOR_SCOPES:
            raise EvidenceError(f"Unsupported generator_scope: {self.generator_scope!r}.")
        for population in self.human_populations:
            _require_nonempty_string(population, "slice human population")
        if self.notes is not None and (not isinstance(self.notes, str)):
            raise EvidenceError("slice notes must be a string or null.")

    def matches(self, conditions: InputConditions) -> SliceMatch:
        reasons: list[str] = []

        language = "unknown"
        effective_language = conditions.effective_language
        if effective_language == "und":
            reasons.append("input language is unknown or low confidence")
        elif "*" in self.languages or effective_language in self.languages:
            language = "match"
        else:
            language = "mismatch"
            reasons.append("input language is not in the slice languages")

        length = "match"
        if self.min_words is not None and conditions.word_count < self.min_words:
            length = "mismatch"
            reasons.append("input is shorter than the slice minimum")
        if self.max_words is not None and conditions.word_count > self.max_words:
            length = "mismatch"
            reasons.append("input is longer than the slice maximum")

        domain = "unknown"
        effective_domain = conditions.effective_domain
        if effective_domain == "unknown":
            reasons.append("input domain is unknown or low confidence")
        elif "*" in self.domains or effective_domain in self.domains:
            domain = "match"
        else:
            domain = "mismatch"
            reasons.append("input domain is not in the slice domains")

        editing = "unknown"
        effective_editing = conditions.effective_editing_regime
        if effective_editing == "unknown":
            reasons.append("input editing regime is undeclared")
        elif "*" in self.editing_regimes or effective_editing in self.editing_regimes:
            editing = "match"
        else:
            editing = "mismatch"
            reasons.append("input editing regime is not in the slice regimes")

        applicable = language != "mismatch" and length != "mismatch"
        return SliceMatch(
            language=language,
            length=length,
            domain=domain,
            editing=editing,
            applicable=applicable,
            reasons=tuple(reasons),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "languages": list(self.languages),
            "domains": list(self.domains),
            "editing_regimes": list(self.editing_regimes),
            "min_words": self.min_words,
            "max_words": self.max_words,
            "generators": list(self.generators),
            "generator_scope": self.generator_scope,
            "human_populations": list(self.human_populations),
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> SliceConditions:
        return cls(
            languages=tuple(payload["languages"]),
            domains=tuple(payload["domains"]),
            editing_regimes=tuple(payload["editing_regimes"]),
            min_words=payload.get("min_words"),
            max_words=payload.get("max_words"),
            generators=tuple(payload.get("generators", [])),
            generator_scope=str(payload.get("generator_scope", "unknown")),
            human_populations=tuple(payload.get("human_populations", [])),
            notes=payload.get("notes"),
        )


@dataclass(frozen=True, slots=True)
class ValidationSlice:
    """One benchmark slice for one detector version."""

    slice_id: str
    conditions: SliceConditions
    n_human: int
    n_ai: int
    metrics: dict[str, MetricEstimate]
    threshold: float | None = None
    calibration_id: str | None = None
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_nonempty_string(self.slice_id, "slice_id")
        _require_int(self.n_human, "n_human")
        _require_int(self.n_ai, "n_ai")
        if self.n_human + self.n_ai <= 0:
            raise EvidenceError("slice must contain at least one sample.")
        if self.threshold is not None:
            _require_number(self.threshold, "threshold")
        if self.calibration_id is not None:
            _require_nonempty_string(self.calibration_id, "calibration_id")
        if not isinstance(self.metrics, Mapping):
            raise EvidenceError("metrics must be an object.")
        for name, metric in self.metrics.items():
            if name not in ALLOWED_METRICS:
                raise EvidenceError(f"Unsupported metric: {name!r}.")
            if not isinstance(metric, MetricEstimate):
                raise EvidenceError(f"metric {name!r} must be a MetricEstimate.")
        if "fpr" in self.metrics and self.threshold is None:
            raise EvidenceError("fpr requires an explicit threshold.")
        if "tpr" in self.metrics and self.threshold is None:
            raise EvidenceError("tpr requires an explicit threshold.")
        if "fpr" in self.metrics and self.metrics["fpr"].n > self.n_human:
            raise EvidenceError("fpr sample count cannot exceed n_human.")
        if "tpr" in self.metrics and self.metrics["tpr"].n > self.n_ai:
            raise EvidenceError("tpr sample count cannot exceed n_ai.")
        for limitation in self.limitations:
            _require_nonempty_string(limitation, "slice limitation")

    @property
    def total_samples(self) -> int:
        return self.n_human + self.n_ai

    @property
    def adequate_samples(self) -> bool:
        return self.n_human >= MIN_HUMAN_SAMPLES and self.n_ai >= MIN_AI_SAMPLES

    def metric(self, name: str) -> MetricEstimate | None:
        return self.metrics.get(name)

    def to_dict(self) -> dict[str, Any]:
        return {
            "slice_id": self.slice_id,
            "conditions": self.conditions.to_dict(),
            "n_human": self.n_human,
            "n_ai": self.n_ai,
            "metrics": {name: metric.to_dict() for name, metric in sorted(self.metrics.items())},
            "threshold": self.threshold,
            "calibration_id": self.calibration_id,
            "limitations": list(self.limitations),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ValidationSlice:
        return cls(
            slice_id=str(payload["slice_id"]),
            conditions=SliceConditions.from_dict(payload["conditions"]),
            n_human=payload["n_human"],
            n_ai=payload["n_ai"],
            metrics={
                str(name): MetricEstimate.from_dict(metric)
                for name, metric in payload.get("metrics", {}).items()
            },
            threshold=payload.get("threshold"),
            calibration_id=payload.get("calibration_id"),
            limitations=tuple(payload.get("limitations", [])),
        )


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BenchmarkProvenance:
    """Provenance for the benchmark/dataset used by an evidence record."""

    name: str
    version: str
    fingerprint_sha256: str
    split: str
    license: str
    artifact_path: str
    artifact_sha256: str
    citation: str = ""
    contamination_controls: tuple[str, ...] = ()
    notes: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty_string(self.name, "benchmark.name")
        _require_nonempty_string(self.version, "benchmark.version")
        _require_hex(self.fingerprint_sha256, "benchmark.fingerprint_sha256")
        _require_nonempty_string(self.split, "benchmark.split")
        _require_nonempty_string(self.license, "benchmark.license")
        _safe_relative_path(self.artifact_path, "benchmark.artifact_path")
        _require_hex(self.artifact_sha256, "benchmark.artifact_sha256")
        if not isinstance(self.citation, str):
            raise EvidenceError("benchmark.citation must be a string.")
        if not self.contamination_controls:
            raise EvidenceError("benchmark.contamination_controls must not be empty.")
        for control in self.contamination_controls:
            _require_nonempty_string(control, "benchmark.contamination_control")
        if self.notes is not None and not isinstance(self.notes, str):
            raise EvidenceError("benchmark.notes must be a string or null.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "fingerprint_sha256": self.fingerprint_sha256,
            "split": self.split,
            "license": self.license,
            "citation": self.citation,
            "artifact_path": self.artifact_path,
            "artifact_sha256": self.artifact_sha256,
            "contamination_controls": list(self.contamination_controls),
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> BenchmarkProvenance:
        return cls(
            name=str(payload["name"]),
            version=str(payload["version"]),
            fingerprint_sha256=str(payload["fingerprint_sha256"]),
            split=str(payload["split"]),
            license=str(payload["license"]),
            citation=str(payload.get("citation", "")),
            artifact_path=str(payload["artifact_path"]),
            artifact_sha256=str(payload["artifact_sha256"]),
            contamination_controls=tuple(payload.get("contamination_controls", [])),
            notes=payload.get("notes"),
        )


@dataclass(frozen=True, slots=True)
class RunProvenance:
    """Reproducible provenance for the run that produced an evidence record."""

    git_sha: str
    command: str
    environment_sha256: str
    executed_at_utc: str
    run_artifact_path: str
    run_artifact_sha256: str
    hardware: str | None = None
    runtime_seconds: float | None = None

    def __post_init__(self) -> None:
        _require_hex(self.git_sha, "provenance.git_sha", lengths=tuple(range(7, 65)))
        _require_nonempty_string(self.command, "provenance.command")
        _require_hex(self.environment_sha256, "provenance.environment_sha256")
        _parse_iso8601(self.executed_at_utc, "provenance.executed_at_utc")
        _safe_relative_path(self.run_artifact_path, "provenance.run_artifact_path")
        _require_hex(self.run_artifact_sha256, "provenance.run_artifact_sha256")
        if self.hardware is not None and not isinstance(self.hardware, str):
            raise EvidenceError("provenance.hardware must be a string or null.")
        if self.runtime_seconds is not None:
            _require_number(self.runtime_seconds, "provenance.runtime_seconds", minimum=0.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "git_sha": self.git_sha,
            "command": self.command,
            "environment_sha256": self.environment_sha256,
            "executed_at_utc": self.executed_at_utc,
            "run_artifact_path": self.run_artifact_path,
            "run_artifact_sha256": self.run_artifact_sha256,
            "hardware": self.hardware,
            "runtime_seconds": self.runtime_seconds,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> RunProvenance:
        return cls(
            git_sha=str(payload["git_sha"]),
            command=str(payload["command"]),
            environment_sha256=str(payload["environment_sha256"]),
            executed_at_utc=str(payload["executed_at_utc"]),
            run_artifact_path=str(payload["run_artifact_path"]),
            run_artifact_sha256=str(payload["run_artifact_sha256"]),
            hardware=payload.get("hardware"),
            runtime_seconds=payload.get("runtime_seconds"),
        )


# ---------------------------------------------------------------------------
# Evidence records
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """A versioned validation evidence record for one detector version."""

    evidence_id: str
    detector_id: str
    detector_version: str
    detector_family: str
    evaluated_at_utc: str
    benchmark: BenchmarkProvenance
    slices: tuple[ValidationSlice, ...]
    provenance: RunProvenance
    calibration_ids: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    status: str = "active"
    supersedes: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty_string(self.evidence_id, "evidence_id")
        _require_nonempty_string(self.detector_id, "detector_id")
        _require_nonempty_string(self.detector_version, "detector_version")
        _require_nonempty_string(self.detector_family, "detector_family")
        _parse_iso8601(self.evaluated_at_utc, "evaluated_at_utc")
        if not self.slices:
            raise EvidenceError("evidence record requires at least one slice.")
        slice_ids = [item.slice_id for item in self.slices]
        if len(set(slice_ids)) != len(slice_ids):
            raise EvidenceError("slice_id values must be unique within a record.")
        for calibration_id in self.calibration_ids:
            _require_nonempty_string(calibration_id, "calibration_id")
        for limitation in self.limitations:
            _require_nonempty_string(limitation, "limitation")
        if self.status not in {"active", "retracted"}:
            raise EvidenceError("status must be 'active' or 'retracted'.")
        if self.supersedes is not None:
            _require_nonempty_string(self.supersedes, "supersedes")

    @property
    def evaluated_at(self) -> datetime:
        return _parse_iso8601(self.evaluated_at_utc, "evaluated_at_utc")

    def age_days(self, now: datetime | str | None = None) -> float:
        current = _coerce_now(now)
        return max(0.0, (current - self.evaluated_at).total_seconds() / 86400.0)

    def is_fresh(self, now: datetime | str | None = None, *, max_age_days: int) -> bool:
        return self.age_days(now) <= max_age_days

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": EVIDENCE_SCHEMA,
            "evidence_id": self.evidence_id,
            "detector_id": self.detector_id,
            "detector_version": self.detector_version,
            "detector_family": self.detector_family,
            "evaluated_at_utc": self.evaluated_at_utc,
            "benchmark": self.benchmark.to_dict(),
            "slices": [item.to_dict() for item in self.slices],
            "calibration_ids": list(self.calibration_ids),
            "provenance": self.provenance.to_dict(),
            "limitations": list(self.limitations),
            "status": self.status,
            "supersedes": self.supersedes,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> EvidenceRecord:
        if payload.get("schema") != EVIDENCE_SCHEMA:
            raise EvidenceError("Unsupported validation-evidence schema.")
        return cls(
            evidence_id=str(payload["evidence_id"]),
            detector_id=str(payload["detector_id"]),
            detector_version=str(payload["detector_version"]),
            detector_family=str(payload["detector_family"]),
            evaluated_at_utc=str(payload["evaluated_at_utc"]),
            benchmark=BenchmarkProvenance.from_dict(payload["benchmark"]),
            slices=tuple(ValidationSlice.from_dict(item) for item in payload["slices"]),
            calibration_ids=tuple(payload.get("calibration_ids", [])),
            provenance=RunProvenance.from_dict(payload["provenance"]),
            limitations=tuple(payload.get("limitations", [])),
            status=str(payload.get("status", "active")),
            supersedes=payload.get("supersedes"),
        )


# ---------------------------------------------------------------------------
# Coverage models
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DimensionCoverage:
    """Coverage of one Trust Map dimension for one detector."""

    dimension: str
    state: str
    reason: str
    evidence_refs: tuple[str, ...] = ()
    observed: dict[str, Any] = field(default_factory=dict)
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.state not in TRUST_STATES:
            raise EvidenceError(f"Invalid coverage state: {self.state!r}.")
        _require_nonempty_string(self.dimension, "dimension")
        _require_nonempty_string(self.reason, "reason")

    def to_dict(self) -> dict[str, Any]:
        return {
            "dimension": self.dimension,
            "state": self.state,
            "reason": self.reason,
            "evidence_refs": list(self.evidence_refs),
            "observed": self.observed,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True)
class DetectorCoverage:
    """All dimension coverage for one detector observation."""

    detector_id: str
    detector_version: str
    detector_family: str
    dimensions: dict[str, DimensionCoverage]
    record_ids: tuple[str, ...] = ()
    matched_slice_ids: tuple[str, ...] = ()
    registry_id: str | None = None
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_nonempty_string(self.detector_id, "detector_id")
        _require_nonempty_string(self.detector_version, "detector_version")
        _require_nonempty_string(self.detector_family, "detector_family")
        missing = {
            "language",
            "text_length",
            "domain_genre",
            "editing_revision",
            "generator_scope",
            "human_population",
            "human_false_positive_evidence",
            "temporal_version_stability",
        } - set(self.dimensions)
        if missing:
            raise EvidenceError(f"Missing coverage dimensions: {', '.join(sorted(missing))}.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector_id": self.detector_id,
            "detector_version": self.detector_version,
            "detector_family": self.detector_family,
            "dimensions": {
                name: dimension.to_dict()
                for name, dimension in sorted(self.dimensions.items())
            },
            "record_ids": list(self.record_ids),
            "matched_slice_ids": list(self.matched_slice_ids),
            "registry_id": self.registry_id,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True)
class RegistryVerification:
    """Result of verifying a registry against files on disk."""

    verified: bool
    errors: tuple[str, ...]
    records: dict[str, dict[str, Any]]
    checked_at_utc: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "verified": self.verified,
            "errors": list(self.errors),
            "records": self.records,
            "checked_at_utc": self.checked_at_utc,
        }


# ---------------------------------------------------------------------------
# Coverage engine
# ---------------------------------------------------------------------------


def _metric_candidate(
    metric: MetricEstimate | None,
    *,
    required: bool = True,
) -> str:
    if metric is None:
        return "unknown" if required else "partial"
    if metric.has_ci:
        return "supported"
    return "partial"


def _sample_state(slice_: ValidationSlice) -> str:
    return "supported" if slice_.adequate_samples else "partial"


def _freshness_state(record: EvidenceRecord, now: datetime, max_age_days: int) -> str:
    age = record.age_days(now)
    if age <= max_age_days:
        return "supported"
    if age <= max_age_days * 2:
        return "partial"
    return "unknown"


def _combine_states(states: Iterable[str]) -> str:
    values = list(states)
    if not values:
        return "unknown"
    return max(values, key=lambda state: _STATE_RANK.get(state, -1))


def _base_dimension(dimension: str, reason: str) -> DimensionCoverage:
    return DimensionCoverage(dimension=dimension, state="unknown", reason=reason)


def _metadata_language(
    supported_languages: Iterable[str],
    conditions: InputConditions,
) -> DimensionCoverage:
    languages = tuple(sorted({item for item in supported_languages if item}))
    effective = conditions.effective_language
    if effective == "und":
        return DimensionCoverage(
            dimension="language",
            state="unknown",
            reason="Input language is unknown or low confidence; no language slice can be matched.",
            observed={"supported_languages": list(languages)},
            limitations=("Declared language metadata is not validation evidence.",),
        )
    if not languages:
        return DimensionCoverage(
            dimension="language",
            state="unknown",
            reason="Detector did not declare supported languages and no evidence registry is available.",
            observed={"input_language": effective},
        )
    if "*" in languages or effective in languages:
        return DimensionCoverage(
            dimension="language",
            state="partial",
            reason="Detector metadata lists the input language, but no validation slice is registered.",
            observed={
                "input_language": effective,
                "supported_languages": list(languages),
                "metadata_only": True,
            },
            limitations=("Capability metadata is not held-out validation evidence.",),
        )
    return DimensionCoverage(
        dimension="language",
        state="out_of_scope",
        reason="Detector metadata does not list the input language.",
        observed={
            "input_language": effective,
            "supported_languages": list(languages),
        },
        limitations=("Language detection itself is heuristic; declare the language when it matters.",),
    )


def _metadata_length(
    min_words: int | None,
    max_words: int | None,
    conditions: InputConditions,
) -> DimensionCoverage:
    if min_words is None and max_words is None:
        return DimensionCoverage(
            dimension="text_length",
            state="unknown",
            reason="Detector did not declare a supported text length and no evidence registry is available.",
            observed={"word_count": conditions.word_count},
        )
    if min_words is not None and conditions.word_count < min_words:
        return DimensionCoverage(
            dimension="text_length",
            state="out_of_scope",
            reason="Input is below the detector's declared minimum word count.",
            observed={
                "word_count": conditions.word_count,
                "min_words": min_words,
                "max_words": max_words,
            },
            limitations=("Declared minimum length is capability metadata, not held-out performance.",),
        )
    if max_words is not None and conditions.word_count > max_words:
        return DimensionCoverage(
            dimension="text_length",
            state="out_of_scope",
            reason="Input is above the detector's declared maximum word count.",
            observed={
                "word_count": conditions.word_count,
                "min_words": min_words,
                "max_words": max_words,
            },
        )
    return DimensionCoverage(
        dimension="text_length",
        state="partial",
        reason="Detector metadata admits this length, but no validation slice is registered.",
        observed={
            "word_count": conditions.word_count,
            "min_words": min_words,
            "max_words": max_words,
            "metadata_only": True,
        },
        limitations=("Capability metadata is not held-out validation evidence.",),
    )


class _Candidate:
    __slots__ = ("state", "reason", "refs", "observed", "limitations", "rank")

    def __init__(
        self,
        *,
        state: str,
        reason: str,
        refs: Iterable[str] = (),
        observed: Mapping[str, Any] | None = None,
        limitations: Iterable[str] = (),
    ) -> None:
        self.state = state
        self.reason = reason
        self.refs = tuple(dict.fromkeys(refs))
        self.observed = dict(observed or {})
        self.limitations = tuple(dict.fromkeys(limitations))
        self.rank = _STATE_RANK[state]


def _best_candidate(candidates: list[_Candidate], dimension: str) -> DimensionCoverage:
    if not candidates:
        return _base_dimension(dimension, "No registered validation evidence covers this input.")
    candidates.sort(key=lambda item: (-item.rank, item.reason))
    best = candidates[0]
    refs: list[str] = []
    limitations: list[str] = []
    for candidate in candidates:
        if candidate.rank == best.rank:
            refs.extend(candidate.refs)
        limitations.extend(candidate.limitations)
    observed = dict(best.observed)
    if len(candidates) > 1:
        observed["candidate_count"] = len(candidates)
        observed["states"] = sorted({item.state for item in candidates})
    return DimensionCoverage(
        dimension=dimension,
        state=best.state,
        reason=best.reason,
        evidence_refs=tuple(dict.fromkeys(refs)),
        observed=observed,
        limitations=tuple(dict.fromkeys(limitations)),
    )


def _record_candidate(
    *,
    record: EvidenceRecord,
    slice_: ValidationSlice,
    match: SliceMatch,
    now: datetime,
    max_age_days: int,
    dimension: str,
    fpr_ceiling: float,
) -> _Candidate | None:
    fresh = _freshness_state(record, now, max_age_days)
    sample = _sample_state(slice_)
    ref = record.evidence_id
    base_observed = {
        "evidence_id": record.evidence_id,
        "slice_id": slice_.slice_id,
        "evaluated_at_utc": record.evaluated_at_utc,
        "age_days": round(record.age_days(now), 2),
        "freshness": fresh,
        "sample_state": sample,
        "n_human": slice_.n_human,
        "n_ai": slice_.n_ai,
        "match": match.to_dict(),
        "benchmark": record.benchmark.name,
        "benchmark_split": record.benchmark.split,
    }
    base_limitations = tuple(record.limitations) + tuple(slice_.limitations)

    if dimension == "language":
        if match.language == "unknown":
            return _Candidate(
                state="unknown",
                reason="Input language is unknown; a language match cannot be established.",
                refs=(ref,),
                observed=base_observed,
                limitations=base_limitations,
            )
        if match.language == "mismatch":
            return None
        states = [match.language == "match", fresh, sample]
        state = "supported" if all(item == "supported" or item is True for item in states) else "partial"
        if fresh == "unknown":
            state = "unknown"
        return _Candidate(
            state=state,
            reason=(
                "A matching language slice has adequate held-out samples and is fresh."
                if state == "supported"
                else "Language evidence exists but is partial or stale."
            ),
            refs=(ref,),
            observed=base_observed,
            limitations=base_limitations,
        )

    if dimension == "text_length":
        if match.length == "mismatch":
            return None
        state = "supported" if fresh == "supported" and sample == "supported" else "partial"
        if fresh == "unknown":
            state = "unknown"
        return _Candidate(
            state=state,
            reason=(
                "A matching length slice has adequate held-out samples and is fresh."
                if state == "supported"
                else "Length evidence exists but is partial or stale."
            ),
            refs=(ref,),
            observed=base_observed,
            limitations=base_limitations,
        )

    if dimension == "domain_genre":
        if match.domain == "unknown":
            return _Candidate(
                state="unknown",
                reason="Input domain is unknown or low confidence; a domain match cannot be established.",
                refs=(ref,),
                observed=base_observed,
                limitations=base_limitations,
            )
        if match.domain == "mismatch":
            return _Candidate(
                state="unknown",
                reason="No registered slice covers the input domain.",
                refs=(ref,),
                observed=base_observed,
                limitations=base_limitations,
            )
        state = "supported" if fresh == "supported" and sample == "supported" else "partial"
        if fresh == "unknown":
            state = "unknown"
        return _Candidate(
            state=state,
            reason=(
                "A matching domain slice has adequate held-out samples and is fresh."
                if state == "supported"
                else "Domain evidence exists but is partial or stale."
            ),
            refs=(ref,),
            observed=base_observed,
            limitations=base_limitations,
        )

    if dimension == "editing_revision":
        if match.editing == "unknown":
            return _Candidate(
                state="unknown",
                reason="Editing regime is undeclared; evidence cannot be matched to it.",
                refs=(ref,),
                observed=base_observed,
                limitations=base_limitations
                + ("Declare the editing regime to evaluate this dimension.",),
            )
        if match.editing == "mismatch":
            return _Candidate(
                state="unknown",
                reason="No registered slice covers the declared editing regime.",
                refs=(ref,),
                observed=base_observed,
                limitations=base_limitations,
            )
        state = "supported" if fresh == "supported" and sample == "supported" else "partial"
        if fresh == "unknown":
            state = "unknown"
        return _Candidate(
            state=state,
            reason=(
                "A matching editing-regime slice has adequate held-out samples and is fresh."
                if state == "supported"
                else "Editing-regime evidence exists but is partial or stale."
            ),
            refs=(ref,),
            observed=base_observed,
            limitations=base_limitations,
        )

    if dimension == "generator_scope":
        if match.language == "mismatch" or match.length == "mismatch":
            return None
        if match.domain == "mismatch":
            return None
        generators = slice_.conditions.generators
        scope = slice_.conditions.generator_scope
        if scope == "representative" or (scope == "multi" and len(generators) >= 3):
            state = "supported" if fresh == "supported" and sample == "supported" else "partial"
            reason = "Evidence covers multiple generators."
        elif generators:
            state = "partial"
            reason = "Evidence covers a limited generator set; scope is not representative."
        else:
            state = "unknown"
            reason = "Evidence does not declare generator scope."
        if fresh == "unknown" and state != "unknown":
            state = "unknown"
        return _Candidate(
            state=state,
            reason=reason,
            refs=(ref,),
            observed={**base_observed, "generators": list(generators), "generator_scope": scope},
            limitations=base_limitations,
        )

    if dimension == "human_population":
        if match.language == "mismatch" or match.length == "mismatch":
            return None
        if match.domain == "mismatch":
            return None
        populations = slice_.conditions.human_populations
        if len(set(populations)) >= 2 or "representative" in populations:
            state = "supported" if fresh == "supported" and sample == "supported" else "partial"
            reason = "Evidence covers multiple human populations."
        elif populations:
            state = "partial"
            reason = "Evidence covers only one human population."
        else:
            state = "unknown"
            reason = "Evidence does not declare human-population coverage."
        if fresh == "unknown" and state != "unknown":
            state = "unknown"
        return _Candidate(
            state=state,
            reason=reason,
            refs=(ref,),
            observed={**base_observed, "human_populations": list(populations)},
            limitations=base_limitations,
        )

    if dimension == "human_false_positive_evidence":
        if match.language == "mismatch" or match.length == "mismatch":
            return None
        if match.domain == "unknown":
            return _Candidate(
                state="unknown",
                reason="Input domain is unknown; human false-positive evidence cannot be matched.",
                refs=(ref,),
                observed=base_observed,
                limitations=base_limitations,
            )
        if match.domain == "mismatch":
            return None
        fpr = slice_.metric("fpr")
        if fpr is None:
            return _Candidate(
                state="unknown",
                reason="Matching slice does not report a human false-positive rate.",
                refs=(ref,),
                observed=base_observed,
                limitations=base_limitations,
            )
        enough_humans = slice_.n_human >= MIN_HUMAN_SAMPLES
        acceptable = enough_humans and fpr.has_ci and fpr.ci_upper is not None and fpr.ci_upper <= fpr_ceiling
        if fresh == "unknown":
            state = "unknown"
        elif acceptable and fresh == "supported":
            state = "supported"
        else:
            state = "partial"
        return _Candidate(
            state=state,
            reason=(
                f"Human FPR {fpr.value:.3f} with 95% CI upper {fpr.ci_upper:.3f} "
                f"is at or below the {fpr_ceiling:.2f} ceiling."
                if state == "supported"
                else "Human false-positive evidence is present but is insufficient, stale, or above the ceiling."
            ),
            refs=(ref,),
            observed={
                **base_observed,
                "fpr": fpr.to_dict(),
                "fpr_ceiling": fpr_ceiling,
                "enough_humans": enough_humans,
            },
            limitations=base_limitations,
        )

    if dimension == "temporal_version_stability":
        if fresh == "supported":
            return _Candidate(
                state="partial",
                reason="Current evidence is fresh, but no longitudinal drift snapshots are registered.",
                refs=(ref,),
                observed=base_observed,
                limitations=base_limitations
                + ("Temporal stability requires repeated snapshots over time.",),
            )
        return _Candidate(
            state="unknown",
            reason="Evidence is stale and no longitudinal drift snapshots are registered.",
            refs=(ref,),
            observed=base_observed,
            limitations=base_limitations,
        )

    raise EvidenceError(f"Unknown coverage dimension: {dimension!r}.")


def assess_detector_coverage(
    *,
    detector_id: str,
    detector_version: str,
    detector_family: str,
    supported_languages: Iterable[str],
    min_words: int | None,
    max_words: int | None,
    conditions: InputConditions,
    registry: EvidenceRegistry | None = None,
    now: datetime | str | None = None,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    fpr_ceiling: float = DEFAULT_FPR_CEILING,
) -> DetectorCoverage:
    """Assess one detector's evidence coverage for an input condition set."""
    current = _coerce_now(now)
    if max_age_days < 1:
        raise ValueError("max_age_days must be positive.")
    if not 0.0 < fpr_ceiling <= 1.0:
        raise ValueError("fpr_ceiling must be in (0, 1].")

    dimensions: dict[str, DimensionCoverage] = {}
    records = registry.records_for(detector_id, detector_version) if registry else []
    record_ids = tuple(record.evidence_id for record in records)
    matched_slice_ids: list[str] = []

    if not records:
        dimensions["language"] = _metadata_language(supported_languages, conditions)
        dimensions["text_length"] = _metadata_length(min_words, max_words, conditions)
        for name, reason in (
            ("domain_genre", "No validation evidence covers this domain."),
            ("editing_revision", "No validation evidence covers this editing regime."),
            ("generator_scope", "No validation evidence declares generator scope."),
            ("human_population", "No validation evidence declares human-population coverage."),
            ("human_false_positive_evidence", "No held-out human false-positive evidence is registered."),
            ("temporal_version_stability", "No longitudinal drift evidence is registered."),
        ):
            dimensions[name] = _base_dimension(name, reason)
    else:
        all_candidates: dict[str, list[_Candidate]] = {
            name: []
            for name in (
                "language",
                "text_length",
                "domain_genre",
                "editing_revision",
                "generator_scope",
                "human_population",
                "human_false_positive_evidence",
                "temporal_version_stability",
            )
        }
        for record in records:
            if record.status != "active":
                continue
            for slice_ in record.slices:
                match = slice_.conditions.matches(conditions)
                if not match.applicable:
                    continue
                matched_slice_ids.append(slice_.slice_id)
                for dimension in all_candidates:
                    candidate = _record_candidate(
                        record=record,
                        slice_=slice_,
                        match=match,
                        now=current,
                        max_age_days=max_age_days,
                        dimension=dimension,
                        fpr_ceiling=fpr_ceiling,
                    )
                    if candidate is not None:
                        all_candidates[dimension].append(candidate)

        for dimension, candidates in all_candidates.items():
            dimensions[dimension] = _best_candidate(candidates, dimension)

        # Metadata can only downgrade, never upgrade, an evidence-backed state.
        metadata_language = _metadata_language(supported_languages, conditions)
        if metadata_language.state == "out_of_scope":
            dimensions["language"] = metadata_language
        metadata_length = _metadata_length(min_words, max_words, conditions)
        if metadata_length.state == "out_of_scope":
            dimensions["text_length"] = metadata_length

    limitations: list[str] = []
    if not records:
        limitations.append("No registered validation evidence for this detector version.")
    if any(item.state in {"unknown", "partial", "out_of_scope"} for item in dimensions.values()):
        limitations.append("At least one Trust Map dimension is not fully supported.")
    limitations.append("Coverage states describe evidence applicability, not authorship probability.")

    return DetectorCoverage(
        detector_id=detector_id,
        detector_version=detector_version,
        detector_family=detector_family,
        dimensions=dimensions,
        record_ids=record_ids,
        matched_slice_ids=tuple(sorted(set(matched_slice_ids))),
        registry_id=registry.registry_id if registry else None,
        limitations=tuple(limitations),
    )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class EvidenceRegistry:
    """A versioned, hash-identified collection of validation evidence records."""

    def __init__(
        self,
        records: Iterable[EvidenceRecord] = (),
        *,
        created_at_utc: str | None = None,
    ) -> None:
        self._records: tuple[EvidenceRecord, ...] = tuple(records)
        ids = [record.evidence_id for record in self._records]
        if len(set(ids)) != len(ids):
            raise EvidenceError("evidence_id values must be unique within a registry.")
        self._created_at_utc = created_at_utc or _now_utc().isoformat()
        _parse_iso8601(self._created_at_utc, "created_at_utc")
        self._registry_id = self._compute_registry_id()

    def _compute_registry_id(self) -> str:
        payload = {
            "schema": REGISTRY_SCHEMA,
            "records": [record.to_dict() for record in self._ordered_records()],
        }
        return _sha256_payload(payload)

    def _ordered_records(self) -> tuple[EvidenceRecord, ...]:
        return tuple(sorted(self._records, key=lambda record: record.evidence_id))

    @property
    def registry_id(self) -> str:
        return self._registry_id

    @property
    def created_at_utc(self) -> str:
        return self._created_at_utc

    @property
    def records(self) -> tuple[EvidenceRecord, ...]:
        return self._ordered_records()

    def records_for(
        self,
        detector_id: str,
        detector_version: str | None = None,
    ) -> tuple[EvidenceRecord, ...]:
        _require_nonempty_string(detector_id, "detector_id")
        selected = [record for record in self._records if record.detector_id == detector_id]
        if detector_version is not None:
            selected = [
                record
                for record in selected
                if record.detector_version == detector_version or record.detector_version == "*"
            ]
        return tuple(sorted(selected, key=lambda record: record.evidence_id))

    def detector_ids(self) -> tuple[str, ...]:
        return tuple(sorted({record.detector_id for record in self._records}))

    def record(self, evidence_id: str) -> EvidenceRecord | None:
        for record in self._records:
            if record.evidence_id == evidence_id:
                return record
        return None

    def summary(self) -> dict[str, Any]:
        detectors = self.detector_ids()
        active = [record for record in self._records if record.status == "active"]
        dates = sorted(record.evaluated_at_utc for record in active)
        return {
            "schema": REGISTRY_SCHEMA,
            "registry_id": self._registry_id,
            "created_at_utc": self._created_at_utc,
            "record_count": len(self._records),
            "active_record_count": len(active),
            "detector_ids": list(detectors),
            "detector_count": len(detectors),
            "slice_count": sum(len(record.slices) for record in self._records),
            "earliest_evaluation": dates[0] if dates else None,
            "latest_evaluation": dates[-1] if dates else None,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": REGISTRY_SCHEMA,
            "registry_id": self._registry_id,
            "created_at_utc": self._created_at_utc,
            "records": [record.to_dict() for record in self._ordered_records()],
        }

    @classmethod
    def from_dict(
        cls,
        payload: Mapping[str, Any],
        *,
        verify_id: bool = True,
    ) -> EvidenceRegistry:
        if payload.get("schema") != REGISTRY_SCHEMA:
            raise EvidenceError("Unsupported evidence-registry schema.")
        records = [
            EvidenceRecord.from_dict(item)
            for item in payload.get("records", [])  # type: ignore[union-attr]
        ]
        registry = cls(records, created_at_utc=payload.get("created_at_utc"))
        supplied_id = payload.get("registry_id")
        if verify_id and supplied_id is not None and supplied_id != registry.registry_id:
            raise EvidenceError("Evidence registry hash does not match its contents.")
        return registry

    def save(self, path: str | Path) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        rendered = json.dumps(self.to_dict(), indent=2, ensure_ascii=False, allow_nan=False) + "\n"
        temp_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=target.parent,
                prefix=f".{target.name}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temp_path = handle.name
                handle.write(rendered)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, target)
            temp_path = None
        finally:
            if temp_path is not None:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(temp_path)

    @classmethod
    def load(cls, path: str | Path, *, verify_id: bool = True) -> EvidenceRegistry:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise EvidenceError("Evidence registry must be a JSON object.")
        return cls.from_dict(payload, verify_id=verify_id)

    def validate(self) -> list[str]:
        """Return structural validation issues (empty when valid)."""
        issues: list[str] = []
        seen: set[str] = set()
        for record in self._records:
            if record.evidence_id in seen:
                issues.append(f"duplicate evidence_id: {record.evidence_id}")
            seen.add(record.evidence_id)
            if record.supersedes is not None and self.record(record.supersedes) is None:
                issues.append(
                    f"{record.evidence_id} supersedes missing record {record.supersedes}"
                )
            for calibration_id in record.calibration_ids:
                if not calibration_id.strip():
                    issues.append(f"{record.evidence_id} has an empty calibration_id")
        return issues

    def verify_artifacts(
        self,
        root: str | Path,
        *,
        now: datetime | str | None = None,
    ) -> RegistryVerification:
        """Verify every referenced artifact against ``root``."""
        base = Path(root).resolve()
        current = _coerce_now(now).isoformat()
        errors: list[str] = []
        rows: dict[str, dict[str, Any]] = {}

        for record in self._records:
            record_errors: list[str] = []
            checks: dict[str, Any] = {}
            for label, path_value, hash_value in (
                (
                    "benchmark_artifact",
                    record.benchmark.artifact_path,
                    record.benchmark.artifact_sha256,
                ),
                (
                    "run_artifact",
                    record.provenance.run_artifact_path,
                    record.provenance.run_artifact_sha256,
                ),
            ):
                candidate = (base / path_value).resolve()
                try:
                    candidate.relative_to(base)
                except ValueError:
                    record_errors.append(f"{label} escapes the registry root")
                    checks[label] = {"path": path_value, "ok": False, "reason": "escapes_root"}
                    continue
                if not candidate.is_file():
                    record_errors.append(f"{label} is missing: {path_value}")
                    checks[label] = {"path": path_value, "ok": False, "reason": "missing"}
                    continue
                actual = sha256_file(candidate)
                ok = actual == hash_value
                checks[label] = {
                    "path": path_value,
                    "ok": ok,
                    "expected_sha256": hash_value,
                    "actual_sha256": actual,
                }
                if not ok:
                    record_errors.append(f"{label} hash mismatch: {path_value}")
            rows[record.evidence_id] = {
                "ok": not record_errors,
                "errors": record_errors,
                "checks": checks,
            }
            errors.extend(f"{record.evidence_id}: {message}" for message in record_errors)

        return RegistryVerification(
            verified=not errors,
            errors=tuple(errors),
            records=rows,
            checked_at_utc=current,
        )


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------


def load_registry(path: str | Path, *, verify_id: bool = True) -> EvidenceRegistry:
    return EvidenceRegistry.load(path, verify_id=verify_id)


def empty_registry() -> EvidenceRegistry:
    return EvidenceRegistry((), created_at_utc="1970-01-01T00:00:00+00:00")


def coverage_for_predictions(
    predictions: Iterable[Any],
    conditions: InputConditions,
    *,
    registry: EvidenceRegistry | None = None,
    now: datetime | str | None = None,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    fpr_ceiling: float = DEFAULT_FPR_CEILING,
) -> tuple[DetectorCoverage, ...]:
    """Assess coverage for detector predictions or protocol-like objects."""
    rows: list[DetectorCoverage] = []
    for prediction in predictions:
        supported_length = getattr(prediction, "supported_length", None) or {}
        min_words = getattr(prediction, "min_words", None)
        max_words = getattr(prediction, "max_words", None)
        if isinstance(supported_length, Mapping):
            min_words = supported_length.get("min_words", min_words)
            max_words = supported_length.get("max_words", max_words)
        rows.append(
            assess_detector_coverage(
                detector_id=str(prediction.detector_id),
                detector_version=str(prediction.detector_version),
                detector_family=str(prediction.detector_family),
                supported_languages=getattr(prediction, "supported_languages", ()),
                min_words=min_words,
                max_words=max_words,
                conditions=conditions,
                registry=registry,
                now=now,
                max_age_days=max_age_days,
                fpr_ceiling=fpr_ceiling,
            )
        )
    return tuple(rows)


def aggregate_coverage_states(rows: Iterable[DetectorCoverage]) -> dict[str, str]:
    """Aggregate per-detector dimension states into one state per dimension."""
    collected: dict[str, list[str]] = {}
    for row in rows:
        for name, dimension in row.dimensions.items():
            collected.setdefault(name, []).append(dimension.state)
    aggregated: dict[str, str] = {}
    for name, states in collected.items():
        if not states:
            aggregated[name] = "unknown"
            continue
        if all(state == "supported" for state in states):
            aggregated[name] = "supported"
        elif all(state == "out_of_scope" for state in states):
            aggregated[name] = "out_of_scope"
        elif all(state == "unknown" for state in states):
            aggregated[name] = "unknown"
        elif any(state == "supported" for state in states) or any(state in {"supported", "partial"} for state in states):
            aggregated[name] = "partial"
        else:
            aggregated[name] = "unknown"
    return aggregated


def age_days_between(earlier: str, later: str | None = None) -> float:
    """Return the age in days between two ISO timestamps."""
    start = _parse_iso8601(earlier, "earlier")
    end = _coerce_now(later)
    return max(0.0, (end - start).total_seconds() / 86400.0)


def fresh_until(evaluated_at_utc: str, *, max_age_days: int = DEFAULT_MAX_AGE_DAYS) -> str:
    """Return the ISO timestamp at which evidence becomes stale."""
    evaluated = _parse_iso8601(evaluated_at_utc, "evaluated_at_utc")
    return (evaluated + timedelta(days=max_age_days)).isoformat()


__all__ = [
    "ALLOWED_EDITING_REGIMES",
    "ALLOWED_GENERATOR_SCOPES",
    "ALLOWED_METRICS",
    "DEFAULT_FPR_CEILING",
    "DEFAULT_MAX_AGE_DAYS",
    "EVIDENCE_SCHEMA",
    "MIN_AI_SAMPLES",
    "MIN_HUMAN_SAMPLES",
    "REGISTRY_SCHEMA",
    "BenchmarkProvenance",
    "DetectorCoverage",
    "DimensionCoverage",
    "EvidenceError",
    "EvidenceRecord",
    "EvidenceRegistry",
    "MetricEstimate",
    "RegistryVerification",
    "RunProvenance",
    "SliceConditions",
    "SliceMatch",
    "ValidationSlice",
    "age_days_between",
    "aggregate_coverage_states",
    "assess_detector_coverage",
    "canonical_json_bytes",
    "coverage_for_predictions",
    "empty_registry",
    "fresh_until",
    "load_registry",
    "sha256_file",
]
