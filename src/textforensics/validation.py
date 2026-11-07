"""Versioned validation-evidence records keyed to a supported input regime (U1).

This module is the registry side of U1: one :class:`ValidationRecord` binds a
detector version to a declared regime (language x length x domain x editing x
generator-vintage x human-population), the dataset and run that measured it,
per-slice metrics with confidence intervals, and its limits. A
:class:`ValidationRegistry` stores those records, verifies them on load, and
answers regime lookups. The Trust Map derivation engine (Package B) reads
this registry; it never reads the v1 ``EvidenceRegistry`` for U1 dimensions.

Contract rules
--------------
* Licence/consent and ``contamination_flag`` are REGISTRATION-BLOCKING:
  a record missing either cannot be registered at any tier. The loader
  raises :class:`ValidationError` for those, for structural violations
  (wrong types, bad enums, malformed hashes), and for signature mismatches.
* Every other field in the record is MANDATORY FOR ``supported`` status:
  if one is missing or null (except the explicitly nullable fields:
  ``calibration_id``, ``supersedes``, ``language_variety``,
  ``length_bucket.max_words``, ``attack_slice``, ``reviewer``/
  ``review_date``, ``near_duplicate_rate``/``near_duplicate_method`` when
  not measured, and ``dependency_lock_sha`` when no lock was captured),
  the validator caps the EFFECTIVE status at ``partial`` — see
  :func:`missing_mandatory_fields` and :func:`effective_status`. The stored
  status is never trusted blindly. Records missing a mandatory field are
  still loadable (at capped status); records missing licence or
  contamination data, or failing structural/signature checks, are refused.
* Staleness is COMPUTED, never stored: a record becomes effectively
  ``stale`` when the detector version changes, when
  ``next_revalidation_due`` passes, or when ``limits.demoted_by`` is set.
  The stored record does not change when it goes stale, so its signature
  stays valid. Default ``next_revalidation_due`` is run date + 90 days.
* ``signature`` is the SHA-256 of the canonical JSON of the record
  excluding ``signature`` itself.
* No raw text anywhere in a record or the registry.

The module has no third-party dependencies. JSON-Schema validation of
records lives in :mod:`textforensics.schema` (``jsonschema`` is a dev extra)
and is not used here.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import math
import os
import re
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any

from .conditions import InputConditions
from .detectors import DetectorPrediction
from .evidence import (
    DEFAULT_FPR_CEILING,
    MIN_AI_SAMPLES,
    MIN_HUMAN_SAMPLES,
    EvidenceError,
    MetricEstimate,
)
from .trust import (
    EVIDENCE_DIMENSIONS,
    TRUST_SCHEMA_V3,
    TRUST_STATES_V3,
    TrustDimension,
    TrustMap,
    _coverage_counts,
    _diversity_dimension,
    _stability_dimension,
)

EVIDENCE_RECORD_SCHEMA = "textforensics.evidence-record/v1"
VALIDATION_REGISTRY_SCHEMA = "textforensics.validation-registry/v1"

VALIDATION_STATUSES = ("supported", "partial", "unknown", "stale", "contested")
CONTAMINATION_FLAGS = ("yes", "no", "unknown")
EDITING_REGIMES = ("raw", "paraphrased", "human-edited", "LLM-edited", "humanised", "mixed-origin")
SPLIT_ROLES = ("fit", "threshold", "test")
DEFAULT_REVALIDATION_DAYS = 90

CONTAMINATED_LABEL = "contaminated — do not report as generalisation"
CONTAMINATION_UNKNOWN_LABEL = "contamination unknown — do not report as generalisation"

_RECORD_ID_RE = re.compile(r"^evr-[0-9]{8}-[a-z0-9-]+$")
_DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")


class ValidationError(ValueError):
    """Raised when a validation record or registry violates the public contract."""


# ---------------------------------------------------------------------------
# Primitive helpers (own implementations; do not import privates from evidence)
# ---------------------------------------------------------------------------


def _require_nonempty_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field_name} must be a non-empty string.")
    return value.strip()


def _require_hex(value: Any, field_name: str, *, lengths: tuple[int, ...] = (64,)) -> str:
    text = _require_nonempty_string(value, field_name)
    if len(text) not in lengths or any(char not in "0123456789abcdef" for char in text):
        expected = " or ".join(str(length) for length in lengths)
        raise ValidationError(f"{field_name} must be {expected} lowercase hex characters.")
    return text


def _require_number(value: Any, field_name: str, *, minimum: float | None = None) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"{field_name} must be a finite number.")
    number = float(value)
    if not math.isfinite(number):
        raise ValidationError(f"{field_name} must be finite.")
    if minimum is not None and number < minimum:
        raise ValidationError(f"{field_name} must be >= {minimum}.")
    return number


def _require_int(value: Any, field_name: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{field_name} must be an integer.")
    if value < minimum:
        raise ValidationError(f"{field_name} must be >= {minimum}.")
    return value


def _parse_date(value: Any, field_name: str) -> date:
    text = _require_nonempty_string(value, field_name)
    if not _DATE_RE.match(text):
        raise ValidationError(f"{field_name} must be an ISO calendar date (YYYY-MM-DD).")
    try:
        return date.fromisoformat(text)
    except ValueError as exc:
        raise ValidationError(f"{field_name} must be a valid calendar date.") from exc


def _parse_iso8601(value: Any, field_name: str) -> datetime:
    text = _require_nonempty_string(value, field_name)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"{field_name} must be an ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _now_utc() -> datetime:
    return datetime.now(UTC)


def _coerce_now(now: datetime | str | None) -> datetime:
    if now is None:
        return _now_utc()
    if isinstance(now, str):
        return _parse_iso8601(now, "now")
    if now.tzinfo is None:
        return now.replace(tzinfo=UTC)
    return now.astimezone(UTC)


def _safe_relative_path(value: Any, field_name: str) -> str:
    text = _require_nonempty_string(value, field_name).replace("\\", "/")
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or (len(path.parts) > 0 and ":" in path.parts[0]):
        raise ValidationError(f"{field_name} must be a portable relative path.")
    return path.as_posix()


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


def default_next_revalidation_due(
    run_date: date | datetime | str, *, days: int = DEFAULT_REVALIDATION_DAYS
) -> str:
    """Return the default ``next_revalidation_due`` date for a run date.

    The default is run date + 90 days, matching the U7 90-day staleness rule.
    """
    if isinstance(run_date, datetime):
        base = run_date.date()
    elif isinstance(run_date, date):
        base = run_date
    else:
        base = _parse_date(run_date, "run_date")
    if days < 1:
        raise ValidationError("days must be positive.")
    return (base + timedelta(days=days)).isoformat()


# ---------------------------------------------------------------------------
# Record dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LengthBucket:
    """Length bucket a record covers, with observed sample statistics."""

    min_words: int
    floor_words: int
    measured_min_words: int
    measured_median_words: int
    measured_max_words: int
    max_words: int | None = None

    def __post_init__(self) -> None:
        _require_int(self.min_words, "length_bucket.min_words")
        _require_int(self.floor_words, "length_bucket.floor_words")
        _require_int(self.measured_min_words, "length_bucket.measured_min_words")
        _require_int(self.measured_median_words, "length_bucket.measured_median_words")
        _require_int(self.measured_max_words, "length_bucket.measured_max_words")
        if self.max_words is not None:
            _require_int(self.max_words, "length_bucket.max_words")
            if self.max_words < self.min_words:
                raise ValidationError("length_bucket.max_words must not be below min_words.")
        if not (self.measured_min_words <= self.measured_median_words <= self.measured_max_words):
            raise ValidationError(
                "length_bucket measured word counts must be ordered min <= median <= max."
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "min_words": self.min_words,
            "max_words": self.max_words,
            "floor_words": self.floor_words,
            "measured_min_words": self.measured_min_words,
            "measured_median_words": self.measured_median_words,
            "measured_max_words": self.measured_max_words,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> LengthBucket:
        if not isinstance(payload, Mapping):
            raise ValidationError("length_bucket must be an object.")
        return cls(
            min_words=payload["min_words"],
            max_words=payload.get("max_words"),
            floor_words=payload["floor_words"],
            measured_min_words=payload["measured_min_words"],
            measured_median_words=payload["measured_median_words"],
            measured_max_words=payload["measured_max_words"],
        )


@dataclass(frozen=True, slots=True)
class GeneratorInfo:
    """Generator families and vintage a record covers."""

    families: tuple[str, ...]
    vintage: str
    current_as_of: str

    def __post_init__(self) -> None:
        if not self.families:
            raise ValidationError("generator.families must not be empty.")
        for family in self.families:
            _require_nonempty_string(family, "generator family")
        _require_nonempty_string(self.vintage, "generator.vintage")
        _parse_date(self.current_as_of, "generator.current_as_of")

    def to_dict(self) -> dict[str, Any]:
        return {
            "families": list(self.families),
            "vintage": self.vintage,
            "current_as_of": self.current_as_of,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> GeneratorInfo:
        if not isinstance(payload, Mapping):
            raise ValidationError("generator must be an object.")
        return cls(
            families=tuple(payload["families"]),
            vintage=str(payload["vintage"]),
            current_as_of=str(payload["current_as_of"]),
        )


@dataclass(frozen=True, slots=True)
class HumanPopulation:
    """Human population a record covers, and how it was determined."""

    populations: tuple[str, ...]
    determined_how: str

    def __post_init__(self) -> None:
        if not self.populations:
            raise ValidationError("human_population.populations must not be empty.")
        for population in self.populations:
            _require_nonempty_string(population, "human population")
        _require_nonempty_string(self.determined_how, "human_population.determined_how")

    def to_dict(self) -> dict[str, Any]:
        return {
            "populations": list(self.populations),
            "determined_how": self.determined_how,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> HumanPopulation:
        if not isinstance(payload, Mapping):
            raise ValidationError("human_population must be an object.")
        return cls(
            populations=tuple(payload["populations"]),
            determined_how=str(payload["determined_how"]),
        )


@dataclass(frozen=True, slots=True)
class Regime:
    """The input regime a validation record covers."""

    language: str
    script: str
    length_bucket: LengthBucket
    domain: tuple[str, ...]
    genre: str | None
    generator: GeneratorInfo
    editing_regime: str
    human_population: HumanPopulation
    language_variety: str | None = None
    attack_slice: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty_string(self.language, "regime.language")
        _require_nonempty_string(self.script, "regime.script")
        if not isinstance(self.length_bucket, LengthBucket):
            raise ValidationError("regime.length_bucket must be a LengthBucket.")
        if not self.domain:
            raise ValidationError("regime.domain must not be empty.")
        for item in self.domain:
            _require_nonempty_string(item, "regime domain")
        if self.genre is not None:
            _require_nonempty_string(self.genre, "regime.genre")
        if not isinstance(self.generator, GeneratorInfo):
            raise ValidationError("regime.generator must be a GeneratorInfo.")
        if self.editing_regime not in EDITING_REGIMES:
            raise ValidationError(f"Unsupported editing regime: {self.editing_regime!r}.")
        if not isinstance(self.human_population, HumanPopulation):
            raise ValidationError("regime.human_population must be a HumanPopulation.")
        if self.language_variety is not None:
            _require_nonempty_string(self.language_variety, "regime.language_variety")
        if self.attack_slice is not None:
            _require_nonempty_string(self.attack_slice, "regime.attack_slice")

    def to_dict(self) -> dict[str, Any]:
        return {
            "language": self.language,
            "script": self.script,
            "language_variety": self.language_variety,
            "length_bucket": self.length_bucket.to_dict(),
            "domain": list(self.domain),
            "genre": self.genre,
            "generator": self.generator.to_dict(),
            "editing_regime": self.editing_regime,
            "human_population": self.human_population.to_dict(),
            "attack_slice": self.attack_slice,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Regime:
        if not isinstance(payload, Mapping):
            raise ValidationError("regime must be an object.")
        return cls(
            language=str(payload["language"]),
            script=str(payload["script"]),
            language_variety=payload.get("language_variety"),
            length_bucket=LengthBucket.from_dict(payload["length_bucket"]),
            domain=tuple(payload["domain"]),
            genre=payload.get("genre"),
            generator=GeneratorInfo.from_dict(payload["generator"]),
            editing_regime=str(payload["editing_regime"]),
            human_population=HumanPopulation.from_dict(payload["human_population"]),
            attack_slice=payload.get("attack_slice"),
        )


@dataclass(frozen=True, slots=True)
class RecordData:
    """Dataset and licence/consent data for a validation record."""

    dataset_name: str
    dataset_version: str
    file_sha256: str
    row_hash_method: str | None
    split: str
    split_role: str
    n_human: int
    n_ai: int
    licence: str
    licence_reference: str | None
    contamination_flag: str
    near_duplicate_rate: float | None = None
    near_duplicate_method: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty_string(self.dataset_name, "data.dataset_name")
        _require_nonempty_string(self.dataset_version, "data.dataset_version")
        _require_hex(self.file_sha256, "data.file_sha256")
        if self.row_hash_method is not None:
            _require_nonempty_string(self.row_hash_method, "data.row_hash_method")
        _require_nonempty_string(self.split, "data.split")
        if self.split_role not in SPLIT_ROLES:
            raise ValidationError(f"Unsupported split_role: {self.split_role!r}.")
        _require_int(self.n_human, "data.n_human")
        _require_int(self.n_ai, "data.n_ai")
        _require_nonempty_string(self.licence, "data.licence")
        if self.licence_reference is not None:
            _require_nonempty_string(self.licence_reference, "data.licence_reference")
        if self.contamination_flag not in CONTAMINATION_FLAGS:
            raise ValidationError(f"Unsupported contamination_flag: {self.contamination_flag!r}.")
        if self.near_duplicate_rate is not None:
            _require_number(self.near_duplicate_rate, "data.near_duplicate_rate")
            if not 0.0 <= self.near_duplicate_rate <= 1.0:
                raise ValidationError("data.near_duplicate_rate must be between 0 and 1.")
        if self.near_duplicate_method is not None:
            _require_nonempty_string(self.near_duplicate_method, "data.near_duplicate_method")

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_name": self.dataset_name,
            "dataset_version": self.dataset_version,
            "file_sha256": self.file_sha256,
            "row_hash_method": self.row_hash_method,
            "split": self.split,
            "split_role": self.split_role,
            "n_human": self.n_human,
            "n_ai": self.n_ai,
            "licence": self.licence,
            "licence_reference": self.licence_reference,
            "contamination_flag": self.contamination_flag,
            "near_duplicate_rate": self.near_duplicate_rate,
            "near_duplicate_method": self.near_duplicate_method,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> RecordData:
        if not isinstance(payload, Mapping):
            raise ValidationError("data must be an object.")
        return cls(
            dataset_name=str(payload["dataset_name"]),
            dataset_version=str(payload["dataset_version"]),
            file_sha256=str(payload["file_sha256"]),
            row_hash_method=payload.get("row_hash_method"),
            split=str(payload["split"]),
            split_role=str(payload["split_role"]),
            n_human=payload["n_human"],
            n_ai=payload["n_ai"],
            licence=str(payload["licence"]),
            licence_reference=payload.get("licence_reference"),
            contamination_flag=str(payload["contamination_flag"]),
            near_duplicate_rate=payload.get("near_duplicate_rate"),
            near_duplicate_method=payload.get("near_duplicate_method"),
        )


@dataclass(frozen=True, slots=True)
class DropItem:
    """One entry of a run's drops manifest: what was excluded, and why."""

    item: str
    reason: str

    def __post_init__(self) -> None:
        _require_nonempty_string(self.item, "drops_manifest item")
        _require_nonempty_string(self.reason, "drops_manifest reason")

    def to_dict(self) -> dict[str, Any]:
        return {"item": self.item, "reason": self.reason}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> DropItem:
        if not isinstance(payload, Mapping):
            raise ValidationError("drops_manifest entry must be an object.")
        return cls(item=str(payload["item"]), reason=str(payload["reason"]))


@dataclass(frozen=True, slots=True)
class RunInfo:
    """Reproducible provenance for the run that produced a validation record."""

    run_id: str
    run_artifact: str
    run_artifact_sha256: str
    run_date: str
    runner: str
    code_version: str
    command: str
    drops_manifest: tuple[DropItem, ...]
    dependency_lock_sha: str | None = None
    hardware: str | None = None
    runtime: str | None = None
    seeds: dict[str, int] = field(default_factory=dict)
    reporting_rules: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty_string(self.run_id, "run.run_id")
        _safe_relative_path(self.run_artifact, "run.run_artifact")
        _require_hex(self.run_artifact_sha256, "run.run_artifact_sha256")
        _parse_date(self.run_date, "run.run_date")
        _require_nonempty_string(self.runner, "run.runner")
        _require_hex(self.code_version, "run.code_version", lengths=tuple(range(7, 41)))
        _require_nonempty_string(self.command, "run.command")
        for drop in self.drops_manifest:
            if not isinstance(drop, DropItem):
                raise ValidationError("run.drops_manifest entries must be DropItem objects.")
        if self.dependency_lock_sha is not None:
            _require_hex(self.dependency_lock_sha, "run.dependency_lock_sha")
        if self.hardware is not None:
            _require_nonempty_string(self.hardware, "run.hardware")
        if self.runtime is not None:
            _require_nonempty_string(self.runtime, "run.runtime")
        if not isinstance(self.seeds, Mapping):
            raise ValidationError("run.seeds must be an object.")
        if "bootstrap_seed" not in self.seeds:
            raise ValidationError("run.seeds.bootstrap_seed is required.")
        for name, value in self.seeds.items():
            _require_nonempty_string(name, "run seed name")
            _require_int(value, f"run.seeds.{name}")
        if self.reporting_rules is not None:
            _require_nonempty_string(self.reporting_rules, "run.reporting_rules")

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "run_artifact": self.run_artifact,
            "run_artifact_sha256": self.run_artifact_sha256,
            "run_date": self.run_date,
            "runner": self.runner,
            "code_version": self.code_version,
            "dependency_lock_sha": self.dependency_lock_sha,
            "hardware": self.hardware,
            "runtime": self.runtime,
            "seeds": dict(self.seeds),
            "command": self.command,
            "drops_manifest": [drop.to_dict() for drop in self.drops_manifest],
            "reporting_rules": self.reporting_rules,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> RunInfo:
        if not isinstance(payload, Mapping):
            raise ValidationError("run must be an object.")
        return cls(
            run_id=str(payload["run_id"]),
            run_artifact=str(payload["run_artifact"]),
            run_artifact_sha256=str(payload["run_artifact_sha256"]),
            run_date=str(payload["run_date"]),
            runner=str(payload["runner"]),
            code_version=str(payload["code_version"]),
            dependency_lock_sha=payload.get("dependency_lock_sha"),
            hardware=payload.get("hardware"),
            runtime=payload.get("runtime"),
            seeds=dict(payload.get("seeds", {})),
            command=str(payload["command"]),
            drops_manifest=tuple(
                DropItem.from_dict(item) for item in payload.get("drops_manifest", [])
            ),
            reporting_rules=payload.get("reporting_rules"),
        )


def _metric_from_dict(payload: Any, field_name: str) -> MetricEstimate:
    try:
        return MetricEstimate.from_dict(payload)
    except (EvidenceError, KeyError, TypeError, AttributeError) as exc:
        raise ValidationError(f"{field_name} is not a valid metric estimate: {exc}.") from exc


@dataclass(frozen=True, slots=True)
class SliceMetrics:
    """Per-slice metrics with confidence intervals.

    Metric objects reuse :class:`textforensics.evidence.MetricEstimate`
    semantics (value in [0, 1], CI bounds both present or both absent, value
    inside the CI). ``fpr_native`` is the empirical human false-positive rate
    at the detector's native categorical operating point; its operating
    point is recorded in ``fpr_operating_point`` because MetricEstimate
    carries no operating-point field. ``tpr_native`` is the paired
    true-positive rate at the same operating point (optional in v1;
    records predating it omit the key).
    """

    slice_id: str
    n_human: int
    n_ai: int
    auroc: MetricEstimate
    tpr_at_fpr_0_01: MetricEstimate
    tpr_at_fpr_0_05: MetricEstimate
    fpr_native: MetricEstimate
    coverage: float
    abstention_rate: float
    worst_slice: bool
    fpr_operating_point: str | None = None
    tpr_native: MetricEstimate | None = None

    def __post_init__(self) -> None:
        _require_nonempty_string(self.slice_id, "slice_id")
        _require_int(self.n_human, "metrics n_human")
        _require_int(self.n_ai, "metrics n_ai")
        if self.n_human + self.n_ai <= 0:
            raise ValidationError("slice must contain at least one sample.")
        for name, metric in (
            ("auroc", self.auroc),
            ("tpr_at_fpr_0_01", self.tpr_at_fpr_0_01),
            ("tpr_at_fpr_0_05", self.tpr_at_fpr_0_05),
            ("fpr_native", self.fpr_native),
        ):
            if not isinstance(metric, MetricEstimate):
                raise ValidationError(f"metrics.{name} must be a MetricEstimate.")
        if self.auroc.n > self.n_human + self.n_ai:
            raise ValidationError("metrics.auroc n cannot exceed the slice sample count.")
        if self.tpr_at_fpr_0_01.n > self.n_ai or self.tpr_at_fpr_0_05.n > self.n_ai:
            raise ValidationError("metrics tpr sample count cannot exceed n_ai.")
        if self.fpr_native.n > self.n_human:
            raise ValidationError("metrics fpr_native sample count cannot exceed n_human.")
        if self.tpr_native is not None:
            if not isinstance(self.tpr_native, MetricEstimate):
                raise ValidationError("metrics.tpr_native must be a MetricEstimate.")
            if self.tpr_native.n > self.n_ai:
                raise ValidationError("metrics tpr_native sample count cannot exceed n_ai.")
        _require_number(self.coverage, "metrics.coverage")
        if not 0.0 <= self.coverage <= 1.0:
            raise ValidationError("metrics.coverage must be between 0 and 1.")
        _require_number(self.abstention_rate, "metrics.abstention_rate")
        if not 0.0 <= self.abstention_rate <= 1.0:
            raise ValidationError("metrics.abstention_rate must be between 0 and 1.")
        if not isinstance(self.worst_slice, bool):
            raise ValidationError("metrics.worst_slice must be a boolean.")
        if self.fpr_operating_point is not None:
            _require_nonempty_string(self.fpr_operating_point, "metrics fpr_operating_point")

    def to_dict(self) -> dict[str, Any]:
        fpr_native = self.fpr_native.to_dict()
        fpr_native["operating_point"] = self.fpr_operating_point
        payload: dict[str, Any] = {
            "slice_id": self.slice_id,
            "n_human": self.n_human,
            "n_ai": self.n_ai,
            "auroc": self.auroc.to_dict(),
            "tpr_at_fpr_0_01": self.tpr_at_fpr_0_01.to_dict(),
            "tpr_at_fpr_0_05": self.tpr_at_fpr_0_05.to_dict(),
            "fpr_native": fpr_native,
            "coverage": self.coverage,
            "abstention_rate": self.abstention_rate,
            "worst_slice": self.worst_slice,
        }
        if self.tpr_native is not None:
            payload["tpr_native"] = self.tpr_native.to_dict()
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> SliceMetrics:
        if not isinstance(payload, Mapping):
            raise ValidationError("metrics entry must be an object.")
        fpr_native = payload["fpr_native"]
        operating_point = None
        if isinstance(fpr_native, Mapping):
            operating_point = fpr_native.get("operating_point")
        return cls(
            slice_id=str(payload["slice_id"]),
            n_human=payload["n_human"],
            n_ai=payload["n_ai"],
            auroc=_metric_from_dict(payload["auroc"], "metrics.auroc"),
            tpr_at_fpr_0_01=_metric_from_dict(
                payload["tpr_at_fpr_0_01"], "metrics.tpr_at_fpr_0_01"
            ),
            tpr_at_fpr_0_05=_metric_from_dict(
                payload["tpr_at_fpr_0_05"], "metrics.tpr_at_fpr_0_05"
            ),
            fpr_native=_metric_from_dict(fpr_native, "metrics.fpr_native"),
            tpr_native=(
                _metric_from_dict(payload["tpr_native"], "metrics.tpr_native")
                if payload.get("tpr_native") is not None
                else None
            ),
            coverage=payload["coverage"],
            abstention_rate=payload["abstention_rate"],
            worst_slice=payload["worst_slice"],
            fpr_operating_point=operating_point,
        )


@dataclass(frozen=True, slots=True)
class RecordLimits:
    """Known failure modes, limitations, and revalidation state of a record."""

    known_failure_modes: tuple[str, ...]
    limitations: tuple[str, ...]
    next_revalidation_due: str
    appeal_note: str | None
    reviewer: str | None = None
    review_date: str | None = None
    demoted_by: str | None = None

    def __post_init__(self) -> None:
        for mode in self.known_failure_modes:
            _require_nonempty_string(mode, "limits known failure mode")
        for limitation in self.limitations:
            _require_nonempty_string(limitation, "limits limitation")
        _parse_date(self.next_revalidation_due, "limits.next_revalidation_due")
        if self.appeal_note is not None:
            _require_nonempty_string(self.appeal_note, "limits.appeal_note")
        if self.reviewer is not None:
            _require_nonempty_string(self.reviewer, "limits.reviewer")
        if self.review_date is not None:
            _parse_date(self.review_date, "limits.review_date")
        if self.demoted_by is not None:
            _require_nonempty_string(self.demoted_by, "limits.demoted_by")

    def to_dict(self) -> dict[str, Any]:
        return {
            "known_failure_modes": list(self.known_failure_modes),
            "limitations": list(self.limitations),
            "next_revalidation_due": self.next_revalidation_due,
            "appeal_note": self.appeal_note,
            "reviewer": self.reviewer,
            "review_date": self.review_date,
            "demoted_by": self.demoted_by,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> RecordLimits:
        if not isinstance(payload, Mapping):
            raise ValidationError("limits must be an object.")
        return cls(
            known_failure_modes=tuple(payload["known_failure_modes"]),
            limitations=tuple(payload["limitations"]),
            next_revalidation_due=str(payload["next_revalidation_due"]),
            appeal_note=payload.get("appeal_note"),
            reviewer=payload.get("reviewer"),
            review_date=payload.get("review_date"),
            demoted_by=payload.get("demoted_by"),
        )


@dataclass(frozen=True, slots=True)
class ValidationRecord:
    """One versioned validation-evidence record for a detector and regime."""

    record_id: str
    detector_id: str
    detector_version: str
    detector_family: str
    status: str
    regime: Regime
    data: RecordData
    run: RunInfo
    metrics: tuple[SliceMetrics, ...]
    limits: RecordLimits
    signature: str
    calibration_id: str | None = None
    supersedes: str | None = None

    def __post_init__(self) -> None:
        if not _RECORD_ID_RE.match(self.record_id or ""):
            raise ValidationError(
                "record_id must look like evr-YYYYMMDD-<dataset>-builtin-heuristic."
            )
        _require_nonempty_string(self.detector_id, "detector_id")
        _require_nonempty_string(self.detector_version, "detector_version")
        _require_nonempty_string(self.detector_family, "detector_family")
        if self.status not in VALIDATION_STATUSES:
            raise ValidationError(f"Unsupported status: {self.status!r}.")
        if not isinstance(self.regime, Regime):
            raise ValidationError("regime must be a Regime.")
        if not isinstance(self.data, RecordData):
            raise ValidationError("data must be a RecordData.")
        if not isinstance(self.run, RunInfo):
            raise ValidationError("run must be a RunInfo.")
        if not self.metrics:
            raise ValidationError("record requires at least one metrics slice.")
        slice_ids = [item.slice_id for item in self.metrics]
        if len(set(slice_ids)) != len(slice_ids):
            raise ValidationError("slice_id values must be unique within a record.")
        if not isinstance(self.limits, RecordLimits):
            raise ValidationError("limits must be a RecordLimits.")
        _require_hex(self.signature, "signature")
        if self.calibration_id is not None:
            _require_nonempty_string(self.calibration_id, "calibration_id")
        if self.supersedes is not None:
            _require_nonempty_string(self.supersedes, "supersedes")

    @property
    def validation_notes(self) -> tuple[str, ...]:
        """Missing mandatory-for-supported fields (empty when fully supported-eligible).

        These are the fields :func:`effective_status` uses to cap the
        effective status at ``partial``; see :func:`missing_mandatory_fields`.
        """
        return tuple(missing_mandatory_fields(self.to_dict()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": EVIDENCE_RECORD_SCHEMA,
            "record_id": self.record_id,
            "detector_id": self.detector_id,
            "detector_version": self.detector_version,
            "detector_family": self.detector_family,
            "calibration_id": self.calibration_id,
            "status": self.status,
            "supersedes": self.supersedes,
            "regime": self.regime.to_dict(),
            "data": self.data.to_dict(),
            "run": self.run.to_dict(),
            "metrics": [item.to_dict() for item in self.metrics],
            "limits": self.limits.to_dict(),
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ValidationRecord:
        issues = _structure_issues(payload)
        if issues:
            raise ValidationError("Invalid validation record: " + "; ".join(issues))
        return cls(
            record_id=str(payload["record_id"]),
            detector_id=str(payload["detector_id"]),
            detector_version=str(payload["detector_version"]),
            detector_family=str(payload["detector_family"]),
            calibration_id=payload.get("calibration_id"),
            status=str(payload["status"]),
            supersedes=payload.get("supersedes"),
            regime=Regime.from_dict(payload["regime"]),
            data=RecordData.from_dict(payload["data"]),
            run=RunInfo.from_dict(payload["run"]),
            metrics=tuple(SliceMetrics.from_dict(item) for item in payload["metrics"]),
            limits=RecordLimits.from_dict(payload["limits"]),
            signature=str(payload["signature"]),
        )


# ---------------------------------------------------------------------------
# Structural validation and the partial cap
# ---------------------------------------------------------------------------

_RECORD_KEYS = frozenset(
    {
        "schema",
        "record_id",
        "detector_id",
        "detector_version",
        "detector_family",
        "calibration_id",
        "status",
        "supersedes",
        "regime",
        "data",
        "run",
        "metrics",
        "limits",
        "signature",
    }
)
_REGIME_KEYS = frozenset(
    {
        "language",
        "script",
        "language_variety",
        "length_bucket",
        "domain",
        "genre",
        "generator",
        "editing_regime",
        "human_population",
        "attack_slice",
    }
)
_LENGTH_BUCKET_KEYS = frozenset(
    {
        "min_words",
        "max_words",
        "floor_words",
        "measured_min_words",
        "measured_median_words",
        "measured_max_words",
    }
)
_GENERATOR_KEYS = frozenset({"families", "vintage", "current_as_of"})
_HUMAN_POPULATION_KEYS = frozenset({"populations", "determined_how"})
_DATA_KEYS = frozenset(
    {
        "dataset_name",
        "dataset_version",
        "file_sha256",
        "row_hash_method",
        "split",
        "split_role",
        "n_human",
        "n_ai",
        "licence",
        "licence_reference",
        "contamination_flag",
        "near_duplicate_rate",
        "near_duplicate_method",
    }
)
_RUN_KEYS = frozenset(
    {
        "run_id",
        "run_artifact",
        "run_artifact_sha256",
        "run_date",
        "runner",
        "code_version",
        "dependency_lock_sha",
        "hardware",
        "runtime",
        "seeds",
        "command",
        "drops_manifest",
        "reporting_rules",
    }
)
_SLICE_KEYS = frozenset(
    {
        "slice_id",
        "n_human",
        "n_ai",
        "auroc",
        "tpr_at_fpr_0_01",
        "tpr_at_fpr_0_05",
        "fpr_native",
        "tpr_native",
        "coverage",
        "abstention_rate",
        "worst_slice",
    }
)
_LIMITS_KEYS = frozenset(
    {
        "known_failure_modes",
        "limitations",
        "next_revalidation_due",
        "appeal_note",
        "reviewer",
        "review_date",
        "demoted_by",
    }
)
_METRIC_KEYS = frozenset({"value", "n", "ci_lower", "ci_upper", "method", "operating_point"})

# Fields that must be present and non-null for a record to hold `supported`
# effective status. Explicitly nullable fields are NOT in this list:
# calibration_id, supersedes, language_variety, length_bucket.max_words,
# attack_slice, reviewer/review_date, near_duplicate_rate/method when not
# measured, and dependency_lock_sha when no lock was captured.
_MANDATORY_FOR_SUPPORTED = (
    "regime.language",
    "regime.script",
    "regime.length_bucket.min_words",
    "regime.length_bucket.floor_words",
    "regime.length_bucket.measured_min_words",
    "regime.length_bucket.measured_median_words",
    "regime.length_bucket.measured_max_words",
    "regime.domain",
    "regime.genre",
    "regime.generator.families",
    "regime.generator.vintage",
    "regime.generator.current_as_of",
    "regime.editing_regime",
    "regime.human_population.populations",
    "regime.human_population.determined_how",
    "data.dataset_name",
    "data.dataset_version",
    "data.file_sha256",
    "data.row_hash_method",
    "data.split",
    "data.split_role",
    "data.n_human",
    "data.n_ai",
    "data.licence_reference",
    "run.run_id",
    "run.run_artifact",
    "run.run_artifact_sha256",
    "run.run_date",
    "run.runner",
    "run.code_version",
    "run.hardware",
    "run.runtime",
    "run.seeds.bootstrap_seed",
    "run.command",
    "run.reporting_rules",
    "limits.known_failure_modes",
    "limits.limitations",
    "limits.next_revalidation_due",
    "limits.appeal_note",
)
_NONEMPTY_LIST_PATHS = frozenset(
    {
        "regime.domain",
        "regime.generator.families",
        "regime.human_population.populations",
    }
)

_MISSING = object()


def _lookup(payload: Mapping[str, Any], dotted: str) -> Any:
    current: Any = payload
    for part in dotted.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return _MISSING
        current = current[part]
    return current


def missing_mandatory_fields(record: Mapping[str, Any] | ValidationRecord) -> list[str]:
    """Return mandatory-for-supported fields missing or null in a record.

    An empty list means the record is eligible for ``supported`` effective
    status on completeness grounds (staleness and contamination are
    evaluated separately by :func:`effective_status`). A zero sample count
    is a value, not a missing field; an empty list counts as missing only
    for the fields whose schema requires at least one entry.
    """
    payload = record.to_dict() if isinstance(record, ValidationRecord) else record
    if not isinstance(payload, Mapping):
        return list(_MANDATORY_FOR_SUPPORTED)
    missing: list[str] = []
    for path in _MANDATORY_FOR_SUPPORTED:
        value = _lookup(payload, path)
        if value is _MISSING or value is None or (path in _NONEMPTY_LIST_PATHS and value == []):
            missing.append(path)
    return missing


def _check_string(
    obj: Mapping[str, Any], key: str, path: str, issues: list[str], *, required: bool = True
) -> None:
    value = obj.get(key)
    if value is None:
        if required:
            issues.append(f"{path} is required and must be a non-empty string.")
        return
    if not isinstance(value, str) or not value.strip():
        issues.append(f"{path} must be a non-empty string.")


def _check_hex(
    obj: Mapping[str, Any],
    key: str,
    path: str,
    issues: list[str],
    *,
    lengths: tuple[int, ...] = (64,),
    required: bool = True,
) -> None:
    value = obj.get(key)
    if value is None:
        if required:
            issues.append(f"{path} is required and must be lowercase hex.")
        return
    try:
        _require_hex(value, path, lengths=lengths)
    except ValidationError as exc:
        issues.append(str(exc))


def _check_int(
    obj: Mapping[str, Any], key: str, path: str, issues: list[str], *, minimum: int = 0
) -> None:
    value = obj.get(key)
    if value is None:
        issues.append(f"{path} is required and must be an integer.")
        return
    try:
        _require_int(value, path, minimum=minimum)
    except ValidationError as exc:
        issues.append(str(exc))


def _check_number_in_range(obj: Mapping[str, Any], key: str, path: str, issues: list[str]) -> None:
    value = obj.get(key)
    if value is None:
        issues.append(f"{path} is required and must be a number between 0 and 1.")
        return
    try:
        number = _require_number(value, path)
    except ValidationError as exc:
        issues.append(str(exc))
        return
    if not 0.0 <= number <= 1.0:
        issues.append(f"{path} must be between 0 and 1.")


def _check_date(
    obj: Mapping[str, Any], key: str, path: str, issues: list[str], *, required: bool = True
) -> None:
    value = obj.get(key)
    if value is None:
        if required:
            issues.append(f"{path} is required and must be an ISO calendar date.")
        return
    try:
        _parse_date(value, path)
    except ValidationError as exc:
        issues.append(str(exc))


def _check_enum(
    obj: Mapping[str, Any],
    key: str,
    path: str,
    issues: list[str],
    allowed: tuple[str, ...],
) -> None:
    value = obj.get(key)
    if value is None:
        issues.append(f"{path} is required.")
    elif value not in allowed:
        issues.append(f"{path} must be one of {', '.join(allowed)}.")


def _check_string_list(obj: Mapping[str, Any], key: str, path: str, issues: list[str]) -> None:
    value = obj.get(key)
    if not isinstance(value, list):
        issues.append(f"{path} must be an array of strings.")
        return
    for entry in value:
        if not isinstance(entry, str) or not entry.strip():
            issues.append(f"{path} entries must be non-empty strings.")
            return


def _check_group(
    payload: Mapping[str, Any],
    key: str,
    path: str,
    issues: list[str],
    allowed_keys: frozenset,
) -> Mapping[str, Any] | None:
    group = payload.get(key)
    if not isinstance(group, Mapping):
        issues.append(f"{path} must be an object.")
        return None
    for sub in sorted(group):
        if sub not in allowed_keys:
            issues.append(f"unexpected field: {path}.{sub}")
    return group


def _check_metric(
    obj: Mapping[str, Any], key: str, path: str, issues: list[str]
) -> MetricEstimate | None:
    value = obj.get(key)
    if value is None:
        issues.append(f"{path} is required.")
        return None
    if isinstance(value, Mapping):
        for sub in sorted(value):
            if sub not in _METRIC_KEYS:
                issues.append(f"unexpected field: {path}.{sub}")
        operating_point = value.get("operating_point")
        if operating_point is not None and (
            not isinstance(operating_point, str) or not operating_point.strip()
        ):
            issues.append(f"{path}.operating_point must be a non-empty string or null.")
    try:
        return MetricEstimate.from_dict(value)
    except (EvidenceError, KeyError, TypeError, AttributeError) as exc:
        issues.append(f"{path} is not a valid metric estimate: {exc}.")
        return None


def _structure_issues(payload: Any) -> list[str]:
    """Collect structural issues (empty when the record is well-formed).

    Structural issues are the registration-blocking kind: wrong types,
    bad enums, malformed hashes, missing licence or contamination flag.
    Missing mandatory-for-supported fields are NOT structural issues;
    they are reported separately by :func:`missing_mandatory_fields` and
    cap the effective status instead of blocking registration.
    """
    issues: list[str] = []
    if not isinstance(payload, Mapping):
        return ["record must be a JSON object."]
    for key in sorted(payload):
        if key not in _RECORD_KEYS:
            issues.append(f"unexpected field: {key}")
    if payload.get("schema") != EVIDENCE_RECORD_SCHEMA:
        issues.append(f"schema must be '{EVIDENCE_RECORD_SCHEMA}'.")
    record_id = payload.get("record_id")
    if not isinstance(record_id, str) or not _RECORD_ID_RE.match(record_id):
        issues.append("record_id must look like evr-YYYYMMDD-<dataset>-builtin-heuristic.")
    _check_string(payload, "detector_id", "detector_id", issues)
    _check_string(payload, "detector_version", "detector_version", issues)
    _check_string(payload, "detector_family", "detector_family", issues)
    _check_string(payload, "calibration_id", "calibration_id", issues, required=False)
    _check_enum(payload, "status", "status", issues, VALIDATION_STATUSES)
    _check_string(payload, "supersedes", "supersedes", issues, required=False)
    _check_hex(payload, "signature", "signature", issues)

    regime = _check_group(payload, "regime", "regime", issues, _REGIME_KEYS)
    if regime is not None:
        _check_string(regime, "language", "regime.language", issues)
        _check_string(regime, "script", "regime.script", issues)
        _check_string(regime, "language_variety", "regime.language_variety", issues, required=False)
        _check_string(regime, "genre", "regime.genre", issues, required=False)
        _check_enum(regime, "editing_regime", "regime.editing_regime", issues, EDITING_REGIMES)
        _check_string(regime, "attack_slice", "regime.attack_slice", issues, required=False)
        bucket = _check_group(
            regime, "length_bucket", "regime.length_bucket", issues, _LENGTH_BUCKET_KEYS
        )
        if bucket is not None:
            _check_int(bucket, "min_words", "regime.length_bucket.min_words", issues)
            max_words = bucket.get("max_words")
            if max_words is not None:
                _check_int(bucket, "max_words", "regime.length_bucket.max_words", issues)
                min_words = bucket.get("min_words")
                if (
                    isinstance(max_words, int)
                    and not isinstance(max_words, bool)
                    and isinstance(min_words, int)
                    and not isinstance(min_words, bool)
                    and max_words < min_words
                ):
                    issues.append("regime.length_bucket.max_words must not be below min_words.")
            _check_int(bucket, "floor_words", "regime.length_bucket.floor_words", issues)
            _check_int(
                bucket,
                "measured_min_words",
                "regime.length_bucket.measured_min_words",
                issues,
            )
            _check_int(
                bucket,
                "measured_median_words",
                "regime.length_bucket.measured_median_words",
                issues,
            )
            _check_int(
                bucket,
                "measured_max_words",
                "regime.length_bucket.measured_max_words",
                issues,
            )
            measured = [
                bucket.get(name)
                for name in (
                    "measured_min_words",
                    "measured_median_words",
                    "measured_max_words",
                )
            ]
            if all(
                isinstance(item, int) and not isinstance(item, bool) for item in measured
            ) and not (measured[0] <= measured[1] <= measured[2]):
                issues.append(
                    "regime.length_bucket measured word counts must be ordered "
                    "min <= median <= max."
                )
        domain = regime.get("domain")
        if not isinstance(domain, list) or not domain:
            issues.append("regime.domain must be a non-empty array of strings.")
        else:
            _check_string_list(regime, "domain", "regime.domain", issues)
        generator = _check_group(regime, "generator", "regime.generator", issues, _GENERATOR_KEYS)
        if generator is not None:
            families = generator.get("families")
            if not isinstance(families, list) or not families:
                issues.append("regime.generator.families must be a non-empty array.")
            else:
                _check_string_list(generator, "families", "regime.generator.families", issues)
            _check_string(generator, "vintage", "regime.generator.vintage", issues)
            _check_date(generator, "current_as_of", "regime.generator.current_as_of", issues)
        population = _check_group(
            regime,
            "human_population",
            "regime.human_population",
            issues,
            _HUMAN_POPULATION_KEYS,
        )
        if population is not None:
            populations = population.get("populations")
            if not isinstance(populations, list) or not populations:
                issues.append("regime.human_population.populations must be a non-empty array.")
            else:
                _check_string_list(
                    population,
                    "populations",
                    "regime.human_population.populations",
                    issues,
                )
            _check_string(
                population,
                "determined_how",
                "regime.human_population.determined_how",
                issues,
            )

    data = _check_group(payload, "data", "data", issues, _DATA_KEYS)
    if data is not None:
        _check_string(data, "dataset_name", "data.dataset_name", issues)
        _check_string(data, "dataset_version", "data.dataset_version", issues)
        _check_hex(data, "file_sha256", "data.file_sha256", issues)
        _check_string(data, "row_hash_method", "data.row_hash_method", issues, required=False)
        _check_string(data, "split", "data.split", issues)
        _check_enum(data, "split_role", "data.split_role", issues, SPLIT_ROLES)
        _check_int(data, "n_human", "data.n_human", issues)
        _check_int(data, "n_ai", "data.n_ai", issues)
        licence = data.get("licence")
        if not isinstance(licence, str) or not licence.strip():
            issues.append(
                "data.licence is required and must be a non-empty string "
                "(licence is registration-blocking)."
            )
        _check_string(data, "licence_reference", "data.licence_reference", issues, required=False)
        flag = data.get("contamination_flag")
        if flag is None:
            issues.append(
                "data.contamination_flag is required "
                "(contamination flagging is registration-blocking)."
            )
        elif flag not in CONTAMINATION_FLAGS:
            issues.append("data.contamination_flag must be one of yes, no, unknown.")
        rate = data.get("near_duplicate_rate")
        if rate is not None:
            try:
                number = _require_number(rate, "data.near_duplicate_rate")
            except ValidationError as exc:
                issues.append(str(exc))
            else:
                if not 0.0 <= number <= 1.0:
                    issues.append("data.near_duplicate_rate must be between 0 and 1.")
        _check_string(
            data,
            "near_duplicate_method",
            "data.near_duplicate_method",
            issues,
            required=False,
        )

    run = _check_group(payload, "run", "run", issues, _RUN_KEYS)
    if run is not None:
        _check_string(run, "run_id", "run.run_id", issues)
        artifact = run.get("run_artifact")
        if artifact is None:
            issues.append("run.run_artifact is required.")
        else:
            try:
                _safe_relative_path(artifact, "run.run_artifact")
            except ValidationError as exc:
                issues.append(str(exc))
        _check_hex(run, "run_artifact_sha256", "run.run_artifact_sha256", issues)
        _check_date(run, "run_date", "run.run_date", issues)
        _check_string(run, "runner", "run.runner", issues)
        _check_hex(run, "code_version", "run.code_version", issues, lengths=tuple(range(7, 41)))
        _check_hex(
            run,
            "dependency_lock_sha",
            "run.dependency_lock_sha",
            issues,
            required=False,
        )
        _check_string(run, "hardware", "run.hardware", issues, required=False)
        _check_string(run, "runtime", "run.runtime", issues, required=False)
        _check_string(run, "command", "run.command", issues)
        _check_string(run, "reporting_rules", "run.reporting_rules", issues, required=False)
        seeds = run.get("seeds")
        if not isinstance(seeds, Mapping):
            issues.append("run.seeds must be an object.")
        else:
            if "bootstrap_seed" not in seeds:
                issues.append("run.seeds.bootstrap_seed is required.")
            for name, value in seeds.items():
                if not isinstance(name, str) or not name.strip():
                    issues.append("run.seeds keys must be non-empty strings.")
                elif not isinstance(value, int) or isinstance(value, bool):
                    issues.append(f"run.seeds.{name} must be an integer.")
        drops = run.get("drops_manifest")
        if not isinstance(drops, list):
            issues.append("run.drops_manifest must be an array.")
        else:
            for index, entry in enumerate(drops):
                path = f"run.drops_manifest[{index}]"
                if not isinstance(entry, Mapping):
                    issues.append(f"{path} must be an object.")
                    continue
                for sub in sorted(entry):
                    if sub not in {"item", "reason"}:
                        issues.append(f"unexpected field: {path}.{sub}")
                _check_string(entry, "item", f"{path}.item", issues)
                _check_string(entry, "reason", f"{path}.reason", issues)

    metrics = payload.get("metrics")
    if not isinstance(metrics, list) or not metrics:
        issues.append("metrics must be a non-empty array.")
    else:
        seen_ids: set[str] = set()
        for index, item in enumerate(metrics):
            path = f"metrics[{index}]"
            if not isinstance(item, Mapping):
                issues.append(f"{path} must be an object.")
                continue
            for sub in sorted(item):
                if sub not in _SLICE_KEYS:
                    issues.append(f"unexpected field: {path}.{sub}")
            slice_id = item.get("slice_id")
            if not isinstance(slice_id, str) or not slice_id.strip():
                issues.append(f"{path}.slice_id is required.")
            elif slice_id in seen_ids:
                issues.append(f"duplicate slice_id: {slice_id}")
            else:
                seen_ids.add(slice_id)
            _check_int(item, "n_human", f"{path}.n_human", issues)
            _check_int(item, "n_ai", f"{path}.n_ai", issues)
            n_human = item.get("n_human")
            n_ai = item.get("n_ai")
            auroc = _check_metric(item, "auroc", f"{path}.auroc", issues)
            tpr_1 = _check_metric(item, "tpr_at_fpr_0_01", f"{path}.tpr_at_fpr_0_01", issues)
            tpr_5 = _check_metric(item, "tpr_at_fpr_0_05", f"{path}.tpr_at_fpr_0_05", issues)
            fpr = _check_metric(item, "fpr_native", f"{path}.fpr_native", issues)
            tpr_native = (
                _check_metric(item, "tpr_native", f"{path}.tpr_native", issues)
                if item.get("tpr_native") is not None
                else None
            )
            if (
                isinstance(n_human, int)
                and not isinstance(n_human, bool)
                and isinstance(n_ai, int)
                and not isinstance(n_ai, bool)
            ):
                if auroc is not None and auroc.n > n_human + n_ai:
                    issues.append(f"{path}.auroc n cannot exceed the slice sample count.")
                if tpr_1 is not None and tpr_1.n > n_ai:
                    issues.append(f"{path}.tpr_at_fpr_0_01 n cannot exceed n_ai.")
                if tpr_5 is not None and tpr_5.n > n_ai:
                    issues.append(f"{path}.tpr_at_fpr_0_05 n cannot exceed n_ai.")
                if fpr is not None and fpr.n > n_human:
                    issues.append(f"{path}.fpr_native n cannot exceed n_human.")
                if tpr_native is not None and tpr_native.n > n_ai:
                    issues.append(f"{path}.tpr_native n cannot exceed n_ai.")
            _check_number_in_range(item, "coverage", f"{path}.coverage", issues)
            _check_number_in_range(item, "abstention_rate", f"{path}.abstention_rate", issues)
            if "worst_slice" not in item:
                issues.append(f"{path}.worst_slice is required.")
            elif not isinstance(item.get("worst_slice"), bool):
                issues.append(f"{path}.worst_slice must be a boolean.")

    limits = _check_group(payload, "limits", "limits", issues, _LIMITS_KEYS)
    if limits is not None:
        _check_string_list(limits, "known_failure_modes", "limits.known_failure_modes", issues)
        _check_string_list(limits, "limitations", "limits.limitations", issues)
        _check_date(limits, "next_revalidation_due", "limits.next_revalidation_due", issues)
        _check_string(limits, "appeal_note", "limits.appeal_note", issues, required=False)
        _check_string(limits, "reviewer", "limits.reviewer", issues, required=False)
        _check_date(limits, "review_date", "limits.review_date", issues, required=False)
        _check_string(limits, "demoted_by", "limits.demoted_by", issues, required=False)

    return issues


def validate_record(record_dict: Mapping[str, Any]) -> list[str]:
    """Return validation issues for a record dict (empty when valid).

    Issues cover structural checks (types, enums, hex formats, required
    fields — including the registration-blocking licence and contamination
    flag) and the partial cap: every missing mandatory-for-supported field
    is reported as ``missing mandatory field for supported status: <path>``.
    A record with only cap issues is loadable; its effective status is
    capped at ``partial`` by :func:`effective_status`.
    """
    if not isinstance(record_dict, Mapping):
        return ["record must be a JSON object."]
    issues = _structure_issues(record_dict)
    for path in missing_mandatory_fields(record_dict):
        issues.append(f"missing mandatory field for supported status: {path}")
    return issues


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------


def compute_signature(record: Mapping[str, Any] | ValidationRecord) -> str:
    """Compute the SHA-256 signature of a record (excluding ``signature``)."""
    payload = record.to_dict() if isinstance(record, ValidationRecord) else dict(record)
    unsigned = {key: value for key, value in payload.items() if key != "signature"}
    return hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()


def verify_signature(record: Mapping[str, Any] | ValidationRecord) -> bool:
    """Return True when a record's ``signature`` matches its contents."""
    payload = record.to_dict() if isinstance(record, ValidationRecord) else record
    if not isinstance(payload, Mapping):
        return False
    signature = payload.get("signature")
    if not isinstance(signature, str):
        return False
    try:
        expected = compute_signature(payload)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(signature, expected)


# ---------------------------------------------------------------------------
# Effective status, contamination
# ---------------------------------------------------------------------------


def effective_status(
    record: Mapping[str, Any] | ValidationRecord,
    *,
    detector_version: str,
    now: datetime | str | None = None,
) -> str:
    """Compute the effective status of a record.

    ``stale`` when the caller's detector version differs from the record's,
    when ``now`` is past ``limits.next_revalidation_due``, or when
    ``limits.demoted_by`` is set. Otherwise the stored status after the
    partial cap: a stored ``supported`` with missing mandatory-for-supported
    fields is capped at ``partial``. ``now`` accepts a datetime or an ISO
    string and defaults to the current UTC time. A record whose freshness
    cannot be established (missing or unparsable due date, version
    mismatch) is ``stale`` — fail-closed.
    """
    payload = record.to_dict() if isinstance(record, ValidationRecord) else record
    if not isinstance(payload, Mapping):
        return "unknown"
    if detector_version != payload.get("detector_version"):
        return "stale"
    limits = payload.get("limits")
    if isinstance(limits, Mapping) and limits.get("demoted_by"):
        return "stale"
    due_raw = limits.get("next_revalidation_due") if isinstance(limits, Mapping) else None
    try:
        due = _parse_date(due_raw, "limits.next_revalidation_due")
    except ValidationError:
        return "stale"
    try:
        current = _coerce_now(now)
    except ValidationError:
        return "stale"
    if current.date() > due:
        return "stale"
    stored = payload.get("status")
    if stored == "supported" and missing_mandatory_fields(payload):
        return "partial"
    if isinstance(stored, str) and stored:
        return stored
    return "unknown"


def contamination_label(record: Mapping[str, Any] | ValidationRecord) -> str | None:
    """Return the contamination label for a record, or None when clean.

    ``yes`` yields ``"contaminated — do not report as generalisation"``;
    ``unknown`` (or a missing flag, treated fail-closed as unknown) yields
    a caution label; ``no`` yields None.
    """
    payload = record.to_dict() if isinstance(record, ValidationRecord) else record
    flag = None
    if isinstance(payload, Mapping):
        data = payload.get("data")
        if isinstance(data, Mapping):
            flag = data.get("contamination_flag")
    if flag == "yes":
        return CONTAMINATED_LABEL
    if flag == "no":
        return None
    return CONTAMINATION_UNKNOWN_LABEL


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class ValidationRegistry:
    """A versioned, hash-identified collection of validation records."""

    def __init__(
        self,
        records: Iterable[ValidationRecord] = (),
        *,
        created_at_utc: str | None = None,
    ) -> None:
        self._records: tuple[ValidationRecord, ...] = tuple(records)
        ids = [record.record_id for record in self._records]
        if len(set(ids)) != len(ids):
            raise ValidationError("record_id values must be unique within a registry.")
        self._created_at_utc = created_at_utc or _now_utc().isoformat()
        _parse_iso8601(self._created_at_utc, "created_at_utc")
        self._registry_id = self._compute_registry_id()

    def _compute_registry_id(self) -> str:
        payload = {
            "schema": VALIDATION_REGISTRY_SCHEMA,
            "records": [record.to_dict() for record in self._ordered_records()],
        }
        return _sha256_payload(payload)

    def _ordered_records(self) -> tuple[ValidationRecord, ...]:
        return tuple(sorted(self._records, key=lambda record: record.record_id))

    @property
    def registry_id(self) -> str:
        return self._registry_id

    @property
    def created_at_utc(self) -> str:
        return self._created_at_utc

    @property
    def records(self) -> tuple[ValidationRecord, ...]:
        return self._ordered_records()

    def records_for(
        self,
        detector_id: str,
        detector_version: str | None = None,
    ) -> tuple[ValidationRecord, ...]:
        _require_nonempty_string(detector_id, "detector_id")
        selected = [record for record in self._records if record.detector_id == detector_id]
        if detector_version is not None:
            selected = [
                record for record in selected if record.detector_version == detector_version
            ]
        return tuple(sorted(selected, key=lambda record: record.record_id))

    def record(self, record_id: str) -> ValidationRecord | None:
        for record in self._records:
            if record.record_id == record_id:
                return record
        return None

    def detector_ids(self) -> tuple[str, ...]:
        return tuple(sorted({record.detector_id for record in self._records}))

    def matching(
        self,
        *,
        language: str | None = None,
        word_count: int | None = None,
        domain: str | None = None,
        editing_regime: str | None = None,
        generator_family: str | None = None,
        detector_id: str | None = None,
        detector_version: str | None = None,
    ) -> tuple[ValidationRecord, ...]:
        """Return records whose declared regime covers the query.

        Language matches exactly; word count must be at or above the
        record's length floor and at or below its maximum when one is set;
        domain must be in the record's domain list; editing regime matches
        exactly; generator family must be in the record's families. Any
        argument left as None is not filtered on. The caller applies the
        input-conditions-to-regime mapping (for example the editing-regime
        vocabulary mapping); this method compares record values only.
        """
        if word_count is not None:
            _require_int(word_count, "word_count")
        selected = list(self._records)
        if detector_id is not None:
            selected = [record for record in selected if record.detector_id == detector_id]
        if detector_version is not None:
            selected = [
                record for record in selected if record.detector_version == detector_version
            ]
        matched: list[ValidationRecord] = []
        for record in selected:
            regime = record.regime
            if language is not None and regime.language != language:
                continue
            if word_count is not None:
                bucket = regime.length_bucket
                if word_count < bucket.floor_words:
                    continue
                if bucket.max_words is not None and word_count > bucket.max_words:
                    continue
            if domain is not None and domain not in regime.domain:
                continue
            if editing_regime is not None and regime.editing_regime != editing_regime:
                continue
            if generator_family is not None and generator_family not in regime.generator.families:
                continue
            matched.append(record)
        return tuple(sorted(matched, key=lambda record: record.record_id))

    def summary(self) -> dict[str, Any]:
        statuses: dict[str, int] = {}
        for record in self._records:
            statuses[record.status] = statuses.get(record.status, 0) + 1
        return {
            "schema": VALIDATION_REGISTRY_SCHEMA,
            "registry_id": self._registry_id,
            "created_at_utc": self._created_at_utc,
            "record_count": len(self._records),
            "detector_ids": list(self.detector_ids()),
            "detector_count": len(self.detector_ids()),
            "statuses": dict(sorted(statuses.items())),
            "record_ids": [record.record_id for record in self._ordered_records()],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": VALIDATION_REGISTRY_SCHEMA,
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
    ) -> ValidationRegistry:
        if not isinstance(payload, Mapping):
            raise ValidationError("Validation registry must be a JSON object.")
        if payload.get("schema") != VALIDATION_REGISTRY_SCHEMA:
            raise ValidationError("Unsupported validation-registry schema.")
        raw_records = payload.get("records")
        if not isinstance(raw_records, list):
            raise ValidationError("Validation registry records must be an array.")
        records: list[ValidationRecord] = []
        for item in raw_records:
            issues = _structure_issues(item)
            if issues:
                raise ValidationError("Invalid validation record in registry: " + "; ".join(issues))
            record = ValidationRecord.from_dict(item)
            if not verify_signature(item):
                raise ValidationError(
                    f"Signature mismatch for validation record {record.record_id}."
                )
            records.append(record)
        registry = cls(records, created_at_utc=payload.get("created_at_utc"))
        supplied_id = payload.get("registry_id")
        if verify_id and supplied_id is not None and supplied_id != registry.registry_id:
            raise ValidationError("Validation registry hash does not match its contents.")
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
    def load(cls, path: str | Path, *, verify_id: bool = True) -> ValidationRegistry:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValidationError("Validation registry must be a JSON object.")
        return cls.from_dict(payload, verify_id=verify_id)


# ---------------------------------------------------------------------------
# Trust Map v3 derivation engine (Package B)
#
# derive_trust_map() derives the 8 evidence dimensions of a Trust Map v3
# from U1 ValidationRegistry records ONLY. It never reads the v1
# EvidenceRegistry. Live dimensions (detector_diversity, benign_stability)
# reuse trust.py's private helpers when live observations are supplied,
# else they are unknown with a reason.
#
# Matching rules (locked in the U1 design note):
# * unknown = no evidence speaks to the dimension at all (no records for
#   the detector, or the input condition itself is unobservable, e.g.
#   language "und").
# * out_of_scope = the registry HAS records for the detector but their
#   declared scope explicitly excludes this input (language, domain, word
#   count, generator family, or editing regime not covered).
# * stale = a matching record exists but its effective status is stale and
#   no non-stale matching record exists. The reason cites the stale record
#   id and why (version change / due date passed / demotion). Staleness is
#   always computed with the CURRENT detector_version and now, never
#   trusted from the stored status.
# * supported requires a matching record with effective status "supported"
#   AND n_human >= 100 AND n_ai >= 100 AND contamination_flag == "no".
#   Contamination "yes"/"unknown" caps the dimension at partial with the
#   contamination label; a contested record caps at partial; a record with
#   effective status "unknown" (or "partial") also caps at partial.
# * human_false_positive_evidence additionally requires an fpr_native
#   metric with CI and ci_upper <= fpr_ceiling for supported.
# * temporal_version_stability caps at partial from a single snapshot;
#   longitudinal data is U3's job. U3 lifts the cap only when
#   MIN_CLEAN_FULL_RUNS_FOR_TEMPORAL_SUPPORT consecutive clean
#   full-corpus probe runs exist at the detector version, supplied via
#   derive_trust_map(longitudinal=...).
# * Every dimension cites its matching record ids in evidence_refs.
# * Overall: strong iff all 10 dimensions are supported; insufficient iff
#   language or text_length is out_of_scope, or supported == 0 and
#   partial == 0; else mixed. Stale counts as neither supported nor
#   partial. Because temporal_version_stability caps at partial from a
#   single snapshot, a v3 map derived from U1 records alone is at most
#   mixed until U3 supplies longitudinal evidence.
# ---------------------------------------------------------------------------

#: Mapping from ``InputConditions`` editing regimes onto the U1 record
#: vocabulary. Records with ``LLM-edited``/``humanised`` regimes are stored
#: and citable but are NOT auto-matched by the v3 engine: no input
#: condition maps onto them, so they can never make a dimension
#: ``supported`` on their own. A future conditions extension can add them.
INPUT_EDITING_REGIME_MAP: dict[str, str] = {
    "machine_only": "raw",
    "human_only": "raw",
    "machine_then_human_edited": "human-edited",
    "machine_then_machine_paraphrased": "paraphrased",
    "mixed": "mixed-origin",
    "unknown": "unknown",
}

_TEMPORAL_SINGLE_SNAPSHOT_LIMITATION = (
    "A single snapshot cannot establish version stability; longitudinal data is U3's job."
)
# Consecutive clean U3 full-corpus runs at one detector version before
# temporal_version_stability may exceed partial (research §7.6; the
# number mirrors U3's 2-consecutive-runs persistence rule). The
# threshold lives here, not in probe_runs.py, because the Trust Map
# owns the rule; probe_runs.py imports it.
MIN_CLEAN_FULL_RUNS_FOR_TEMPORAL_SUPPORT = 2
_FPR_OPERATING_POINT_LIMITATION = (
    "FPR is measured at the detector's native categorical operating point; "
    "no score threshold is fitted."
)


def _stale_triggers(
    record: ValidationRecord,
    *,
    detector_version: str,
    now: datetime | str | None,
) -> tuple[str, ...]:
    """Return the reason(s) a record is effectively stale (empty when fresh)."""
    triggers: list[str] = []
    if detector_version != record.detector_version:
        triggers.append(
            f"detector version {detector_version!r} differs from the record's "
            f"version {record.detector_version!r}"
        )
    if record.limits.demoted_by:
        triggers.append(f"demoted by {record.limits.demoted_by}")
    try:
        due = _parse_date(record.limits.next_revalidation_due, "limits.next_revalidation_due")
    except ValidationError:
        triggers.append("next_revalidation_due is missing or unparsable")
    else:
        try:
            current = _coerce_now(now)
        except ValidationError:
            triggers.append("evaluation time could not be parsed")
        else:
            if current.date() > due:
                triggers.append(f"next_revalidation_due {due.isoformat()} has passed")
    return tuple(triggers)


# --- Regime-aspect matchers: one per Trust Map evidence dimension --------
# Each matcher answers "does this record's declared regime cover this
# aspect of the input?" The caller decides what an empty match set means
# for the dimension (unknown when the aspect is unobservable, else
# out_of_scope when records exist for the detector).


def _record_matches_language(record: ValidationRecord, conditions: InputConditions) -> bool:
    return record.regime.language == conditions.effective_language


def _record_matches_length(record: ValidationRecord, conditions: InputConditions) -> bool:
    bucket = record.regime.length_bucket
    if conditions.word_count < bucket.floor_words:
        return False
    return bucket.max_words is None or conditions.word_count <= bucket.max_words


def _record_matches_domain(record: ValidationRecord, conditions: InputConditions) -> bool:
    return conditions.effective_domain in record.regime.domain


def _record_matches_editing(record: ValidationRecord, conditions: InputConditions) -> bool:
    mapped = INPUT_EDITING_REGIME_MAP.get(conditions.effective_editing_regime, "unknown")
    return mapped != "unknown" and record.regime.editing_regime == mapped


def _record_matches_generator(record: ValidationRecord, conditions: InputConditions) -> bool:
    return (
        conditions.generator is not None
        and conditions.generator in record.regime.generator.families
    )


def _record_matches_population(record: ValidationRecord, conditions: InputConditions) -> bool:
    return (
        conditions.human_population != "unknown"
        and conditions.human_population in record.regime.human_population.populations
    )


def _record_matches_full_regime(record: ValidationRecord, conditions: InputConditions) -> bool:
    """True when a record covers the whole observable input regime.

    Language, length, domain, and editing must all match. Generator and
    human population are only required when the caller declared them; an
    undeclared generator/population does not exclude a record.
    """
    if not (
        _record_matches_language(record, conditions)
        and _record_matches_length(record, conditions)
        and _record_matches_domain(record, conditions)
        and _record_matches_editing(record, conditions)
    ):
        return False
    if conditions.generator is not None and not _record_matches_generator(record, conditions):
        return False
    if conditions.human_population == "unknown":
        return True
    return _record_matches_population(record, conditions)


def _fpr_blockers(record: ValidationRecord, fpr_ceiling: float) -> list[str]:
    """Blockers to ``supported`` for human_false_positive_evidence."""
    with_ci = [item for item in record.metrics if item.fpr_native.has_ci]
    if not with_ci:
        return ["no fpr_native metric carries a confidence interval"]
    best_upper = min(
        item.fpr_native.ci_upper for item in with_ci if item.fpr_native.ci_upper is not None
    )
    if best_upper > fpr_ceiling:
        return [
            f"best fpr_native ci_upper is {best_upper}, which exceeds the ceiling {fpr_ceiling}"
        ]
    return []


def _support_blockers(
    record: ValidationRecord,
    *,
    dimension: str,
    detector_version: str,
    now: datetime | str | None,
    fpr_ceiling: float,
    longitudinal_clean_runs: int = 0,
) -> list[str]:
    """Reasons a fresh matching record cannot yield ``supported``.

    An empty list means the record can support the dimension.
    """
    blockers: list[str] = []
    status = effective_status(record, detector_version=detector_version, now=now)
    if status != "supported":
        blockers.append(f"effective record status is {status!r}")
    if record.data.n_human < MIN_HUMAN_SAMPLES or record.data.n_ai < MIN_AI_SAMPLES:
        blockers.append(
            f"sample counts are thin (n_human={record.data.n_human}, "
            f"n_ai={record.data.n_ai}; at least {MIN_HUMAN_SAMPLES} each "
            "are required)"
        )
    label = contamination_label(record)
    if label is not None:
        blockers.append(label)
    if dimension == "human_false_positive_evidence":
        blockers.extend(_fpr_blockers(record, fpr_ceiling))
    if (
        dimension == "temporal_version_stability"
        and longitudinal_clean_runs < MIN_CLEAN_FULL_RUNS_FOR_TEMPORAL_SUPPORT
    ):
        # A single snapshot can never support version stability, however
        # fresh the record is; longitudinal data is U3's job. U3 lifts
        # the cap only when MIN_CLEAN_FULL_RUNS_FOR_TEMPORAL_SUPPORT
        # consecutive clean full-corpus runs exist at this detector
        # version (see derive_trust_map's ``longitudinal`` argument).
        blockers.append(
            "a single snapshot cannot establish version stability; longitudinal data is U3's job"
        )
    return blockers


def _validate_longitudinal(
    longitudinal: Mapping[str, Any] | None,
    *,
    detector_id: str,
    detector_version: str,
) -> dict[str, Any] | None:
    """Validate U3 longitudinal evidence for ``derive_trust_map``.

    Returns a normalised dict (or None when no evidence is supplied).
    Fail-closed: a mapping for another detector/version, a malformed
    fingerprint, or a negative run count raises instead of silently
    applying somebody else's longitudinal evidence to this map.
    """
    if longitudinal is None:
        return None
    if not isinstance(longitudinal, Mapping):
        raise ValidationError("longitudinal must be a mapping or None.")
    ev_detector = longitudinal.get("detector_id")
    ev_version = longitudinal.get("detector_version")
    if ev_detector != detector_id or ev_version != detector_version:
        raise ValidationError(
            "longitudinal evidence is for detector "
            f"{ev_detector!r} version {ev_version!r}, not {detector_id!r} "
            f"version {detector_version!r}; refusing to apply it."
        )
    fingerprint = longitudinal.get("corpus_fingerprint")
    if (
        not isinstance(fingerprint, str)
        or len(fingerprint) != 64
        or any(char not in "0123456789abcdef" for char in fingerprint.lower())
    ):
        raise ValidationError("longitudinal corpus_fingerprint must be a 64-character hex digest.")
    clean_runs = longitudinal.get("consecutive_clean_full_runs")
    if isinstance(clean_runs, bool) or not isinstance(clean_runs, int) or clean_runs < 0:
        raise ValidationError(
            "longitudinal consecutive_clean_full_runs must be a non-negative integer."
        )
    run_ids = longitudinal.get("clean_full_run_ids")
    if run_ids is None:
        run_ids = []
    if not isinstance(run_ids, (list, tuple)) or not all(
        isinstance(item, str) and item for item in run_ids
    ):
        raise ValidationError("longitudinal clean_full_run_ids must be a list of strings.")
    if len(run_ids) != clean_runs:
        raise ValidationError(
            "longitudinal clean_full_run_ids must list exactly consecutive_clean_full_runs run ids."
        )
    watch = longitudinal.get("watch")
    if watch is not None and not isinstance(watch, Mapping):
        raise ValidationError("longitudinal watch must be a mapping or None.")
    return {
        "detector_id": ev_detector,
        "detector_version": ev_version,
        "corpus_fingerprint": fingerprint,
        "consecutive_clean_full_runs": clean_runs,
        "clean_full_run_ids": list(run_ids),
        "watch": dict(watch) if watch is not None else None,
    }


def _derive_evidence_dimension(
    name: str,
    *,
    matching: tuple[ValidationRecord, ...],
    detector_records: tuple[ValidationRecord, ...],
    detector_id: str,
    detector_version: str,
    now: datetime | str | None,
    fpr_ceiling: float,
    unobservable: bool,
    unobservable_reason: str,
    out_of_scope_reason: str,
    out_of_scope_observed: dict[str, Any],
    longitudinal: dict[str, Any] | None = None,
) -> TrustDimension:
    """Derive one evidence dimension from its regime-matching records.

    ``matching`` is the subset of ``detector_records`` whose declared regime
    covers this dimension's aspect of the input. When ``matching`` is empty
    the dimension is ``unknown`` if the aspect itself is unobservable, else
    ``out_of_scope`` (records exist for the detector but exclude the input).
    When every matching record is stale the dimension is ``stale``; when at
    least one fresh matching record can support the dimension it is
    ``supported``; any fresh matching record that cannot support it yields
    ``partial`` with the blocker named.
    """
    record_ids = sorted({record.record_id for record in matching})
    if not detector_records:
        return TrustDimension(
            dimension=name,
            state="unknown",
            reason=f"No validation records exist for detector {detector_id!r}.",
            observed={"record_count_for_detector": 0},
            detectors={detector_id: "unknown"},
        )
    if unobservable:
        return TrustDimension(
            dimension=name,
            state="unknown",
            reason=unobservable_reason,
            detectors={detector_id: "unknown"},
        )
    if not matching:
        return TrustDimension(
            dimension=name,
            state="out_of_scope",
            reason=out_of_scope_reason,
            observed=out_of_scope_observed,
            detectors={detector_id: "out_of_scope"},
        )

    limitations: list[str] = []
    for record in matching:
        label = contamination_label(record)
        if label is not None and label not in limitations:
            limitations.append(label)
    if any(
        effective_status(record, detector_version=detector_version, now=now) == "contested"
        for record in matching
    ):
        limitations.append("A matching record is contested; it can never yield supported.")
    clean_runs = int(longitudinal["consecutive_clean_full_runs"]) if longitudinal else 0
    if name == "temporal_version_stability":
        if clean_runs < MIN_CLEAN_FULL_RUNS_FOR_TEMPORAL_SUPPORT:
            limitations.append(_TEMPORAL_SINGLE_SNAPSHOT_LIMITATION)
        elif longitudinal is not None and longitudinal.get("watch") is not None:
            limitations.append(
                "A U3 observatory watch is active for this detector; "
                "human review is required (see u3_watch in observed)."
            )
    if name == "human_false_positive_evidence":
        limitations.append(_FPR_OPERATING_POINT_LIMITATION)

    fresh = tuple(
        record
        for record in matching
        if effective_status(record, detector_version=detector_version, now=now) != "stale"
    )
    if not fresh:
        triggers: list[str] = []
        for record in matching:
            for trigger in _stale_triggers(record, detector_version=detector_version, now=now):
                triggers.append(f"{record.record_id}: {trigger}")
        if not triggers:  # pragma: no cover - effective_status said stale
            triggers = [
                f"{record.record_id}: stale for an unspecified reason" for record in matching
            ]
        return TrustDimension(
            dimension=name,
            state="stale",
            reason="Matching record(s) are stale: " + "; ".join(triggers) + ".",
            evidence_refs=record_ids,
            observed={"record_ids": record_ids},
            limitations=limitations,
            detectors={detector_id: "stale"},
        )

    supporting = tuple(
        record
        for record in fresh
        if not _support_blockers(
            record,
            dimension=name,
            detector_version=detector_version,
            now=now,
            fpr_ceiling=fpr_ceiling,
            longitudinal_clean_runs=clean_runs,
        )
    )
    if supporting:
        supporting_ids = sorted({record.record_id for record in supporting})
        reason = (
            f"Matching record(s) {', '.join(supporting_ids)} cover this input "
            f"with effective status supported, n_human >= {MIN_HUMAN_SAMPLES}, "
            f"n_ai >= {MIN_AI_SAMPLES}, and no contamination."
        )
        observed: dict[str, Any] = {"record_ids": record_ids}
        if name == "temporal_version_stability" and longitudinal is not None:
            observed["u3_clean_full_runs"] = clean_runs
            observed["u3_clean_full_run_ids"] = list(longitudinal["clean_full_run_ids"])
            observed["u3_corpus_fingerprint"] = longitudinal["corpus_fingerprint"]
            reason += (
                f" Longitudinal U3 evidence: {clean_runs} consecutive clean "
                "full-corpus probe runs at this detector version "
                f"({', '.join(longitudinal['clean_full_run_ids'])})."
            )
            if longitudinal.get("watch") is not None:
                observed["u3_watch"] = dict(longitudinal["watch"])
        if name == "human_false_positive_evidence":
            best_upper = min(
                item.fpr_native.ci_upper
                for record in supporting
                for item in record.metrics
                if item.fpr_native.has_ci and item.fpr_native.ci_upper is not None
            )
            observed["fpr_ci_upper"] = best_upper
            observed["fpr_ceiling"] = fpr_ceiling
            reason += f" Best fpr_native ci_upper is {best_upper} (ceiling {fpr_ceiling})."
        return TrustDimension(
            dimension=name,
            state="supported",
            reason=reason,
            evidence_refs=record_ids,
            observed=observed,
            limitations=limitations,
            detectors={detector_id: "supported"},
        )

    details = []
    for record in fresh:
        blockers = _support_blockers(
            record,
            dimension=name,
            detector_version=detector_version,
            now=now,
            fpr_ceiling=fpr_ceiling,
            longitudinal_clean_runs=clean_runs,
        )
        details.append(f"{record.record_id}: {'; '.join(blockers)}")
    observed_partial: dict[str, Any] = {"record_ids": record_ids}
    if name == "temporal_version_stability" and longitudinal is not None:
        observed_partial["u3_clean_full_runs"] = clean_runs
        observed_partial["u3_clean_full_run_ids"] = list(longitudinal["clean_full_run_ids"])
        observed_partial["u3_corpus_fingerprint"] = longitudinal["corpus_fingerprint"]
        if longitudinal.get("watch") is not None:
            observed_partial["u3_watch"] = dict(longitudinal["watch"])
    return TrustDimension(
        dimension=name,
        state="partial",
        reason=(
            f"Matching record(s) {', '.join(record_ids)} cover this input but "
            f"cannot support {name}: " + " | ".join(details) + "."
        ),
        evidence_refs=record_ids,
        observed=observed_partial,
        limitations=limitations,
        detectors={detector_id: "partial"},
    )


def _overall_state_v3(dimensions: list[TrustDimension]) -> str:
    """Overall state for a Trust Map v3.

    Strong iff every dimension is supported; insufficient iff language or
    text_length is out_of_scope, or no dimension is supported or partial;
    else mixed. Stale counts as neither supported nor partial. An empty
    dimension list yields insufficient, never strong (0 == 0 must not
    report "strong" for no evidence), mirroring
    ``verify._recompute_overall_v3`` and the v2 behaviour.
    """
    by_name = {item.dimension: item.state for item in dimensions}
    supported = sum(state == "supported" for state in by_name.values())
    partial = sum(state == "partial" for state in by_name.values())
    if by_name.get("language") == "out_of_scope" or by_name.get("text_length") == "out_of_scope":
        return "insufficient"
    if not dimensions:
        return "insufficient"
    if supported == len(dimensions):
        return "strong"
    if supported == 0 and partial == 0:
        return "insufficient"
    return "mixed"


def _live_dimensions(
    predictions: list[DetectorPrediction],
    robustness: list[Mapping[str, Any]],
    failure_count: int,
) -> tuple[TrustDimension, TrustDimension]:
    """Live dimensions from observations, else unknown with a reason."""
    if predictions:
        diversity = _diversity_dimension(predictions, failure_count)
    else:
        diversity = TrustDimension(
            dimension="detector_diversity",
            state="unknown",
            reason=(
                "No detector observations were supplied, so detector diversity cannot be assessed."
            ),
            limitations=[
                "Family labels are methodological metadata; empirical error "
                "correlation has not been measured here."
            ],
        )
    if robustness:
        # 0.10 mirrors assess_trust_map's default max_native_drift.
        stability = _stability_dimension(robustness, max_native_drift=0.10)
    else:
        stability = TrustDimension(
            dimension="benign_stability",
            state="unknown",
            reason=(
                "No benign-transformation probes were supplied, so benign "
                "stability cannot be assessed."
            ),
            limitations=[
                "Representation probes are not semantic rewrites and do not "
                "establish paraphrase robustness."
            ],
        )
    return diversity, stability


def derive_trust_map(
    conditions: InputConditions,
    registry: ValidationRegistry,
    *,
    detector_id: str,
    detector_version: str,
    now: datetime | str | None = None,
    fpr_ceiling: float = DEFAULT_FPR_CEILING,
    predictions: Iterable[DetectorPrediction] = (),
    robustness: Iterable[Mapping[str, Any]] = (),
    failure_count: int = 0,
    longitudinal: Mapping[str, Any] | None = None,
) -> TrustMap:
    """Derive a Trust Map v3 for one input condition set from U1 records.

    The 8 evidence dimensions are derived from ``registry`` records for
    ``detector_id`` ONLY — the v1 ``EvidenceRegistry`` is never consulted.
    A dimension is ``supported`` only when a regime-matching record has
    effective status ``supported`` (computed with the CURRENT
    ``detector_version`` and ``now``, never trusted from the stored
    status), n_human >= 100 and n_ai >= 100, and contamination_flag
    ``"no"``. Contamination ``"yes"``/``"unknown"`` and contested records
    cap at ``partial``. ``human_false_positive_evidence`` additionally
    requires an ``fpr_native`` metric with CI and ci_upper <=
    ``fpr_ceiling``. ``temporal_version_stability`` caps at ``partial``
    from a single snapshot, unless ``longitudinal`` (U3 probe-run
    evidence, see ``probe_runs.summarize_longitudinal``) shows at least
    ``MIN_CLEAN_FULL_RUNS_FOR_TEMPORAL_SUPPORT`` consecutive clean
    full-corpus runs at this detector version — then, and only then,
    may it be ``supported``. An active U3 watch (``longitudinal``'s
    ``watch``) is surfaced on the temporal dimension's ``observed``
    (``u3_watch``) and in the map limitations; it never changes a state
    by itself. The 2 live dimensions reuse trust.py's private helpers
    private helpers when ``predictions``/``robustness`` observations are
    supplied, else they are ``unknown`` with a reason.

    Input editing regimes are mapped onto the record vocabulary as
    machine_only/human_only -> raw, machine_then_human_edited ->
    human-edited, machine_then_machine_paraphrased -> paraphrased, mixed
    -> mixed-origin, unknown -> unknown. Records with ``LLM-edited`` or
    ``humanised`` regimes are stored but not auto-matched by this engine
    (documented limitation).

    Overall is ``strong`` iff all 10 dimensions are supported,
    ``insufficient`` iff language or text_length is out_of_scope or no
    dimension is supported or partial, else ``mixed``. Because temporal
    stability caps at partial from a single snapshot, a v3 map derived
    from U1 records alone is at most ``mixed`` until U3 supplies
    longitudinal evidence.
    """
    if not isinstance(conditions, InputConditions):
        raise TypeError("conditions must be an InputConditions instance.")
    if not isinstance(registry, ValidationRegistry):
        raise TypeError("registry must be a ValidationRegistry instance.")
    detector_id = _require_nonempty_string(detector_id, "detector_id")
    detector_version = _require_nonempty_string(detector_version, "detector_version")
    longitudinal = _validate_longitudinal(
        longitudinal, detector_id=detector_id, detector_version=detector_version
    )
    if isinstance(fpr_ceiling, bool) or not isinstance(fpr_ceiling, (int, float)):
        raise TypeError("fpr_ceiling must be a number.")
    if not 0.0 <= float(fpr_ceiling) <= 1.0:
        raise ValueError("fpr_ceiling must be between 0 and 1.")
    if isinstance(failure_count, bool) or not isinstance(failure_count, int):
        raise TypeError("failure_count must be an integer.")
    if failure_count < 0:
        raise ValueError("failure_count must be non-negative.")
    prediction_list = list(predictions)
    robustness_list = list(robustness)

    records = registry.records_for(detector_id)
    language = conditions.effective_language
    domain = conditions.effective_domain
    mapped_editing = INPUT_EDITING_REGIME_MAP.get(conditions.effective_editing_regime, "unknown")
    common = {
        "detector_records": records,
        "detector_id": detector_id,
        "detector_version": detector_version,
        "now": now,
        "fpr_ceiling": fpr_ceiling,
        "longitudinal": longitudinal,
    }

    dimensions: list[TrustDimension] = []
    # language: unknown when the input language itself is unobservable
    # ("und"); out_of_scope when records exist but none covers it.
    dimensions.append(
        _derive_evidence_dimension(
            "language",
            matching=tuple(
                record for record in records if _record_matches_language(record, conditions)
            ),
            unobservable=language == "und",
            unobservable_reason=(
                "The input language could not be determined (und), so no "
                "language evidence can be matched."
            ),
            out_of_scope_reason=(
                f"Records exist for detector {detector_id!r} but none covers language {language!r}."
            ),
            out_of_scope_observed={
                "languages_covered": sorted({record.regime.language for record in records})
            },
            **common,
        )
    )
    # text_length: always observable (word count); out_of_scope when the
    # word count is below every record's floor (or above every maximum).
    dimensions.append(
        _derive_evidence_dimension(
            "text_length",
            matching=tuple(
                record for record in records if _record_matches_length(record, conditions)
            ),
            unobservable=False,
            unobservable_reason="",
            out_of_scope_reason=(
                f"Input word count {conditions.word_count} is outside every "
                f"record's length bucket for detector {detector_id!r}."
            ),
            out_of_scope_observed={
                "length_floors": sorted(
                    {record.regime.length_bucket.floor_words for record in records}
                ),
                "length_maxima": sorted(
                    {
                        record.regime.length_bucket.max_words
                        for record in records
                        if record.regime.length_bucket.max_words is not None
                    }
                ),
            },
            **common,
        )
    )
    # domain_genre: unknown when the domain itself is unobservable
    # ("unknown"); out_of_scope when records exist but none covers it.
    dimensions.append(
        _derive_evidence_dimension(
            "domain_genre",
            matching=tuple(
                record for record in records if _record_matches_domain(record, conditions)
            ),
            unobservable=domain == "unknown",
            unobservable_reason=(
                "The input domain could not be determined (unknown), so no "
                "domain evidence can be matched."
            ),
            out_of_scope_reason=(
                f"Records exist for detector {detector_id!r} but none covers domain {domain!r}."
            ),
            out_of_scope_observed={
                "domains_covered": sorted(
                    {item for record in records for item in record.regime.domain}
                )
            },
            **common,
        )
    )
    # editing_revision: unknown when the input editing regime is
    # undeclared ("unknown"); out_of_scope when records exist but none
    # covers the mapped regime. LLM-edited/humanised records never match
    # here: no input condition maps onto them.
    dimensions.append(
        _derive_evidence_dimension(
            "editing_revision",
            matching=tuple(
                record for record in records if _record_matches_editing(record, conditions)
            ),
            unobservable=mapped_editing == "unknown",
            unobservable_reason=(
                "The input editing regime is unknown, so no editing evidence can be matched."
            ),
            out_of_scope_reason=(
                f"Records exist for detector {detector_id!r} but none covers "
                f"editing regime {mapped_editing!r} (input "
                f"{conditions.editing_regime!r}). Records with LLM-edited or "
                "humanised regimes are stored but not auto-matched."
            ),
            out_of_scope_observed={
                "editing_regimes_covered": sorted(
                    {record.regime.editing_regime for record in records}
                )
            },
            **common,
        )
    )
    # generator_scope: unknown when no generator was declared (None);
    # out_of_scope when records exist but none lists the family.
    dimensions.append(
        _derive_evidence_dimension(
            "generator_scope",
            matching=tuple(
                record for record in records if _record_matches_generator(record, conditions)
            ),
            unobservable=conditions.generator is None,
            unobservable_reason=(
                "No generator was declared for the input, so no generator evidence can be matched."
            ),
            out_of_scope_reason=(
                f"Records exist for detector {detector_id!r} but none lists "
                f"generator family {conditions.generator!r}."
            ),
            out_of_scope_observed={
                "generator_families_covered": sorted(
                    {family for record in records for family in record.regime.generator.families}
                )
            },
            **common,
        )
    )
    # human_population: unknown when the population is undeclared
    # ("unknown"); out_of_scope when records exist but none covers it.
    dimensions.append(
        _derive_evidence_dimension(
            "human_population",
            matching=tuple(
                record for record in records if _record_matches_population(record, conditions)
            ),
            unobservable=conditions.human_population == "unknown",
            unobservable_reason=(
                "No human population was declared for the input, so no "
                "human-population evidence can be matched."
            ),
            out_of_scope_reason=(
                f"Records exist for detector {detector_id!r} but none covers "
                f"human population {conditions.human_population!r}."
            ),
            out_of_scope_observed={
                "human_populations_covered": sorted(
                    {
                        item
                        for record in records
                        for item in record.regime.human_population.populations
                    }
                )
            },
            **common,
        )
    )
    # human_false_positive_evidence and temporal_version_stability are
    # regime-level dimensions: a record speaks to them only when it covers
    # the whole observable input regime. When the core regime itself is
    # unobservable (language und, domain unknown, or editing unknown) the
    # dimension is unknown, not out_of_scope; when records exist but none
    # covers the full regime, it is out_of_scope.
    full_matching = tuple(
        record for record in records if _record_matches_full_regime(record, conditions)
    )
    unobservable_aspects = [
        label
        for label, is_unknown in (
            ("language und", language == "und"),
            ("domain unknown", domain == "unknown"),
            ("editing regime unknown", mapped_editing == "unknown"),
        )
        if is_unknown
    ]
    regime_unobservable = bool(unobservable_aspects)
    regime_unobservable_reason = (
        "The input regime cannot be observed ("
        + ", ".join(unobservable_aspects)
        + "), so no false-positive or version-stability evidence can be "
        "tied to it."
    )
    regime_out_of_scope_reason = (
        f"Records exist for detector {detector_id!r} but none covers the "
        f"full input regime (language {language!r}, "
        f"{conditions.word_count} words, domain {domain!r}, editing "
        f"{mapped_editing!r})."
    )
    regime_out_of_scope_observed = {"record_count_for_detector": len(records)}
    dimensions.append(
        _derive_evidence_dimension(
            "human_false_positive_evidence",
            matching=full_matching,
            unobservable=regime_unobservable,
            unobservable_reason=regime_unobservable_reason,
            out_of_scope_reason=regime_out_of_scope_reason,
            out_of_scope_observed=regime_out_of_scope_observed,
            **common,
        )
    )
    dimensions.append(
        _derive_evidence_dimension(
            "temporal_version_stability",
            matching=full_matching,
            unobservable=regime_unobservable,
            unobservable_reason=regime_unobservable_reason,
            out_of_scope_reason=regime_out_of_scope_reason,
            out_of_scope_observed=regime_out_of_scope_observed,
            **common,
        )
    )
    assert [item.dimension for item in dimensions] == list(EVIDENCE_DIMENSIONS)
    dimensions.extend(_live_dimensions(prediction_list, robustness_list, failure_count))

    limitations = [
        "Trust Map states describe evidence coverage, not probability of authorship.",
        "Trust Map v3 states are derived from U1 validation records only; "
        "the v1 EvidenceRegistry is never consulted.",
        "A supported state requires a matching U1 record with effective "
        "status supported, at least 100 human and 100 AI samples, and no "
        "contamination.",
        "Temporal version stability is capped at partial from a single "
        "snapshot; longitudinal data is U3's job.",
        "Text-only detection cannot prove authorship.",
    ]
    if longitudinal is not None:
        clean_runs = int(longitudinal["consecutive_clean_full_runs"])
        limitations.append(
            f"Longitudinal U3 evidence supplied: {clean_runs} consecutive "
            "clean full-corpus probe runs at this detector version "
            f"({', '.join(longitudinal['clean_full_run_ids'])}); "
            f"{MIN_CLEAN_FULL_RUNS_FOR_TEMPORAL_SUPPORT} are needed before "
            "temporal_version_stability may exceed partial."
        )
        if longitudinal.get("watch") is not None:
            watch = longitudinal["watch"]
            limitations.append(
                "U3 observatory watch active: Tier-2 alert(s) on probe run "
                f"{watch.get('run_id')} ({watch.get('run_at_utc')}); human "
                "review required."
            )
    if not records:
        limitations.append(f"No validation records exist for detector {detector_id!r}.")

    try:
        generated_at_utc = _coerce_now(now).isoformat()
    except ValidationError:
        generated_at_utc = datetime.now(UTC).isoformat()

    return TrustMap(
        schema=TRUST_SCHEMA_V3,
        overall=_overall_state_v3(dimensions),
        dimensions=dimensions,
        limitations=limitations,
        input_conditions=conditions.to_dict(),
        evidence_registry={
            "registry_id": registry.registry_id,
            "record_count": len(registry.records),
            "verified": False,
            "verification_status": "not_checked",
        },
        coverage=_coverage_counts(dimensions, TRUST_STATES_V3),
        generated_at_utc=generated_at_utc,
    )


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------


def load_validation_registry(path: str | Path, *, verify_id: bool = True) -> ValidationRegistry:
    return ValidationRegistry.load(path, verify_id=verify_id)


def empty_validation_registry() -> ValidationRegistry:
    return ValidationRegistry((), created_at_utc="1970-01-01T00:00:00+00:00")


__all__ = [
    "CONTAMINATED_LABEL",
    "CONTAMINATION_FLAGS",
    "CONTAMINATION_UNKNOWN_LABEL",
    "DEFAULT_REVALIDATION_DAYS",
    "MIN_CLEAN_FULL_RUNS_FOR_TEMPORAL_SUPPORT",
    "EDITING_REGIMES",
    "EVIDENCE_RECORD_SCHEMA",
    "INPUT_EDITING_REGIME_MAP",
    "SPLIT_ROLES",
    "VALIDATION_REGISTRY_SCHEMA",
    "VALIDATION_STATUSES",
    "DropItem",
    "GeneratorInfo",
    "HumanPopulation",
    "LengthBucket",
    "RecordData",
    "RecordLimits",
    "Regime",
    "RunInfo",
    "SliceMetrics",
    "ValidationError",
    "ValidationRecord",
    "ValidationRegistry",
    "canonical_json_bytes",
    "compute_signature",
    "contamination_label",
    "default_next_revalidation_due",
    "derive_trust_map",
    "effective_status",
    "empty_validation_registry",
    "load_validation_registry",
    "missing_mandatory_fields",
    "validate_record",
    "verify_signature",
]
