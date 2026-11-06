"""Detector-local calibration artifacts and maps.

A detector score is *not* a probability.  This module implements the
calibration contract defined in ``docs/REVAMP_SPEC.md``:

* explicit, mathematically correct calibration maps (Platt, temperature,
  isotonic, beta, and a diagnostic-only identity map);
* artifacts that carry fit/evaluation dataset provenance;
* fail-closed eligibility: a probability may only be emitted from an
  artifact that records a held-out, disjoint evaluation with metrics;
* deterministic serialization and content hashing.

This module never produces an ensemble probability.  Detector-local
calibration is not ensemble calibration (AGENTS.md, hard rule 3).
"""

from __future__ import annotations

import bisect
import contextlib
import hashlib
import json
import math
import os
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

__all__ = [
    "CALIBRATION_SCHEMA",
    "CURVE_SCHEMA",
    "SUPPORTED_METHODS",
    "DIAGNOSTIC_METHODS",
    "MIN_CALIBRATION_SAMPLES",
    "CalibrationCurve",
    "CalibrationArtifact",
    "CalibrationResult",
    "CalibrationManager",
    "CalibrationError",
    "DatasetReference",
    "validate_calibration_artifact",
    "create_calibration_manager",
    "load_calibration_artifact",
    "save_calibration_artifact",
]

CALIBRATION_SCHEMA = "textforensics.calibration-artifact/v2"
CURVE_SCHEMA = "textforensics.calibration-curve/v2"
SUPPORTED_METHODS = frozenset({"platt", "temperature", "isotonic", "beta", "identity"})
DIAGNOSTIC_METHODS = frozenset({"identity"})
#: Minimum held-out evaluation size for probability eligibility.  This is a
#: product policy, chosen to make a calibration artifact auditable.  It is
#: recorded in the artifact and can be raised by callers, never lowered
#: silently.
MIN_CALIBRATION_SAMPLES = 100
_HELD_OUT_SPLIT_HINTS = frozenset(
    {"test", "eval", "evaluation", "heldout", "held-out", "holdout", "validation", "dev"}
)
_HEX_DIGITS = frozenset("0123456789abcdef")


class CalibrationError(ValueError):
    """Raised when a calibration map or artifact violates the contract."""


# ---------------------------------------------------------------------------
# Math helpers
# ---------------------------------------------------------------------------


def _sigmoid(value: float) -> float:
    """Numerically stable logistic function."""
    if value >= 0.0:
        z = math.exp(-value)
        return 1.0 / (1.0 + z)
    z = math.exp(value)
    return z / (1.0 + z)


def _finite_number(value: Any, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CalibrationError(f"{field_name} must be a finite number.")
    number = float(value)
    if not math.isfinite(number):
        raise CalibrationError(f"{field_name} must be finite.")
    return number


def _unit_interval(value: Any, field_name: str) -> float:
    number = _finite_number(value, field_name)
    if not 0.0 <= number <= 1.0:
        raise CalibrationError(f"{field_name} must lie in [0, 1].")
    return number


def _nonempty_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CalibrationError(f"{field_name} must be a non-empty string.")
    return value


def _sha256_hex(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise CalibrationError(f"{field_name} must be a 64-character SHA-256 hex string.")
    if any(character not in _HEX_DIGITS for character in value):
        raise CalibrationError(f"{field_name} must be lowercase hexadecimal.")
    return value


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _canonical_json(payload: Any) -> str:
    return json.dumps(
        payload,
        separators=(",", ":"),
        ensure_ascii=False,
        sort_keys=True,
        allow_nan=False,
    )


def _compute_content_hash(content: Any) -> str:
    return hashlib.sha256(_canonical_json(content).encode("utf-8")).hexdigest()


def _parse_iso8601(value: Any, field_name: str) -> datetime:
    text = _nonempty_string(value, field_name)
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise CalibrationError(f"{field_name} must be ISO-8601.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


# ---------------------------------------------------------------------------
# Curves
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CalibrationCurve:
    """A validated detector-local score-to-probability map.

    ``parameters`` are method-specific:

    * ``platt``: ``{"A": float, "B": float}`` → ``sigmoid(A*x + B)``
    * ``temperature``: ``{"T": float > 0}`` → ``sigmoid(x / T)``
    * ``isotonic``: ``{"x": [...], "y": [...]}`` → piecewise-linear monotone map
    * ``beta``: ``{"a": float >= 0, "b": float >= 0, "c": float}`` →
      ``sigmoid(a*ln(x) - b*ln(1-x) + c)`` (Kull et al., 2017)
    * ``identity``: no parameters; diagnostic only, never probability-eligible

    ``x`` is a native detector score on the documented ``[0, 1]`` scale.
    Out-of-range scores raise :class:`CalibrationError`; they are never
    silently clipped or passed through.
    """

    method: str
    parameters: Mapping[str, Any]
    reference_dataset_hash: str = ""
    reference_dataset_name: str = ""
    calibrated_at: str = ""
    sample_count: int = 0
    calibration_error: float | None = None
    schema: str = CURVE_SCHEMA
    native_score_direction: str = "higher_means_ai"
    score_range: tuple[float, float] = (0.0, 1.0)

    def __post_init__(self) -> None:
        if self.method not in SUPPORTED_METHODS:
            raise CalibrationError(
                f"Unsupported calibration method {self.method!r}; "
                f"expected one of {', '.join(sorted(SUPPORTED_METHODS))}."
            )
        if self.schema != CURVE_SCHEMA:
            raise CalibrationError("Unsupported calibration-curve schema.")
        if not isinstance(self.parameters, Mapping):
            raise CalibrationError("parameters must be a mapping.")
        if self.native_score_direction not in {
            "higher_means_ai",
            "lower_means_ai",
            "not_applicable",
            "unknown",
        }:
            raise CalibrationError("Invalid native_score_direction.")
        if isinstance(self.sample_count, bool) or not isinstance(self.sample_count, int):
            raise CalibrationError("sample_count must be an integer.")
        if self.sample_count < 0:
            raise CalibrationError("sample_count must be non-negative.")
        if self.calibration_error is not None:
            _unit_interval(self.calibration_error, "calibration_error")
        self._validate_score_range()
        self._validate_parameters()

    def _validate_score_range(self) -> None:
        if not isinstance(self.score_range, (tuple, list)) or len(self.score_range) != 2:
            raise CalibrationError("score_range must be a (min, max) pair.")
        minimum = _finite_number(self.score_range[0], "score_range[0]")
        maximum = _finite_number(self.score_range[1], "score_range[1]")
        if minimum >= maximum:
            raise CalibrationError("score_range minimum must be below maximum.")
        object.__setattr__(self, "score_range", (minimum, maximum))

    def _validate_parameters(self) -> None:
        parameters = self.parameters
        if self.method == "platt":
            coefficient = _finite_number(parameters.get("A"), "parameters.A")
            _finite_number(parameters.get("B"), "parameters.B")
            if coefficient == 0.0:
                raise CalibrationError("Platt coefficient A must be non-zero.")
        elif self.method == "temperature":
            temperature = _finite_number(parameters.get("T"), "parameters.T")
            if temperature <= 0.0:
                raise CalibrationError("Temperature T must be positive.")
        elif self.method == "beta":
            a = _finite_number(parameters.get("a"), "parameters.a")
            b = _finite_number(parameters.get("b"), "parameters.b")
            _finite_number(parameters.get("c", 0.0), "parameters.c")
            if a < 0.0 or b < 0.0:
                raise CalibrationError("Beta-calibration a and b must be non-negative.")
            if a == 0.0 and b == 0.0:
                raise CalibrationError(
                    "Beta-calibration a and b cannot both be zero (degenerate map)."
                )
        elif self.method == "isotonic":
            x_values = parameters.get("x")
            y_values = parameters.get("y")
            if not isinstance(x_values, (list, tuple)) or not isinstance(y_values, (list, tuple)):
                raise CalibrationError("Isotonic parameters require x and y sequences.")
            if len(x_values) != len(y_values):
                raise CalibrationError("Isotonic x and y must have the same length.")
            if len(x_values) < 2:
                raise CalibrationError("Isotonic maps require at least two points.")
            parsed_x = [_unit_interval(item, "isotonic x") for item in x_values]
            parsed_y = [_unit_interval(item, "isotonic y") for item in y_values]
            if any(parsed_x[index] >= parsed_x[index + 1] for index in range(len(parsed_x) - 1)):
                raise CalibrationError("Isotonic x values must be strictly increasing.")
            if any(parsed_y[index] > parsed_y[index + 1] for index in range(len(parsed_y) - 1)):
                raise CalibrationError("Isotonic y values must be non-decreasing.")
            object.__setattr__(
                self,
                "parameters",
                {"x": parsed_x, "y": parsed_y},
            )
        elif parameters:
            raise CalibrationError("Identity calibration takes no parameters.")

    @property
    def is_diagnostic_only(self) -> bool:
        return self.method in DIAGNOSTIC_METHODS

    def calibrate(self, score: float) -> float:
        """Apply the map to a native score in ``[0, 1]``."""
        value = _unit_interval(score, "score")
        if self.method == "platt":
            return _sigmoid(float(self.parameters["A"]) * value + float(self.parameters["B"]))
        if self.method == "temperature":
            return _sigmoid(value / float(self.parameters["T"]))
        if self.method == "isotonic":
            return self._calibrate_isotonic(value)
        if self.method == "beta":
            return self._calibrate_beta(value)
        if self.method == "identity":
            return value
        # Unreachable because __post_init__ rejects unknown methods, but keep
        # the failure explicit rather than falling back to the raw score.
        raise CalibrationError(f"Unsupported calibration method {self.method!r}.")

    def _calibrate_isotonic(self, value: float) -> float:
        x_values: list[float] = list(self.parameters["x"])
        y_values: list[float] = list(self.parameters["y"])
        if value <= x_values[0]:
            return y_values[0]
        if value >= x_values[-1]:
            return y_values[-1]
        upper = bisect.bisect_right(x_values, value)
        lower = upper - 1
        x0, x1 = x_values[lower], x_values[upper]
        y0, y1 = y_values[lower], y_values[upper]
        fraction = (value - x0) / (x1 - x0)
        return y0 + fraction * (y1 - y0)

    def _calibrate_beta(self, value: float) -> float:
        a = float(self.parameters["a"])
        b = float(self.parameters["b"])
        c = float(self.parameters.get("c", 0.0))
        left = (-math.inf if a > 0.0 else 0.0) if value <= 0.0 else a * math.log(value)
        right = (math.inf if b > 0.0 else 0.0) if value >= 1.0 else -b * math.log1p(-value)
        return _sigmoid(left + right + c)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "method": self.method,
            "parameters": dict(self.parameters),
            "reference_dataset_hash": self.reference_dataset_hash,
            "reference_dataset_name": self.reference_dataset_name,
            "calibrated_at": self.calibrated_at,
            "sample_count": self.sample_count,
            "calibration_error": self.calibration_error,
            "native_score_direction": self.native_score_direction,
            "score_range": list(self.score_range),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CalibrationCurve:
        if not isinstance(data, Mapping):
            raise CalibrationError("Calibration curve must be a mapping.")
        method = _nonempty_string(data.get("method"), "method")
        score_range = data.get("score_range", [0.0, 1.0])
        if not isinstance(score_range, (list, tuple)) or len(score_range) != 2:
            raise CalibrationError("score_range must be a two-element sequence.")
        return cls(
            method=method,
            parameters=dict(data.get("parameters", {})),
            reference_dataset_hash=str(data.get("reference_dataset_hash", "")),
            reference_dataset_name=str(data.get("reference_dataset_name", "")),
            calibrated_at=str(data.get("calibrated_at", "")),
            sample_count=int(data.get("sample_count", 0)),
            calibration_error=data.get("calibration_error"),
            schema=str(data.get("schema", CURVE_SCHEMA)),
            native_score_direction=str(data.get("native_score_direction", "higher_means_ai")),
            score_range=(float(score_range[0]), float(score_range[1])),
        )


# ---------------------------------------------------------------------------
# Dataset references and artifacts
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DatasetReference:
    """A fingerprinted dataset split used to fit or evaluate a calibration."""

    name: str
    fingerprint_sha256: str
    split: str
    sample_count: int
    manifest_sha256: str | None = None
    license: str | None = None

    def __post_init__(self) -> None:
        _nonempty_string(self.name, "dataset name")
        _sha256_hex(self.fingerprint_sha256, "dataset fingerprint_sha256")
        _nonempty_string(self.split, "dataset split")
        if isinstance(self.sample_count, bool) or not isinstance(self.sample_count, int):
            raise CalibrationError("dataset sample_count must be an integer.")
        if self.sample_count <= 0:
            raise CalibrationError("dataset sample_count must be positive.")
        if self.manifest_sha256 is not None:
            _sha256_hex(self.manifest_sha256, "dataset manifest_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "fingerprint_sha256": self.fingerprint_sha256,
            "split": self.split,
            "sample_count": self.sample_count,
            "manifest_sha256": self.manifest_sha256,
            "license": self.license,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DatasetReference:
        if not isinstance(data, Mapping):
            raise CalibrationError("Dataset reference must be a mapping.")
        return cls(
            name=_nonempty_string(data.get("name"), "dataset name"),
            fingerprint_sha256=_sha256_hex(
                data.get("fingerprint_sha256"), "dataset fingerprint_sha256"
            ),
            split=_nonempty_string(data.get("split"), "dataset split"),
            sample_count=int(data.get("sample_count", 0)),
            manifest_sha256=data.get("manifest_sha256"),
            license=data.get("license"),
        )


@dataclass(frozen=True, slots=True)
class CalibrationResult:
    """The outcome of applying a calibration artifact."""

    value: float
    calibration_id: str
    status: str
    probability_eligible: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "calibration_id": self.calibration_id,
            "status": self.status,
            "probability_eligible": self.probability_eligible,
        }


@dataclass(frozen=True, slots=True)
class CalibrationArtifact:
    """A versioned calibration artifact with fit/evaluation provenance.

    An artifact is *probability-eligible* only when all contract fields are
    present and the evaluation is held out and disjoint from fitting.  A
    fit-only artifact may still be inspected and applied by diagnostics with
    ``allow_unvalidated=True``; the result is then marked ``unvalidated``.
    """

    artifact_id: str
    detector_id: str
    detector_version: str
    curve: CalibrationCurve
    calibration_id: str
    parent_calibration_id: str | None = None
    validation_results: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_now_iso)
    schema: str = CALIBRATION_SCHEMA
    fit_dataset: DatasetReference | None = None
    evaluation_dataset: DatasetReference | None = None
    disjointness: Mapping[str, Any] = field(default_factory=dict)
    metrics: Mapping[str, Any] = field(default_factory=dict)
    code_version: str | None = None
    run_artifact_sha256: str | None = None
    content_hash: str = ""

    def __post_init__(self) -> None:
        if self.schema != CALIBRATION_SCHEMA:
            raise CalibrationError("Unsupported calibration-artifact schema.")
        _nonempty_string(self.artifact_id, "artifact_id")
        _nonempty_string(self.detector_id, "detector_id")
        _nonempty_string(self.detector_version, "detector_version")
        _nonempty_string(self.calibration_id, "calibration_id")
        if not isinstance(self.curve, CalibrationCurve):
            raise CalibrationError("curve must be a CalibrationCurve.")
        _parse_iso8601(self.created_at, "created_at")
        if self.parent_calibration_id is not None:
            _nonempty_string(self.parent_calibration_id, "parent_calibration_id")
        if self.code_version is not None:
            _nonempty_string(self.code_version, "code_version")
        if self.run_artifact_sha256 is not None:
            _sha256_hex(self.run_artifact_sha256, "run_artifact_sha256")
        if not isinstance(self.disjointness, Mapping):
            raise CalibrationError("disjointness must be a mapping.")
        if not isinstance(self.metrics, Mapping):
            raise CalibrationError("metrics must be a mapping.")
        if not self.content_hash:
            object.__setattr__(self, "content_hash", self.compute_content_hash())
        elif not isinstance(self.content_hash, str) or len(self.content_hash) != 64:
            raise CalibrationError("content_hash must be a 64-character hex string.")
        else:
            computed = self.compute_content_hash()
            if self.content_hash != computed:
                raise CalibrationError("content_hash does not match the artifact content.")

    # -- serialization ---------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "artifact_id": self.artifact_id,
            "detector_id": self.detector_id,
            "detector_version": self.detector_version,
            "curve": self.curve.to_dict(),
            "calibration_id": self.calibration_id,
            "parent_calibration_id": self.parent_calibration_id,
            "validation_results": dict(self.validation_results),
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
            "fit_dataset": self.fit_dataset.to_dict() if self.fit_dataset else None,
            "evaluation_dataset": (
                self.evaluation_dataset.to_dict() if self.evaluation_dataset else None
            ),
            "disjointness": dict(self.disjointness),
            "metrics": dict(self.metrics),
            "code_version": self.code_version,
            "run_artifact_sha256": self.run_artifact_sha256,
            "content_hash": self.content_hash,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CalibrationArtifact:
        if not isinstance(data, Mapping):
            raise CalibrationError("Calibration artifact must be a mapping.")
        fit_payload = data.get("fit_dataset")
        evaluation_payload = data.get("evaluation_dataset")
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
            schema=str(data.get("schema", CALIBRATION_SCHEMA)),
            fit_dataset=(
                DatasetReference.from_dict(fit_payload) if fit_payload is not None else None
            ),
            evaluation_dataset=(
                DatasetReference.from_dict(evaluation_payload)
                if evaluation_payload is not None
                else None
            ),
            disjointness=dict(data.get("disjointness", {})),
            metrics=dict(data.get("metrics", {})),
            code_version=data.get("code_version"),
            run_artifact_sha256=data.get("run_artifact_sha256"),
            content_hash=str(data.get("content_hash", "")),
        )

    def _content_payload(self) -> dict[str, Any]:
        """The canonical content used to derive ``content_hash``.

        Excludes ``artifact_id`` (the storage key) and ``content_hash`` itself
        so the hash is self-referential only through the payload, not through
        the stored digest.
        """
        payload = self.to_dict()
        payload.pop("artifact_id", None)
        payload.pop("content_hash", None)
        return payload

    def compute_content_hash(self) -> str:
        """SHA-256 over the artifact content, excluding ``artifact_id``."""
        return _compute_content_hash(self._content_payload())

    # -- eligibility -----------------------------------------------------

    def validation_issues(self) -> list[str]:
        """Return every structural and eligibility issue (empty when valid)."""
        issues: list[str] = []
        if not self.detector_id:
            issues.append("detector_id is required")
        if not self.detector_version:
            issues.append("detector_version is required")
        if not self.calibration_id:
            issues.append("calibration_id is required")
        if self.curve.is_diagnostic_only:
            issues.append("identity calibration is diagnostic only and never probability-eligible")
        if self.fit_dataset is None:
            issues.append("fit_dataset is required for probability eligibility")
        if self.evaluation_dataset is None:
            issues.append("evaluation_dataset is required for probability eligibility")
        if self.fit_dataset is not None and self.evaluation_dataset is not None:
            issues.extend(self._disjointness_issues())
            issues.extend(self._sample_size_issues())
        if not self.disjointness:
            issues.append("disjointness declaration is required")
        else:
            issues.extend(self._disjointness_declaration_issues())
        issues.extend(self._metric_issues())
        if not self.code_version:
            issues.append("code_version is required for probability eligibility")
        if not self.run_artifact_sha256:
            issues.append("run_artifact_sha256 is required for probability eligibility")
        try:
            _parse_iso8601(self.created_at, "created_at")
        except CalibrationError as exc:
            issues.append(str(exc))
        return issues

    def _disjointness_issues(self) -> list[str]:
        assert self.fit_dataset is not None and self.evaluation_dataset is not None
        issues: list[str] = []
        if self.fit_dataset.fingerprint_sha256 == self.evaluation_dataset.fingerprint_sha256:
            issues.append("fit and evaluation dataset fingerprints must differ")
        split = self.evaluation_dataset.split.strip().lower()
        if split not in _HELD_OUT_SPLIT_HINTS:
            issues.append(
                "evaluation split must be an explicit held-out split "
                f"({', '.join(sorted(_HELD_OUT_SPLIT_HINTS))})"
            )
        if self.fit_dataset.split.strip().lower() == split:
            issues.append("fit and evaluation splits must differ")
        return issues

    def _sample_size_issues(self) -> list[str]:
        assert self.fit_dataset is not None and self.evaluation_dataset is not None
        issues: list[str] = []
        if self.fit_dataset.sample_count < MIN_CALIBRATION_SAMPLES:
            issues.append(f"fit_dataset.sample_count must be at least {MIN_CALIBRATION_SAMPLES}")
        if self.evaluation_dataset.sample_count < MIN_CALIBRATION_SAMPLES:
            issues.append(
                f"evaluation_dataset.sample_count must be at least {MIN_CALIBRATION_SAMPLES}"
            )
        return issues

    def _disjointness_declaration_issues(self) -> list[str]:
        issues: list[str] = []
        strategy = self.disjointness.get("strategy")
        if not isinstance(strategy, str) or not strategy.strip():
            issues.append("disjointness.strategy must be a non-empty string")
        evidence = self.disjointness.get("evidence")
        manifest = self.disjointness.get("sample_id_manifest_sha256")
        if not evidence and not manifest:
            issues.append(
                "disjointness must record evidence (evidence text or sample_id_manifest_sha256)"
            )
        if manifest is not None:
            try:
                _sha256_hex(manifest, "disjointness.sample_id_manifest_sha256")
            except CalibrationError as exc:
                issues.append(str(exc))
        return issues

    def _metric_issues(self) -> list[str]:
        issues: list[str] = []
        bounds = {"brier": (0.0, 1.0), "ece": (0.0, 1.0), "log_loss": (0.0, None)}
        for name, (minimum, maximum) in bounds.items():
            if name not in self.metrics:
                issues.append(f"metrics.{name} is required for probability eligibility")
                continue
            try:
                value = _finite_number(self.metrics[name], f"metrics.{name}")
            except CalibrationError as exc:
                issues.append(str(exc))
                continue
            if value < minimum or (maximum is not None and value > maximum):
                issues.append(f"metrics.{name} is outside its valid range")
        return issues

    @property
    def eligible_for_probability(self) -> bool:
        return not self.validation_issues()

    @property
    def calibration_status(self) -> str:
        if self.curve.is_diagnostic_only:
            return "diagnostic"
        if self.eligible_for_probability:
            return "validated"
        if self.fit_dataset is not None and self.evaluation_dataset is not None:
            return "evaluated_incomplete"
        if self.fit_dataset is not None:
            return "fit_only"
        return "incomplete"

    def calibrate(self, score: float, *, allow_unvalidated: bool = False) -> float:
        """Apply the map, refusing ineligible artifacts by default."""
        if not self.eligible_for_probability and not allow_unvalidated:
            issues = "; ".join(self.validation_issues())
            raise CalibrationError(
                "Calibration artifact is not eligible for probability emission: "
                f"{issues}. Pass allow_unvalidated=True only for diagnostics."
            )
        return self.curve.calibrate(score)

    def apply(self, score: float, *, allow_unvalidated: bool = False) -> CalibrationResult:
        """Apply the map and return a status-bearing result."""
        eligible = self.eligible_for_probability
        if not eligible and not allow_unvalidated:
            issues = "; ".join(self.validation_issues())
            raise CalibrationError(
                "Calibration artifact is not eligible for probability emission: "
                f"{issues}. Pass allow_unvalidated=True only for diagnostics."
            )
        return CalibrationResult(
            value=self.curve.calibrate(score),
            calibration_id=self.calibration_id,
            status="validated" if eligible else "unvalidated",
            probability_eligible=eligible,
        )


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class CalibrationManager:
    """Store, retrieve, validate, and apply calibration artifacts.

    The manager is a local filesystem registry.  It does not contact the
    network and does not infer calibration from detector output.
    """

    def __init__(self, storage_path: str | Path):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._artifacts: dict[str, CalibrationArtifact] = {}
        self._load_all()

    def _load_all(self) -> None:
        seen_hashes: set[str] = set()
        for file_path in sorted(self.storage_path.glob("*.json")):
            try:
                payload = json.loads(file_path.read_text(encoding="utf-8"))
                artifact = CalibrationArtifact.from_dict(payload)
            except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                raise CalibrationError(
                    f"Failed to load calibration artifact {file_path.name}: {exc}"
                ) from exc
            if artifact.content_hash in seen_hashes:
                raise CalibrationError(
                    f"Duplicate calibration content hash {artifact.content_hash} "
                    f"for artifact {artifact.artifact_id} in {file_path.name}; "
                    "refusing to load ambiguous registry."
                )
            seen_hashes.add(artifact.content_hash)
            existing = self._artifacts.get(artifact.artifact_id)
            if existing is not None and existing.content_hash != artifact.content_hash:
                raise CalibrationError(
                    f"Artifact id {artifact.artifact_id} maps to two different "
                    "contents on disk; refusing to load ambiguous registry."
                )
            self._artifacts[artifact.artifact_id] = artifact

    def _artifact_path(self, artifact: CalibrationArtifact) -> Path:
        # Filename is derived from the content hash, not the artifact ID, so
        # colliding IDs (e.g. "det1:cal1" vs "det1.cal1") cannot overwrite
        # each other and re-storing the same content is idempotent.
        return self.storage_path / f"{artifact.content_hash}.json"

    def _save_artifact(self, artifact: CalibrationArtifact) -> None:
        target = self._artifact_path(artifact)
        target.parent.mkdir(parents=True, exist_ok=True)
        rendered = (
            json.dumps(
                artifact.to_dict(),
                indent=2,
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        )
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

    def store(
        self,
        detector_id: str,
        detector_version: str,
        curve: CalibrationCurve,
        calibration_id: str | None = None,
        parent_calibration_id: str | None = None,
        validation_results: Mapping[str, Any] | None = None,
        metadata: Mapping[str, Any] | None = None,
        *,
        fit_dataset: DatasetReference | None = None,
        evaluation_dataset: DatasetReference | None = None,
        disjointness: Mapping[str, Any] | None = None,
        metrics: Mapping[str, Any] | None = None,
        code_version: str | None = None,
        run_artifact_sha256: str | None = None,
        created_at: str | None = None,
    ) -> CalibrationArtifact:
        """Store a calibration artifact and return it.

        The artifact may be fit-only or probability-eligible; eligibility is
        derived from the recorded provenance and is never asserted by the
        caller.
        """
        if calibration_id is None:
            calibration_id = _compute_content_hash(
                {
                    "detector_id": detector_id,
                    "detector_version": detector_version,
                    "curve": curve.to_dict(),
                    "created_at": created_at or _now_iso(),
                }
            )[:24]
        artifact = CalibrationArtifact(
            artifact_id=f"{detector_id}:{calibration_id}",
            detector_id=detector_id,
            detector_version=detector_version,
            curve=curve,
            calibration_id=calibration_id,
            parent_calibration_id=parent_calibration_id,
            validation_results=dict(validation_results or {}),
            metadata=dict(metadata or {}),
            created_at=created_at or _now_iso(),
            fit_dataset=fit_dataset,
            evaluation_dataset=evaluation_dataset,
            disjointness=dict(disjointness or {}),
            metrics=dict(metrics or {}),
            code_version=code_version,
            run_artifact_sha256=run_artifact_sha256,
        )
        existing = self._artifacts.get(artifact.artifact_id)
        if existing is not None and existing.content_hash != artifact.content_hash:
            raise CalibrationError(
                f"Artifact id {artifact.artifact_id} is already stored with "
                "different content; choose a new calibration_id."
            )
        self._artifacts[artifact.artifact_id] = artifact
        self._save_artifact(artifact)
        return artifact

    def get(self, artifact_id: str) -> CalibrationArtifact | None:
        return self._artifacts.get(artifact_id)

    def get_latest_for_detector(self, detector_id: str) -> CalibrationArtifact | None:
        artifacts = [item for item in self._artifacts.values() if item.detector_id == detector_id]
        if not artifacts:
            return None
        return max(artifacts, key=lambda item: _parse_iso8601(item.created_at, "created_at"))

    def get_lineage(self, detector_id: str) -> list[CalibrationArtifact]:
        artifacts = [item for item in self._artifacts.values() if item.detector_id == detector_id]
        return sorted(artifacts, key=lambda item: _parse_iso8601(item.created_at, "created_at"))

    def validate_artifact(
        self,
        artifact_id: str,
        validation_dataset_path: str | Path,
        *,
        strict: bool = True,
    ) -> dict[str, Any]:
        """Evaluate an artifact on an external JSONL dataset.

        Rows must contain ``score`` in ``[0, 1]`` and ``label`` in
        ``{ai, machine, 1, true, human, 0, false}``.  This method *measures*
        calibration; it does not make the artifact eligible retroactively.
        """
        artifact = self.get(artifact_id)
        if artifact is None:
            raise CalibrationError(f"Artifact not found: {artifact_id}")

        calibrated: list[float] = []
        labels: list[int] = []
        with Path(validation_dataset_path).open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    if strict:
                        raise CalibrationError(f"Line {line_number}: invalid JSON") from exc
                    continue
                if not isinstance(row, dict) or "score" not in row or "label" not in row:
                    if strict:
                        raise CalibrationError(f"Line {line_number}: missing score or label")
                    continue
                try:
                    score = artifact.curve.calibrate(float(row["score"]))
                except (TypeError, ValueError) as exc:
                    if strict:
                        raise CalibrationError(f"Line {line_number}: invalid score") from exc
                    continue
                label = _coerce_label(row["label"])
                if label is None:
                    if strict:
                        raise CalibrationError(f"Line {line_number}: invalid label")
                    continue
                calibrated.append(score)
                labels.append(label)

        if not calibrated:
            raise CalibrationError("No valid samples in validation dataset.")
        return _probability_metrics(calibrated, labels)

    def get_calibrated_score(
        self,
        detector_id: str,
        raw_score: float,
        *,
        allow_unvalidated: bool = False,
    ) -> float | None:
        """Return a calibrated probability, or ``None`` when no artifact exists.

        A fit-only artifact raises :class:`CalibrationError` unless the caller
        explicitly opts into diagnostics.
        """
        artifact = self.get_latest_for_detector(detector_id)
        if artifact is None:
            return None
        return artifact.calibrate(raw_score, allow_unvalidated=allow_unvalidated)

    def get_calibrated_result(
        self,
        detector_id: str,
        raw_score: float,
        *,
        allow_unvalidated: bool = False,
    ) -> CalibrationResult | None:
        artifact = self.get_latest_for_detector(detector_id)
        if artifact is None:
            return None
        return artifact.apply(raw_score, allow_unvalidated=allow_unvalidated)


def _coerce_label(value: Any) -> int | None:
    if value in (1, True):
        return 1
    if value in (0, False):
        return 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"ai", "machine", "1", "true"}:
            return 1
        if normalized in {"human", "0", "false"}:
            return 0
    return None


def _probability_metrics(probabilities: Iterable[float], labels: Iterable[int]) -> dict[str, Any]:
    values = list(probabilities)
    targets = list(labels)
    if len(values) != len(targets) or not values:
        raise CalibrationError("Metrics require equally sized, non-empty samples.")
    count = len(values)
    brier = (
        sum((value - target) ** 2 for value, target in zip(values, targets, strict=True)) / count
    )

    n_bins = 10
    bin_counts = [0] * n_bins
    bin_confidence = [0.0] * n_bins
    bin_positive = [0.0] * n_bins
    for value, target in zip(values, targets, strict=True):
        index = min(int(value * n_bins), n_bins - 1)
        bin_counts[index] += 1
        bin_confidence[index] += value
        bin_positive[index] += target
    ece = 0.0
    for index in range(n_bins):
        if bin_counts[index]:
            average_confidence = bin_confidence[index] / bin_counts[index]
            average_positive = bin_positive[index] / bin_counts[index]
            ece += (bin_counts[index] / count) * abs(average_confidence - average_positive)

    epsilon = 1e-15
    log_loss = (
        -sum(
            target * math.log(max(value, epsilon))
            + (1 - target) * math.log(max(1.0 - value, epsilon))
            for value, target in zip(values, targets, strict=True)
        )
        / count
    )
    return {
        "brier": brier,
        "ece": ece,
        "log_loss": log_loss,
        "sample_count": count,
        "positive_rate": sum(targets) / count,
    }


def validate_calibration_artifact(artifact: CalibrationArtifact) -> list[str]:
    """Return structural and eligibility issues (empty when valid)."""
    if not isinstance(artifact, CalibrationArtifact):
        raise CalibrationError("artifact must be a CalibrationArtifact.")
    return artifact.validation_issues()


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------


def create_calibration_manager(storage_path: str | Path) -> CalibrationManager:
    return CalibrationManager(storage_path)


def load_calibration_artifact(path: str | Path) -> CalibrationArtifact:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise CalibrationError(f"Failed to read calibration artifact: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise CalibrationError(f"Calibration artifact is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise CalibrationError("Calibration artifact must be a JSON object.")
    return CalibrationArtifact.from_dict(payload)


def save_calibration_artifact(artifact: CalibrationArtifact, path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(
            artifact.to_dict(),
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
    )
