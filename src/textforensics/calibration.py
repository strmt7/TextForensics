"""Detector-local calibration artifacts and maps.

A detector score is *not* a probability.  This module implements the
calibration contract defined in ``docs/REVAMP_SPEC.md``:

* explicit, mathematically correct calibration maps (Platt, temperature,
  isotonic, beta, and a diagnostic-only identity map);
* artifacts that carry fit/evaluation dataset provenance;
* fail-closed eligibility: a probability may only be emitted from an
  artifact that records a held-out, disjoint evaluation with metrics;
* deterministic serialization and content hashing.

Temperature scaling (Guo et al., 2017) is defined on the logit domain.
A ``temperature`` curve therefore declares its input semantics
explicitly (curve contract v3, ``textforensics.calibration-curve/v3``):

* ``"probability"`` — the input is P(AI) in [0, 1] and the map is
  ``sigmoid(logit(p) / T)``, with the documented endpoints ``p = 0 -> 0``
  and ``p = 1 -> 1``;
* ``"logit"`` — the input is an unbounded logit ``z`` and the map is
  ``sigmoid(z / T)``.

The v2 curve contract applied ``sigmoid(x / T)`` directly to a [0, 1]
score.  That map is preserved only as a legacy verification behaviour
(``input_semantics="legacy_raw_score"``, schema v2): legacy temperature
curves load and compute exactly as before, but are never
probability-eligible.  Migrating a legacy curve creates a new v3 curve
with the same ``T`` and drops all fit/evaluation metrics — the migrated
curve must be refit and re-evaluated before it can support a
probability; old metrics are never presented as proof of the new map.

Calibration artifacts are deeply immutable after construction, and a
probability may only be emitted for an exact
:class:`InferenceIdentity` (detector, version, provider, model,
configuration hash, native-score semantics, calibration id, regime).
Held-out evaluation requires a :class:`DisjointnessProof` (see
``benchmark.prove_disjointness``) — without a verified proof an
evaluation is diagnostic, never held out.

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
from types import MappingProxyType
from typing import Any

from .benchmark import (
    DisjointnessProof,
    _compute_sample_hashes,
    _load_scores,
    _metrics,
    dataset_sha256,
    prove_disjointness,
)

__all__ = [
    "CALIBRATION_SCHEMA",
    "CURVE_SCHEMA",
    "LEGACY_CURVE_SCHEMA",
    "SUPPORTED_METHODS",
    "DIAGNOSTIC_METHODS",
    "MIN_CALIBRATION_SAMPLES",
    "THRESHOLD_SELECTION_SCHEMA",
    "THRESHOLD_CALIBRATION_SCHEMA",
    "EVALUATION_RESULT_SCHEMA",
    "CalibrationCurve",
    "CalibrationArtifact",
    "CalibrationResult",
    "CalibrationManager",
    "CalibrationError",
    "DatasetReference",
    "DisjointnessProof",
    "InferenceIdentity",
    "ThresholdSelectionResult",
    "EvaluationResult",
    "validate_calibration_artifact",
    "create_calibration_manager",
    "load_calibration_artifact",
    "save_calibration_artifact",
    "select_threshold",
    "evaluate_threshold",
    "validate_no_contamination",
    "load_threshold_artifact",
    "create_threshold_selection_artifact",
    "run_calibration_evaluation",
    "prove_disjointness",
    "migrate_legacy_temperature_curve",
]

CALIBRATION_SCHEMA = "textforensics.calibration-artifact/v2"
#: Schema of the v1 threshold-selection artifacts produced by
#: ``select_threshold``. A threshold-selection artifact is a different
#: artifact type from this module's v2 calibration maps: a threshold is
#: not a score-to-probability map, and the two must never be confused.
THRESHOLD_SELECTION_SCHEMA = "textforensics.threshold-selection/v1"
#: Schema of benchmark.py-style v1 calibration artifacts
#: (``benchmark.CALIBRATION_SCHEMA``), accepted by
#: ``load_threshold_artifact`` alongside threshold-selection artifacts.
THRESHOLD_CALIBRATION_SCHEMA = "textforensics.calibration/v1"
#: Schema of the evaluation results produced by ``evaluate_threshold``.
EVALUATION_RESULT_SCHEMA = "textforensics.evaluation-result/v1"
#: Current calibration-curve contract (v3): temperature input semantics
#: are explicit (``"probability"`` or ``"logit"``).  See module docstring.
CURVE_SCHEMA = "textforensics.calibration-curve/v3"
#: Superseded curve contract (v2): temperature was ``sigmoid(x / T)``
#: applied directly to a [0, 1] score.  V2 temperature curves load for
#: verification of old artifacts only; they are never
#: probability-eligible and must be migrated (same ``T``, metrics
#: dropped) and re-evaluated.  V2 curves of other methods have
#: identical mathematics under v3 and are unaffected.
LEGACY_CURVE_SCHEMA = "textforensics.calibration-curve/v2"
#: Fields that make up an artifact's exact inference identity.  They
#: are part of the content hash only when at least one is set, so
#: pre-identity artifacts keep their original hash (and are
#: ineligible, because the identity is incomplete).
_IDENTITY_FIELDS = (
    "provider",
    "model",
    "config_hash",
    "native_score_semantics",
    "regime",
)
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


def _logit(probability: float) -> float:
    """log(p / (1 - p)), computed stably for p in (0, 1)."""
    return math.log(probability) - math.log1p(-probability)


def _deep_freeze(value: Any) -> Any:
    """Recursively copy a JSON-like value into immutable containers.

    Mappings become :class:`~types.MappingProxyType`, sequences become
    tuples.  The result shares no mutable structure with its input, so
    mutating a constructor argument after construction cannot change a
    frozen artifact, and mutating a returned mapping raises
    :class:`TypeError` instead of silently corrupting hashed content.
    """
    if isinstance(value, Mapping):
        return MappingProxyType({key: _deep_freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_deep_freeze(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_deep_freeze(item) for item in value)
    return value


def _deep_thaw(value: Any) -> Any:
    """Recursively convert frozen containers back to plain JSON values."""
    if isinstance(value, Mapping):
        return {key: _deep_thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_deep_thaw(item) for item in value]
    if isinstance(value, frozenset):
        return [_deep_thaw(item) for item in sorted(value, key=repr)]
    return value


# ---------------------------------------------------------------------------
# Inference identity
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class InferenceIdentity:
    """The exact identity a calibration artifact must match to be applied.

    All eight fields are required and compared exactly.  An artifact
    whose recorded identity differs in any field — detector version,
    provider, model, configuration hash, native-score semantics,
    calibration id or regime — must not emit a validated probability
    for this identity, and latest-by-time selection never crosses
    identity epochs.  ``config_hash`` is the SHA-256 of the canonical
    detector configuration; ``native_score_semantics`` names the input
    domain and direction the curve was fitted for, e.g.
    ``"probability_higher_means_ai"`` or ``"logit_lower_means_ai"``.
    """

    detector_id: str
    detector_version: str
    provider: str
    model: str
    config_hash: str
    native_score_semantics: str
    calibration_id: str
    regime: str

    def __post_init__(self) -> None:
        _nonempty_string(self.detector_id, "detector_id")
        _nonempty_string(self.detector_version, "detector_version")
        _nonempty_string(self.provider, "provider")
        _nonempty_string(self.model, "model")
        _sha256_hex(self.config_hash, "config_hash")
        _nonempty_string(self.native_score_semantics, "native_score_semantics")
        _nonempty_string(self.calibration_id, "calibration_id")
        _nonempty_string(self.regime, "regime")

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector_id": self.detector_id,
            "detector_version": self.detector_version,
            "provider": self.provider,
            "model": self.model,
            "config_hash": self.config_hash,
            "native_score_semantics": self.native_score_semantics,
            "calibration_id": self.calibration_id,
            "regime": self.regime,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> InferenceIdentity:
        if not isinstance(data, Mapping):
            raise CalibrationError("Inference identity must be a mapping.")
        return cls(
            detector_id=_nonempty_string(data.get("detector_id"), "detector_id"),
            detector_version=_nonempty_string(data.get("detector_version"), "detector_version"),
            provider=_nonempty_string(data.get("provider"), "provider"),
            model=_nonempty_string(data.get("model"), "model"),
            config_hash=_sha256_hex(data.get("config_hash"), "config_hash"),
            native_score_semantics=_nonempty_string(
                data.get("native_score_semantics"), "native_score_semantics"
            ),
            calibration_id=_nonempty_string(data.get("calibration_id"), "calibration_id"),
            regime=_nonempty_string(data.get("regime"), "regime"),
        )


# ---------------------------------------------------------------------------
# Curves
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CalibrationCurve:
    """A validated detector-local score-to-probability map.

    ``parameters`` are method-specific:

    * ``platt``: ``{"A": float, "B": float}`` → ``sigmoid(A*x + B)``
    * ``temperature``: ``{"T": float > 0}`` → ``sigmoid(logit(p) / T)``
      when ``input_semantics="probability"`` (``p`` in [0, 1], the
      probability of AI authorship; endpoints ``0 -> 0`` and ``1 -> 1``),
      or ``sigmoid(z / T)`` when ``input_semantics="logit"`` (``z`` any
      finite logit).  The v2 legacy form ``sigmoid(x / T)`` on a raw
      [0, 1] score is preserved only for verification of old artifacts
      (``input_semantics="legacy_raw_score"``, schema v2) and is never
      probability-eligible.
    * ``isotonic``: ``{"x": [...], "y": [...]}`` → piecewise-linear monotone map
    * ``beta``: ``{"a": float >= 0, "b": float >= 0, "c": float}`` →
      ``sigmoid(a*ln(x) - b*ln(1-x) + c)`` (Kull et al., 2017)
    * ``identity``: no parameters; diagnostic only, never probability-eligible

    For ``temperature`` with ``input_semantics="probability"`` the input
    is the AI-direction probability: when
    ``native_score_direction="lower_means_ai"`` the raw score is
    inverted (``1 - p``) before the logit transform, because a lower
    native score means more AI-like.  Other methods are defined in the
    detector's native-score space as recorded; their direction is
    descriptive metadata, not an input transform.

    ``x`` is a native detector score on the documented ``[0, 1]`` scale
    for probability semantics.  Out-of-range or nonfinite scores raise
    :class:`CalibrationError`; they are never silently clipped or
    passed through.  Constructor inputs are deep-copied and frozen:
    mutating the original ``parameters`` mapping (or a returned one)
    after construction cannot change the applied map.
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
    input_semantics: str = "probability"

    def __post_init__(self) -> None:
        if self.method not in SUPPORTED_METHODS:
            raise CalibrationError(
                f"Unsupported calibration method {self.method!r}; "
                f"expected one of {', '.join(sorted(SUPPORTED_METHODS))}."
            )
        if self.schema not in {CURVE_SCHEMA, LEGACY_CURVE_SCHEMA}:
            raise CalibrationError("Unsupported calibration-curve schema.")
        if not isinstance(self.parameters, Mapping):
            raise CalibrationError("parameters must be a mapping.")
        if self.input_semantics not in {"probability", "logit", "legacy_raw_score"}:
            raise CalibrationError(
                "input_semantics must be 'probability', 'logit' or 'legacy_raw_score'."
            )
        if self.input_semantics == "legacy_raw_score" and (
            self.schema != LEGACY_CURVE_SCHEMA or self.method != "temperature"
        ):
            raise CalibrationError(
                "The legacy_raw_score input semantics are only available "
                "for v2 temperature curves loaded from stored artifacts."
            )
        if self.schema == CURVE_SCHEMA and self.input_semantics == "legacy_raw_score":
            raise CalibrationError(
                "The legacy_raw_score input semantics are not available "
                "under the v3 curve contract."
            )
        if self.input_semantics == "logit" and self.method != "temperature":
            raise CalibrationError(
                "Logit input semantics are only defined for temperature "
                "calibration; other methods take probability-domain inputs."
            )
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
        # Deep-freeze a copy: the caller's mapping (and any nested
        # lists) can no longer affect this curve.
        object.__setattr__(self, "parameters", _deep_freeze(dict(self.parameters)))

    @property
    def is_legacy(self) -> bool:
        """True for v2 temperature curves using the superseded map."""
        return self.schema == LEGACY_CURVE_SCHEMA

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
        """Apply the map.

        For ``temperature`` with ``input_semantics="probability"`` the
        input is P(AI) in [0, 1] and the map is ``sigmoid(logit(p)/T)``
        (endpoints 0 -> 0, 1 -> 1); with ``input_semantics="logit"``
        the input is any finite logit ``z`` and the map is
        ``sigmoid(z/T)``.  A legacy v2 temperature curve applies the
        superseded ``sigmoid(x/T)`` to a [0, 1] score.  All other
        methods take a [0, 1] native score.  Nonfinite inputs raise.
        """
        if self.method == "temperature" and self.input_semantics == "logit":
            value = _finite_number(score, "score")
            if self.native_score_direction == "lower_means_ai":
                value = -value
            return _sigmoid(value / float(self.parameters["T"]))
        value = _unit_interval(score, "score")
        if self.method == "platt":
            return _sigmoid(float(self.parameters["A"]) * value + float(self.parameters["B"]))
        if self.method == "temperature":
            if self.input_semantics == "legacy_raw_score":
                return _sigmoid(value / float(self.parameters["T"]))
            probability = 1.0 - value if self.native_score_direction == "lower_means_ai" else value
            if probability == 0.0:
                return 0.0
            if probability == 1.0:
                return 1.0
            return _sigmoid(_logit(probability) / float(self.parameters["T"]))
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
            "parameters": _deep_thaw(self.parameters),
            "reference_dataset_hash": self.reference_dataset_hash,
            "reference_dataset_name": self.reference_dataset_name,
            "calibrated_at": self.calibrated_at,
            "sample_count": self.sample_count,
            "calibration_error": self.calibration_error,
            "native_score_direction": self.native_score_direction,
            "score_range": list(self.score_range),
            "input_semantics": self.input_semantics,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CalibrationCurve:
        if not isinstance(data, Mapping):
            raise CalibrationError("Calibration curve must be a mapping.")
        method = _nonempty_string(data.get("method"), "method")
        score_range = data.get("score_range", [0.0, 1.0])
        if not isinstance(score_range, (list, tuple)) or len(score_range) != 2:
            raise CalibrationError("score_range must be a two-element sequence.")
        schema = str(data.get("schema", CURVE_SCHEMA))
        raw_semantics = data.get("input_semantics")
        if schema == LEGACY_CURVE_SCHEMA and method == "temperature":
            # A stored v2 temperature curve keeps its original map and
            # meaning; it is loaded as legacy, never reinterpreted.
            input_semantics = "legacy_raw_score"
        elif raw_semantics is None:
            input_semantics = "probability"
        else:
            input_semantics = str(raw_semantics)
        return cls(
            method=method,
            parameters=dict(data.get("parameters", {})),
            reference_dataset_hash=str(data.get("reference_dataset_hash", "")),
            reference_dataset_name=str(data.get("reference_dataset_name", "")),
            calibrated_at=str(data.get("calibrated_at", "")),
            sample_count=int(data.get("sample_count", 0)),
            calibration_error=data.get("calibration_error"),
            schema=schema,
            native_score_direction=str(data.get("native_score_direction", "higher_means_ai")),
            score_range=(float(score_range[0]), float(score_range[1])),
            input_semantics=input_semantics,
        )


def migrate_legacy_temperature_curve(curve: CalibrationCurve) -> CalibrationCurve:
    """Migrate a legacy v2 temperature curve to the v3 contract.

    Returns a new ``"probability"`` curve with the same ``T`` and no
    fit/evaluation provenance: ``sample_count`` 0, no calibration
    error, no reference dataset.  The migrated curve must be refit and
    re-evaluated before it can support a probability — metrics recorded
    under the superseded ``sigmoid(x/T)`` map are not carried over and
    must not be presented as evidence for the new map.
    """
    if not isinstance(curve, CalibrationCurve):
        raise CalibrationError("curve must be a CalibrationCurve.")
    if curve.method != "temperature" or not curve.is_legacy:
        raise CalibrationError(
            "Only legacy v2 temperature curves can be migrated; "
            f"got method={curve.method!r} schema={curve.schema!r}."
        )
    return CalibrationCurve(
        method="temperature",
        parameters={"T": float(curve.parameters["T"])},
        input_semantics="probability",
        native_score_direction=curve.native_score_direction,
        score_range=curve.score_range,
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
    # Exact inference identity (CORE-05).  All five must be present for
    # probability eligibility; artifacts recorded before the identity
    # contract keep ``None`` here, retain their original content hash
    # (see ``_content_payload``), and are ineligible.
    provider: str | None = None
    model: str | None = None
    config_hash: str | None = None
    native_score_semantics: str | None = None
    regime: str | None = None
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
        if self.provider is not None:
            _nonempty_string(self.provider, "provider")
        if self.model is not None:
            _nonempty_string(self.model, "model")
        if self.config_hash is not None:
            _sha256_hex(self.config_hash, "config_hash")
        if self.native_score_semantics is not None:
            _nonempty_string(self.native_score_semantics, "native_score_semantics")
        if self.regime is not None:
            _nonempty_string(self.regime, "regime")
        # Deep-freeze copies of every nested mapping: mutating a
        # constructor argument or a returned mapping after construction
        # cannot change the applied probability or the hashed content.
        object.__setattr__(self, "validation_results", _deep_freeze(dict(self.validation_results)))
        object.__setattr__(self, "metadata", _deep_freeze(dict(self.metadata)))
        object.__setattr__(self, "disjointness", _deep_freeze(dict(self.disjointness)))
        object.__setattr__(self, "metrics", _deep_freeze(dict(self.metrics)))
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
            "validation_results": _deep_thaw(self.validation_results),
            "metadata": _deep_thaw(self.metadata),
            "created_at": self.created_at,
            "fit_dataset": self.fit_dataset.to_dict() if self.fit_dataset else None,
            "evaluation_dataset": (
                self.evaluation_dataset.to_dict() if self.evaluation_dataset else None
            ),
            "disjointness": _deep_thaw(self.disjointness),
            "metrics": _deep_thaw(self.metrics),
            "code_version": self.code_version,
            "run_artifact_sha256": self.run_artifact_sha256,
            "provider": self.provider,
            "model": self.model,
            "config_hash": self.config_hash,
            "native_score_semantics": self.native_score_semantics,
            "regime": self.regime,
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
            provider=data.get("provider"),
            model=data.get("model"),
            config_hash=data.get("config_hash"),
            native_score_semantics=data.get("native_score_semantics"),
            regime=data.get("regime"),
            content_hash=str(data.get("content_hash", "")),
        )

    def _content_payload(self) -> dict[str, Any]:
        """The canonical content used to derive ``content_hash``.

        Excludes ``artifact_id`` (the storage key) and ``content_hash`` itself
        so the hash is self-referential only through the payload, not through
        the stored digest.  The inference-identity fields are excluded
        while all five are unset, so artifacts recorded before the
        identity contract keep their original hash; once any identity
        field is set, all five are hashed.  An artifact's hash is never
        refreshed silently: adding identity to an old artifact creates
        a new artifact with a new hash.
        """
        payload = self.to_dict()
        payload.pop("artifact_id", None)
        payload.pop("content_hash", None)
        if all(payload.get(field) is None for field in _IDENTITY_FIELDS):
            for field in _IDENTITY_FIELDS:
                payload.pop(field, None)
        return payload

    def compute_content_hash(self) -> str:
        """SHA-256 over the artifact content, excluding ``artifact_id``."""
        return _compute_content_hash(self._content_payload())

    def check_content_hash(self) -> bool:
        """True when the stored hash still matches the frozen content."""
        return self.compute_content_hash() == self.content_hash

    def _check_integrity(self) -> None:
        if not self.check_content_hash():
            raise CalibrationError(
                "Calibration artifact content_hash does not match its content; "
                "the artifact is tampered or corrupt and cannot be applied."
            )

    def inference_identity(self) -> InferenceIdentity | None:
        """The exact inference identity, or ``None`` when incomplete."""
        if (
            self.provider is None
            or self.model is None
            or self.config_hash is None
            or self.native_score_semantics is None
            or self.regime is None
        ):
            return None
        return InferenceIdentity(
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            provider=self.provider,
            model=self.model,
            config_hash=self.config_hash,
            native_score_semantics=self.native_score_semantics,
            calibration_id=self.calibration_id,
            regime=self.regime,
        )

    def matches_identity(self, identity: InferenceIdentity) -> bool:
        """True only when the artifact matches the identity exactly."""
        if not isinstance(identity, InferenceIdentity):
            raise CalibrationError("identity must be an InferenceIdentity.")
        return self.inference_identity() == identity

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
        if self.curve.is_legacy:
            issues.append(
                "legacy temperature curve (calibration-curve/v2) uses the superseded "
                "sigmoid(x/T) map; migrate to the v3 contract and re-evaluate — "
                "it is never probability-eligible"
            )
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
        issues.extend(self._identity_issues())
        if not self.code_version:
            issues.append("code_version is required for probability eligibility")
        if not self.run_artifact_sha256:
            issues.append("run_artifact_sha256 is required for probability eligibility")
        try:
            _parse_iso8601(self.created_at, "created_at")
        except CalibrationError as exc:
            issues.append(str(exc))
        return issues

    def _identity_issues(self) -> list[str]:
        """Every inference-identity field must be present and coherent."""
        issues: list[str] = []
        missing = [field for field in _IDENTITY_FIELDS if getattr(self, field) is None]
        if missing:
            issues.append(
                "inference identity is incomplete: missing "
                + ", ".join(missing)
                + "; an artifact without an exact inference identity "
                "cannot support a probability"
            )
            return issues
        direction = self.curve.native_score_direction
        if direction in {"higher_means_ai", "lower_means_ai"}:
            expected = f"{self.curve.input_semantics}_{direction}"
            if self.native_score_semantics != expected:
                issues.append(
                    "native_score_semantics "
                    f"{self.native_score_semantics!r} does not match the curve's "
                    f"input semantics and direction ({expected!r})"
                )
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

    def calibrate(
        self,
        score: float,
        *,
        allow_unvalidated: bool = False,
        identity: InferenceIdentity | None = None,
    ) -> float:
        """Apply the map, refusing ineligible artifacts by default.

        When ``identity`` is given, the artifact must match it exactly;
        a mismatched identity raises instead of emitting a probability
        for the wrong detector version, provider, model, configuration
        or regime.  The stored content hash is verified before use.
        """
        self._check_integrity()
        if identity is not None and not self.matches_identity(identity):
            raise CalibrationError(
                "Calibration artifact does not match the required "
                "InferenceIdentity; refusing to apply it."
            )
        if not self.eligible_for_probability and not allow_unvalidated:
            issues = "; ".join(self.validation_issues())
            raise CalibrationError(
                "Calibration artifact is not eligible for probability emission: "
                f"{issues}. Pass allow_unvalidated=True only for diagnostics."
            )
        return self.curve.calibrate(score)

    def apply(
        self,
        score: float,
        *,
        allow_unvalidated: bool = False,
        identity: InferenceIdentity | None = None,
    ) -> CalibrationResult:
        """Apply the map and return a status-bearing result."""
        self._check_integrity()
        eligible = self.eligible_for_probability
        if identity is not None and not self.matches_identity(identity):
            raise CalibrationError(
                "Calibration artifact does not match the required "
                "InferenceIdentity; refusing to apply it."
            )
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
        identity: InferenceIdentity | None = None,
        provider: str | None = None,
        model: str | None = None,
        config_hash: str | None = None,
        native_score_semantics: str | None = None,
        regime: str | None = None,
    ) -> CalibrationArtifact:
        """Store a calibration artifact and return it.

        The artifact may be fit-only or probability-eligible; eligibility is
        derived from the recorded provenance and is never asserted by the
        caller.  The artifact is published to the in-memory map only
        after durable storage succeeds: a failed write leaves memory
        and disk consistent (no in-memory artifact without a file).
        The exact inference identity may be given as ``identity`` or
        as the individual ``provider``/``model``/``config_hash``/
        ``native_score_semantics``/``regime`` fields; when both are
        given they must agree.
        """
        if identity is not None:
            if identity.detector_id != detector_id:
                raise CalibrationError("identity.detector_id does not match detector_id.")
            if identity.detector_version != detector_version:
                raise CalibrationError("identity.detector_version does not match detector_version.")
            if calibration_id is not None and identity.calibration_id != calibration_id:
                raise CalibrationError("identity.calibration_id does not match calibration_id.")
            if calibration_id is None:
                calibration_id = identity.calibration_id
            for field_name in _IDENTITY_FIELDS:
                explicit = locals()[field_name]
                identity_value = getattr(identity, field_name)
                if explicit is not None and explicit != identity_value:
                    raise CalibrationError(
                        f"identity.{field_name} does not match the explicit {field_name}."
                    )
            provider = identity.provider
            model = identity.model
            config_hash = identity.config_hash
            native_score_semantics = identity.native_score_semantics
            regime = identity.regime
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
            provider=provider,
            model=model,
            config_hash=config_hash,
            native_score_semantics=native_score_semantics,
            regime=regime,
        )
        existing = self._artifacts.get(artifact.artifact_id)
        if existing is not None and existing.content_hash != artifact.content_hash:
            raise CalibrationError(
                f"Artifact id {artifact.artifact_id} is already stored with "
                "different content; choose a new calibration_id."
            )
        # Publish to durable storage FIRST; only then to memory, so a
        # failed write cannot leave a phantom in-memory artifact.
        self._save_artifact(artifact)
        self._artifacts[artifact.artifact_id] = artifact
        return artifact

    def get(self, artifact_id: str) -> CalibrationArtifact | None:
        return self._artifacts.get(artifact_id)

    def get_latest_for_detector(self, detector_id: str) -> CalibrationArtifact | None:
        """Newest artifact for a detector, for lineage/diagnostics only.

        This is NOT an application path: it cannot bind an inference
        identity, so it must never be used to select an artifact for
        emitting a probability.  Use :meth:`get_for_identity`.
        """
        artifacts = [item for item in self._artifacts.values() if item.detector_id == detector_id]
        if not artifacts:
            return None
        return max(artifacts, key=lambda item: _parse_iso8601(item.created_at, "created_at"))

    def get_for_identity(self, identity: InferenceIdentity) -> CalibrationArtifact | None:
        """Newest artifact matching an exact inference identity.

        Only artifacts whose recorded identity equals ``identity`` in
        every field are candidates, so latest-by-time never crosses
        identity epochs.  Returns ``None`` when no artifact matches.
        """
        if not isinstance(identity, InferenceIdentity):
            raise CalibrationError("identity must be an InferenceIdentity.")
        artifacts = [item for item in self._artifacts.values() if item.matches_identity(identity)]
        if not artifacts:
            return None
        return max(artifacts, key=lambda item: _parse_iso8601(item.created_at, "created_at"))

    def _verify_artifact_integrity(self, artifact: CalibrationArtifact) -> None:
        artifact._check_integrity()

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

    def get_calibrated_score_for_identity(
        self,
        identity: InferenceIdentity,
        raw_score: float,
        *,
        allow_unvalidated: bool = False,
    ) -> float | None:
        """Return a calibrated probability for an exact inference identity.

        Returns ``None`` when no artifact matches the identity exactly;
        a matching but ineligible artifact raises
        :class:`CalibrationError` unless the caller explicitly opts
        into diagnostics with ``allow_unvalidated=True``.  A mismatched
        identity never yields a validated probability.
        """
        artifact = self.get_for_identity(identity)
        if artifact is None:
            return None
        self._verify_artifact_integrity(artifact)
        return artifact.calibrate(raw_score, allow_unvalidated=allow_unvalidated, identity=identity)

    def get_calibrated_result_for_identity(
        self,
        identity: InferenceIdentity,
        raw_score: float,
        *,
        allow_unvalidated: bool = False,
    ) -> CalibrationResult | None:
        """Return a status-bearing calibrated result for an exact identity.

        Returns ``None`` when no artifact matches the identity exactly.
        Explicit diagnostic use (``allow_unvalidated=True``) returns a
        result with status ``"unvalidated"``, never ``"validated"``.
        """
        artifact = self.get_for_identity(identity)
        if artifact is None:
            return None
        self._verify_artifact_integrity(artifact)
        return artifact.apply(raw_score, allow_unvalidated=allow_unvalidated, identity=identity)

    def get_calibrated_score(
        self,
        detector_id: str,
        raw_score: float,
        *,
        identity: InferenceIdentity | None = None,
        allow_unvalidated: bool = False,
    ) -> float | None:
        """Return a calibrated probability, or ``None`` when no artifact exists.

        An exact :class:`InferenceIdentity` is required: selecting by
        detector id alone cannot bind the current detector version,
        provider, model, configuration or regime, so it raises
        :class:`CalibrationError`.  Use
        :meth:`get_calibrated_score_for_identity`.
        """
        if identity is None:
            raise CalibrationError(
                "An exact InferenceIdentity is required to apply calibration; "
                "selecting by detector id alone cannot bind the current "
                "detector version, provider, model, configuration or regime. "
                "Use get_calibrated_score_for_identity()."
            )
        if identity.detector_id != detector_id:
            raise CalibrationError("identity.detector_id does not match detector_id.")
        return self.get_calibrated_score_for_identity(
            identity, raw_score, allow_unvalidated=allow_unvalidated
        )

    def get_calibrated_result(
        self,
        detector_id: str,
        raw_score: float,
        *,
        identity: InferenceIdentity | None = None,
        allow_unvalidated: bool = False,
    ) -> CalibrationResult | None:
        """Return a calibrated result for an exact inference identity.

        An exact :class:`InferenceIdentity` is required; see
        :meth:`get_calibrated_score`.  Use
        :meth:`get_calibrated_result_for_identity`.
        """
        if identity is None:
            raise CalibrationError(
                "An exact InferenceIdentity is required to apply calibration; "
                "selecting by detector id alone cannot bind the current "
                "detector version, provider, model, configuration or regime. "
                "Use get_calibrated_result_for_identity()."
            )
        if identity.detector_id != detector_id:
            raise CalibrationError("identity.detector_id does not match detector_id.")
        return self.get_calibrated_result_for_identity(
            identity, raw_score, allow_unvalidated=allow_unvalidated
        )


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


# ---------------------------------------------------------------------------
# Threshold selection and held-out evaluation (v1 artifacts)
# (merged from threshold_selection.py, Phase 2 wave e)
# ---------------------------------------------------------------------------
# These functions select operating thresholds on calibration data and
# evaluate them on held-out data. They produce/consume v1
# threshold-selection artifacts, which are a DIFFERENT artifact type from
# this module's v2 calibration maps above: a threshold is not a
# score-to-probability map, and the two artifact types must never be
# confused (see THRESHOLD_SELECTION_SCHEMA / THRESHOLD_CALIBRATION_SCHEMA
# below; benchmark.py's CALIBRATION_SCHEMA is the v1 calibration schema).


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
            "schema": THRESHOLD_SELECTION_SCHEMA,
            "created_at_utc": datetime.now(UTC).isoformat(),
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
        record["calibration_record_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

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
    # Disjointness proof state (CORE-06).  ``evaluation_mode`` is
    # ``"held_out"`` only when ``disjointness_status`` is ``"verified"``.
    # ``overlap_count`` is -1 when the overlap is unknown.
    disjointness_status: str = "unknown"
    overlap_count: int = -1
    training_hash: str = ""
    evaluation_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "schema": EVALUATION_RESULT_SCHEMA,
            "created_at_utc": datetime.now(UTC).isoformat(),
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
            "disjointness_status": self.disjointness_status,
            "overlap_count": self.overlap_count,
            "training_hash": self.training_hash,
            "evaluation_hash": self.evaluation_hash,
        }


def select_threshold(
    calibration_path: str | Path,
    *,
    target_fpr: float = 0.01,
    strict: bool = True,
    detector_id: str = "textforensics/builtin-heuristic",
    # Default matches the live builtin detector's version
    # (detectors.BuiltinHeuristicDetector.detector_version). An earlier
    # default of "1.0.0" matched no detector, so artifacts produced with
    # defaults carried a version no validator would accept.
    detector_version: str = "0.1.0",
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
            if best is None or (
                candidate.observed_tpr > best.observed_tpr
                or (
                    candidate.observed_tpr == best.observed_tpr
                    and candidate.threshold < best.threshold
                )
            ):
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
    disjointness_proof: DisjointnessProof | None = None,
    diagnostic: bool = False,
) -> EvaluationResult:
    """Evaluate a threshold on held-out test data.

    This is the EVALUATION step that must use data separate from calibration.

    The result is labelled ``held_out`` only when the caller supplies a
    :class:`DisjointnessProof` with status ``"verified"`` for exactly
    this evaluation file.  Without a proof the result is ``diagnostic``
    with ``disjointness_status`` ``"unknown"``.  A contaminated or
    unknown proof raises :class:`ValueError` unless ``diagnostic=True``,
    in which case the result is diagnostic and records the actual
    overlap (or ``"unknown"`` status).  ``allow_same_dataset=True`` is
    likewise a diagnostic override and never yields a held-out label.

    Args:
        test_path: Path to test/evaluation JSONL dataset
        threshold: Threshold to evaluate
        calibration_dataset_hash: Hash of calibration dataset (for verification)
        strict: Whether to fail on invalid JSON lines
        allow_same_dataset: Allow evaluation on same dataset as calibration (diagnostic only)
        disjointness_proof: Sample/group-level proof linking the
            calibration (training/selection/fit) data to this evaluation
        diagnostic: Allow a contaminated/unknown proof to produce a
            diagnostic result instead of raising

    Returns:
        EvaluationResult with metrics
    """
    test_path = Path(test_path)
    test_hash = dataset_sha256(test_path)

    if (
        not allow_same_dataset
        and calibration_dataset_hash
        and test_hash == calibration_dataset_hash
    ):
        raise ValueError(
            "Evaluation dataset matches the calibration dataset. "
            "Use a separate held-out dataset for release-quality validation. "
            "Use allow_same_dataset=True only for diagnostics."
        )

    rows, skipped = _load_scores(test_path, strict=strict)

    # Metrics arithmetic lives in benchmark._metrics; this function used
    # to duplicate it inline (Phase 2 wave e dedup — verify.py keeps its
    # own copy deliberately as the N-version check). Values are rounded
    # to 4 decimals by _metrics, matching what to_dict() emits.
    metrics = _metrics(rows, threshold)

    if disjointness_proof is not None:
        if disjointness_proof.evaluation_hash and disjointness_proof.evaluation_hash != test_hash:
            raise ValueError("Disjointness proof does not match the evaluation dataset.")
        if (
            calibration_dataset_hash
            and disjointness_proof.training_hash
            and disjointness_proof.training_hash != calibration_dataset_hash
        ):
            raise ValueError("Disjointness proof does not match the calibration dataset.")
    if allow_same_dataset:
        evaluation_mode = "diagnostic"
        if disjointness_proof is not None:
            disjointness_status = disjointness_proof.status
            overlap_count = disjointness_proof.overlap_count
        elif calibration_dataset_hash and test_hash == calibration_dataset_hash:
            disjointness_status = "contaminated"
            overlap_count = len(rows)
        else:
            disjointness_status = "unknown"
            overlap_count = -1
        contamination_detected = disjointness_status == "contaminated"
    elif disjointness_proof is None:
        evaluation_mode = "diagnostic"
        disjointness_status = "unknown"
        overlap_count = -1
        contamination_detected = False
    elif disjointness_proof.status == "verified":
        evaluation_mode = "held_out"
        disjointness_status = "verified"
        overlap_count = 0
        contamination_detected = False
    elif disjointness_proof.status == "contaminated":
        if not diagnostic:
            raise ValueError(
                "Contamination detected: "
                f"{disjointness_proof.overlap_count} overlapping samples "
                "between calibration and evaluation datasets. "
                "Use disjoint datasets to prevent data leakage."
            )
        evaluation_mode = "diagnostic"
        disjointness_status = "contaminated"
        overlap_count = disjointness_proof.overlap_count
        contamination_detected = True
    else:  # unknown proof
        if not diagnostic:
            raise ValueError(
                "Disjointness could not be verified for the evaluation dataset: "
                + "; ".join(disjointness_proof.errors or ("unknown reason",))
                + ". Refusing to treat unverifiable datasets as held out."
            )
        evaluation_mode = "diagnostic"
        disjointness_status = "unknown"
        overlap_count = disjointness_proof.overlap_count
        contamination_detected = False

    return EvaluationResult(
        threshold=threshold,
        tp=metrics["tp"],
        fp=metrics["fp"],
        tn=metrics["tn"],
        fn=metrics["fn"],
        accuracy=metrics["accuracy"],
        fpr=metrics["false_positive_rate"],
        fnr=metrics["false_negative_rate"],
        tpr=metrics["true_positive_rate"],
        specificity=metrics["specificity"],
        precision=metrics["precision"],
        evaluated=metrics["evaluated"],
        test_dataset_hash=test_hash,
        calibration_dataset_hash=calibration_dataset_hash or "",
        evaluation_mode=evaluation_mode,
        contamination_detected=contamination_detected,
        disjointness_status=disjointness_status,
        overlap_count=overlap_count,
        training_hash=(disjointness_proof.training_hash if disjointness_proof is not None else ""),
        evaluation_hash=(
            disjointness_proof.evaluation_hash if disjointness_proof is not None else test_hash
        ),
    )


def validate_no_contamination(
    calibration_path: str | Path,
    test_path: str | Path,
) -> dict[str, Any]:
    """Assert that calibration and test sets are disjoint.

    This is a critical validation step before any evaluation.
    It checks for sample overlap to detect contamination, at both
    sample level (reordered/relabeled rows) and source-document group
    level (repeated ids with changed text, whitespace variants).

    Returns:
        Dict with 'contamination_detected' bool, 'shared_samples' count,
        'shared_hashes' list if overlap found, and 'proof' — the
        :class:`DisjointnessProof` (as a dict) this check is based on.
        A file that cannot be read yields ``valid=False`` with status
        ``"unknown"``, never a clean verdict.
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
        try:
            _, count = _compute_sample_hashes(calibration_path, strict=False)
        except Exception:
            count = 0
        proof = DisjointnessProof(
            status="contaminated",
            overlap_count=count,
            training_count=count,
            evaluation_count=count,
            training_hash=cal_hash,
            evaluation_hash=test_hash,
            group_overlap_count=count,
        )
        result["contamination_detected"] = True
        result["shared_samples"] = -1  # Identical files
        result["warning"] = "Files are identical; all samples overlap"
        result["valid"] = False
        result["proof"] = proof.to_dict()
        result["disjointness_status"] = "contaminated"
        result["group_overlap_count"] = count
        return result

    proof = prove_disjointness(calibration_path, test_path, strict=False)
    result["proof"] = proof.to_dict()
    result["disjointness_status"] = proof.status
    result["group_overlap_count"] = proof.group_overlap_count
    if proof.status == "unknown":
        result["warning"] = "; ".join(proof.errors) or "Disjointness could not be verified."
        result["valid"] = False
        return result
    if proof.status == "contaminated":
        try:
            cal_hashes, _ = _compute_sample_hashes(calibration_path, strict=False)
            test_hashes, _ = _compute_sample_hashes(test_path, strict=False)
            shared = sorted(set(cal_hashes) & set(test_hashes))
        except Exception:
            shared = []
        result["contamination_detected"] = True
        result["shared_samples"] = proof.overlap_count
        result["shared_hashes"] = shared
        result["valid"] = False
        return result
    return result


def load_threshold_artifact(path: str | Path) -> dict[str, Any]:
    """Load a threshold selection artifact.

    Validates the artifact format and returns the dictionary.
    """
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise ValueError("Threshold artifact must be a JSON object")

    validation_errors = []

    if data.get("schema") not in (THRESHOLD_SELECTION_SCHEMA, THRESHOLD_CALIBRATION_SCHEMA):
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


def create_threshold_selection_artifact(
    calibration_result: ThresholdSelectionResult,
    output_path: str | Path,
) -> Path:
    """Create a threshold-selection artifact file from a threshold selection result.

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
    diagnostic: bool = False,
) -> dict[str, Any]:
    """Run the full calibration + evaluation pipeline.

    This is a convenience function that:
    1. Selects threshold on calibration data
    2. Validates disjointness (sample + source-document group level)
    3. Evaluates on held-out test data
    4. Returns combined results

    The evaluation is labelled ``held_out`` only when the
    disjointness proof is ``"verified"``.  A contaminated or unknown
    proof raises :class:`ValueError` unless ``diagnostic=True``, in
    which case the returned evaluation is labelled ``diagnostic`` and
    records the actual overlap / unknown status.

    Args:
        calibration_path: Path to calibration JSONL
        evaluation_path: Path to evaluation JSONL
        target_fpr: Target false positive rate
        strict: Whether to fail on invalid JSON
        diagnostic: Allow a contaminated/unknown proof to produce a
            diagnostic result instead of raising

    Returns:
        Dict with calibration_result, evaluation_result, and validation
    """
    # Validate disjointness first (sample + group level).
    validation = validate_no_contamination(calibration_path, evaluation_path)
    proof = DisjointnessProof.from_dict(validation["proof"])
    if validation["contamination_detected"]:
        if not diagnostic:
            raise ValueError(
                f"Contamination detected: {validation['shared_samples']} overlapping "
                f"samples. Calibration and evaluation datasets must be disjoint."
            )
    elif not validation["valid"] and not diagnostic:
        raise ValueError(
            "Disjointness could not be verified for calibration and "
            "evaluation datasets: "
            + "; ".join(proof.errors or ("unknown reason",))
            + ". Refusing to treat unverifiable datasets as held out."
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
        disjointness_proof=proof,
        diagnostic=diagnostic,
    )
    evaluation_result.contamination_detected = validation["contamination_detected"]

    return {
        "calibration_result": calibration_result.to_dict(),
        "evaluation_result": evaluation_result.to_dict(),
        "validation": validation,
    }
