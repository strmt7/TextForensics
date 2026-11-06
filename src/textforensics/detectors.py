from __future__ import annotations

import hashlib
import importlib.metadata
import math
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol, runtime_checkable

from .engine import analyze_text


class DetectorContractError(ValueError):
    """Raised when a detector violates the public TFDP contract."""


DETECTOR_SCHEMA_V1 = "textforensics.detector-result/v1"
DETECTOR_SCHEMA_V2 = "textforensics.detector-result/v2"
DETECTOR_EVIDENCE_SCHEMA = "textforensics.detector-evidence/v1"

_NATIVE_SCORE_DIRECTIONS = frozenset(
    {"higher_means_ai", "lower_means_ai", "not_applicable", "unknown"}
)
_SUPPORTED_EDITING_REGIMES = frozenset(
    {
        "human_only",
        "machine_only",
        "machine_then_human_edited",
        "machine_then_machine_paraphrased",
        "mixed",
        "*",
    }
)
_CALIBRATION_METHODS = frozenset({"platt", "temperature", "isotonic", "beta", "identity"})


@dataclass(slots=True)
class DetectorPrediction:
    """Portable detector output for the TextForensics Detector Protocol.

    TFDP/2 adds explicit score direction, score range, supported-condition
    metadata, calibration provenance and runtime provenance.  TFDP/1
    predictions remain accepted and are normalized by
    :func:`normalize_prediction`.

    `score` is an instrument output, not automatically a probability.
    `calibrated_ai_probability` may only be populated with a calibration ID.
    """

    schema: str
    detector_id: str
    detector_version: str
    detector_family: str
    execution: str
    score: float | None
    score_semantics: str
    verdict: str
    threshold: float | None
    calibrated_ai_probability: float | None = None
    calibration_id: str | None = None
    reliability: float | None = None
    supported_languages: list[str] = field(default_factory=list)
    min_words: int | None = None
    evidence: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    runtime_ms: float | None = None
    native_score_direction: str = "unknown"
    score_range: list[float] | None = None
    supported_length: dict[str, int | None] | None = None
    supported_domains: list[str] = field(default_factory=list)
    supported_editing_regimes: list[str] = field(default_factory=list)
    supported_generators: list[str] = field(default_factory=list)
    calibration: dict[str, Any] | None = None
    runtime: dict[str, Any] | None = None
    evidence_schema: str = DETECTOR_EVIDENCE_SCHEMA
    protocol_version: str = "TFDP/2"
    normalized_from: str | None = None

    def validate(self, *, detector: Detector | None = None) -> DetectorPrediction:
        validate_prediction(self, detector=detector)
        return self

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class DetectorFailure:
    detector_id: str
    detector_version: str
    detector_family: str
    error_type: str
    message: str
    runtime_ms: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class PluginHealth:
    entry_point: str
    status: str
    detector_id: str | None = None
    error_type: str | None = None
    message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class DetectorRegistry:
    detectors: dict[str, Detector] = field(default_factory=dict)
    plugin_health: list[PluginHealth] = field(default_factory=list)


@runtime_checkable
class Detector(Protocol):
    detector_id: str
    detector_version: str
    detector_family: str

    def detect(self, text: str) -> DetectorPrediction: ...


def _require_nonempty_string(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise DetectorContractError(f"{field_name} must be a non-empty string.")


def _require_finite_number(value: Any, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DetectorContractError(f"{field_name} must be a finite number.")
    if not math.isfinite(float(value)):
        raise DetectorContractError(f"{field_name} must be finite.")


_FORBIDDEN_EVIDENCE_KEYS = {
    "text",
    "raw_text",
    "source_text",
    "document_text",
    "content",
    "snippet",
    "quote",
    "excerpt",
}


def _forbidden_evidence_paths(value: Any, path: str = "evidence") -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            key_string = str(key)
            child_path = f"{path}.{key_string}"
            if key_string.strip().lower() in _FORBIDDEN_EVIDENCE_KEYS:
                found.append(child_path)
            found.extend(_forbidden_evidence_paths(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_forbidden_evidence_paths(child, f"{path}[{index}]"))
    return found


def _iter_strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _iter_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_strings(child)


def _normalize_for_echo_check(value: str) -> str:
    return " ".join(value.split())


def _validate_no_source_echo(prediction: DetectorPrediction, source_text: str) -> None:
    source = _normalize_for_echo_check(source_text)
    if not source:
        return

    candidates = list(prediction.warnings)
    candidates.extend(_iter_strings(prediction.evidence))
    for candidate in candidates:
        normalized = _normalize_for_echo_check(candidate)
        if not normalized:
            continue
        exact_source = normalized == source and len(source) >= 8
        long_excerpt = len(normalized) >= 32 and normalized in source
        source_embedded = len(source) >= 32 and source in normalized
        if exact_source or long_excerpt or source_embedded:
            raise DetectorContractError("Detector output appears to echo submitted source text.")


def normalize_prediction(prediction: DetectorPrediction) -> DetectorPrediction:
    """Normalize TFDP/1 predictions to TFDP/2 without inventing evidence.

    The normalization is recorded on the prediction so a report can state
    exactly what was upgraded.  Missing TFDP/2 metadata remains ``unknown``;
    it is never guessed from the detector's name or output.
    """
    if not isinstance(prediction, DetectorPrediction):
        raise DetectorContractError("Detector must return DetectorPrediction.")
    if prediction.schema == DETECTOR_SCHEMA_V2:
        return prediction
    if prediction.schema != DETECTOR_SCHEMA_V1:
        raise DetectorContractError("Unsupported detector-result schema.")

    prediction.schema = DETECTOR_SCHEMA_V2
    prediction.protocol_version = "TFDP/1"
    prediction.normalized_from = DETECTOR_SCHEMA_V1
    if prediction.native_score_direction == "unknown" and prediction.score is not None:
        # TFDP/1 did not declare direction.  ``unknown`` is retained rather
        # than guessed from score_semantics prose.
        prediction.native_score_direction = "unknown"
    if prediction.supported_length is None and prediction.min_words is not None:
        prediction.supported_length = {
            "min_words": prediction.min_words,
            "max_words": None,
        }
    if prediction.runtime is None:
        prediction.runtime = {"mode": prediction.execution}
    return prediction


def _validate_string_list(values: Any, field_name: str) -> None:
    if not isinstance(values, list) or any(
        not isinstance(item, str) or not item.strip() for item in values
    ):
        raise DetectorContractError(f"{field_name} must be a list of non-empty strings.")


def _validate_supported_length(value: Any) -> None:
    if value is None:
        return
    if not isinstance(value, dict):
        raise DetectorContractError("supported_length must be an object or null.")
    unknown = set(value) - {"min_words", "max_words"}
    if unknown:
        raise DetectorContractError(
            f"supported_length has unknown key(s): {', '.join(sorted(unknown))}."
        )
    if not value:
        raise DetectorContractError("supported_length must declare at least one bound.")
    minimum = value.get("min_words")
    maximum = value.get("max_words")
    for name, bound in (("min_words", minimum), ("max_words", maximum)):
        if bound is None:
            continue
        if isinstance(bound, bool) or not isinstance(bound, int):
            raise DetectorContractError(f"supported_length.{name} must be an integer or null.")
        if bound < 0:
            raise DetectorContractError(f"supported_length.{name} must be non-negative.")
    if minimum is not None and maximum is not None and minimum > maximum:
        raise DetectorContractError(
            "supported_length.min_words cannot exceed supported_length.max_words."
        )


def _validate_score_range(prediction: DetectorPrediction) -> None:
    if prediction.score_range is None:
        return
    if not isinstance(prediction.score_range, (list, tuple)) or len(prediction.score_range) != 2:
        raise DetectorContractError("score_range must be a two-element sequence or null.")
    minimum = prediction.score_range[0]
    maximum = prediction.score_range[1]
    _require_finite_number(minimum, "score_range[0]")
    _require_finite_number(maximum, "score_range[1]")
    if float(minimum) >= float(maximum):
        raise DetectorContractError("score_range minimum must be below maximum.")
    if prediction.score is not None and not (
        float(minimum) <= float(prediction.score) <= float(maximum)
    ):
        raise DetectorContractError("score lies outside the declared score_range.")


def _validate_calibration_metadata(prediction: DetectorPrediction) -> None:
    if prediction.calibration is None:
        return
    if not isinstance(prediction.calibration, dict):
        raise DetectorContractError("calibration must be an object or null.")
    calibration_id = prediction.calibration.get("calibration_id")
    _require_nonempty_string(calibration_id, "calibration.calibration_id")
    method = prediction.calibration.get("method")
    if method not in _CALIBRATION_METHODS:
        raise DetectorContractError(
            f"calibration.method must be one of {', '.join(sorted(_CALIBRATION_METHODS))}."
        )
    fingerprint = prediction.calibration.get("evaluation_fingerprint")
    if fingerprint is not None and (
        not isinstance(fingerprint, str)
        or len(fingerprint) != 64
        or any(character not in "0123456789abcdef" for character in fingerprint)
    ):
        raise DetectorContractError(
            "calibration.evaluation_fingerprint must be a 64-character lowercase hex digest."
        )
    if prediction.calibration_id is not None and prediction.calibration_id != calibration_id:
        raise DetectorContractError("calibration.calibration_id does not match calibration_id.")


def _validate_runtime_metadata(prediction: DetectorPrediction) -> None:
    if prediction.runtime is None:
        return
    if not isinstance(prediction.runtime, dict):
        raise DetectorContractError("runtime must be an object or null.")
    mode = prediction.runtime.get("mode")
    if mode not in {"local", "remote"}:
        raise DetectorContractError("runtime.mode must be 'local' or 'remote'.")
    if mode != prediction.execution:
        raise DetectorContractError("runtime.mode must match execution.")
    for key in ("provider", "provider_version", "model_id", "device"):
        value = prediction.runtime.get(key)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise DetectorContractError(f"runtime.{key} must be a non-empty string or null.")


def validate_prediction(
    prediction: DetectorPrediction,
    *,
    detector: Detector | None = None,
) -> None:
    if not isinstance(prediction, DetectorPrediction):
        raise DetectorContractError("Detector must return DetectorPrediction.")

    normalize_prediction(prediction)

    if prediction.protocol_version not in {"TFDP/1", "TFDP/2"}:
        raise DetectorContractError("Unsupported detector protocol version.")
    if prediction.evidence_schema != DETECTOR_EVIDENCE_SCHEMA:
        raise DetectorContractError("Unsupported detector-evidence schema.")
    if prediction.native_score_direction not in _NATIVE_SCORE_DIRECTIONS:
        raise DetectorContractError("Invalid native_score_direction.")

    for name in (
        "detector_id",
        "detector_version",
        "detector_family",
        "score_semantics",
    ):
        _require_nonempty_string(getattr(prediction, name), name)

    if prediction.execution not in {"local", "remote"}:
        raise DetectorContractError("execution must be 'local' or 'remote'.")

    if prediction.verdict not in {"ai_like", "human_like", "abstain"}:
        raise DetectorContractError("verdict must be 'ai_like', 'human_like', or 'abstain'.")

    if prediction.score is not None:
        _require_finite_number(prediction.score, "score")

    if prediction.threshold is not None:
        _require_finite_number(prediction.threshold, "threshold")

    if prediction.calibrated_ai_probability is not None:
        _require_finite_number(
            prediction.calibrated_ai_probability,
            "calibrated_ai_probability",
        )
        probability = float(prediction.calibrated_ai_probability)
        if not 0.0 <= probability <= 1.0:
            raise DetectorContractError("calibrated_ai_probability must be between 0 and 1.")
        _require_nonempty_string(prediction.calibration_id, "calibration_id")
    elif prediction.calibration_id is not None:
        raise DetectorContractError(
            "calibration_id cannot be set without calibrated_ai_probability."
        )

    if prediction.reliability is not None:
        _require_finite_number(prediction.reliability, "reliability")
        if not 0.0 <= float(prediction.reliability) <= 1.0:
            raise DetectorContractError("reliability must be between 0 and 1.")

    if prediction.min_words is not None:
        if isinstance(prediction.min_words, bool) or not isinstance(prediction.min_words, int):
            raise DetectorContractError("min_words must be an integer or null.")
        if prediction.min_words < 0:
            raise DetectorContractError("min_words must be non-negative.")

    if prediction.runtime_ms is not None:
        _require_finite_number(prediction.runtime_ms, "runtime_ms")
        if float(prediction.runtime_ms) < 0:
            raise DetectorContractError("runtime_ms must be non-negative.")

    if not isinstance(prediction.supported_languages, list) or any(
        not isinstance(item, str) or not item.strip() for item in prediction.supported_languages
    ):
        raise DetectorContractError("supported_languages must be a list of non-empty strings.")

    _validate_supported_length(prediction.supported_length)
    if (
        prediction.supported_length is not None
        and prediction.min_words is not None
        and prediction.supported_length.get("min_words") != prediction.min_words
    ):
        raise DetectorContractError("supported_length.min_words does not match min_words.")
    _validate_score_range(prediction)
    _validate_calibration_metadata(prediction)
    _validate_runtime_metadata(prediction)
    _validate_string_list(prediction.supported_domains, "supported_domains")
    _validate_string_list(prediction.supported_editing_regimes, "supported_editing_regimes")
    _validate_string_list(prediction.supported_generators, "supported_generators")
    invalid_editing = set(prediction.supported_editing_regimes) - _SUPPORTED_EDITING_REGIMES
    if invalid_editing:
        raise DetectorContractError(
            "supported_editing_regimes contains unsupported value(s): "
            f"{', '.join(sorted(invalid_editing))}."
        )
    if prediction.normalized_from not in {None, DETECTOR_SCHEMA_V1}:
        raise DetectorContractError("normalized_from must be null or a TFDP/1 schema.")

    if not isinstance(prediction.warnings, list) or any(
        not isinstance(item, str) for item in prediction.warnings
    ):
        raise DetectorContractError("warnings must be a list of strings.")

    if not isinstance(prediction.evidence, list) or any(
        not isinstance(item, dict) for item in prediction.evidence
    ):
        raise DetectorContractError("evidence must be a list of objects.")

    forbidden_paths = _forbidden_evidence_paths(prediction.evidence)
    if forbidden_paths:
        raise DetectorContractError("Detector evidence must not embed raw source-text fields.")

    if detector is not None:
        for attr in ("detector_id", "detector_version", "detector_family"):
            if getattr(prediction, attr) != getattr(detector, attr):
                raise DetectorContractError(
                    f"Prediction {attr} does not match the detector adapter."
                )


class BuiltinHeuristicDetector:
    detector_id = "textforensics/builtin-heuristic"
    detector_version = "0.1.0"
    detector_family = "stylometric-heuristic"

    def detect(self, text: str) -> DetectorPrediction:
        started = time.perf_counter()
        result = analyze_text(text)
        if result.verdict == "machine_like_patterns":
            verdict = "ai_like"
        elif result.verdict == "human_like_patterns":
            verdict = "human_like"
        else:
            verdict = "abstain"

        evidence = [
            {
                "analyzer": analyzer.name,
                "score": round(analyzer.score, 4),
                "reliability": round(analyzer.reliability, 4),
            }
            for analyzer in result.analyzers
        ]

        prediction = DetectorPrediction(
            schema=DETECTOR_SCHEMA_V2,
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            detector_family=self.detector_family,
            execution="local",
            score=result.score,
            score_semantics=("higher_means_more_machine_like; uncalibrated pattern score"),
            verdict=verdict,
            threshold=None,
            calibrated_ai_probability=None,
            calibration_id=None,
            reliability=result.diagnostic_reliability,
            supported_languages=["en"],
            min_words=80,
            evidence=evidence,
            warnings=[
                *result.warnings,
                (
                    "The reliability value is an uncalibrated heuristic diagnostic "
                    "for the built-in baseline."
                ),
            ],
            runtime_ms=round((time.perf_counter() - started) * 1000, 3),
            native_score_direction="higher_means_ai",
            score_range=[0.0, 1.0],
            supported_length={"min_words": 80, "max_words": None},
            supported_domains=[],
            supported_editing_regimes=[],
            supported_generators=[],
            calibration=None,
            runtime={
                "mode": "local",
                "provider": "textforensics",
                "provider_version": self.detector_version,
                "model_id": "builtin-stylometric-heuristic",
                "device": "cpu",
            },
        )
        return prediction.validate(detector=self)


_BUILTINS: dict[str, type[Detector]] = {
    BuiltinHeuristicDetector.detector_id: BuiltinHeuristicDetector,
}


def _entry_points() -> list[Any]:
    try:
        eps = importlib.metadata.entry_points()
        selected = (
            eps.select(group="textforensics.detectors")
            if hasattr(eps, "select")
            else eps.get("textforensics.detectors", [])
        )
        return list(selected)
    except Exception:
        return []


def discover_detector_registry() -> DetectorRegistry:
    found: dict[str, Detector] = {}
    health: list[PluginHealth] = []

    for detector_id, detector_class in _BUILTINS.items():
        detector = detector_class()
        found[detector_id] = detector
        health.append(
            PluginHealth(
                entry_point="builtin",
                status="ok",
                detector_id=detector_id,
            )
        )

    for entry_point in _entry_points():
        entry_name = getattr(entry_point, "name", repr(entry_point))
        try:
            candidate = entry_point.load()()
            if not isinstance(candidate, Detector):
                raise DetectorContractError(
                    "Plugin object does not implement the Detector protocol."
                )
            for attr in ("detector_id", "detector_version", "detector_family"):
                _require_nonempty_string(getattr(candidate, attr, None), attr)
            if candidate.detector_id in found:
                raise DetectorContractError(f"Duplicate detector_id: {candidate.detector_id}")
            found[candidate.detector_id] = candidate
            health.append(
                PluginHealth(
                    entry_point=entry_name,
                    status="ok",
                    detector_id=candidate.detector_id,
                )
            )
        except Exception as exc:
            health.append(
                PluginHealth(
                    entry_point=entry_name,
                    status="error",
                    error_type=type(exc).__name__,
                    message="Plugin could not be loaded or failed contract validation.",
                )
            )

    return DetectorRegistry(detectors=found, plugin_health=health)


def discover_detectors() -> dict[str, Detector]:
    return discover_detector_registry().detectors


def list_detector_metadata() -> list[dict[str, str]]:
    registry = discover_detector_registry()
    return [
        {
            "detector_id": item.detector_id,
            "detector_version": item.detector_version,
            "detector_family": item.detector_family,
        }
        for item in sorted(registry.detectors.values(), key=lambda x: x.detector_id)
    ]


def list_detector_health() -> list[dict[str, Any]]:
    return [row.to_dict() for row in discover_detector_registry().plugin_health]


def execute_detector(
    detector: Detector,
    text: str,
) -> tuple[DetectorPrediction | None, DetectorFailure | None]:
    started = time.perf_counter()
    try:
        prediction = detector.detect(text)
        validate_prediction(prediction, detector=detector)
        _validate_no_source_echo(prediction, text)
        if prediction.runtime_ms is None:
            prediction.runtime_ms = round((time.perf_counter() - started) * 1000, 3)
        return prediction, None
    except Exception as exc:
        elapsed = round((time.perf_counter() - started) * 1000, 3)
        return None, DetectorFailure(
            detector_id=str(getattr(detector, "detector_id", "unknown")),
            detector_version=str(getattr(detector, "detector_version", "unknown")),
            detector_family=str(getattr(detector, "detector_family", "unknown")),
            error_type=type(exc).__name__,
            message=(
                "Detector execution failed. Raw exception text is intentionally "
                "omitted to avoid leaking submitted content."
            ),
            runtime_ms=elapsed,
        )


def text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def run_all_detectors(text: str) -> list[dict[str, Any]]:
    """Run all discovered detectors on the given text and return their predictions as dicts."""
    registry = discover_detector_registry()
    detector_list = list(registry.detectors.values())

    results = []
    for detector in detector_list:
        prediction, failure = execute_detector(detector, text)
        if prediction is not None:
            results.append(prediction.to_dict())
        elif failure is not None:
            results.append(
                {
                    "detector_id": failure.detector_id,
                    "detector_version": failure.detector_version,
                    "detector_family": failure.detector_family,
                    "error_type": failure.error_type,
                    "message": failure.message,
                    "runtime_ms": failure.runtime_ms,
                    "failed": True,
                }
            )

    return results
