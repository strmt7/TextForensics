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


@dataclass(slots=True)
class DetectorPrediction:
    """Portable detector output for the TextForensics Detector Protocol (TFDP/1).

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

    def validate(self, *, detector: "Detector | None" = None) -> "DetectorPrediction":
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
    detectors: dict[str, "Detector"] = field(default_factory=dict)
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


def validate_prediction(
    prediction: DetectorPrediction,
    *,
    detector: Detector | None = None,
) -> None:
    if not isinstance(prediction, DetectorPrediction):
        raise DetectorContractError("Detector must return DetectorPrediction.")

    if prediction.schema != "textforensics.detector-result/v1":
        raise DetectorContractError("Unsupported detector-result schema.")

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
        raise DetectorContractError(
            "verdict must be 'ai_like', 'human_like', or 'abstain'."
        )

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
            raise DetectorContractError(
                "calibrated_ai_probability must be between 0 and 1."
            )
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
        if isinstance(prediction.min_words, bool) or not isinstance(
            prediction.min_words, int
        ):
            raise DetectorContractError("min_words must be an integer or null.")
        if prediction.min_words < 0:
            raise DetectorContractError("min_words must be non-negative.")

    if prediction.runtime_ms is not None:
        _require_finite_number(prediction.runtime_ms, "runtime_ms")
        if float(prediction.runtime_ms) < 0:
            raise DetectorContractError("runtime_ms must be non-negative.")

    if not isinstance(prediction.supported_languages, list) or any(
        not isinstance(item, str) or not item.strip()
        for item in prediction.supported_languages
    ):
        raise DetectorContractError(
            "supported_languages must be a list of non-empty strings."
        )

    if not isinstance(prediction.warnings, list) or any(
        not isinstance(item, str) for item in prediction.warnings
    ):
        raise DetectorContractError("warnings must be a list of strings.")

    if not isinstance(prediction.evidence, list) or any(
        not isinstance(item, dict) for item in prediction.evidence
    ):
        raise DetectorContractError("evidence must be a list of objects.")

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
            schema="textforensics.detector-result/v1",
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            detector_family=self.detector_family,
            execution="local",
            score=result.score,
            score_semantics=(
                "higher_means_more_machine_like; uncalibrated pattern score"
            ),
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
                raise DetectorContractError(
                    f"Duplicate detector_id: {candidate.detector_id}"
                )
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
