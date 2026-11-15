from __future__ import annotations

import hashlib
import importlib.metadata
import math
import time
from dataclasses import asdict, dataclass, field, replace
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from .engine import analyze_text
from .execution_policy import (
    CancellationToken,
    ExecutionPolicy,
    assert_execution_allowed,
)


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
    """A detector adapter.

    A detector MAY additionally declare two optional class attributes:

    - ``deterministic: bool | None`` — ``True`` when the detector
      re-runs exactly on the same text (same score, verdict and
      version), ``False`` when it may not (for example a sampled LLM
      adapter), ``None`` (or absent) when determinism is unknown.
    - ``determinism_reason: str | None`` — why the detector is (not)
      deterministic, recorded at seal time when the detector is
      declared non-deterministic.

    These are deliberately NOT protocol members: this protocol is
    ``runtime_checkable``, and ``isinstance`` against it rejects any
    object missing a declared member, so making them members would
    break every existing detector that does not declare them.  They
    are read with :func:`detector_determinism`, which treats a
    missing or ``None`` declaration as ``"unknown"``.
    """

    detector_id: str
    detector_version: str
    detector_family: str

    def detect(self, text: str) -> DetectorPrediction: ...


DETERMINISM_VALUES = frozenset({"deterministic", "non_deterministic", "unknown"})


def detector_determinism(detector: Any) -> tuple[str, str | None]:
    """Return a detector's ``(determinism, reason)`` declaration.

    Reads the optional ``deterministic`` / ``determinism_reason``
    attributes (see :class:`Detector`).  A detector that declares
    nothing is ``"unknown"`` with no reason; a non-boolean
    declaration is treated as unknown rather than trusted.
    """
    declared = getattr(detector, "deterministic", None)
    if declared is True:
        value = "deterministic"
    elif declared is False:
        value = "non_deterministic"
    else:
        value = "unknown"
    reason = getattr(detector, "determinism_reason", None)
    if not isinstance(reason, str) or not reason.strip():
        reason = None
    return value, reason


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
    # CC-17: the binding check refuses an id mismatch and any recorded identity that does not match.
    _validate_calibration_binding(prediction, calibration_id)


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
    # Pure function of the input text: re-running it returns the same
    # score, verdict and version, so replay can reproduce it exactly.
    deterministic = True
    determinism_reason = None

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


def detector_execution(detector: Any) -> str:
    """Return a detector's declared execution mode.

    Reads the optional ``execution`` (``"local"`` / ``"remote"``) or
    ``remote`` (bool) attributes. Adapters that declare neither — like
    the builtin heuristic detector, which only states execution in its
    predictions — report ``"unknown"``. Unknown is treated as local
    before the call and is re-checked against the returned prediction
    after the call (see :func:`execute_detector`); it is never assumed
    to be remote, and never assumed to be local after the fact.
    """
    declared = getattr(detector, "execution", None)
    if declared in {"local", "remote"}:
        return str(declared)
    remote = getattr(detector, "remote", None)
    if remote is True:
        return "remote"
    if remote is False:
        return "local"
    return "unknown"


def is_remote_detector(detector: Any) -> bool:
    """Return ``True`` iff the detector declares remote execution.

    This is the shared pre-call classification used by the execution
    policy. It never imports or runs the adapter.
    """
    return detector_execution(detector) == "remote"


def filter_detectors_by_policy(
    detectors: list[Detector],
    policy: ExecutionPolicy,
) -> tuple[list[Detector], list[dict[str, str]]]:
    """Split detectors into (allowed, skipped) under ``policy``.

    Skipped entries are ``{"detector_id": ..., "reason":
    "remote_not_consented"}`` records for provenance. Detectors with
    undeclared execution pass through here; a remote prediction from
    one is refused by :func:`execute_detector` instead.
    """
    allowed: list[Detector] = []
    skipped: list[dict[str, str]] = []
    for detector in detectors:
        detector_id = str(getattr(detector, "detector_id", "unknown"))
        if is_remote_detector(detector) and not policy.allows_remote(detector_id):
            skipped.append({"detector_id": detector_id, "reason": "remote_not_consented"})
        else:
            allowed.append(detector)
    return allowed, skipped


def _remote_not_consented_failure(detector: Any, started: float) -> DetectorFailure:
    """Build the failure record for a remote detector refused by policy."""
    return DetectorFailure(
        detector_id=str(getattr(detector, "detector_id", "unknown")),
        detector_version=str(getattr(detector, "detector_version", "unknown")),
        detector_family=str(getattr(detector, "detector_family", "unknown")),
        error_type="RemoteNotConsented",
        message=(
            "Remote detector execution was refused by the execution "
            "policy: no explicit consent for this detector."
        ),
        runtime_ms=round((time.perf_counter() - started) * 1000, 3),
    )


def execute_detector(
    detector: Detector,
    text: str,
    *,
    policy: ExecutionPolicy | None = None,
    cancellation: CancellationToken | None = None,
) -> tuple[DetectorPrediction | None, DetectorFailure | None]:
    """Execute one detector under the shared execution policy.

    Enforcement lives here — in the detector loop — not only in
    transport middleware:

    * the shared stop/cancellation check runs before the call and
      again after it returns (a stop that activates mid-call discards
      the result; the error propagates, it is never converted into an
      ordinary detector failure);
    * a detector that declares remote execution runs only when
      ``policy`` explicitly consents to its ID — otherwise it is not
      called at all and a ``RemoteNotConsented`` failure is returned;
    * a detector that only reveals remote execution in its returned
      prediction has that prediction discarded with the same failure;
    * a configured ``max_input_bytes`` bound is enforced before the
      call.

    With no policy given, the default local-only policy applies, so
    every pre-existing caller is fail-closed by default.
    """
    effective_policy = policy or ExecutionPolicy.default_local_only()
    assert_execution_allowed(effective_policy, cancellation=cancellation)
    started = time.perf_counter()
    if (
        effective_policy.max_input_bytes is not None
        and len(text.encode("utf-8")) > effective_policy.max_input_bytes
    ):
        raise ValueError(
            f"Text exceeds the configured input limit of {effective_policy.max_input_bytes} bytes."
        )
    detector_id = str(getattr(detector, "detector_id", "unknown"))
    if is_remote_detector(detector) and not effective_policy.allows_remote(detector_id):
        return None, _remote_not_consented_failure(detector, started)
    try:
        prediction = detector.detect(text)
        validate_prediction(prediction, detector=detector)
        _validate_no_source_echo(prediction, text)
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
    # Post-call gates run outside the failure conversion above: a stop
    # or cancellation is terminal, never an ordinary detector failure.
    assert_execution_allowed(effective_policy, cancellation=cancellation)
    if prediction.execution == "remote" and not effective_policy.allows_remote(
        prediction.detector_id
    ):
        return None, _remote_not_consented_failure(detector, started)
    if prediction.runtime_ms is None:
        prediction.runtime_ms = round((time.perf_counter() - started) * 1000, 3)
    return prediction, None


def text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def run_all_detectors(
    text: str,
    *,
    policy: ExecutionPolicy | None = None,
    cancellation: CancellationToken | None = None,
) -> list[dict[str, Any]]:
    """Run all discovered detectors on the given text and return their predictions as dicts.

    Enforced under ``policy`` (default local-only): remote detectors
    without explicit consent are not called and appear as
    ``RemoteNotConsented`` failure rows. The shared stop check runs
    before the run and before each detector; an active stop raises
    :class:`textforensics.emergency_stop.EmergencyStopError` instead
    of returning partial results.
    """
    effective_policy = policy or ExecutionPolicy.default_local_only()
    assert_execution_allowed(effective_policy, cancellation=cancellation)
    registry = discover_detector_registry()
    detector_list = list(registry.detectors.values())

    results = []
    for detector in detector_list:
        prediction, failure = execute_detector(
            detector, text, policy=effective_policy, cancellation=cancellation
        )
        if prediction is not None:
            row = prediction.to_dict()
            value, reason = detector_determinism(detector)
            row["determinism"] = value
            row["determinism_reason"] = reason
            results.append(row)
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


# ---------------------------------------------------------------------------
# Adapter-level calibration binding (audit W6, CC-17 / CORE-05)
# ---------------------------------------------------------------------------
# The CalibrationManager API (W2) already requires an exact
# InferenceIdentity to select or apply an artifact — but no production
# call site threaded an identity through the adapter layer, so a curve
# fitted for a stale detector version, provider, model or configuration
# could be bound to a current prediction without any check. These
# functions are that call site: the identity is derived from the
# prediction (and its adapter) itself, and any mismatch — stale
# version, provider, model, semantics, config or regime, or a
# partially-bound identity — refuses the binding fail-closed. Nothing
# here changes the uncalibrated paths: predictions without calibration
# are untouched, and a refused binding leaves the input prediction
# uncalibrated rather than silently stamping a probability on it.
#
# These functions are appended here, after all existing code, so the
# line numbers of the functions above — and the mutation-baseline
# entries pinned to them — do not move. The two imports they need
# (``evidence`` for InferenceIdentity, ``calibration`` for
# CalibrationArtifact) are deferred to call time: ``calibration``
# imports ``benchmark``, which imports this module, so a top-level
# import would be circular.


def _identity_native_score_semantics(prediction: DetectorPrediction) -> str | None:
    """Identity descriptor for a prediction's native score (CC-17).

    The calibration layer's ``native_score_semantics`` is the
    normalised ``"{input_semantics}_{direction}"`` vocabulary — an
    eligible artifact's semantics must equal its curve's input
    semantics and direction — so it is derived from the prediction's
    controlled ``native_score_direction``, NOT from the free-text
    ``score_semantics`` (which no eligible artifact can record: deriving
    from it would make every binding refuse, including a genuinely
    matching curve). A [0, 1] native score is a probability-domain
    input to the curve, hence the ``"probability_"`` prefix; "probability"
    here names the input domain, not a claim that the raw score is a
    probability. An unknown or non-applicable direction has no
    descriptor and stays unbound, so binding refuses fail-closed.
    """
    if prediction.native_score_direction in {"higher_means_ai", "lower_means_ai"}:
        return f"probability_{prediction.native_score_direction}"
    return None


def _validate_calibration_binding(prediction: DetectorPrediction, calibration_id: str) -> None:
    """Refuse calibration metadata bound to a stale identity (CC-17).

    Called from :func:`_validate_calibration_metadata`: the
    prediction's ``calibration_id`` must match the ``calibration``
    dict's, and a ``calibration`` dict may record the inference
    identity the curve was fitted for (``detector_id``,
    ``detector_version``, ``provider``, ``model``,
    ``native_score_semantics``, ``config_hash``). Any such field that
    is present must agree with the prediction's own identity: a curve
    fitted for another detector version, provider, model or score
    semantics cannot be silently bound to this prediction — the
    prediction is refused instead. A declared ``config_hash`` must
    additionally be a 64-character lowercase hex digest. Fields the
    prediction cannot determine have no prediction-side counterpart
    and are not cross-checked here: ``regime`` (the prediction declares
    supported regimes, not the regime of the text at hand) is enforced
    where a curve is applied (:func:`apply_calibration`, via the
    artifact's exact identity match), and an absent field is simply
    unbound, never assumed.
    """
    if prediction.calibration_id is not None and prediction.calibration_id != calibration_id:
        raise DetectorContractError("calibration.calibration_id does not match calibration_id.")
    calibration = prediction.calibration
    if calibration is None:
        return
    runtime = prediction.runtime if isinstance(prediction.runtime, dict) else None
    expected: dict[str, Any] = {
        "detector_id": prediction.detector_id,
        "detector_version": prediction.detector_version,
        "provider": runtime.get("provider") if runtime is not None else None,
        "model": runtime.get("model_id") if runtime is not None else None,
        "native_score_semantics": _identity_native_score_semantics(prediction),
    }
    for field_name, current in expected.items():
        declared = calibration.get(field_name)
        if declared is None:
            continue
        if not isinstance(declared, str) or not declared.strip():
            raise DetectorContractError(
                f"calibration.{field_name} must be a non-empty string or null."
            )
        if current is None or declared != current:
            raise DetectorContractError(
                f"calibration.{field_name} {declared!r} does not match the "
                f"prediction's {field_name} {current!r}: the calibration was "
                "fitted for a different inference identity and must not be "
                "bound to this prediction."
            )
    config_hash = calibration.get("config_hash")
    if config_hash is not None and (
        not isinstance(config_hash, str)
        or len(config_hash) != 64
        or any(character not in "0123456789abcdef" for character in config_hash)
    ):
        raise DetectorContractError(
            "calibration.config_hash must be a 64-character lowercase hex digest."
        )


def inference_identity_for_prediction(
    prediction: DetectorPrediction,
    *,
    detector: Detector | None = None,
    config_hash: str | None = None,
    regime: str | None = None,
) -> InferenceIdentity:
    """Derive the current inference identity of a detector prediction.

    The identity is built from the prediction's own fields — detector
    id/version, runtime provider/model, score semantics and calibration
    id — so it states exactly what ran. ``config_hash`` and ``regime``
    have no prediction-side field and must be supplied by the caller;
    leaving them ``None`` yields a partially-bound identity, which can
    never select or apply an artifact. The score semantics in the
    identity is the calibration layer's normalised descriptor derived
    from the prediction's ``native_score_direction`` (see
    :func:`_identity_native_score_semantics`), not the free-text
    ``score_semantics``. The prediction is validated first (against
    ``detector`` when given, as in :func:`execute_detector`): no identity
    is derived from a contract-violating prediction.
    """
    from .evidence import InferenceIdentity

    validate_prediction(prediction, detector=detector)
    runtime = prediction.runtime if isinstance(prediction.runtime, dict) else {}
    return InferenceIdentity(
        detector_id=prediction.detector_id,
        detector_version=prediction.detector_version,
        provider=runtime.get("provider"),
        model=runtime.get("model_id"),
        config_hash=config_hash,
        native_score_semantics=_identity_native_score_semantics(prediction),
        calibration_id=prediction.calibration_id,
        regime=regime,
    )


def apply_calibration(
    prediction: DetectorPrediction,
    artifact: Any,
    *,
    identity: InferenceIdentity | None = None,
    detector: Detector | None = None,
    config_hash: str | None = None,
    regime: str | None = None,
    allow_unvalidated: bool = False,
) -> DetectorPrediction:
    """Bind a calibration artifact to a prediction, or refuse (CC-17).

    Returns a NEW prediction carrying the calibrated probability, the
    calibration id and the calibration metadata recording the exact
    binding identity; the input prediction is left uncalibrated, so a
    refused binding can never leave a stale probability behind.

    The binding identity is assembled from three sources, each of
    which is authoritative for its own fields: the prediction (detector
    id/version, provider, model, score semantics), the artifact (its
    ``calibration_id`` — an uncalibrated prediction carries none yet,
    so requiring it from the prediction would make a first binding
    impossible), and the caller (``config_hash`` and ``regime``, via
    the keyword arguments or an explicit ``identity``). An explicitly
    supplied ``identity`` must agree with the prediction on every
    field the prediction determines, and its ``calibration_id`` — when
    set — must equal the artifact's; it may additionally supply the
    ``config_hash``/``regime`` the keyword arguments did not.

    Refusals (all fail-closed, nothing is stamped):

    * ``artifact`` is not a :class:`CalibrationArtifact`, or the
      prediction has no score to calibrate;
    * an explicitly supplied ``identity`` disagrees with the identity
      derived from the prediction on any field the prediction
      determines (detector id/version, provider, model, score
      semantics), or names a different ``calibration_id`` than the
      artifact's;
    * the binding identity is not fully bound (a ``config_hash`` or
      ``regime`` the caller did not supply);
    * the artifact's recorded identity does not match the binding
      identity exactly — a stale curve (old version, provider, model,
      configuration or regime) raises :class:`CalibrationError`
      instead of emitting a probability for the wrong inference;
    * the artifact is not eligible for probability emission (unless
      the caller explicitly opts into diagnostics with
      ``allow_unvalidated=True``, which yields an ``"unvalidated"``
      result, never ``"validated"``).
    """
    from .calibration import CalibrationArtifact
    from .evidence import InferenceIdentity

    if not isinstance(artifact, CalibrationArtifact):
        raise DetectorContractError("artifact must be a CalibrationArtifact.")
    if prediction.score is None:
        raise DetectorContractError("cannot apply calibration to a prediction without a score.")
    current = inference_identity_for_prediction(
        prediction, detector=detector, config_hash=config_hash, regime=regime
    )
    if identity is not None:
        if not isinstance(identity, InferenceIdentity):
            raise DetectorContractError("identity must be an InferenceIdentity.")
        for field_name in (
            "detector_id",
            "detector_version",
            "provider",
            "model",
            "native_score_semantics",
        ):
            if getattr(identity, field_name) != getattr(current, field_name):
                raise DetectorContractError(
                    f"identity.{field_name} {getattr(identity, field_name)!r} does "
                    f"not match the prediction's current {field_name} "
                    f"{getattr(current, field_name)!r}; refusing to bind the "
                    "calibration."
                )
        if (
            identity.calibration_id is not None
            and identity.calibration_id != artifact.calibration_id
        ):
            raise DetectorContractError(
                f"identity.calibration_id {identity.calibration_id!r} does not "
                f"match the artifact's calibration_id "
                f"{artifact.calibration_id!r}; refusing to bind the calibration."
            )
        binding = InferenceIdentity(
            detector_id=current.detector_id,
            detector_version=current.detector_version,
            provider=current.provider,
            model=current.model,
            config_hash=(
                identity.config_hash if identity.config_hash is not None else current.config_hash
            ),
            native_score_semantics=current.native_score_semantics,
            calibration_id=artifact.calibration_id,
            regime=identity.regime if identity.regime is not None else current.regime,
        )
    else:
        binding = InferenceIdentity(
            detector_id=current.detector_id,
            detector_version=current.detector_version,
            provider=current.provider,
            model=current.model,
            config_hash=current.config_hash,
            native_score_semantics=current.native_score_semantics,
            calibration_id=artifact.calibration_id,
            regime=current.regime,
        )
    missing = [
        name
        for name in (
            "provider",
            "model",
            "config_hash",
            "native_score_semantics",
            "calibration_id",
            "regime",
        )
        if getattr(binding, name) is None
    ]
    if missing:
        raise DetectorContractError(
            "cannot bind calibration: the current inference identity is not "
            "fully bound (missing "
            + ", ".join(missing)
            + "); a fully-bound identity is required to apply a calibration "
            "artifact."
        )
    result = artifact.apply(
        float(prediction.score),
        identity=binding,
        allow_unvalidated=allow_unvalidated,
    )
    calibration: dict[str, Any] = {
        "calibration_id": result.calibration_id,
        "method": artifact.curve.method,
        "detector_id": binding.detector_id,
        "detector_version": binding.detector_version,
        "provider": binding.provider,
        "model": binding.model,
        "config_hash": binding.config_hash,
        "native_score_semantics": binding.native_score_semantics,
        "regime": binding.regime,
    }
    if artifact.evaluation_dataset is not None:
        calibration["evaluation_fingerprint"] = artifact.evaluation_dataset.fingerprint_sha256
    bound = replace(
        prediction,
        calibrated_ai_probability=result.value,
        calibration_id=result.calibration_id,
        calibration=calibration,
    )
    validate_prediction(bound, detector=detector)
    return bound


# TYPE_CHECKING-only import for the ``InferenceIdentity`` annotations in
# inference_identity_for_prediction / apply_calibration above. It lives
# at the end of the file (rather than with the imports at the top) so
# the line numbers of the functions above — and the mutation-baseline
# entries pinned to them — do not move; the name is only needed for
# static annotation resolution, never at runtime (the functions import
# it lazily when they need it).
if TYPE_CHECKING:
    from .evidence import InferenceIdentity
