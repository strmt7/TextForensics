from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from .consensus import family_balanced_consensus
from .detectors import (
    Detector,
    DetectorFailure,
    DetectorPrediction,
    discover_detector_registry,
    execute_detector,
    text_sha256,
)
from .features import extract_features
from .provenance import verify_ledger
from .robustness import benign_variants
from .trust import build_trust_map


@dataclass(slots=True)
class VerdictIntegrity:
    """Legacy alpha diagnostic retained for compatibility.

    The hand-weighted score/grade is not calibrated and must not be interpreted
    as the probability that a detector verdict is correct.
    """

    status: str
    grade: str
    score: float
    detector_count: int
    independent_families: int
    verdict_agreement: float | None
    calibrated_detector_count: int
    robustness_stability: float | None
    factors: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ForensicBundle:
    schema: str
    generated_at_utc: str
    content_sha256: str
    input: dict[str, Any]
    detector_results: list[dict[str, Any]]
    detector_failures: list[dict[str, Any]]
    plugin_health: list[dict[str, Any]]
    consensus: dict[str, Any]
    trust_map: dict[str, Any]
    verdict_integrity: VerdictIntegrity
    robustness: dict[str, Any]
    provenance: dict[str, Any] | None
    limitations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _robustness_for_detector(
    detector: Detector,
    text: str,
    original_prediction: DetectorPrediction,
) -> dict[str, Any]:
    probes: dict[str, Any] = {}
    scores: list[float] = []
    labels: list[str] = []
    failures: list[dict[str, Any]] = []

    for name, variant in benign_variants(text).items():
        if name == "original":
            prediction, failure = original_prediction, None
        else:
            prediction, failure = execute_detector(detector, variant)
        if failure is not None:
            failures.append({"probe": name, **failure.to_dict()})
            probes[name] = {"score": None, "verdict": "error"}
            continue
        if prediction is None:  # defensive: execute_detector pairs (prediction, None)
            raise ValueError(
                "Detector returned neither a prediction nor a failure."
            )
        probes[name] = {
            "score": prediction.score,
            "verdict": prediction.verdict,
        }
        if prediction.score is not None:
            scores.append(float(prediction.score))
        labels.append(prediction.verdict)

    native_score_range = None
    if len(scores) >= 2:
        native_score_range = max(scores) - min(scores)

    verdict_stability = None
    if labels:
        verdict_stability = max(labels.count(label) for label in set(labels)) / len(labels)

    return {
        "detector_id": str(getattr(detector, "detector_id", "unknown")),
        "native_score_range": (
            round(native_score_range, 6)
            if native_score_range is not None
            else None
        ),
        "score_range_semantics": (
            "Raw movement in this detector's native score units; "
            "not normalized and not comparable across detectors."
        ),
        "verdict_stability": (
            round(verdict_stability, 4) if verdict_stability is not None else None
        ),
        "probes": probes,
        "failures": failures,
    }


def _integrity(
    predictions: list[DetectorPrediction],
    word_count: int,
    robustness: list[dict[str, Any]],
) -> VerdictIntegrity:
    """Return the legacy alpha evidence-grade diagnostic.

    Kept only for compatibility while the Trust Map becomes the primary
    applicability surface.
    """
    families = {prediction.detector_family for prediction in predictions}
    consensus = family_balanced_consensus(predictions)
    agreement = consensus.family_agreement
    calibrated_families = sum(
        vote.calibrated_ai_probability is not None
        for vote in consensus.family_votes
    )
    stability_values = [
        float(row["verdict_stability"])
        for row in robustness
        if row.get("verdict_stability") is not None
    ]
    robustness_stability = (
        sum(stability_values) / len(stability_values)
        if stability_values
        else None
    )

    score = 0.0
    factors: list[str] = ["legacy_unvalidated_integrity_heuristic"]

    if word_count >= 250:
        score += 0.18
    elif word_count >= 100:
        score += 0.10
        factors.append("moderate_text_length")
    else:
        factors.append("short_text_limits_detector_evidence")

    if len(families) >= 3:
        score += 0.28
    elif len(families) == 2:
        score += 0.18
    else:
        score += 0.05
        factors.append("single_detector_family")

    if calibrated_families >= 2:
        score += 0.22
    elif calibrated_families == 1:
        score += 0.10
    else:
        factors.append("no_probability_calibration")

    if agreement is not None:
        score += 0.17 * agreement
        if agreement < 0.75:
            factors.append("detectors_disagree")
    else:
        factors.append("agreement_unavailable")

    if robustness_stability is not None:
        score += 0.15 * robustness_stability
        if robustness_stability < 0.9:
            factors.append("categorical_verdict_sensitive_to_benign_normalization")

    score = min(1.0, score)
    if score >= 0.85:
        grade = "A"
    elif score >= 0.70:
        grade = "B"
    elif score >= 0.52:
        grade = "C"
    elif score >= 0.35:
        grade = "D"
    else:
        grade = "INSUFFICIENT"

    return VerdictIntegrity(
        status="alpha_unvalidated_heuristic",
        grade=grade,
        score=round(score, 4),
        detector_count=len(predictions),
        independent_families=len(families),
        verdict_agreement=round(agreement, 4) if agreement is not None else None,
        calibrated_detector_count=calibrated_families,
        robustness_stability=(
            round(robustness_stability, 4)
            if robustness_stability is not None
            else None
        ),
        factors=factors,
    )


def build_forensic_bundle(
    text: str,
    *,
    detectors: Iterable[Detector] | None = None,
    ledger_path: str | None = None,
    deterministic: bool = False,
    fixed_timestamp: str | None = None,
) -> ForensicBundle:
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Text must not be empty.")

    if detectors is None:
        registry = discover_detector_registry()
        detector_list = list(registry.detectors.values())
        plugin_health = [row.to_dict() for row in registry.plugin_health]
    else:
        detector_list = list(detectors)
        plugin_health = []

    if not detector_list:
        raise ValueError("No detectors are configured.")

    predictions: list[DetectorPrediction] = []
    failures: list[DetectorFailure] = []
    successful_detectors: list[Detector] = []

    for detector in detector_list:
        prediction, failure = execute_detector(detector, text)
        if prediction is not None:
            predictions.append(prediction)
            successful_detectors.append(detector)
        if failure is not None:
            failures.append(failure)

    robustness = [
        _robustness_for_detector(detector, text, prediction)
        for detector, prediction in zip(successful_detectors, predictions, strict=False)
    ]
    features = extract_features(text)
    provenance = verify_ledger(ledger_path) if ledger_path else None
    consensus = family_balanced_consensus(predictions)
    trust_map = build_trust_map(
        predictions,
        word_count=int(features["word_count"]),
        robustness=robustness,
        failure_count=len(failures),
    )
    integrity = _integrity(
        predictions,
        int(features["word_count"]),
        robustness,
    )

    # Deterministic timestamp for reproducible outputs
    if deterministic:
        generated_at_utc = fixed_timestamp or "1970-01-01T00:00:00+00:00"
    else:
        generated_at_utc = datetime.now(timezone.utc).isoformat()

    # Strip runtime_ms from detector_results and detector_failures in deterministic mode
    if deterministic:
        detector_results = [
            {k: v for k, v in pred.to_dict().items() if k != "runtime_ms"}
            for pred in predictions
        ]
        detector_failures = [
            {k: v for k, v in fail.to_dict().items() if k != "runtime_ms"}
            for fail in failures
        ]
        # Also strip runtime_ms from robustness failures
        for rob in robustness:
            rob["failures"] = [
                {k: v for k, v in f.items() if k != "runtime_ms"}
                for f in rob["failures"]
            ]
    else:
        detector_results = [pred.to_dict() for pred in predictions]
        detector_failures = [fail.to_dict() for fail in failures]

    limitations = [
        (
            "Text-only detector evidence is not proof of authorship. False "
            "positives and false negatives remain possible."
        ),
        (
            "Detector-native scores are not treated as comparable probabilities "
            "unless explicit calibration evidence exists."
        ),
        (
            "The Trust Map describes evidence coverage; it is not an authorship "
            "probability."
        ),
        (
            "Verdict Integrity is a deprecated alpha heuristic retained for "
            "compatibility and is not a validated trust score."
        ),
    ]
    if failures:
        limitations.append(
            f"{len(failures)} configured detector(s) failed and were excluded "
            "from consensus."
        )

    return ForensicBundle(
        schema="textforensics.forensic-bundle/v1",
        generated_at_utc=generated_at_utc,
        content_sha256=text_sha256(text),
        input={
            "word_count": features["word_count"],
            "sentence_count": features["sentence_count"],
            "paragraph_count": features["paragraph_count"],
            "raw_text_included": False,
        },
        detector_results=detector_results,
        detector_failures=detector_failures,
        plugin_health=plugin_health,
        consensus=consensus.to_dict(),
        trust_map=trust_map.to_dict(),
        verdict_integrity=integrity,
        robustness={"detectors": robustness},
        provenance=provenance,
        limitations=limitations,
    )
