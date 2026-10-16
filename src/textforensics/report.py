from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from .detectors import Detector, DetectorPrediction, discover_detectors, text_sha256
from .consensus import family_balanced_consensus
from .features import extract_features
from .provenance import verify_ledger
from .robustness import benign_variants


@dataclass(slots=True)
class VerdictIntegrity:
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
    consensus: dict[str, Any]
    verdict_integrity: VerdictIntegrity
    robustness: dict[str, Any]
    provenance: dict[str, Any] | None
    limitations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _robustness_for_detector(detector: Detector, text: str) -> dict[str, Any]:
    probes: dict[str, Any] = {}
    scores: list[float] = []
    labels: list[str] = []
    for name, variant in benign_variants(text).items():
        prediction = detector.detect(variant)
        probes[name] = {
            "score": prediction.score,
            "verdict": prediction.verdict,
        }
        if prediction.score is not None:
            scores.append(prediction.score)
        labels.append(prediction.verdict)

    score_stability = None
    if scores:
        score_stability = max(0.0, 1.0 - (max(scores) - min(scores)))
    verdict_stability = max(labels.count(label) for label in set(labels)) / len(labels) if labels else None
    return {
        "detector_id": detector.detector_id,
        "score_stability": round(score_stability, 4) if score_stability is not None else None,
        "verdict_stability": round(verdict_stability, 4) if verdict_stability is not None else None,
        "probes": probes,
    }


def _integrity(
    predictions: list[DetectorPrediction],
    word_count: int,
    robustness: list[dict[str, Any]],
) -> VerdictIntegrity:
    families = {p.detector_family for p in predictions}
    consensus = family_balanced_consensus(predictions)
    agreement = consensus.family_agreement
    calibrated_families = sum(v.calibrated_ai_probability is not None for v in consensus.family_votes)
    stability_values = [
        r["score_stability"] for r in robustness if r.get("score_stability") is not None
    ]
    robustness_stability = sum(stability_values) / len(stability_values) if stability_values else None

    # Evidence-quality score, NOT authorship probability.
    score = 0.0
    factors: list[str] = []

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
            factors.append("verdict_sensitive_to_benign_normalization")

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
        grade=grade,
        score=round(score, 4),
        detector_count=len(predictions),
        independent_families=len(families),
        verdict_agreement=round(agreement, 4) if agreement is not None else None,
        calibrated_detector_count=calibrated_families,
        robustness_stability=round(robustness_stability, 4) if robustness_stability is not None else None,
        factors=factors,
    )


def build_forensic_bundle(
    text: str,
    *,
    detectors: Iterable[Detector] | None = None,
    ledger_path: str | None = None,
) -> ForensicBundle:
    if not text or not text.strip():
        raise ValueError("Text must not be empty.")

    detector_list = list(detectors) if detectors is not None else list(discover_detectors().values())
    if not detector_list:
        raise ValueError("No detectors are available.")

    predictions = [detector.detect(text) for detector in detector_list]
    robustness = [_robustness_for_detector(detector, text) for detector in detector_list]
    features = extract_features(text)
    provenance = verify_ledger(ledger_path) if ledger_path else None
    consensus = family_balanced_consensus(predictions)
    integrity = _integrity(predictions, int(features["word_count"]), robustness)

    return ForensicBundle(
        schema="textforensics.forensic-bundle/v1",
        generated_at_utc=datetime.now(timezone.utc).isoformat(),
        content_sha256=text_sha256(text),
        input={
            "word_count": features["word_count"],
            "sentence_count": features["sentence_count"],
            "paragraph_count": features["paragraph_count"],
        },
        detector_results=[prediction.to_dict() for prediction in predictions],
        consensus=consensus.to_dict(),
        verdict_integrity=integrity,
        robustness={"detectors": robustness},
        provenance=provenance,
        limitations=[
            "Verdict integrity measures the quality of the available evidence; it is not the probability that AI wrote the text.",
            "Detector scores are not treated as comparable probabilities unless explicitly calibrated.",
            "Text-only evidence cannot prove authorship. Provenance and contextual evidence should be considered separately.",
        ],
    )
