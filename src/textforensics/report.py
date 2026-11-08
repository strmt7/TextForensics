"""Forensic bundle orchestration.

The bundle is a deterministic, portable record of:

* what each detector observed, in native units;
* which input conditions were observed or declared;
* which validation evidence registry was consulted;
* the resulting evidence-conditioned Trust Map;
* failures, provenance and explicit limitations.

Raw source text is never included.  A detector score is never promoted to a
probability without detector-local calibration provenance.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .conditions import InputConditions, extract_conditions
from .consensus import family_balanced_consensus
from .detectors import (
    DETECTOR_EVIDENCE_SCHEMA,
    DETECTOR_SCHEMA_V1,
    DETECTOR_SCHEMA_V2,
    Detector,
    DetectorFailure,
    DetectorPrediction,
    detector_determinism,
    discover_detector_registry,
    execute_detector,
    text_sha256,
)
from .evidence import EvidenceRegistry, load_registry
from .features import benign_variants, extract_features
from .ledger import verify_ledger
from .trust import TrustMap, assess_trust_map

BUNDLE_SCHEMA = "textforensics.forensic-bundle/v2"
LEGACY_BUNDLE_SCHEMA = "textforensics.forensic-bundle/v1"


@dataclass(slots=True)
class VerdictIntegrity:
    """Legacy alpha diagnostic retained for migration only.

    The hand-weighted score/grade is not calibrated and must not be interpreted
    as the probability that a detector verdict is correct.  It is excluded
    from the default v2 bundle.
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
    input_conditions: dict[str, Any]
    detector_results: list[dict[str, Any]]
    detector_failures: list[dict[str, Any]]
    plugin_health: list[dict[str, Any]]
    detector_protocols: dict[str, Any]
    consensus: dict[str, Any]
    trust_map: dict[str, Any]
    robustness: dict[str, Any]
    provenance: dict[str, Any] | None
    evidence_registry: dict[str, Any]
    limitations: list[str]
    legacy: dict[str, Any] | None = None

    @property
    def verdict_integrity(self) -> dict[str, Any] | None:
        """Compatibility accessor for the deprecated alpha diagnostic."""
        if self.legacy is None:
            return None
        return self.legacy.get("verdict_integrity")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "generated_at_utc": self.generated_at_utc,
            "content_sha256": self.content_sha256,
            "input": self.input,
            "input_conditions": self.input_conditions,
            "detector_results": self.detector_results,
            "detector_failures": self.detector_failures,
            "plugin_health": self.plugin_health,
            "detector_protocols": self.detector_protocols,
            "consensus": self.consensus,
            "trust_map": self.trust_map,
            "robustness": self.robustness,
            "provenance": self.provenance,
            "evidence_registry": self.evidence_registry,
            "limitations": self.limitations,
            "legacy": self.legacy,
        }


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
            raise ValueError("Detector returned neither a prediction nor a failure.")
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
            round(native_score_range, 6) if native_score_range is not None else None
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
    """Return the legacy alpha diagnostic for explicit migration callers."""
    families = {prediction.detector_family for prediction in predictions}
    consensus = family_balanced_consensus(predictions)
    agreement = consensus.family_agreement
    calibrated_families = sum(
        vote.calibrated_ai_probability is not None for vote in consensus.family_votes
    )
    stability_values = [
        float(row["verdict_stability"])
        for row in robustness
        if row.get("verdict_stability") is not None
    ]
    robustness_stability = (
        sum(stability_values) / len(stability_values) if stability_values else None
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
            round(robustness_stability, 4) if robustness_stability is not None else None
        ),
        factors=factors,
    )


def _detector_protocol_summary(
    predictions: Iterable[DetectorPrediction],
) -> dict[str, Any]:
    normalized: list[str] = []
    schemas: set[str] = set()
    for prediction in predictions:
        schemas.add(prediction.schema)
        if prediction.normalized_from == DETECTOR_SCHEMA_V1:
            normalized.append(prediction.detector_id)
    return {
        "detector_result_schema": DETECTOR_SCHEMA_V2,
        "accepted_legacy_schemas": [DETECTOR_SCHEMA_V1],
        "evidence_schema": DETECTOR_EVIDENCE_SCHEMA,
        "normalized_from_tfdp1": sorted(set(normalized)),
        "observed_schemas": sorted(schemas),
    }


def _registry_summary(
    registry: EvidenceRegistry | None,
    *,
    verified: bool | None,
) -> dict[str, Any]:
    if registry is None:
        return {
            "registry_id": None,
            "record_count": 0,
            "verified": False,
            "verification_status": "not_supplied",
            "summary": None,
        }
    return {
        "registry_id": registry.registry_id,
        "record_count": len(registry.records),
        "verified": bool(verified),
        "verification_status": (
            "verified" if verified is True else "failed" if verified is False else "not_checked"
        ),
        "summary": registry.summary(),
    }


def build_forensic_bundle(
    text: str,
    *,
    detectors: Iterable[Detector] | None = None,
    ledger_path: str | None = None,
    registry: EvidenceRegistry | None = None,
    registry_path: str | None = None,
    declared_conditions: Mapping[str, Any] | None = None,
    verify_evidence: bool = False,
    evidence_root: str | None = None,
    deterministic: bool = False,
    fixed_timestamp: str | None = None,
    include_legacy: bool = False,
    trust_max_age_days: int | None = None,
    trust_fpr_ceiling: float | None = None,
) -> ForensicBundle:
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Text must not be empty.")
    if registry is not None and registry_path is not None:
        raise ValueError("Pass registry or registry_path, not both.")
    if registry_path is not None:
        registry = load_registry(registry_path)

    registry_verified: bool | None = None
    if verify_evidence:
        if registry is None:
            raise ValueError("verify_evidence requires a registry.")
        verification = registry.verify_artifacts(root=evidence_root or ".")
        registry_verified = verification.verified
        if not verification.verified:
            raise ValueError(
                "Evidence artifact verification failed: " + "; ".join(verification.errors[:5])
            )

    if detectors is None:
        discovered = discover_detector_registry()
        detector_list = list(discovered.detectors.values())
        plugin_health = [row.to_dict() for row in discovered.plugin_health]
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
        for detector, prediction in zip(successful_detectors, predictions, strict=True)
    ]
    features = extract_features(text)
    conditions: InputConditions = extract_conditions(text, declared=declared_conditions)
    provenance = verify_ledger(ledger_path) if ledger_path else None
    consensus = family_balanced_consensus(predictions)

    if deterministic:
        generated_at_utc = fixed_timestamp or "1970-01-01T00:00:00+00:00"
    else:
        generated_at_utc = datetime.now(UTC).isoformat()

    trust_kwargs: dict[str, Any] = {}
    if trust_max_age_days is not None:
        trust_kwargs["max_age_days"] = trust_max_age_days
    if trust_fpr_ceiling is not None:
        trust_kwargs["fpr_ceiling"] = trust_fpr_ceiling
    trust_map: TrustMap = assess_trust_map(
        conditions,
        predictions,
        registry=registry,
        robustness=robustness,
        failure_count=len(failures),
        registry_verified=registry_verified,
        generated_at_utc=generated_at_utc,
        **trust_kwargs,
    )

    # Strip runtime_ms from detector output in deterministic mode.
    if deterministic:
        detector_results = [
            {key: value for key, value in prediction.to_dict().items() if key != "runtime_ms"}
            for prediction in predictions
        ]
        detector_failures = [
            {key: value for key, value in failure.to_dict().items() if key != "runtime_ms"}
            for failure in failures
        ]
        for row in robustness:
            row["failures"] = [
                {key: value for key, value in item.items() if key != "runtime_ms"}
                for item in row["failures"]
            ]
    else:
        detector_results = [prediction.to_dict() for prediction in predictions]
        detector_failures = [failure.to_dict() for failure in failures]

    # Record each detector's determinism declaration at analysis time,
    # so the sealer can declare it without re-running the detector.
    # A detector that declares nothing records "unknown".
    for detector, row in zip(successful_detectors, detector_results, strict=True):
        value, reason = detector_determinism(detector)
        row["determinism"] = value
        row["determinism_reason"] = reason

    limitations = [
        (
            "Text-only detector evidence is not proof of authorship. False "
            "positives and false negatives remain possible."
        ),
        (
            "Detector-native scores are not treated as comparable probabilities "
            "unless explicit calibration evidence exists."
        ),
        ("The Trust Map describes evidence coverage; it is not an authorship probability."),
        (
            "A Trust Map 'supported' state requires registered, held-out, "
            "evidence-grade validation slices for this input regime."
        ),
    ]
    if failures:
        limitations.append(
            f"{len(failures)} configured detector(s) failed and were excluded from consensus."
        )
    if registry is None:
        limitations.append(
            "No validation evidence registry was supplied; evidence dimensions cannot be supported."
        )
    if include_legacy:
        limitations.append(
            "legacy.verdict_integrity is a deprecated alpha heuristic retained for migration; "
            "it is not a validated trust score."
        )

    legacy = None
    if include_legacy:
        legacy = {
            "verdict_integrity": _integrity_dict(
                predictions,
                int(features["word_count"]),
                robustness,
            ),
            "deprecated": True,
        }

    return ForensicBundle(
        schema=BUNDLE_SCHEMA,
        generated_at_utc=generated_at_utc,
        content_sha256=text_sha256(text),
        input={
            "word_count": features["word_count"],
            "sentence_count": features["sentence_count"],
            "paragraph_count": features["paragraph_count"],
            "raw_text_included": False,
        },
        input_conditions=conditions.to_dict(),
        detector_results=detector_results,
        detector_failures=detector_failures,
        plugin_health=plugin_health,
        detector_protocols=_detector_protocol_summary(predictions),
        consensus=consensus.to_dict(),
        trust_map=trust_map.to_dict(),
        robustness={"detectors": robustness},
        provenance=provenance,
        evidence_registry=_registry_summary(registry, verified=registry_verified),
        limitations=limitations,
        legacy=legacy,
    )


def _integrity_dict(
    predictions: list[DetectorPrediction],
    word_count: int,
    robustness: list[dict[str, Any]],
) -> dict[str, Any]:
    integrity = _integrity(predictions, word_count, robustness)
    return {
        "status": integrity.status,
        "grade": integrity.grade,
        "score": integrity.score,
        "detector_count": integrity.detector_count,
        "independent_families": integrity.independent_families,
        "verdict_agreement": integrity.verdict_agreement,
        "calibrated_detector_count": integrity.calibrated_detector_count,
        "robustness_stability": integrity.robustness_stability,
        "factors": integrity.factors,
    }
