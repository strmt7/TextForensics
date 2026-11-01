from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .detectors import DetectorPrediction

TRUST_STATES = {"supported", "partial", "unknown", "out_of_scope"}


@dataclass(slots=True)
class TrustDimension:
    dimension: str
    state: str
    reason: str
    evidence_refs: list[str] = field(default_factory=list)
    observed: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class TrustMap:
    schema: str
    overall: str
    dimensions: list[TrustDimension]
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _length_dimension(
    predictions: list[DetectorPrediction],
    word_count: int,
) -> TrustDimension:
    declared = [
        (prediction.detector_id, prediction.min_words)
        for prediction in predictions
        if prediction.min_words is not None
    ]
    if not declared:
        return TrustDimension(
            dimension="text_length",
            state="unknown",
            reason="No detector supplied a minimum supported text length.",
            observed={"word_count": word_count},
        )

    supported = [
        detector_id
        for detector_id, minimum in declared
        if minimum is not None and word_count >= minimum
    ]
    unsupported = [
        {"detector_id": detector_id, "min_words": minimum}
        for detector_id, minimum in declared
        if minimum is not None and word_count < minimum
    ]

    if supported and not unsupported:
        state = "supported"
        reason = "The text meets every detector's declared minimum word count."
    elif supported:
        state = "partial"
        reason = "The text meets some, but not all, declared detector length limits."
    else:
        state = "out_of_scope"
        reason = "The text is below every detector's declared minimum word count."

    return TrustDimension(
        dimension="text_length",
        state=state,
        reason=reason,
        observed={
            "word_count": word_count,
            "supported_detectors": supported,
            "unsupported_detectors": unsupported,
        },
        limitations=[
            "Declared minimum length is capability metadata, not proof of "
            "held-out performance at this exact length."
        ],
    )


def _diversity_dimension(
    predictions: list[DetectorPrediction],
    failure_count: int,
) -> TrustDimension:
    families = sorted({prediction.detector_family for prediction in predictions})
    if len(families) >= 2 and failure_count == 0:
        state = "supported"
        reason = "At least two detector families produced usable observations."
    elif families:
        state = "partial"
        reason = (
            "Detector-family diversity is limited or one or more configured "
            "detectors failed."
        )
    else:
        state = "unknown"
        reason = "No usable detector observations are available."

    return TrustDimension(
        dimension="detector_diversity",
        state=state,
        reason=reason,
        observed={
            "families": families,
            "independent_family_count": len(families),
            "detector_failures": failure_count,
        },
        limitations=[
            "Family labels are methodological metadata; empirical error "
            "correlation must still be measured."
        ],
    )


def _stability_dimension(
    robustness: list[dict[str, Any]],
) -> TrustDimension:
    usable = [
        row
        for row in robustness
        if row.get("verdict_stability") is not None
    ]
    if not usable:
        return TrustDimension(
            dimension="benign_stability",
            state="unknown",
            reason="No usable benign-transformation stability evidence is available.",
        )

    verdict_floor = min(float(row["verdict_stability"]) for row in usable)
    if verdict_floor == 1.0:
        state = "supported"
        reason = (
            "All usable detectors kept the same categorical verdict under "
            "the current benign probes."
        )
    else:
        state = "partial"
        reason = (
            "At least one detector changed categorical verdict under a benign "
            "representation probe."
        )

    return TrustDimension(
        dimension="benign_stability",
        state=state,
        reason=reason,
        observed={
            "detectors": [
                {
                    "detector_id": row.get("detector_id"),
                    "verdict_stability": row.get("verdict_stability"),
                    "native_score_range": row.get("native_score_range"),
                }
                for row in usable
            ]
        },
        limitations=[
            "Native score ranges remain in each detector's own units and are "
            "not compared across detectors.",
            "Current probes cover representation stability, not semantic rewriting.",
        ],
    )


def build_trust_map(
    predictions: list[DetectorPrediction],
    *,
    word_count: int,
    robustness: list[dict[str, Any]],
    failure_count: int = 0,
) -> TrustMap:
    dimensions = [
        TrustDimension(
            dimension="language",
            state="unknown",
            reason=(
                "The core does not yet have validated language-identification "
                "evidence for this document."
            ),
        ),
        _length_dimension(predictions, word_count),
        TrustDimension(
            dimension="domain_genre",
            state="unknown",
            reason=(
                "No benchmark-backed domain or genre match is available in the "
                "current alpha."
            ),
        ),
        TrustDimension(
            dimension="editing_revision",
            state="unknown",
            reason=(
                "No benchmark-backed evidence for this document's editing or "
                "revision regime is available."
            ),
        ),
        TrustDimension(
            dimension="human_false_positive_evidence",
            state="unknown",
            reason=(
                "No nearest-slice held-out human false-positive evidence is "
                "registered yet."
            ),
        ),
        _diversity_dimension(predictions, failure_count),
        _stability_dimension(robustness),
        TrustDimension(
            dimension="temporal_version_stability",
            state="unknown",
            reason=(
                "No longitudinal detector/provider observatory evidence is "
                "registered yet."
            ),
        ),
    ]

    unknown_count = sum(item.state == "unknown" for item in dimensions)
    out_of_scope = any(item.state == "out_of_scope" for item in dimensions)
    partial = any(item.state == "partial" for item in dimensions)

    if out_of_scope or unknown_count >= 3:
        overall = "insufficient"
    elif unknown_count or partial:
        overall = "mixed"
    else:
        overall = "strong"

    return TrustMap(
        schema="textforensics.trust-map/v1",
        overall=overall,
        dimensions=dimensions,
        limitations=[
            "Trust Map states describe evidence coverage, not probability of authorship.",
            "The alpha Trust Map is intentionally conservative until benchmark "
            "registries provide slice-level validation evidence.",
        ],
    )
