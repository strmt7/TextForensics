"""Evidence-conditioned Trust Map.

The Trust Map answers a different question from a detector score:

    "Does the registered validation evidence actually cover *this* input?"

It is deliberately qualitative.  States are ``supported``, ``partial``,
``unknown`` and ``out_of_scope``.  There is no numeric trust score, percentage,
grade, or authorship probability.

Two surfaces are exposed:

* :func:`assess_trust_map` — Trust Map v2, driven by
  :mod:`textforensics.conditions`, :mod:`textforensics.evidence`, live
  detector observations and benign-transformation probes.
* :func:`trust_map_from_capability_ledger` — a legacy v1 compatibility view of
  capability claims.  It is **not** evidence-conditioned and must not be used
  to claim Trust Map v2 coverage.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from .conditions import InputConditions, length_band
from .detectors import DetectorPrediction
from .evidence import (
    DEFAULT_FPR_CEILING,
    DEFAULT_MAX_AGE_DAYS,
    DetectorCoverage,
    EvidenceRegistry,
    aggregate_coverage_states,
    coverage_for_predictions,
)

TRUST_STATES = frozenset({"supported", "partial", "unknown", "out_of_scope"})
TRUST_SCHEMA = "textforensics.trust-map/v2"
LEGACY_TRUST_SCHEMA = "textforensics.trust-map/v1"

EVIDENCE_DIMENSIONS = (
    "language",
    "text_length",
    "domain_genre",
    "editing_revision",
    "generator_scope",
    "human_population",
    "human_false_positive_evidence",
    "temporal_version_stability",
)
LIVE_DIMENSIONS = ("detector_diversity", "benign_stability")
TRUST_DIMENSIONS = EVIDENCE_DIMENSIONS + LIVE_DIMENSIONS


@dataclass(slots=True)
class TrustDimension:
    """One qualitative Trust Map dimension."""

    dimension: str
    state: str
    reason: str
    evidence_refs: list[str] = field(default_factory=list)
    observed: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)
    detectors: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.dimension not in TRUST_DIMENSIONS:
            raise ValueError(f"Unknown Trust Map dimension: {self.dimension!r}.")
        if self.state not in TRUST_STATES:
            raise ValueError(f"Invalid Trust Map state: {self.state!r}.")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("Trust Map dimension reason must be non-empty.")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class TrustMap:
    """A versioned, qualitative Trust Map."""

    schema: str
    overall: str
    dimensions: list[TrustDimension]
    limitations: list[str] = field(default_factory=list)
    input_conditions: dict[str, Any] | None = None
    evidence_registry: dict[str, Any] | None = None
    coverage: dict[str, int] = field(default_factory=dict)
    generated_at_utc: str | None = None

    def __post_init__(self) -> None:
        if self.schema not in {TRUST_SCHEMA, LEGACY_TRUST_SCHEMA}:
            raise ValueError("Unsupported Trust Map schema.")
        if self.overall not in {"strong", "mixed", "insufficient"}:
            raise ValueError("Invalid Trust Map overall state.")
        if self.coverage:
            missing = TRUST_STATES - set(self.coverage)
            if missing:
                raise ValueError(f"coverage is missing state(s): {', '.join(sorted(missing))}.")

    def dimension(self, name: str) -> TrustDimension | None:
        return next((item for item in self.dimensions if item.dimension == name), None)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Live-observation dimensions
# ---------------------------------------------------------------------------


def _diversity_dimension(
    predictions: list[DetectorPrediction],
    failure_count: int,
) -> TrustDimension:
    families = sorted({prediction.detector_family for prediction in predictions})
    if not families:
        state = "unknown"
        reason = "No usable detector observations are available."
    elif len(families) >= 2 and failure_count == 0:
        state = "supported"
        reason = (
            "At least two detector-family labels produced usable observations "
            "and no configured detector failed."
        )
    else:
        state = "partial"
        reason = "Detector-family diversity is limited, or one or more configured detectors failed."
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
            "correlation has not been measured here."
        ],
    )


def _stability_dimension(
    robustness: Iterable[Mapping[str, Any]],
    *,
    max_native_drift: float | None,
) -> TrustDimension:
    usable: list[Mapping[str, Any]] = []
    for row in robustness:
        if not isinstance(row, Mapping):
            continue
        value = row.get("verdict_stability")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        usable.append(row)

    if not usable:
        return TrustDimension(
            dimension="benign_stability",
            state="unknown",
            reason="No usable benign-transformation stability evidence is available.",
            limitations=[
                "Representation probes are not semantic rewrites and do not "
                "establish paraphrase robustness."
            ],
        )

    verdict_floor = min(float(row["verdict_stability"]) for row in usable)
    drift_rows: list[dict[str, Any]] = []
    drift_known = True
    drift_ok = True
    for row in usable:
        native_range = row.get("native_score_range")
        known = isinstance(native_range, (int, float)) and not isinstance(native_range, bool)
        if not known:
            drift_known = False
            drift_rows.append({"detector_id": row.get("detector_id"), "native_score_range": None})
            continue
        value = float(native_range)
        drift_rows.append({"detector_id": row.get("detector_id"), "native_score_range": value})
        if max_native_drift is not None and value > max_native_drift:
            drift_ok = False

    if verdict_floor >= 1.0 and drift_known and drift_ok:
        state = "supported"
        reason = (
            "Every usable detector kept its categorical verdict and native-score "
            "drift stayed within the declared bound under benign probes."
        )
    else:
        state = "partial"
        reason = (
            "At least one detector changed categorical verdict, omitted a native "
            "score range, or exceeded the declared drift bound under a benign probe."
        )

    return TrustDimension(
        dimension="benign_stability",
        state=state,
        reason=reason,
        observed={
            "detectors": drift_rows,
            "verdict_stability_floor": round(verdict_floor, 6),
            "max_native_drift_policy": max_native_drift,
        },
        limitations=[
            "Native score ranges remain in each detector's own units and are "
            "not compared across detectors.",
            "Current probes cover representation stability, not semantic rewriting.",
        ],
    )


# ---------------------------------------------------------------------------
# Evidence dimensions
# ---------------------------------------------------------------------------


def _aggregate_evidence_dimension(
    name: str,
    rows: tuple[DetectorCoverage, ...],
) -> TrustDimension:
    if not rows:
        return TrustDimension(
            dimension=name,
            state="unknown",
            reason="No detector observations are available for evidence matching.",
        )

    aggregated = aggregate_coverage_states(rows)[name]
    detector_states = {row.detector_id: row.dimensions[name].state for row in rows}
    refs: list[str] = []
    limitations: list[str] = []
    observed: dict[str, Any] = {"detector_states": detector_states}
    reasons: list[str] = []
    for row in rows:
        dimension = row.dimensions[name]
        refs.extend(dimension.evidence_refs)
        limitations.extend(dimension.limitations)
        reasons.append(f"{row.detector_id}: {dimension.reason}")
        if dimension.observed:
            observed.setdefault("detector_observed", {})[row.detector_id] = dict(dimension.observed)
    if len(set(detector_states.values())) == 1:
        reason = next(iter(detector_states.values())) and rows[0].dimensions[name].reason
    else:
        reason = "Per-detector coverage differs: " + " | ".join(reasons)

    return TrustDimension(
        dimension=name,
        state=aggregated,
        reason=reason,
        evidence_refs=list(dict.fromkeys(refs)),
        observed=observed,
        limitations=list(dict.fromkeys(limitations)),
        detectors=detector_states,
    )


def _overall_state(dimensions: list[TrustDimension]) -> str:
    by_name = {item.dimension: item.state for item in dimensions}
    supported = sum(state == "supported" for state in by_name.values())
    partial = sum(state == "partial" for state in by_name.values())
    unknown = sum(state == "unknown" for state in by_name.values())
    if by_name.get("language") == "out_of_scope" or by_name.get("text_length") == "out_of_scope":
        return "insufficient"
    if supported == len(TRUST_DIMENSIONS):
        return "strong"
    if supported == 0 and partial == 0:
        return "insufficient"
    if supported == 0 and unknown >= 4:
        return "insufficient"
    return "mixed"


def _coverage_counts(dimensions: Iterable[TrustDimension]) -> dict[str, int]:
    counts = {state: 0 for state in TRUST_STATES}
    for dimension in dimensions:
        counts[dimension.state] += 1
    return counts


# ---------------------------------------------------------------------------
# Public assessment
# ---------------------------------------------------------------------------


def assess_trust_map(
    conditions: InputConditions,
    predictions: Iterable[DetectorPrediction],
    *,
    registry: EvidenceRegistry | None = None,
    robustness: Iterable[Mapping[str, Any]] = (),
    failure_count: int = 0,
    registry_verified: bool | None = None,
    now: datetime | str | None = None,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    fpr_ceiling: float = DEFAULT_FPR_CEILING,
    max_native_drift: float | None = 0.10,
    generated_at_utc: str | None = None,
) -> TrustMap:
    """Build a Trust Map v2 for one input condition set and detector set.

    Evidence dimensions are derived from ``registry``.  Live dimensions
    (diversity and benign stability) are derived from the observations and
    probes supplied by the caller.  An empty registry can never produce a
    ``supported`` evidence dimension.
    """
    if not isinstance(conditions, InputConditions):
        raise TypeError("conditions must be an InputConditions instance.")
    prediction_list = list(predictions)
    robustness_list = list(robustness)
    if isinstance(failure_count, bool) or not isinstance(failure_count, int):
        raise TypeError("failure_count must be an integer.")
    if failure_count < 0:
        raise ValueError("failure_count must be non-negative.")
    if max_native_drift is not None and max_native_drift < 0:
        raise ValueError("max_native_drift must be non-negative or None.")

    rows = coverage_for_predictions(
        prediction_list,
        conditions,
        registry=registry,
        now=now,
        max_age_days=max_age_days,
        fpr_ceiling=fpr_ceiling,
    )
    dimensions = [_aggregate_evidence_dimension(name, rows) for name in EVIDENCE_DIMENSIONS]
    dimensions.append(_diversity_dimension(prediction_list, failure_count))
    dimensions.append(_stability_dimension(robustness_list, max_native_drift=max_native_drift))

    limitations = [
        "Trust Map states describe evidence coverage, not probability of authorship.",
        "A supported state requires registered, held-out, evidence-grade validation "
        "slices; detector metadata alone can only produce partial coverage.",
        "Text-only detection cannot prove authorship.",
    ]
    if registry is None:
        limitations.append("No validation evidence registry was supplied.")
    elif not registry.records:
        limitations.append("The supplied validation evidence registry is empty.")
    if registry_verified is False:
        limitations.append("Evidence artifact verification failed.")

    if registry is None:
        registry_summary = {
            "registry_id": None,
            "record_count": 0,
            "verified": False,
            "verification_status": "not_checked",
        }
    else:
        summary = registry.summary()
        registry_summary = {
            "registry_id": summary["registry_id"],
            "record_count": summary["record_count"],
            "verified": bool(registry_verified),
            "verification_status": (
                "verified"
                if registry_verified is True
                else "failed"
                if registry_verified is False
                else "not_checked"
            ),
        }

    return TrustMap(
        schema=TRUST_SCHEMA,
        overall=_overall_state(dimensions),
        dimensions=dimensions,
        limitations=limitations,
        input_conditions=conditions.to_dict(),
        evidence_registry=registry_summary,
        coverage=_coverage_counts(dimensions),
        generated_at_utc=generated_at_utc or datetime.now(UTC).isoformat(),
    )


def build_trust_map(
    predictions: Iterable[DetectorPrediction],
    *,
    word_count: int,
    robustness: Iterable[Mapping[str, Any]] = (),
    failure_count: int = 0,
    conditions: InputConditions | None = None,
    registry: EvidenceRegistry | None = None,
    registry_verified: bool | None = None,
    now: datetime | str | None = None,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    fpr_ceiling: float = DEFAULT_FPR_CEILING,
    max_native_drift: float | None = 0.10,
    generated_at_utc: str | None = None,
) -> TrustMap:
    """Compatibility wrapper for :func:`assess_trust_map`.

    When ``conditions`` is omitted, a minimal condition set is synthesized from
    ``word_count``.  Language, domain and editing regime are then ``unknown``;
    metadata alone can only produce ``partial`` coverage.
    """
    if conditions is None:
        if isinstance(word_count, bool) or not isinstance(word_count, int):
            raise TypeError("word_count must be an integer.")
        if word_count < 0:
            raise ValueError("word_count must be non-negative.")
        conditions = InputConditions(
            schema="textforensics.input-conditions/v1",
            language="und",
            language_confidence="unknown",
            script="unknown",
            word_count=word_count,
            char_count=0,
            length_band=length_band(word_count),
            domain_genre="unknown",
            domain_confidence="unknown",
            editing_regime="unknown",
            generator=None,
            human_population="unknown",
            declared={"source": "none", "fields": [], "values": {}},
            cues={"reason": "legacy_build_trust_map_without_conditions"},
            extraction_version="1",
        )
    elif conditions.word_count != word_count:
        raise ValueError("conditions.word_count does not match word_count.")
    return assess_trust_map(
        conditions,
        predictions,
        registry=registry,
        robustness=robustness,
        failure_count=failure_count,
        registry_verified=registry_verified,
        now=now,
        max_age_days=max_age_days,
        fpr_ceiling=fpr_ceiling,
        max_native_drift=max_native_drift,
        generated_at_utc=generated_at_utc,
    )


# ---------------------------------------------------------------------------
# Legacy capability-ledger view (v1)
# ---------------------------------------------------------------------------


def trust_map_from_capability_ledger(ledger: Any) -> TrustMap:
    """Build a legacy v1 Trust Map from capability-ledger claims.

    This view maps claim tiers to states for compatibility.  It is *not*
    evidence-conditioned, intentionally stays on schema v1, and must not be
    presented as a Trust Map v2 result.
    """
    from .capability_ledger import EvidenceTier

    dimensions: list[TrustDimension] = []
    detector_capabilities: dict[str, set[str]] = {}
    for detector_id, claims in ledger._claims.items():
        capabilities: set[str] = set()
        for claim in claims:
            capabilities.add(claim.capability)
        detector_capabilities[detector_id] = capabilities

    for detector_id in sorted(detector_capabilities):
        claims = ledger._claims.get(detector_id, [])
        for capability in sorted(detector_capabilities[detector_id]):
            relevant = [claim for claim in claims if claim.capability == capability]
            evidence_refs: list[str] = []
            limitations: list[str] = []
            for claim in relevant:
                for reference in claim.evidence:
                    evidence_refs.append(reference.artifact)
                if claim.valid_until:
                    limitations.append(f"Claim for {claim.capability} expires {claim.valid_until}.")
            if not relevant:
                state = "unknown"
                reason = f"No capability claim registered for {detector_id}/{capability}."
            elif any(claim.tier == EvidenceTier.VALIDATED for claim in relevant):
                state = "supported"
                reason = f"Capability '{capability}' for {detector_id} has VALIDATED-tier evidence."
            elif any(claim.tier == EvidenceTier.TOOL_BACKED for claim in relevant):
                state = "partial"
                reason = f"Capability '{capability}' for {detector_id} is TOOL_BACKED."
            else:
                state = "partial"
                reason = (
                    f"Capability '{capability}' for {detector_id} is documented "
                    "but not machine-verifiable."
                )
            dimensions.append(
                TrustDimension(
                    dimension=_legacy_dimension_name(capability),
                    state=state,
                    reason=reason,
                    evidence_refs=list(dict.fromkeys(evidence_refs)),
                    limitations=limitations,
                )
            )

    if not dimensions:
        overall = "insufficient"
        limitations = [
            "No capability claims are registered in the ledger.",
            "Trust Map states describe evidence coverage, not probability of authorship.",
            "This is a legacy capability-claim view, not evidence-conditioned Trust Map v2.",
        ]
    else:
        unknown_count = sum(item.state == "unknown" for item in dimensions)
        out_of_scope_count = sum(item.state == "out_of_scope" for item in dimensions)
        partial_count = sum(item.state == "partial" for item in dimensions)
        if out_of_scope_count or unknown_count >= max(1, len(dimensions) // 2):
            overall = "insufficient"
        elif unknown_count or partial_count:
            overall = "mixed"
        else:
            overall = "strong"
        limitations = [
            "Trust Map states describe evidence coverage, not probability of authorship.",
            "This is a legacy capability-claim view, not evidence-conditioned Trust Map v2.",
        ]

    return TrustMap(
        schema=LEGACY_TRUST_SCHEMA,
        overall=overall,
        dimensions=dimensions,
        limitations=limitations,
    )


def _legacy_dimension_name(capability: str) -> str:
    """Map a legacy capability label onto a declared Trust Map dimension."""
    normalized = capability.replace(".", "_").lower()
    aliases = {
        "language": "language",
        "language_coverage": "language",
        "lang": "language",
        "length": "text_length",
        "length_robustness": "text_length",
        "text_length": "text_length",
        "domain": "domain_genre",
        "domain_genre": "domain_genre",
        "editing": "editing_revision",
        "editing_revision": "editing_revision",
        "generator": "generator_scope",
        "generator_scope": "generator_scope",
        "human_population": "human_population",
        "human_false_positive_evidence": "human_false_positive_evidence",
        "temporal_version_stability": "temporal_version_stability",
        "detector_diversity": "detector_diversity",
        "benign_stability": "benign_stability",
    }
    for prefix, dimension in aliases.items():
        if normalized == prefix or normalized.startswith(f"{prefix}_"):
            return dimension
    # Legacy claims that do not map to a declared dimension are represented as
    # unknown metadata rather than inventing a new Trust Map dimension.
    return "domain_genre"


__all__ = [
    "EVIDENCE_DIMENSIONS",
    "LEGACY_TRUST_SCHEMA",
    "LIVE_DIMENSIONS",
    "TRUST_DIMENSIONS",
    "TRUST_SCHEMA",
    "TRUST_STATES",
    "TrustDimension",
    "TrustMap",
    "assess_trust_map",
    "build_trust_map",
    "trust_map_from_capability_ledger",
]
