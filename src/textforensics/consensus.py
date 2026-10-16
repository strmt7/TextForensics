from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .detectors import DetectorPrediction


@dataclass(slots=True)
class FamilyVote:
    family: str
    detector_count: int
    verdict: str
    calibrated_ai_probability: float | None
    members: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ConsensusResult:
    verdict: str
    family_agreement: float | None
    independent_families: int
    voting_families: int
    calibrated_ai_probability: float | None
    ensemble_calibration_id: str | None
    family_votes: list[FamilyVote]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _family_vote(
    family: str,
    predictions: list[DetectorPrediction],
) -> FamilyVote:
    usable = [
        prediction.verdict
        for prediction in predictions
        if prediction.verdict in {"ai_like", "human_like"}
    ]
    if not usable:
        verdict = "abstain"
    else:
        ai = usable.count("ai_like")
        human = usable.count("human_like")
        verdict = "ai_like" if ai > human else "human_like" if human > ai else "abstain"

    warnings: list[str] = []
    probability = None
    if len(predictions) == 1:
        probability = predictions[0].calibrated_ai_probability
    elif any(
        prediction.calibrated_ai_probability is not None
        for prediction in predictions
    ):
        warnings.append(
            "Family probability withheld: combining component probabilities "
            "requires an independently calibrated family fusion model."
        )

    return FamilyVote(
        family=family,
        detector_count=len(predictions),
        verdict=verdict,
        calibrated_ai_probability=probability,
        members=[prediction.detector_id for prediction in predictions],
        warnings=warnings,
    )


def family_balanced_consensus(
    predictions: list[DetectorPrediction],
    *,
    ensemble_probability: float | None = None,
    ensemble_calibration_id: str | None = None,
) -> ConsensusResult:
    """Build categorical consensus without pretending it is calibrated inference.

    A top-level probability is emitted only when the caller provides a separately
    calibrated ensemble probability and a calibration identifier.
    """
    if (ensemble_probability is None) != (ensemble_calibration_id is None):
        raise ValueError(
            "ensemble_probability and ensemble_calibration_id must be provided together."
        )
    if ensemble_probability is not None and not 0.0 <= ensemble_probability <= 1.0:
        raise ValueError("ensemble_probability must be between 0 and 1.")

    grouped: dict[str, list[DetectorPrediction]] = {}
    for prediction in predictions:
        grouped.setdefault(prediction.detector_family, []).append(prediction)

    family_votes = [
        _family_vote(family, rows)
        for family, rows in sorted(grouped.items())
    ]
    voting = [
        vote
        for vote in family_votes
        if vote.verdict in {"ai_like", "human_like"}
    ]

    warnings: list[str] = []
    if len(grouped) < 2:
        warnings.append(
            "Consensus requires multiple methodologically independent detector "
            "families; fewer than two families are available."
        )

    if len(voting) < 2:
        consensus_verdict = "abstain"
        agreement = None
    else:
        ai = sum(vote.verdict == "ai_like" for vote in voting)
        human = sum(vote.verdict == "human_like" for vote in voting)
        consensus_verdict = (
            "abstain"
            if ai == human
            else "ai_like"
            if ai > human
            else "human_like"
        )
        agreement = max(ai, human) / len(voting)
        if agreement < 1.0:
            warnings.append(
                "Independent detector families disagree on the categorical verdict."
            )

    if ensemble_probability is None and any(
        prediction.calibrated_ai_probability is not None
        for prediction in predictions
    ):
        warnings.append(
            "Component calibrated probabilities are not fused. A separately "
            "validated ensemble calibration is required for a top-level probability."
        )

    return ConsensusResult(
        verdict=consensus_verdict,
        family_agreement=round(agreement, 4) if agreement is not None else None,
        independent_families=len(grouped),
        voting_families=len(voting),
        calibrated_ai_probability=(
            round(ensemble_probability, 4)
            if ensemble_probability is not None
            else None
        ),
        ensemble_calibration_id=ensemble_calibration_id,
        family_votes=family_votes,
        warnings=warnings,
    )
