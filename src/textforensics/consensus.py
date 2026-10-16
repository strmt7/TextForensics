from __future__ import annotations

from dataclasses import asdict, dataclass, field
from statistics import mean

from .detectors import DetectorPrediction


@dataclass(slots=True)
class FamilyVote:
    family: str
    detector_count: int
    verdict: str
    calibrated_ai_probability: float | None
    members: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ConsensusResult:
    verdict: str
    family_agreement: float | None
    independent_families: int
    voting_families: int
    calibrated_ai_probability: float | None
    family_votes: list[FamilyVote]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _family_vote(family: str, predictions: list[DetectorPrediction]) -> FamilyVote:
    usable = [p.verdict for p in predictions if p.verdict in {"ai_like", "human_like"}]
    if not usable:
        verdict = "abstain"
    else:
        ai = usable.count("ai_like")
        human = usable.count("human_like")
        verdict = "ai_like" if ai > human else "human_like" if human > ai else "abstain"

    calibrated = [
        p.calibrated_ai_probability
        for p in predictions
        if p.calibrated_ai_probability is not None
    ]
    probability = mean(calibrated) if calibrated and len(calibrated) == len(predictions) else None
    return FamilyVote(
        family=family,
        detector_count=len(predictions),
        verdict=verdict,
        calibrated_ai_probability=round(probability, 4) if probability is not None else None,
        members=[p.detector_id for p in predictions],
    )


def family_balanced_consensus(predictions: list[DetectorPrediction]) -> ConsensusResult:
    """Build consensus without letting one detector family multiply its voting power."""
    grouped: dict[str, list[DetectorPrediction]] = {}
    for prediction in predictions:
        grouped.setdefault(prediction.detector_family, []).append(prediction)

    family_votes = [_family_vote(family, rows) for family, rows in sorted(grouped.items())]
    voting = [vote for vote in family_votes if vote.verdict in {"ai_like", "human_like"}]

    warnings: list[str] = []
    if len(grouped) < 2:
        warnings.append("Consensus requires multiple independent detector families; only one family is available.")

    if len(voting) < 2:
        consensus_verdict = "abstain"
        agreement = None
    else:
        ai = sum(v.verdict == "ai_like" for v in voting)
        human = sum(v.verdict == "human_like" for v in voting)
        if ai == human:
            consensus_verdict = "abstain"
        else:
            consensus_verdict = "ai_like" if ai > human else "human_like"
        agreement = max(ai, human) / len(voting)
        if agreement < 1.0:
            warnings.append("Independent detector families disagree on the categorical verdict.")

    family_probabilities = [
        vote.calibrated_ai_probability
        for vote in family_votes
        if vote.calibrated_ai_probability is not None
    ]
    calibrated_probability = None
    if family_probabilities and len(family_probabilities) == len(family_votes):
        calibrated_probability = round(mean(family_probabilities), 4)
    elif family_probabilities:
        warnings.append("Calibrated probability is withheld because not every detector family supplied calibrated probabilities.")

    return ConsensusResult(
        verdict=consensus_verdict,
        family_agreement=round(agreement, 4) if agreement is not None else None,
        independent_families=len(grouped),
        voting_families=len(voting),
        calibrated_ai_probability=calibrated_probability,
        family_votes=family_votes,
        warnings=warnings,
    )
