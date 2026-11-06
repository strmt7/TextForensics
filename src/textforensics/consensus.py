"""Combine detector verdicts: family-balanced consensus and agreement statistics.

Family-balanced consensus groups predictions by detector family so three
correlated classifiers do not count as three independent evidence families
(AGENTS.md rule 13). A top-level probability is emitted only when the caller
provides a separately calibrated ensemble probability and calibration ID
(rule 3: detector-local calibration is not ensemble calibration).

Agreement statistics (Cohen's kappa, Fleiss' kappa, percentage agreement,
pairwise agreement matrix) quantify whether detectors behave as independent
evidence families or as correlated instruments. They are diagnostic only:
consensus above deliberately does not use them to weight votes.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from typing import Any

from .detectors import DetectorPrediction

__all__ = [
    "FamilyVote",
    "ConsensusResult",
    "family_balanced_consensus",
    "PairwiseAgreement",
    "AgreementMatrix",
    "cohens_kappa",
    "fleiss_kappa",
    "percent_agreement",
    "build_agreement_matrix",
]


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
    elif any(prediction.calibrated_ai_probability is not None for prediction in predictions):
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

    family_votes = [_family_vote(family, rows) for family, rows in sorted(grouped.items())]
    voting = [vote for vote in family_votes if vote.verdict in {"ai_like", "human_like"}]

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
        consensus_verdict = "abstain" if ai == human else "ai_like" if ai > human else "human_like"
        agreement = max(ai, human) / len(voting)
        if agreement < 1.0:
            warnings.append("Independent detector families disagree on the categorical verdict.")

    if ensemble_probability is None and any(
        prediction.calibrated_ai_probability is not None for prediction in predictions
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
            round(ensemble_probability, 4) if ensemble_probability is not None else None
        ),
        ensemble_calibration_id=ensemble_calibration_id,
        family_votes=family_votes,
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# Inter-detector agreement statistics (merged from agreement.py, Phase 2 wave e)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PairwiseAgreement:
    """Agreement statistics between two detectors over shared texts.

    Attributes:
        detector_a: First detector ID.
        detector_b: Second detector ID.
        paired_n: Number of texts where BOTH detectors emitted a non-abstain verdict.
        percent_agreement: Raw fraction of agreeing pairs (0-1).
        cohens_kappa: Chance-corrected agreement (-1 to 1); None when undefined.
        kappa_interpretation: Human-readable interpretation of kappa.
        confusion: Counts keyed by f"{verdict_a}|{verdict_b}".
    """

    detector_a: str
    detector_b: str
    paired_n: int
    percent_agreement: float
    cohens_kappa: float | None
    kappa_interpretation: str
    confusion: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector_a": self.detector_a,
            "detector_b": self.detector_b,
            "paired_n": self.paired_n,
            "percent_agreement": self.percent_agreement,
            "cohens_kappa": self.cohens_kappa,
            "kappa_interpretation": self.kappa_interpretation,
            "confusion": self.confusion,
        }


@dataclass
class AgreementMatrix:
    """Multi-detector agreement analysis results."""

    detectors: list[str]
    pairwise: list[PairwiseAgreement]
    fleiss_kappa: float | None
    fleiss_n_texts: int
    fleiss_n_raters: int
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "detectors": list(self.detectors),
            "pairwise": [p.to_dict() for p in self.pairwise],
            "fleiss_kappa": self.fleiss_kappa,
            "fleiss_n_texts": self.fleiss_n_texts,
            "fleiss_n_raters": self.fleiss_n_raters,
            "warnings": list(self.warnings),
        }

    def summary(self) -> dict[str, Any]:
        """Compact summary with independence hint.

        A mean pairwise kappa above ~0.8 suggests the detector set is highly
        correlated and should NOT be treated as independent evidence families
        (AGENTS.md rule 13).
        """
        valid_kappas = [p.cohens_kappa for p in self.pairwise if p.cohens_kappa is not None]
        mean_kappa = sum(valid_kappas) / len(valid_kappas) if valid_kappas else None
        if mean_kappa is None:
            independence = "undetermined"
        elif mean_kappa >= 0.8:
            independence = "highly_correlated"
        elif mean_kappa >= 0.6:
            independence = "substantially_correlated"
        elif mean_kappa >= 0.4:
            independence = "moderate_agreement"
        else:
            independence = "weakly_correlated"

        return {
            "n_detectors": len(self.detectors),
            "n_pairwise_comparisons": len(self.pairwise),
            "mean_pairwise_kappa": mean_kappa,
            "fleiss_kappa": self.fleiss_kappa,
            "independence_hint": independence,
        }


def _interpret_kappa(kappa: float) -> str:
    """Landis & Koch interpretation scale."""
    if kappa < 0:
        return "poor (less than chance)"
    if kappa < 0.20:
        return "slight"
    if kappa < 0.40:
        return "fair"
    if kappa < 0.60:
        return "moderate"
    if kappa < 0.80:
        return "substantial"
    return "almost perfect"


def _is_abstain(verdict: str | None) -> bool:
    """Treat None and 'abstain' as missing observations (never agreement)."""
    if verdict is None:
        return True
    return str(verdict).strip().lower() in {"abstain", "insufficient_evidence", ""}


def percent_agreement(
    verdicts_a: Sequence[str | None],
    verdicts_b: Sequence[str | None],
) -> tuple[float, int]:
    """Raw percentage agreement between two verdict sequences.

    Abstaining entries are excluded from both sides before comparison.

    Returns:
        (agreement_fraction, paired_n)
    """
    if len(verdicts_a) != len(verdicts_b):
        raise ValueError("verdict sequences must have equal length")

    paired = 0
    agreed = 0
    for a, b in zip(verdicts_a, verdicts_b, strict=False):
        if _is_abstain(a) or _is_abstain(b):
            continue
        paired += 1
        if str(a).strip().lower() == str(b).strip().lower():
            agreed += 1

    if paired == 0:
        return 0.0, 0
    return agreed / paired, paired


def cohens_kappa(
    verdicts_a: Sequence[str | None],
    verdicts_b: Sequence[str | None],
) -> tuple[float | None, float, int, dict[str, int]]:
    """Cohen's kappa between two raters over paired verdicts.

    kappa = (p_o - p_e) / (1 - p_e), where p_o is observed agreement and
    p_e is agreement expected by chance from the marginal distributions.

    Returns:
        (kappa or None if undefined, percent_agreement, paired_n, confusion)
        kappa is None when paired_n == 0 or p_e == 1 (degenerate marginals).
    """
    if len(verdicts_a) != len(verdicts_b):
        raise ValueError("verdict sequences must have equal length")

    confusion: dict[str, int] = {}
    counts_a: Counter[str] = Counter()
    counts_b: Counter[str] = Counter()
    paired = 0
    agreed = 0

    for a, b in zip(verdicts_a, verdicts_b, strict=False):
        if _is_abstain(a) or _is_abstain(b):
            continue
        va = str(a).strip().lower()
        vb = str(b).strip().lower()
        paired += 1
        counts_a[va] += 1
        counts_b[vb] += 1
        if va == vb:
            agreed += 1
        confusion[f"{va}|{vb}"] = confusion.get(f"{va}|{vb}", 0) + 1

    p_o = agreed / paired if paired else 0.0

    if paired == 0:
        return None, 0.0, 0, confusion

    # Chance agreement from marginals
    p_e = sum(
        (counts_a.get(cat, 0) / paired) * (counts_b.get(cat, 0) / paired)
        for cat in set(counts_a) | set(counts_b)
    )

    if math.isclose(p_e, 1.0):
        # Degenerate: both raters constant — kappa undefined
        return None, p_o, paired, confusion

    kappa = (p_o - p_e) / (1.0 - p_e)
    return kappa, p_o, paired, confusion


def fleiss_kappa(
    verdict_matrix: Sequence[Sequence[str | None]],
) -> tuple[float | None, int, int, list[str]]:
    """Fleiss' kappa across multiple raters over shared items.

    Args:
        verdict_matrix: rows = texts, columns = detectors (raters).
                        Abstain/None cells are excluded: items are only
                        counted when at least 2 raters gave a verdict, and
                        category counts use only non-abstaining raters.

    Returns:
        (kappa or None, n_usable_items, n_raters, warnings)
        kappa is None when fewer than 2 usable items or degenerate marginals.
    """
    warnings: list[str] = []
    if not verdict_matrix:
        return None, 0, 0, ["empty matrix"]

    n_raters = len(verdict_matrix[0])
    for i, row in enumerate(verdict_matrix):
        if len(row) != n_raters:
            raise ValueError(f"Row {i} has {len(row)} raters, expected {n_raters}")

    # Build per-item category counts excluding abstentions
    item_counts: list[Counter[str]] = []
    for row in verdict_matrix:
        counts: Counter[str] = Counter()
        for v in row:
            if not _is_abstain(v):
                counts[str(v).strip().lower()] += 1
        item_counts.append(counts)

    # Usable items: at least 2 non-abstaining raters
    usable = [c for c in item_counts if sum(c.values()) >= 2]
    if len(usable) < 2:
        warnings.append("fewer than 2 usable items with >=2 non-abstaining raters")
        return None, len(usable), n_raters, warnings

    n_items = len(usable)

    # Global category totals and proportions
    totals: Counter[str] = Counter()
    for c in usable:
        totals.update(c)

    total_ratings = sum(totals.values())
    categories = sorted(totals)
    p_j = {cat: totals[cat] / total_ratings for cat in categories}

    # Observed per-item agreement: P_i = (sum_j n_ij(n_ij - 1)) / (n(n-1))
    # where n = number of non-abstaining raters for that item.
    p_bar_sum = 0.0
    for c in usable:
        n_i = sum(c.values())
        if n_i < 2:
            continue
        agree_pairs = sum(cnt * (cnt - 1) for cnt in c.values())
        p_i = agree_pairs / (n_i * (n_i - 1))
        p_bar_sum += p_i
    p_bar = p_bar_sum / n_items

    # Chance agreement
    p_e = sum(p**2 for p in p_j.values())

    if math.isclose(p_e, 1.0):
        warnings.append("degenerate marginals: all raters constant")
        return None, n_items, n_raters, warnings

    kappa = (p_bar - p_e) / (1.0 - p_e)
    return kappa, n_items, n_raters, warnings


def build_agreement_matrix(
    detector_verdicts: dict[str, Sequence[str | None]],
) -> AgreementMatrix:
    """Build a full agreement analysis across detectors.

    Args:
        detector_verdicts: mapping detector_id -> per-text verdict sequence.
                           All sequences must have equal length (one slot per
                           text, abstain/None allowed).

    Returns:
        AgreementMatrix with pairwise stats and Fleiss' kappa.
    """
    if not detector_verdicts:
        return AgreementMatrix(
            detectors=[],
            pairwise=[],
            fleiss_kappa=None,
            fleiss_n_texts=0,
            fleiss_n_raters=0,
            warnings=["no detectors provided"],
        )

    detector_ids = sorted(detector_verdicts.keys())
    n_texts = len(next(iter(detector_verdicts.values())))

    for det_id, verdicts in detector_verdicts.items():
        if len(verdicts) != n_texts:
            raise ValueError(
                f"Detector {det_id!r} has {len(verdicts)} verdicts, expected {n_texts}"
            )

    pairwise: list[PairwiseAgreement] = []
    for i, det_a in enumerate(detector_ids):
        for det_b in detector_ids[i + 1 :]:
            kappa, p_o, paired, confusion = cohens_kappa(
                detector_verdicts[det_a], detector_verdicts[det_b]
            )
            interpretation = _interpret_kappa(kappa) if kappa is not None else "undefined"
            pairwise.append(
                PairwiseAgreement(
                    detector_a=det_a,
                    detector_b=det_b,
                    paired_n=paired,
                    percent_agreement=p_o,
                    cohens_kappa=kappa,
                    kappa_interpretation=interpretation,
                    confusion=confusion,
                )
            )

    # Fleiss' kappa over the full matrix (texts as rows)
    matrix = [
        list(detector_veroids)
        for detector_veroids in zip(*(detector_verdicts[d] for d in detector_ids), strict=False)
    ]
    fleiss, n_usable, n_raters, warnings = fleiss_kappa(matrix)

    if len(detector_ids) < 2:
        warnings.append("fewer than 2 detectors: no pairwise or Fleiss statistics")
        fleiss = None

    return AgreementMatrix(
        detectors=detector_ids,
        pairwise=pairwise,
        fleiss_kappa=fleiss,
        fleiss_n_texts=n_usable,
        fleiss_n_raters=n_raters,
        warnings=warnings,
    )
