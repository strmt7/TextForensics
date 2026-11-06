"""Explainable detection: feature attribution for detector verdicts.

This module provides counterfactual explanations for detector decisions -
identifying which text segments drive the detector toward its verdict by
measuring score sensitivity to targeted perturbations.

This implements the forensic-audit principle that every verdict must be
inspectable: an enterprise reviewer can see *which sentences* most increase
or decrease the detector's machine-likeness score.

Methods:
- **Counterfactual sentence removal**: remove each sentence and re-score;
  the score delta attributes responsibility to that sentence.
- **Perturbation ranking**: rank segments by |delta| to produce an
  explanation profile.

Raw text never leaves the machine: explanations are computed locally.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC
from typing import Any

__all__ = [
    "SegmentAttribution",
    "ExplanationReport",
    "CounterfactualExplainer",
    "split_sentences",
    "explain_verdict",
]


@dataclass(frozen=True, slots=True)
class SegmentAttribution:
    """Attribution of detector score change to one text segment.

    Attributes:
        segment_index: 0-based index of the segment in the original text.
        segment_text: The segment text (safe to include: it's the user's own input).
        original_score: Detector score for the full text.
        perturbed_score: Detector score with this segment removed.
        delta: perturbed_score - original_score. Positive means removing this
               segment *increased* the score (segment was pulling the score down);
               negative means removing it *decreased* the score (segment pushed
               score up, i.e. contributed AI-likeness).
        abs_delta: Absolute contribution magnitude.
        direction: "pushes_ai" if delta < 0, "pushes_human" if delta > 0, "neutral" otherwise.
    """

    segment_index: int
    segment_text: str
    original_score: float
    perturbed_score: float
    delta: float
    abs_delta: float
    direction: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "segment_index": self.segment_index,
            "segment_text": self.segment_text,
            "original_score": self.original_score,
            "perturbed_score": self.perturbed_score,
            "delta": self.delta,
            "abs_delta": self.abs_delta,
            "direction": self.direction,
        }


@dataclass
class ExplanationReport:
    """Full counterfactual explanation report for a detector verdict."""

    detector_id: str
    detector_version: str
    text_sha256: str
    original_score: float | None
    verdict: str
    n_segments: int
    n_scored: int
    segment_attribution: list[SegmentAttribution] = field(default_factory=list)
    top_ai_driving: list[SegmentAttribution] = field(default_factory=list)
    top_human_driving: list[SegmentAttribution] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    explanation_id: str = ""
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector_id": self.detector_id,
            "detector_version": self.detector_version,
            "text_sha256": self.text_sha256,
            "original_score": self.original_score,
            "verdict": self.verdict,
            "n_segments": self.n_segments,
            "n_scored": self.n_scored,
            "segment_attribution": [s.to_dict() for s in self.segment_attribution],
            "top_ai_driving": [s.to_dict() for s in self.top_ai_driving],
            "top_human_driving": [s.to_dict() for s in self.top_human_driving],
            "limitations": list(self.limitations),
            "explanation_id": self.explanation_id,
            "created_at": self.created_at,
        }

    def summary(self) -> dict[str, Any]:
        """Compact summary: which segments drove the verdict most."""
        return {
            "detector_id": self.detector_id,
            "verdict": self.verdict,
            "n_segments": self.n_segments,
            "n_scored": self.n_scored,
            "top_ai_driving_count": len(self.top_ai_driving),
            "top_human_driving_count": len(self.top_human_driving),
            "most_ai_driving_segment": (
                self.top_ai_driving[0].segment_text[:80] if self.top_ai_driving else None
            ),
            "most_human_driving_segment": (
                self.top_human_driving[0].segment_text[:80] if self.top_human_driving else None
            ),
        }


_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")


def split_sentences(text: str, min_words: int = 2) -> list[str]:
    """Split text into sentence segments for counterfactual analysis.

    Args:
        text: Input text.
        min_words: Minimum words for a segment to stand alone. Segments with
                   fewer words are merged with the previous segment (or kept
                   alone if it is the only segment).

    Returns:
        List of sentence segments (non-empty, stripped).
    """
    if not text or not text.strip():
        return []

    raw = _SENTENCE_SPLIT_RE.split(text.strip())
    segments: list[str] = []
    for part in raw:
        part = part.strip()
        if not part:
            continue
        # Merge very short fragments with previous segment
        if segments and len(part.split()) < min_words:
            segments[-1] = segments[-1] + " " + part
        else:
            segments.append(part)
    return segments


# Default limitations for explanation reports
EXPLANATION_LIMITATIONS = [
    "Counterfactual attribution measures score sensitivity, not causal proof of authorship.",
    "Sentence-level attribution does not constitute a sentence-level authorship probability.",
    "Attribution deltas depend on detector internals and may not generalise across detectors.",
    "Explanations are computed on the exact detector version recorded; results may differ after detector updates.",
]


def _noop_progress(completed: int, total: int) -> None:
    pass


class CounterfactualExplainer:
    """Counterfactual explainer for any score_fn-based detector.

    The explainer is detector-agnostic: it accepts a scoring function
    ``score_fn(text) -> float | None`` and produces per-segment attribution
    by removing each segment and re-scoring.
    """

    def __init__(
        self,
        score_fn: Callable[[str], float | None],
        *,
        detector_id: str = "unknown",
        detector_version: str = "0.0.0",
        top_k: int = 3,
        merge_short_segments: bool = True,
    ) -> None:
        """
        Args:
            score_fn: Function mapping text to a detector score (None = abstain).
            detector_id: Detector identifier for the report.
            detector_version: Detector version for the report.
            top_k: Number of top AI-driving and human-driving segments to report.
            merge_short_segments: Whether to merge short fragments (passed to split_sentences).
        """
        if not callable(score_fn):
            raise ValueError("score_fn must be callable")
        self.score_fn = score_fn
        self.detector_id = detector_id
        self.detector_version = detector_version
        self.top_k = max(1, int(top_k))
        self.merge_short_segments = merge_short_segments

    def explain(
        self,
        text: str,
        *,
        progress: Callable[[int, int], None] | None = None,
    ) -> ExplanationReport:
        """Explain a detector verdict via counterfactual sentence removal.

        For each sentence segment, the segment is removed and the remaining
        text is re-scored. The score delta attributes responsibility.

        Args:
            text: Text to explain.
            progress: Optional callback(completed, total) for progress reporting.

        Returns:
            ExplanationReport with per-segment attribution.
        """
        if progress is None:
            progress = _noop_progress

        segments = split_sentences(text)
        original_score = self.score_fn(text)

        attributions: list[SegmentAttribution] = []
        n_scored = 0

        if original_score is not None and len(segments) > 1:
            n_scored = len(segments)
            for idx, segment in enumerate(segments):
                # Remove this segment
                remaining = [s for i, s in enumerate(segments) if i != idx]
                perturbed_text = " ".join(remaining)
                perturbed_score = self.score_fn(perturbed_text)

                if perturbed_score is None:
                    # Detector abstained on the perturbed text; skip
                    progress(idx + 1, n_scored)
                    continue

                delta = perturbed_score - original_score
                if delta < 0:
                    direction = "pushes_ai"
                elif delta > 0:
                    direction = "pushes_human"
                else:
                    direction = "neutral"

                attributions.append(
                    SegmentAttribution(
                        segment_index=idx,
                        segment_text=segment,
                        original_score=original_score,
                        perturbed_score=perturbed_score,
                        delta=round(delta, 6),
                        abs_delta=round(abs(delta), 6),
                        direction=direction,
                    )
                )
                progress(idx + 1, n_scored)

        # Rank by |delta| descending, split by direction
        ranked = sorted(attributions, key=lambda a: a.abs_delta, reverse=True)
        top_ai = [a for a in ranked if a.direction == "pushes_ai"][: self.top_k]
        top_human = [a for a in ranked if a.direction == "pushes_human"][: self.top_k]

        report = ExplanationReport(
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            text_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            original_score=original_score,
            verdict="",  # Filled by caller if known
            n_segments=len(segments),
            n_scored=n_scored,
            segment_attribution=attributions,
            top_ai_driving=top_ai,
            top_human_driving=top_human,
            limitations=list(EXPLANATION_LIMITATIONS),
        )
        report.explanation_id = _explanation_id(report)
        report.created_at = _now_iso()
        return report

    def explain_ranked(self, text: str) -> list[SegmentAttribution]:
        """Convenience: return all segments ranked by |delta| descending."""
        report = self.explain(text)
        return sorted(report.segment_attribution, key=lambda a: a.abs_delta, reverse=True)


def _now_iso() -> str:
    from datetime import datetime

    return datetime.now(UTC).isoformat()


def _explanation_id(report: ExplanationReport) -> str:
    """Deterministic explanation ID from detector + text + attribution."""
    canonical = json.dumps(
        {
            "detector_id": report.detector_id,
            "text_sha256": report.text_sha256,
            "n_scored": report.n_scored,
            "deltas": [a.delta for a in report.segment_attribution],
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def explain_verdict(
    text: str,
    score_fn: Callable[[str], float | None],
    *,
    detector_id: str = "unknown",
    detector_version: str = "0.0.0",
    verdict: str = "",
    top_k: int = 3,
) -> ExplanationReport:
    """One-shot counterfactual explanation of a detector verdict.

    Args:
        text: Text to explain.
        score_fn: Scoring function (text -> score or None).
        detector_id: Detector identifier.
        detector_version: Detector version.
        verdict: Known verdict string (recorded in the report).
        top_k: Number of top segments per direction.

    Returns:
        ExplanationReport with attribution and limitations.
    """
    explainer = CounterfactualExplainer(
        score_fn,
        detector_id=detector_id,
        detector_version=detector_version,
        top_k=top_k,
    )
    report = explainer.explain(text)
    # Record the verdict for provenance
    report.verdict = verdict
    report.explanation_id = _explanation_id(report)
    return report


def save_explanation_report(report: ExplanationReport, path: str) -> None:
    """Save an explanation report to a JSON file."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)
        f.write("\n")


def load_explanation_report(path: str) -> ExplanationReport:
    """Load an explanation report from a JSON file."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return ExplanationReport(
        detector_id=data["detector_id"],
        detector_version=data["detector_version"],
        text_sha256=data["text_sha256"],
        original_score=data.get("original_score"),
        verdict=data.get("verdict", ""),
        n_segments=data["n_segments"],
        n_scored=data["n_scored"],
        segment_attribution=[SegmentAttribution(**s) for s in data.get("segment_attribution", [])],
        top_ai_driving=[SegmentAttribution(**s) for s in data.get("top_ai_driving", [])],
        top_human_driving=[SegmentAttribution(**s) for s in data.get("top_human_driving", [])],
        limitations=list(data.get("limitations", [])),
        explanation_id=data.get("explanation_id", ""),
        created_at=data.get("created_at", ""),
    )
