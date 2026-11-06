from __future__ import annotations

import math
import statistics
from dataclasses import asdict, dataclass
from difflib import SequenceMatcher
from typing import Any

from .analyzers import run_builtin_analyzers
from .emergency_stop import assert_not_stopped
from .features import WORD_RE, benign_variants, extract_features
from .models import AnalysisResult, AnalyzerResult


def _import_telemetry():
    """Lazily import telemetry module."""
    from . import telemetry

    return telemetry


def _weighted_score(results: list[AnalyzerResult]) -> float:
    weights = [max(0.05, result.reliability) for result in results]
    return sum(
        result.score * weight for result, weight in zip(results, weights, strict=False)
    ) / sum(weights)


def _disagreement(results: list[AnalyzerResult]) -> float:
    if len(results) < 2:
        return 0.0
    return min(
        1.0,
        statistics.pstdev(result.score for result in results) * 2.0,
    )


def _base_score(
    text: str,
) -> tuple[float, list[AnalyzerResult], dict]:
    features = extract_features(text)
    results = run_builtin_analyzers(features)
    return _weighted_score(results), results, features


def _verdict(score: float, diagnostic_reliability: float) -> str:
    if not math.isfinite(float(score)):
        raise ValueError("score must be finite.")
    if not math.isfinite(float(diagnostic_reliability)):
        raise ValueError("diagnostic_reliability must be finite.")
    if diagnostic_reliability < 0.28:
        return "insufficient_evidence"
    if score >= 0.68:
        return "machine_like_patterns"
    if score <= 0.32:
        return "human_like_patterns"
    return "indeterminate"


def analyze_text(
    text: str,
    *,
    include_robustness: bool = True,
) -> AnalysisResult:
    # Emergency stop gate: checked at dispatch entry before any analysis.
    assert_not_stopped()
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Text must not be empty.")

    # Use telemetry timer if enabled
    telemetry = _import_telemetry()
    if telemetry.is_telemetry_initialized():
        with telemetry.AnalysisTimer() as timer:
            return _analyze_text_internal(
                text,
                include_robustness=include_robustness,
                timer=timer,
            )
    else:
        return _analyze_text_internal(
            text,
            include_robustness=include_robustness,
            timer=None,
        )


def _analyze_text_internal(
    text: str,
    *,
    include_robustness: bool = True,
    timer: Any | None = None,
) -> AnalysisResult:
    try:
        score, results, features = _base_score(text)
        disagreement = _disagreement(results)

        stability = 1.0
        if include_robustness:
            variant_scores = []
            for variant in benign_variants(text).values():
                variant_score, _, _ = _base_score(variant)
                variant_scores.append(variant_score)
            if variant_scores:
                stability = max(
                    0.0,
                    1.0 - (max(variant_scores) - min(variant_scores)),
                )

        length_reliability = min(1.0, features["word_count"] / 250.0)
        diagnostic_reliability = (
            length_reliability * (0.65 + 0.35 * (1.0 - disagreement)) * (0.7 + 0.3 * stability)
        )
        diagnostic_reliability = max(
            0.0,
            min(1.0, diagnostic_reliability),
        )

        warnings: list[str] = []
        if features["word_count"] < 80:
            warnings.append(
                "Short text: detector-style signals are especially unreliable "
                "below the built-in baseline's 80-word minimum."
            )
        if disagreement > 0.45:
            warnings.append(
                "High analyzer disagreement: treat the aggregate score as weak evidence."
            )
        if stability < 0.85:
            warnings.append("The baseline score is sensitive to harmless formatting normalization.")
        warnings.extend(
            [
                (
                    "Diagnostic reliability is an uncalibrated alpha heuristic, "
                    "not an authorship probability or validated confidence."
                ),
                (
                    "This is a text-pattern assessment, not proof of authorship. "
                    "False positives and false negatives are expected."
                ),
            ]
        )

        verdict = _verdict(score, diagnostic_reliability)

        # Update timer with verdict and detector info for metrics
        if timer is not None:
            timer.verdict = verdict
            timer.detector_scores = [r.score for r in results]
            timer.detector_names = [r.name for r in results]

        return AnalysisResult(
            score=round(score, 4),
            verdict=verdict,
            confidence=round(diagnostic_reliability, 4),
            disagreement=round(disagreement, 4),
            robustness_stability=round(stability, 4),
            word_count=features["word_count"],
            analyzers=results,
            features=features,
            warnings=warnings,
        )
    except Exception as e:
        telemetry = _import_telemetry()
        telemetry.record_error(type(e).__name__, "engine")
        raise


# ---------------------------------------------------------------------------
# Before/after text comparison (merged from compare.py, Phase 2 wave e)
# ---------------------------------------------------------------------------
# NOTE (unchanged behaviour): a "replace" opcode counts words as both
# added and removed, so words_added_estimate + words_removed_estimate
# double-counts replaced words by design (see analysis §5.3).


@dataclass(slots=True)
class ComparisonResult:
    similarity: float
    before_score: float
    after_score: float
    score_delta: float
    before_verdict: str
    after_verdict: str
    words_added_estimate: int
    words_removed_estimate: int

    def to_dict(self) -> dict:
        return asdict(self)


def compare_texts(before: str, after: str) -> ComparisonResult:
    before_words = WORD_RE.findall(before)
    after_words = WORD_RE.findall(after)
    matcher = SequenceMatcher(a=before_words, b=after_words, autojunk=False)
    added = 0
    removed = 0
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in {"insert", "replace"}:
            added += j2 - j1
        if tag in {"delete", "replace"}:
            removed += i2 - i1

    a = analyze_text(before)
    b = analyze_text(after)
    return ComparisonResult(
        similarity=round(matcher.ratio(), 4),
        before_score=a.score,
        after_score=b.score,
        score_delta=round(b.score - a.score, 4),
        before_verdict=a.verdict,
        after_verdict=b.verdict,
        words_added_estimate=added,
        words_removed_estimate=removed,
    )
