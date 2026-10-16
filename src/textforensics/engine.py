from __future__ import annotations

import statistics

from .analyzers import run_builtin_analyzers
from .features import extract_features
from .models import AnalysisResult, AnalyzerResult
from .robustness import benign_variants


def _weighted_score(results: list[AnalyzerResult]) -> float:
    weights = [max(0.05, result.reliability) for result in results]
    return sum(
        result.score * weight
        for result, weight in zip(results, weights)
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
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Text must not be empty.")

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
        length_reliability
        * (0.65 + 0.35 * (1.0 - disagreement))
        * (0.7 + 0.3 * stability)
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
        warnings.append(
            "The baseline score is sensitive to harmless formatting normalization."
        )
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

    return AnalysisResult(
        score=round(score, 4),
        verdict=_verdict(score, diagnostic_reliability),
        confidence=round(diagnostic_reliability, 4),
        disagreement=round(disagreement, 4),
        robustness_stability=round(stability, 4),
        word_count=features["word_count"],
        analyzers=results,
        features=features,
        warnings=warnings,
    )
