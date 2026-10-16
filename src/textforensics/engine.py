from __future__ import annotations

import statistics

from .analyzers import run_builtin_analyzers
from .features import extract_features
from .models import AnalysisResult, AnalyzerResult
from .robustness import benign_variants


def _weighted_score(results: list[AnalyzerResult]) -> float:
    weights = [max(0.05, r.reliability) for r in results]
    return sum(r.score * w for r, w in zip(results, weights)) / sum(weights)


def _disagreement(results: list[AnalyzerResult]) -> float:
    if len(results) < 2:
        return 0.0
    return min(1.0, statistics.pstdev(r.score for r in results) * 2.0)


def _base_score(text: str) -> tuple[float, list[AnalyzerResult], dict]:
    features = extract_features(text)
    results = run_builtin_analyzers(features)
    return _weighted_score(results), results, features


def _verdict(score: float, confidence: float) -> str:
    if confidence < 0.28:
        return "insufficient_evidence"
    if score >= 0.68:
        return "machine_like_patterns"
    if score <= 0.32:
        return "human_like_patterns"
    return "indeterminate"


def analyze_text(text: str, *, include_robustness: bool = True) -> AnalysisResult:
    if not text or not text.strip():
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
            stability = max(0.0, 1.0 - (max(variant_scores) - min(variant_scores)))

    length_reliability = min(1.0, features["word_count"] / 250.0)
    confidence = length_reliability * (0.65 + 0.35 * (1.0 - disagreement)) * (0.7 + 0.3 * stability)
    confidence = max(0.0, min(1.0, confidence))

    warnings: list[str] = []
    if features["word_count"] < 80:
        warnings.append("Short text: detector-style signals are especially unreliable below ~80 words.")
    if disagreement > 0.45:
        warnings.append("High analyzer disagreement: treat the aggregate score as weak evidence.")
    if stability < 0.85:
        warnings.append("Verdict is sensitive to harmless formatting normalization.")
    warnings.append(
        "This is a text-pattern assessment, not proof of authorship. False positives and false negatives are expected."
    )

    return AnalysisResult(
        score=round(score, 4),
        verdict=_verdict(score, confidence),
        confidence=round(confidence, 4),
        disagreement=round(disagreement, 4),
        robustness_stability=round(stability, 4),
        word_count=features["word_count"],
        analyzers=results,
        features=features,
        warnings=warnings,
    )
