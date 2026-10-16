from __future__ import annotations

from .models import AnalyzerResult, Evidence


def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


def _high_when_low(value: float, low: float, high: float) -> float:
    if value <= low:
        return 1.0
    if value >= high:
        return 0.0
    return 1.0 - (value - low) / (high - low)


def _high_when_high(value: float, low: float, high: float) -> float:
    if value <= low:
        return 0.0
    if value >= high:
        return 1.0
    return (value - low) / (high - low)


def analyze_uniformity(f: dict) -> AnalyzerResult:
    sent = _high_when_low(float(f["sentence_length_cv"]), 0.22, 0.65)
    para = _high_when_low(float(f["paragraph_length_cv"]), 0.18, 0.80)
    starts = _high_when_high(float(f["repeated_sentence_start_ratio"]), 0.05, 0.30)
    score = 0.52 * sent + 0.25 * para + 0.23 * starts
    reliability = _clamp(float(f["sentence_count"]) / 12.0)
    return AnalyzerResult(
        name="structural_uniformity",
        score=_clamp(score),
        reliability=reliability,
        evidence=[
            Evidence("sentence_length_cv", f["sentence_length_cv"], 0.52 * sent,
                     "Very uniform sentence lengths can be a weak machine-like signal."),
            Evidence("paragraph_length_cv", f["paragraph_length_cv"], 0.25 * para,
                     "Uniform paragraph sizes can indicate templated prose."),
            Evidence("repeated_sentence_start_ratio", f["repeated_sentence_start_ratio"],
                     0.23 * starts, "Repeated sentence openings can indicate formulaic structure."),
        ],
    )


def analyze_formulaic_language(f: dict) -> AnalyzerResult:
    transitions = _high_when_high(float(f["transition_density"]), 0.25, 2.0)
    cliches = _high_when_high(float(f["cliche_density"]), 0.10, 1.20)
    repetition = _high_when_high(float(f["repeated_trigram_ratio"]), 0.01, 0.10)
    score = 0.35 * transitions + 0.40 * cliches + 0.25 * repetition
    reliability = _clamp(float(f["word_count"]) / 180.0)
    return AnalyzerResult(
        name="formulaic_language",
        score=_clamp(score),
        reliability=reliability,
        evidence=[
            Evidence("transition_density", f["transition_density"], 0.35 * transitions,
                     "Dense explicit transitions can make prose read formulaically."),
            Evidence("cliche_density", f["cliche_density"], 0.40 * cliches,
                     "Common AI-associated stock phrases are present."),
            Evidence("repeated_trigram_ratio", f["repeated_trigram_ratio"], 0.25 * repetition,
                     "Repeated three-word sequences can indicate templated phrasing."),
        ],
    )


def analyze_lexical_profile(f: dict) -> AnalyzerResult:
    # This is deliberately conservative: lexical diversity is heavily domain dependent.
    low_ttr = _high_when_low(float(f["type_token_ratio"]), 0.34, 0.58)
    low_hapax = _high_when_low(float(f["hapax_ratio"]), 0.42, 0.72)
    low_punct = _high_when_low(float(f["punctuation_variety"]), 2.0, 6.0)
    score = 0.40 * low_ttr + 0.30 * low_hapax + 0.30 * low_punct
    reliability = _clamp(float(f["word_count"]) / 300.0) * 0.75
    return AnalyzerResult(
        name="lexical_profile",
        score=_clamp(score),
        reliability=reliability,
        evidence=[
            Evidence("type_token_ratio", f["type_token_ratio"], 0.40 * low_ttr,
                     "Lower lexical variety can be a weak signal, but depends strongly on genre."),
            Evidence("hapax_ratio", f["hapax_ratio"], 0.30 * low_hapax,
                     "A low share of one-off words can indicate repetitive vocabulary."),
            Evidence("punctuation_variety", f["punctuation_variety"], 0.30 * low_punct,
                     "Low punctuation variety can accompany syntactically uniform prose."),
        ],
    )


def run_builtin_analyzers(features: dict) -> list[AnalyzerResult]:
    return [
        analyze_uniformity(features),
        analyze_formulaic_language(features),
        analyze_lexical_profile(features),
    ]
