from __future__ import annotations

from .features import extract_features


def audit_naturalness(text: str) -> list[dict[str, str]]:
    """Return transparent editing observations; does not rewrite or optimize for detector evasion."""
    f = extract_features(text)
    issues: list[dict[str, str]] = []

    if f["sentence_count"] >= 5 and f["sentence_length_cv"] < 0.28:
        issues.append({
            "issue": "uniform_sentence_rhythm",
            "suggestion": "Vary sentence length where it improves readability; combine or split sentences based on meaning.",
        })
    if f["transition_density"] > 1.2:
        issues.append({
            "issue": "heavy_explicit_transitions",
            "suggestion": "Remove transitions that merely announce the relationship between adjacent sentences when the relationship is already obvious.",
        })
    if f["cliche_density"] > 0.3:
        issues.append({
            "issue": "stock_phrasing",
            "suggestion": "Replace generic stock phrases with concrete claims, examples, names, measurements, or direct wording.",
        })
    if f["repeated_sentence_start_ratio"] > 0.12:
        issues.append({
            "issue": "repeated_sentence_openings",
            "suggestion": "Check repeated sentence openings and keep them only when repetition is intentional.",
        })
    if f["paragraph_count"] <= 1 and f["word_count"] > 250:
        issues.append({
            "issue": "dense_paragraphing",
            "suggestion": "Consider paragraph breaks at genuine topic or argument shifts.",
        })
    if not issues:
        issues.append({
            "issue": "no_obvious_formulaic_pattern",
            "suggestion": "No strong rule-based naturalness issue was found. Preserve the author's voice rather than changing text just to change it.",
        })
    return issues
