from __future__ import annotations

import math
import re
import statistics
from collections import Counter
from typing import Any

WORD_RE = re.compile(r"\b[\w]+(?:['’][\w]+)?\b", re.UNICODE)
SENTENCE_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"'“‘(])")

TRANSITIONS = (
    "additionally", "furthermore", "moreover", "however", "therefore", "consequently",
    "in conclusion", "overall", "in summary", "it is important to note", "notably",
    "on the other hand", "as a result", "in addition", "for example", "for instance",
)

AI_CLICHES = (
    "delve into", "tapestry", "ever-evolving", "ever evolving", "in today's world",
    "in today’s world", "landscape", "multifaceted", "robust solution", "seamlessly",
    "unlock the potential", "game-changer", "game changer", "it is worth noting",
    "it is important to note", "navigate the complexities", "a testament to",
)

CONTRACTION_RE = re.compile(
    r"\b(?:can't|cannot|won't|don't|doesn't|didn't|isn't|aren't|wasn't|weren't|i'm|i've|"
    r"i'd|i'll|you're|you've|you'd|you'll|we're|we've|we'd|we'll|they're|they've|"
    r"they'd|they'll|it's|that's|there's|here's|what's|who's|let's)\b",
    re.IGNORECASE,
)


def _cv(values: list[int]) -> float:
    if len(values) < 2:
        return 0.0
    mean = statistics.mean(values)
    if mean == 0:
        return 0.0
    return statistics.pstdev(values) / mean


def _entropy(items: list[str]) -> float:
    if not items:
        return 0.0
    counts = Counter(items)
    total = len(items)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _sentence_starts(sentences: list[str]) -> list[str]:
    starts: list[str] = []
    for sentence in sentences:
        words = WORD_RE.findall(sentence.lower())
        if words:
            starts.append(" ".join(words[:2]))
    return starts


def extract_features(text: str) -> dict[str, Any]:
    clean = text.strip()
    words = WORD_RE.findall(clean)
    lower_words = [w.lower() for w in words]
    sentences = [s.strip() for s in SENTENCE_RE.split(clean) if s.strip()]
    if not sentences and clean:
        sentences = [clean]
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", clean) if p.strip()]

    sentence_lengths = [len(WORD_RE.findall(s)) for s in sentences]
    paragraph_lengths = [len(WORD_RE.findall(p)) for p in paragraphs]
    token_count = len(words)
    vocab = Counter(lower_words)
    hapax = sum(1 for n in vocab.values() if n == 1)

    trigrams = [tuple(lower_words[i : i + 3]) for i in range(max(0, token_count - 2))]
    trigram_counts = Counter(trigrams)
    repeated_trigrams = sum(n - 1 for n in trigram_counts.values() if n > 1)

    lower = clean.lower()
    transition_hits = sum(lower.count(phrase) for phrase in TRANSITIONS)
    cliche_hits = sum(lower.count(phrase) for phrase in AI_CLICHES)
    punctuation_types = sum(1 for ch in ",;:—-()?!" if ch in clean)
    starts = _sentence_starts(sentences)
    start_counts = Counter(starts)
    repeated_starts = sum(n - 1 for n in start_counts.values() if n > 1)

    return {
        "word_count": token_count,
        "sentence_count": len(sentences),
        "paragraph_count": len(paragraphs),
        "mean_sentence_length": statistics.mean(sentence_lengths) if sentence_lengths else 0.0,
        "sentence_length_cv": _cv(sentence_lengths),
        "paragraph_length_cv": _cv(paragraph_lengths),
        "type_token_ratio": (len(vocab) / token_count) if token_count else 0.0,
        "hapax_ratio": (hapax / len(vocab)) if vocab else 0.0,
        "word_entropy": _entropy(lower_words),
        "transition_density": (transition_hits * 100 / token_count) if token_count else 0.0,
        "cliche_density": (cliche_hits * 100 / token_count) if token_count else 0.0,
        "contraction_density": (len(CONTRACTION_RE.findall(clean)) * 100 / token_count)
        if token_count
        else 0.0,
        "punctuation_variety": punctuation_types,
        "repeated_trigram_ratio": (repeated_trigrams / len(trigrams)) if trigrams else 0.0,
        "repeated_sentence_start_ratio": (repeated_starts / len(starts)) if starts else 0.0,
        "question_rate": (clean.count("?") / max(1, len(sentences))),
        "semicolon_rate": (clean.count(";") / max(1, len(sentences))),
        "parenthetical_rate": ((clean.count("(") + clean.count(")")) / 2 / max(1, len(sentences))),
    }
