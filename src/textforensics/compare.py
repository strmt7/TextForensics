from __future__ import annotations

from dataclasses import asdict, dataclass
from difflib import SequenceMatcher

from .engine import analyze_text
from .features import WORD_RE


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
