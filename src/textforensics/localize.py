from __future__ import annotations

from dataclasses import asdict, dataclass

from .engine import analyze_text
from .features import SENTENCE_RE, WORD_RE


@dataclass(slots=True)
class SegmentResult:
    index: int
    text: str
    word_count: int
    score: float
    confidence: float
    verdict: str

    def to_dict(self) -> dict:
        return asdict(self)


def localize_text(text: str, *, sentences_per_segment: int = 4) -> list[SegmentResult]:
    sentences = [s.strip() for s in SENTENCE_RE.split(text.strip()) if s.strip()]
    if not sentences:
        return []
    segments: list[SegmentResult] = []
    for index, start in enumerate(range(0, len(sentences), sentences_per_segment)):
        chunk = " ".join(sentences[start : start + sentences_per_segment])
        analysis = analyze_text(chunk, include_robustness=False)
        segments.append(
            SegmentResult(
                index=index,
                text=chunk,
                word_count=len(WORD_RE.findall(chunk)),
                score=analysis.score,
                confidence=analysis.confidence,
                verdict=analysis.verdict,
            )
        )
    return segments
