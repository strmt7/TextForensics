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
        data = asdict(self)
        data["diagnostic_reliability"] = self.confidence
        return data


def localize_text(
    text: str,
    *,
    sentences_per_segment: int = 4,
) -> list[SegmentResult]:
    if sentences_per_segment < 1:
        raise ValueError("sentences_per_segment must be at least 1.")
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Text must not be empty.")

    sentences = [
        sentence.strip()
        for sentence in SENTENCE_RE.split(text.strip())
        if sentence.strip()
    ]
    if not sentences:
        return []

    segments: list[SegmentResult] = []
    for index, start in enumerate(
        range(0, len(sentences), sentences_per_segment)
    ):
        chunk = " ".join(
            sentences[start : start + sentences_per_segment]
        )
        analysis = analyze_text(chunk, include_robustness=False)
        segments.append(
            SegmentResult(
                index=index,
                text=chunk,
                word_count=len(WORD_RE.findall(chunk)),
                score=analysis.score,
                confidence=analysis.diagnostic_reliability,
                verdict=analysis.verdict,
            )
        )
    return segments
