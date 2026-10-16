from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class Evidence:
    feature: str
    value: float | int | str
    contribution: float
    explanation: str


@dataclass(slots=True)
class AnalyzerResult:
    name: str
    score: float
    reliability: float
    evidence: list[Evidence] = field(default_factory=list)


@dataclass(slots=True)
class AnalysisResult:
    score: float
    verdict: str
    confidence: float
    disagreement: float
    robustness_stability: float
    word_count: int
    analyzers: list[AnalyzerResult]
    features: dict[str, Any]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
