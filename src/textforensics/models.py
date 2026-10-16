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
    confidence_semantics: str = (
        "Uncalibrated heuristic diagnostic reliability for the built-in baseline; "
        "not an authorship probability or validated confidence."
    )

    @property
    def diagnostic_reliability(self) -> float:
        """Preferred name for the legacy alpha `confidence` field."""
        return self.confidence

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["diagnostic_reliability"] = self.confidence
        return data
