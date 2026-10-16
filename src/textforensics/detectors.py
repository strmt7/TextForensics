from __future__ import annotations

import hashlib
import importlib.metadata
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol, runtime_checkable

from .engine import analyze_text


@dataclass(slots=True)
class DetectorPrediction:
    """Portable detector output for the TextForensics Detector Protocol (TFDP/1).

    `score` is deliberately called a score, not a probability. A detector may only
    populate `calibrated_ai_probability` when it has an explicit calibration model.
    """

    schema: str
    detector_id: str
    detector_version: str
    detector_family: str
    execution: str
    score: float | None
    score_semantics: str
    verdict: str
    threshold: float | None
    calibrated_ai_probability: float | None = None
    calibration_id: str | None = None
    reliability: float | None = None
    supported_languages: list[str] = field(default_factory=list)
    min_words: int | None = None
    evidence: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    runtime_ms: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@runtime_checkable
class Detector(Protocol):
    detector_id: str
    detector_version: str
    detector_family: str

    def detect(self, text: str) -> DetectorPrediction: ...


class BuiltinHeuristicDetector:
    detector_id = "textforensics/builtin-heuristic"
    detector_version = "0.1.0"
    detector_family = "stylometric-heuristic"

    def detect(self, text: str) -> DetectorPrediction:
        started = time.perf_counter()
        result = analyze_text(text)
        if result.verdict == "machine_like_patterns":
            verdict = "ai_like"
        elif result.verdict == "human_like_patterns":
            verdict = "human_like"
        else:
            verdict = "abstain"

        evidence = []
        for analyzer in result.analyzers:
            evidence.append(
                {
                    "analyzer": analyzer.name,
                    "score": round(analyzer.score, 4),
                    "reliability": round(analyzer.reliability, 4),
                }
            )

        return DetectorPrediction(
            schema="textforensics.detector-result/v1",
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            detector_family=self.detector_family,
            execution="local",
            score=result.score,
            score_semantics="higher_means_more_machine_like; uncalibrated pattern score",
            verdict=verdict,
            threshold=None,
            calibrated_ai_probability=None,
            calibration_id=None,
            reliability=result.confidence,
            supported_languages=["en"],
            min_words=80,
            evidence=evidence,
            warnings=result.warnings,
            runtime_ms=round((time.perf_counter() - started) * 1000, 3),
        )


_BUILTINS: dict[str, type[Detector]] = {
    BuiltinHeuristicDetector.detector_id: BuiltinHeuristicDetector,
}


def discover_detectors() -> dict[str, Detector]:
    """Discover built-ins plus third-party entry points in `textforensics.detectors`.

    A broken third-party plugin is skipped rather than breaking the forensic core.
    The caller can inspect package/plugin health separately in a future release.
    """

    found: dict[str, Detector] = {name: cls() for name, cls in _BUILTINS.items()}
    try:
        eps = importlib.metadata.entry_points()
        selected = eps.select(group="textforensics.detectors") if hasattr(eps, "select") else eps.get("textforensics.detectors", [])
    except Exception:
        selected = []

    for entry_point in selected:
        try:
            candidate = entry_point.load()()
            if isinstance(candidate, Detector):
                found[candidate.detector_id] = candidate
        except Exception:
            continue
    return found


def list_detector_metadata() -> list[dict[str, str]]:
    detectors = discover_detectors()
    return [
        {
            "detector_id": item.detector_id,
            "detector_version": item.detector_version,
            "detector_family": item.detector_family,
        }
        for item in sorted(detectors.values(), key=lambda x: x.detector_id)
    ]


def text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
