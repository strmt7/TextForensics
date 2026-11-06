"""Semantic Consistency Checker for TextForensics.

Analyzes semantic coherence and consistency across text to detect AI-generated
content. AI-generated text often exhibits unnatural semantic patterns:
- Overly consistent style/tone across diverse topics
- Unnaturally smooth semantic transitions
- Lack of genuine digressions or associative thinking
- Excessive semantic coherence (too coherent to be human)
- Repetitive semantic structures
- Lack of genuine contradictions or self-corrections

This module provides statistical and embedding-based analysis of semantic
consistency to detect AI-generated text.
"""

from __future__ import annotations

import hashlib
import math
import re
import statistics
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

__all__ = [
    "SemanticSegment",
    "ConsistencyFinding",
    "SemanticConsistencyReport",
    "SemanticConsistencyChecker",
    "analyze_semantic_consistency",
]


@dataclass(frozen=True, slots=True)
class SemanticSegment:
    """A text segment with its semantic features."""

    index: int
    text: str
    word_count: int
    sentence_count: int
    avg_word_length: float
    type_token_ratio: float
    hapax_ratio: float
    pos_distribution: dict[str, float]  # Simplified: we'll approximate
    semantic_density: float  # Words per sentence / unique concepts
    entropy: float  # Lexical entropy


@dataclass(frozen=True, slots=True)
class ConsistencyFinding:
    """A detected consistency anomaly."""

    finding_id: str
    category: str  # "style", "topic", "structure", "lexical", "semantic", "coherence"
    description: str
    evidence: float  # Quantitative evidence (0-1 scale)
    severity: str  # "critical", "high", "medium", "low"
    confidence: float  # 0-1
    segment_indices: tuple[int, int]  # Segment range affected
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "category": self.category,
            "description": self.description,
            "evidence": self.evidence,
            "severity": self.severity,
            "confidence": self.confidence,
            "segment_indices": list(self.segment_indices),
            "details": self.details,
        }


@dataclass
class SemanticConsistencyReport:
    """Complete semantic consistency analysis report."""

    text_sha256: str
    text_length: int
    n_segments: int
    findings: list[dict[str, Any]] = field(default_factory=list)
    overall_consistency_score: float = 0.0  # 0 = human-like variation, 1 = AI-like consistency
    risk_level: str = "none"  # "none", "low", "medium", "high", "critical"
    confidence: float = 0.0
    segments_analyzed: int = 0
    limitations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    report_id: str = ""
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "text_sha256": self.text_sha256,
            "text_length": self.text_length,
            "n_segments": self.n_segments,
            "findings": self.findings,
            "overall_consistency_score": self.overall_consistency_score,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "segments_analyzed": self.segments_analyzed,
            "limitations": list(self.limitations),
            "metadata": self.metadata,
            "report_id": self.report_id,
            "created_at": self.created_at,
        }

    def summary(self) -> dict[str, Any]:
        return {
            "text_sha256": self.text_sha256[:16] + "...",
            "risk_level": self.risk_level,
            "consistency_score": self.overall_consistency_score,
            "confidence": self.confidence,
            "total_findings": len(self.findings),
        }


# ============================================================
# Helper Functions
# ============================================================

_WORD_RE = re.compile(r"\b\w+\b")
_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+")


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _split_into_segments(text: str, target_segment_words: int = 100) -> list[str]:
    """Split text into roughly equal semantic segments."""
    if not text or not text.strip():
        return []

    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    if not sentences:
        return []

    segments = []
    current_segment = []
    current_words = 0

    for sentence in sentences:
        words = sentence.split()
        if current_words + len(words) > target_segment_words and current_segment:
            segments.append(" ".join(current_segment))
            current_segment = [sentence]
            current_words = len(words)
        else:
            current_segment.append(sentence)
            current_words += len(words)

    if current_segment:
        segments.append(" ".join(current_segment))

    return segments


def _analyze_segment(text: str, index: int) -> SemanticSegment:
    """Analyze a single text segment for semantic features."""
    words = text.split()
    word_count = len(words)
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    sentence_count = len([s for s in sentences if s.strip()])

    # Type-token ratio
    words_lower = [w.lower() for w in text.split()]
    unique_words = len(set(words_lower))
    type_token_ratio = unique_words / word_count if word_count > 0 else 0.0

    # Hapax ratio (words appearing exactly once)
    word_counts = Counter(w.lower() for w in text.split())
    hapax_count = sum(1 for c in word_counts.values() if c == 1)
    hapax_ratio = hapax_count / unique_words if unique_words > 0 else 0.0

    # Average word length
    avg_word_length = sum(len(w) for w in words) / word_count if word_count > 0 else 0.0

    # Lexical entropy
    if word_count > 0:
        probs = [count / word_count for count in word_counts.values()]
        entropy = -sum(p * math.log2(p) for p in probs if p > 0)
    else:
        entropy = 0.0

    # Semantic density: concepts per sentence (approximated by unique words / sentence count)
    semantic_density = unique_words / sentence_count if sentence_count > 0 else 0.0

    # POS distribution approximation (simplified)
    pos_dist = {"noun": 0.25, "verb": 0.2, "adj": 0.15, "adv": 0.1, "other": 0.3}

    return SemanticSegment(
        index=0,  # Will be set by caller
        text=text[:200],  # Truncate for storage
        word_count=word_count,
        sentence_count=sentence_count,
        avg_word_length=avg_word_length,
        type_token_ratio=type_token_ratio,
        hapax_ratio=hapax_ratio,
        pos_distribution=pos_dist,
        semantic_density=semantic_density,
        entropy=entropy,
    )


# ============================================================
# Consistency Detectors
# ============================================================


def _detect_excessive_coherence(segments: list[SemanticSegment]) -> list[dict]:
    """Detect unnaturally high semantic coherence across segments."""
    if len(segments) < 3:
        return []

    findings = []

    # Check type-token ratio consistency (too consistent = suspicious)
    ttr_values = [s.type_token_ratio for s in segments]
    ttr_mean = statistics.mean(ttr_values)
    ttr_stdev = statistics.stdev(ttr_values) if len(ttr_values) > 1 else 0.0

    # Too low variance in TTR = suspiciously consistent
    if ttr_stdev < 0.02 and ttr_mean > 0.3:
        findings.append(
            {
                "finding_id": f"excessive_ttr_consistency_{_sha256('ttr')[:8]}",
                "category": "lexical",
                "description": "Unnaturally consistent type-token ratio across segments",
                "evidence": round(ttr_stdev, 4),
                "severity": "medium",
                "confidence": 0.7,
                "segment_indices": (0, len(segments) - 1),
                "details": {
                    "ttr_mean": round(ttr_mean, 4),
                    "ttr_stdev": round(ttr_stdev, 4),
                    "threshold": 0.02,
                },
            }
        )

    # Check entropy consistency
    entropy_values = [s.entropy for s in segments]
    entropy_mean = statistics.mean(entropy_values)
    entropy_stdev = statistics.stdev(entropy_values) if len(entropy_values) > 1 else 0.0

    if entropy_stdev < 0.15 and entropy_mean > 2.0:
        findings.append(
            {
                "finding_id": f"excessive_entropy_consistency_{_sha256('entropy')[:8]}",
                "category": "lexical",
                "description": "Unnaturally consistent lexical entropy across segments",
                "evidence": round(entropy_stdev, 4),
                "severity": "medium",
                "confidence": 0.65,
                "segment_indices": (0, len(segments) - 1),
                "details": {
                    "entropy_mean": round(entropy_mean, 4),
                    "entropy_stdev": round(entropy_stdev, 4),
                },
            }
        )

    return findings


def _detect_structural_rigidity(segments: list[SemanticSegment]) -> list[dict]:
    """Detect unnaturally rigid structure (same sentence/word counts, etc.)."""
    if len(segments) < 3:
        return []

    findings = []

    # Check word count consistency
    word_counts = [s.word_count for s in segments]
    wc_mean = statistics.mean(word_counts)
    wc_stdev = statistics.stdev(word_counts) if len(word_counts) > 1 else 0.0

    if wc_stdev < 5.0 and wc_mean > 20:
        findings.append(
            {
                "finding_id": f"structural_word_count_rigidity_{_sha256('wc')[:8]}",
                "category": "structure",
                "description": "Unnaturally consistent segment word counts",
                "evidence": round(wc_stdev, 2),
                "severity": "medium",
                "confidence": 0.65,
                "segment_indices": (0, len(segments) - 1),
                "details": {"mean": round(wc_mean, 1), "stdev": round(wc_stdev, 2)},
            }
        )

    # Check sentence count consistency
    sentence_counts = [s.sentence_count for s in segments]
    sc_mean = statistics.mean(sentence_counts)
    sc_stdev = statistics.stdev(sentence_counts) if len(sentence_counts) > 1 else 0.0

    if sc_stdev < 1.0 and sc_mean > 2:
        findings.append(
            {
                "finding_id": f"structural_sentence_rigidity_{_sha256('sc')[:8]}",
                "category": "structure",
                "description": "Unnaturally consistent sentence counts per segment",
                "evidence": round(sc_stdev, 2),
                "severity": "medium",
                "confidence": 0.6,
                "segment_indices": (0, len(segments) - 1),
                "details": {"mean": round(sc_mean, 1), "stdev": round(sc_stdev, 2)},
            }
        )

    return findings


def _detect_semantic_overcoherence(segments: list[SemanticSegment]) -> list[dict]:
    """Detect semantic overcoherence - too smooth transitions between topics."""
    if len(segments) < 4:
        return []

    findings = []

    # Check hapax ratio consistency (too consistent = AI)
    hapax_values = [s.hapax_ratio for s in segments]
    hapax_mean = statistics.mean(hapax_values)
    hapax_stdev = statistics.stdev(hapax_values) if len(hapax_values) > 1 else 0.0

    if hapax_stdev < 0.03 and hapax_mean > 0.2:
        findings.append(
            {
                "finding_id": f"semantic_hapax_overcoherence_{_sha256('hapax')[:8]}",
                "category": "semantic",
                "description": "Suspiciously consistent hapax legomena ratio (overcoherent vocabulary)",
                "evidence": round(hapax_stdev, 4),
                "severity": "medium",
                "confidence": 0.65,
                "segment_indices": (0, len(segments) - 1),
                "details": {"mean": round(hapax_mean, 4), "stdev": round(hapax_stdev, 4)},
            }
        )

    # Check semantic density consistency
    density_values = [s.semantic_density for s in segments]
    density_mean = statistics.mean(density_values)
    density_stdev = statistics.stdev(density_values) if len(density_values) > 1 else 0.0

    if density_stdev < 0.1 and density_mean > 1.0:
        findings.append(
            {
                "finding_id": f"semantic_density_overcoherence_{_sha256('density')[:8]}",
                "category": "semantic",
                "description": "Suspiciously consistent semantic density (concepts per sentence)",
                "evidence": round(density_stdev, 4),
                "severity": "medium",
                "confidence": 0.6,
                "segment_indices": (0, len(segments) - 1),
                "details": {"mean": round(density_mean, 4), "stdev": round(density_stdev, 4)},
            }
        )

    return findings


def _detect_lack_of_digression(segments: list[SemanticSegment]) -> list[dict]:
    """Detect lack of natural digressions or topic shifts."""
    if len(segments) < 5:
        return []

    findings = []

    # Check for unnatural consistency in avg word length
    awl_values = [s.avg_word_length for s in segments]
    awl_stdev = statistics.stdev(awl_values) if len(awl_values) > 1 else 0.0

    if awl_stdev < 0.15:
        findings.append(
            {
                "finding_id": f"no_digression_awl_{_sha256('awl')[:8]}",
                "category": "style",
                "description": "Lack of natural digression: suspiciously consistent word lengths",
                "evidence": round(awl_stdev, 4),
                "severity": "low",
                "confidence": 0.55,
                "segment_indices": (0, len(segments) - 1),
                "details": {"awl_stdev": round(awl_stdev, 4)},
            }
        )

    return findings


def _detect_repetitive_structures(segments: list[SemanticSegment]) -> list[dict]:
    """Detect repetitive sentence/paragraph structures."""
    if len(segments) < 3:
        return []

    findings = []

    # Check for repetitive sentence starts (simplified)
    # This is a simplified check - in practice would use NLP
    # For now, check word count patterns that might indicate template use
    word_counts = [s.word_count for s in segments]
    if len(set(word_counts)) == 1 and len(segments) > 2:
        findings.append(
            {
                "finding_id": f"repetitive_word_counts_{_sha256('wc')[:8]}",
                "category": "structure",
                "description": "Identical word counts across multiple segments (template-like)",
                "evidence": 1.0,
                "severity": "high",
                "confidence": 0.85,
                "segment_indices": (0, len(segments) - 1),
                "details": {"word_count": segments[0].word_count, "count": len(segments)},
            }
        )

    return findings


# ============================================================
# Main Checker Class
# ============================================================


class SemanticConsistencyChecker:
    """Analyzes semantic consistency to detect AI-generated text."""

    def __init__(self, segment_word_target: int = 100):
        self.segment_word_target = segment_word_target

    def analyze(
        self, text: str, *, metadata: dict[str, Any] | None = None
    ) -> SemanticConsistencyReport:
        """Analyze text for semantic consistency anomalies."""
        if not text or not text.strip():
            return SemanticConsistencyReport(
                text_sha256=_sha256(""),
                text_length=0,
                n_segments=0,
                limitations=["Empty input text"],
            )

        _sha256(text)
        len(text)

        # Split into segments
        raw_segments = _split_into_segments(text, self.segment_word_target)
        segments = []
        for i, seg_text in enumerate(raw_segments):
            seg = _analyze_segment(seg_text, i)
            seg = SemanticSegment(
                index=i,
                text=seg.text,
                word_count=seg.word_count,
                sentence_count=seg.sentence_count,
                avg_word_length=seg.avg_word_length,
                type_token_ratio=seg.type_token_ratio,
                hapax_ratio=seg.hapax_ratio,
                pos_distribution=seg.pos_distribution,
                semantic_density=seg.semantic_density,
                entropy=seg.entropy,
            )
            segments.append(seg)

        # Run all detectors
        all_findings = []
        all_findings.extend(_detect_excessive_coherence(segments))
        all_findings.extend(_detect_structural_rigidity(segments))
        all_findings.extend(_detect_semantic_overcoherence(segments))
        all_findings.extend(_detect_lack_of_digression(segments))
        all_findings.extend(_detect_repetitive_structures(segments))

        # Compute overall consistency score (0 = human-like, 1 = AI-like)
        consistency_score = self._compute_consistency_score(segments)
        risk_level, confidence = self._assess_risk(all_findings)

        report = SemanticConsistencyReport(
            text_sha256=_sha256(text),
            text_length=len(text),
            n_segments=len(segments),
            findings=[f for f in all_findings],
            overall_consistency_score=consistency_score,
            risk_level=risk_level,
            confidence=confidence,
            segments_analyzed=len(segments),
            limitations=[
                "Semantic consistency is a heuristic, not proof of AI authorship.",
                "Highly edited human text may appear consistent.",
                "Technical/formal writing naturally has higher consistency.",
                "Short texts (< 3 segments) have reduced reliability.",
            ],
            metadata={"segment_word_target": 100},
            report_id=_sha256(str(uuid.uuid4()))[:16],
            created_at=_now_iso(),
        )

        return report

    def _compute_consistency_score(self, segments: list[SemanticSegment]) -> float:
        """Compute overall consistency score (0 = human-like, 1 = AI-like)."""
        if len(segments) < 3:
            return 0.0

        scores = []

        # TTR consistency
        ttr_values = [s.type_token_ratio for s in segments]
        ttr_stdev = statistics.stdev(ttr_values) if len(ttr_values) > 1 else 0.0
        ttr_score = max(0, 1.0 - (ttr_stdev / 0.05))  # Normalize: stdev 0.05 = 0, 0 = 1
        scores.append(max(0.0, min(1.0, ttr_score)))

        # Entropy consistency
        entropy_values = [s.entropy for s in segments]
        entropy_stdev = statistics.stdev(entropy_values) if len(entropy_values) > 1 else 0.0
        entropy_score = max(0.0, 1.0 - (entropy_stdev / 0.3))
        scores.append(max(0.0, min(1.0, entropy_score)))

        # Hapax consistency
        hapax_values = [s.hapax_ratio for s in segments]
        hapax_stdev = statistics.stdev(hapax_values) if len(hapax_values) > 1 else 0.0
        hapax_score = max(0.0, 1.0 - (hapax_stdev / 0.05))
        scores.append(max(0.0, min(1.0, hapax_score)))

        # Structural rigidity
        word_counts = [s.word_count for s in segments]
        wc_stdev = statistics.stdev(word_counts) if len(word_counts) > 1 else 0.0
        wc_score = max(0.0, 1.0 - (wc_stdev / 10.0))
        scores.append(max(0.0, min(1.0, wc_score)))

        # Hapax consistency
        hapax_values = [s.hapax_ratio for s in segments]
        hapax_stdev = statistics.stdev(hapax_values) if len(hapax_values) > 1 else 0.0
        hapax_score = max(0.0, 1.0 - (hapax_stdev / 0.05))
        scores.append(max(0.0, min(1.0, hapax_score)))

        return statistics.mean(scores) if scores else 0.0

    def _assess_risk(
        self,
        findings: list[dict],
    ) -> tuple[str, float]:
        """Assess overall risk from findings."""
        if not findings:
            return "none", 1.0

        total_weight = sum(
            {"critical": 1.5, "high": 1.0, "medium": 0.6, "low": 0.3}.get(
                f.get("severity", "low"), 0.3
            )
            * f.get("confidence", 0.5)
            for f in findings
        )
        max_possible = len(findings) * 1.5

        risk_score = total_weight / max_possible if max_possible > 0 else 0.0

        if risk_score >= 0.7:
            return "critical", 0.9
        elif risk_score >= 0.5:
            return "high", 0.8
        elif risk_score >= 0.3:
            return "medium", 0.7
        elif risk_score >= 0.15:
            return "low", 0.6
        else:
            return "low", 0.5


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _uuid() -> str:
    return str(uuid.uuid4())


def analyze_semantic_consistency(
    text: str,
    *,
    segment_word_target: int = 100,
    metadata: dict[str, Any] | None = None,
) -> SemanticConsistencyReport:
    """Convenience function for one-shot semantic consistency analysis."""
    checker = SemanticConsistencyChecker(segment_word_target=segment_word_target)
    return checker.analyze(text, metadata=metadata)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _uuid() -> str:
    return str(uuid.uuid4())
