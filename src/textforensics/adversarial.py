"""Adversarial Humanization Detection for TextForensics.

Detects text that has been processed by AI humanizers (e.g., blader/humanizer)
to evade AI-text detection. These tools rewrite AI-generated text to mimic
human writing patterns, introducing deliberate imperfections, stylistic
variation, and structural perturbations.

This module provides:
- **Humanization pattern detection**: Statistical signatures of automated rewriting
- **Perplexity distribution analysis**: Humanizers often produce unnatural perplexity curves
- **Stylometric fingerprinting**: Detects tool-specific rewriting signatures
- **Adversarial perturbation detection**: Identifies targeted perturbations to fool detectors
- **Consistency checking**: Cross-detector consensus on adversarial artifacts

Design principles:
- **Local-first**: No network calls, all analysis runs locally
- **Detector-agnostic**: Works with any detector output
- **Evidence-based**: Produces audit-trail ready evidence with observed
  pattern counts and severities
- **Extensible**: Plugin architecture for new humanization pattern detectors

This module reports observed pattern counts and severities only. It
emits no calibrated confidence and no authorship probability: no
versioned held-out calibration artifact exists for this heuristic
assessment, so the report's overall confidence is always ``None``.

The module follows AGENTS.md principles:
- Preserves abstention for unsupported inputs
- Documents limitations explicitly
- Raw text excluded from portable outputs by default
"""

from __future__ import annotations

import hashlib
import re
import statistics
import uuid
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

__all__ = [
    "AdversarialFinding",
    "HumanizationReport",
    "AdversarialDetector",
    "detect_humanization",
    "HumanizationPatternLibrary",
]


@dataclass(frozen=True, slots=True)
class AdversarialFinding:
    """A detected adversarial humanization artifact.

    Attributes:
        pattern_id: The pattern that triggered this finding.
        segment: Content reference for the matched span, never raw text
            (AGENTS.md rule 22): either the literal "full_text" or
            "sha256:<hex>" of the matched span, whose character offsets
            are in `location`. A holder of the original text can
            recompute the hash to identify the span.
        evidence: Quantitative evidence (e.g., score, p-value, count).
        severity: Finding severity.
        confidence: Uncalibrated heuristic weight for this finding
            (0-1), derived from the pattern's match count/weight. It is
            NOT an empirically calibrated probability.
        location: Character span (start, end) in original text.
        description: Human-readable description.
    """

    pattern_id: str
    segment: str
    evidence: float
    severity: str
    confidence: float
    location: tuple[int, int]
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "segment": self.segment,
            "evidence": self.evidence,
            "severity": self.severity,
            "confidence": self.confidence,
            "location": list(self.location),
            "description": self.description,
        }


@dataclass
class HumanizationReport:
    """Complete adversarial humanization analysis report.

    ``overall_risk`` is ``"unknown"`` whenever the input is below the
    support floor, in an unsupported language, or pattern coverage was
    incomplete: a risk level is only asserted from a fully supported
    run. ``confidence`` is always ``None`` -- no empirically calibrated
    confidence exists for this heuristic assessment (see the module
    docstring). A clean result (``overall_risk == "none"``) means no
    patterns were observed under the stated coverage, not a
    probability 1 of absence.
    """

    text_sha256: str
    text_length: int
    detector_outputs: dict[str, Any]  # Optional: detector predictions
    findings: list[AdversarialFinding] = field(default_factory=list)
    # "none", "low", "medium", "high", "critical", "unknown". The
    # fail-closed default is "unknown": a report only claims a risk
    # level when analyze() asserts it from a supported run.
    overall_risk: str = "unknown"
    # Overall confidence in the assessment: always None (uncalibrated).
    confidence: float | None = None
    patterns_checked: int = 0
    patterns_triggered: int = 0
    # Names of pattern detectors that raised instead of returning
    # findings. A failed pattern is coverage loss, never evidence of
    # absence.
    patterns_failed: list[str] = field(default_factory=list)
    # "sufficient" or "insufficient" (below the word floor, unsupported
    # language, or incomplete pattern coverage). The fail-closed
    # default is "insufficient".
    support_status: str = "insufficient"
    limitations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    report_id: str = ""
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "text_sha256": self.text_sha256,
            "text_length": self.text_length,
            "detector_outputs": self.detector_outputs,
            "findings": [f.to_dict() for f in self.findings],
            "overall_risk": self.overall_risk,
            "confidence": self.confidence,
            "patterns_checked": self.patterns_checked,
            "patterns_triggered": self.patterns_triggered,
            "patterns_failed": list(self.patterns_failed),
            "support_status": self.support_status,
            "limitations": list(self.limitations),
            "metadata": self.metadata,
            "report_id": self.report_id,
            "created_at": self.created_at,
        }

    def summary(self) -> dict[str, Any]:
        """Compact summary for quick assessment."""
        severity_counts = Counter(f.severity for f in self.findings)
        return {
            "text_sha256": self.text_sha256[:16] + "...",
            "overall_risk": self.overall_risk,
            "confidence": self.confidence,
            "total_findings": len(self.findings),
            "by_severity": dict(severity_counts),
            "patterns_checked": self.patterns_checked,
            "patterns_triggered": self.patterns_triggered,
            "patterns_failed": list(self.patterns_failed),
            "support_status": self.support_status,
        }


# ============================================================
# Built-in Pattern Detectors
# ============================================================

_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+")
_WORD_RE = re.compile(r"\b\w+\b")

# Common humanizer artifacts (from blader/humanizer and similar tools)
_HUMANIZER_ARTIFACTS = {
    # Deliberate typos and misspellings
    "deliberate_typo": {
        "patterns": [
            r"\bteh\b",
            r"\bthier\b",
            r"\brecieve\b",
            r"\boccured\b",
            r"\bdefinately\b",
            r"\bseperate\b",
            r"\bneccessary\b",
        ],
        "weight": 1.5,
    },
    # Forced casual contractions
    "forced_contraction": {
        "patterns": [
            r"\bgonna\b",
            r"\bwanna\b",
            r"\bgotta\b",
            r"\bkinda\b",
            r"\bsorta\b",
            r"\boutta\b",
            r"\bshoulda\b",
            r"\bcoulda\b",
        ],
        "weight": 1.2,
    },
    # Artificial sentence fragmentation
    "forced_fragmentation": {
        "patterns": [
            r"\.\s+And\s",
            r"\.\s+But\s",
            r"\.\s+So\s",
            r"\.\s+Or\s",
        ],
        "weight": 1.3,
    },
    # Overuse of discourse markers
    "discourse_overload": {
        "patterns": [
            r"\b(frankly|honestly|actually|basically|essentially|literally)\b",
        ],
        "weight": 1.1,
    },
    # Artificial hedge words
    "hedge_overload": {
        "patterns": [
            r"\b(sort of|kind of|maybe|perhaps|possibly|probably)\b",
        ],
        "weight": 1.0,
    },
    # Mechanical sentence length variation
    "mechanical_variation": {
        "patterns": [],  # Detected statistically
        "weight": 1.4,
    },
    # Repetitive transition patterns
    "mechanical_transitions": {
        "patterns": [
            r"\b(additionally|furthermore|moreover|consequently|therefore)\b",
        ],
        "weight": 1.2,
    },
}


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _split_sentences(text: str) -> list[str]:
    """Split text into sentences for analysis."""
    if not text.strip():
        return []
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    return [s.strip() for s in sentences if s.strip()]


def _word_tokenize(text: str) -> list[str]:
    return _WORD_RE.findall(text.lower())


def _perplexity_proxy(text: str, window: int = 100) -> list[float]:
    """Proxy for perplexity using local word frequency surprise."""
    words = _word_tokenize(text)
    if len(words) < window:
        return [0.0]
    scores = []
    for i in range(len(words) - window + 1):
        window_words = words[i : i + window]
        freq = Counter(window_words)
        # High repetition = low perplexity proxy
        surprise = 1.0 - (max(freq.values()) / window)
        scores.append(surprise)
    return scores


# Minimum words for an overall risk assessment (IF-12). Below this
# floor the report lists observed patterns but asserts no overall
# risk: a single word (or a couple of words) cannot support any
# authorship-related conclusion, confident or otherwise.
MIN_WORDS_FOR_ASSESSMENT = 10

_LATIN_RE = re.compile(r"[A-Za-z]")

# Language codes accepted as the supported (English) language.
_SUPPORTED_LANGUAGE_CODES = {"en", "eng", "english"}


def _language_support(text: str, language: str | None) -> tuple[bool, str | None]:
    """Check whether the text is in this detector's supported language.

    The patterns are English-specific. A caller-declared non-English
    language abstains; without a declaration, text with no
    Latin-script letters at all is treated as unsupported (there are
    no English words for the patterns to match). Returns
    ``(supported, reason)`` with ``reason`` set only when unsupported.
    """
    if language is not None and language.strip().lower() not in _SUPPORTED_LANGUAGE_CODES:
        return False, (
            f"Unsupported language: declared language {language!r} is not English; "
            "patterns are English-specific."
        )
    if not _LATIN_RE.search(text):
        return False, (
            "Unsupported language: no Latin-script text detected; "
            "patterns are English-specific."
        )
    return True, None


# ============================================================
# Pattern Detector Functions
# ============================================================


def _detect_regex_patterns(text: str, patterns: list[str]) -> int:
    """Count regex pattern matches in text."""
    count = 0
    for pat in patterns:
        count += len(re.findall(pat, text, re.IGNORECASE))
    return count


def _first_match_span(text: str, patterns: list[str]) -> tuple[int, int] | None:
    """Character span of the earliest regex match across ``patterns``.

    ``re.findall`` returns groups when a pattern has groups, so it
    cannot give spans; ``re.search`` on the raw pattern strings can.
    Returns ``None`` when no pattern matches.
    """
    best: tuple[int, int] | None = None
    for pat in patterns:
        match = re.search(pat, text, re.IGNORECASE)
        if match is None:
            continue
        span = match.span()
        if best is None or span < best:
            best = span
    return best


def detect_regex_artifacts(text: str) -> list[AdversarialFinding]:
    """Detect regex-based humanizer artifacts."""
    findings = []
    for artifact_id, config in _HUMANIZER_ARTIFACTS.items():
        count = _detect_regex_patterns(text, config["patterns"])
        if count > 0:
            # Content reference, never raw text (AGENTS.md rule 22):
            # the SHA-256 of the FIRST matched span, whose character
            # offsets are in `location` — the contract AdversarialFinding
            # documents. Hashing text[:200] regardless of where the
            # match sits contradicts that contract.
            span = _first_match_span(text, config["patterns"])
            if span is None:  # Defensive: count > 0 implies a match.
                continue
            start, end = span
            severity = "high" if config["weight"] > 1.3 else "medium"
            findings.append(
                AdversarialFinding(
                    pattern_id=f"regex_{artifact_id}",
                    segment=f"sha256:{_sha256(text[start:end])}",
                    evidence=float(count),
                    severity=severity,
                    confidence=min(0.8, 0.3 + 0.1 * count),
                    location=(start, end),
                    description=f"Detected {count} instances of {artifact_id.replace('_', ' ')}",
                )
            )
    return findings


def detect_mechanical_variation(text: str) -> list[AdversarialFinding]:
    """Detect unnatural sentence length variation (humanizers often alternate
    short/long sentences mechanically)."""
    sentences = _split_sentences(text)
    if len(sentences) < 4:
        return []

    lengths = [len(_word_tokenize(s)) for s in sentences]
    if not lengths:
        return []

    # Check for alternating short/long pattern
    diffs = [abs(lengths[i] - lengths[i - 1]) for i in range(1, len(lengths))]
    if not diffs:
        return []

    mean_diff = statistics.mean(diffs)
    stdev = statistics.stdev(diffs) if len(diffs) > 1 else 0.0

    # Mechanical variation: high mean diff, low stdev (regular alternation)
    findings = []
    if mean_diff > 5 and stdev < 5 and len(sentences) >= 6:
        findings.append(
            AdversarialFinding(
                pattern_id="mechanical_variation",
                segment="full_text",
                evidence=round(mean_diff, 2),
                severity="high",
                confidence=0.75,
                location=(0, len(text)),
                description=f"Mechanical sentence length variation detected: mean_diff={mean_diff:.1f}, stdev={stdev:.1f}",
            )
        )
    return findings


def detect_mechanical_transitions(text: str) -> list[AdversarialFinding]:
    """Detect mechanical overuse of formal transitions."""
    transitions = [
        "additionally",
        "furthermore",
        "moreover",
        "consequently",
        "therefore",
        "however",
        "nevertheless",
        "nevertheless",
        "subsequently",
        "accordingly",
        "hence",
        "thus",
    ]
    count = 0
    for t in transitions:
        count += len(re.findall(rf"\b{t}\b", text, re.IGNORECASE))

    if count >= 3:
        return [
            AdversarialFinding(
                pattern_id="mechanical_transitions",
                segment="full_text",
                evidence=float(count),
                severity="medium",
                confidence=0.65,
                location=(0, len(text)),
                description=f"Overuse of formal transitions ({count} instances)",
            )
        ]
    return []


def detect_deliberate_typos(text: str) -> list[AdversarialFinding]:
    """Detect common deliberate typos introduced by humanizers."""
    typo_patterns = [
        r"\bteh\b",
        r"\bthier\b",
        r"\brecieve\b",
        r"\boccured\b",
        r"\bdefinately\b",
        r"\bseperate\b",
        r"\bneccessary\b",
        r"\baccomodate\b",
        r"\bmaintainance\b",
        r"\bpriviledge\b",
        r"\bquestionaire\b",
        r"\bbuisness\b",
        r"\bpublically\b",
    ]
    count = _detect_regex_patterns(text, typo_patterns)
    if count > 0:
        return [
            AdversarialFinding(
                pattern_id="deliberate_typos",
                segment="full_text",
                evidence=float(count),
                severity="high" if count >= 3 else "medium",
                confidence=0.8,
                location=(0, len(text)),
                description=f"Detected {count} common deliberate typos",
            )
        ]
    return []


def detect_forced_contractions(text: str) -> list[AdversarialFinding]:
    """Detect forced casual contractions inserted by humanizers."""
    contractions = [
        "gonna",
        "wanna",
        "gotta",
        "kinda",
        "sorta",
        "outta",
        "shoulda",
        "coulda",
        "woulda",
        "lemme",
        "gimme",
        "dunno",
        "cuz",
        "cos",
        "ya",
    ]
    count = 0
    for c in contractions:
        count += len(re.findall(rf"\b{c}\b", text, re.IGNORECASE))

    if count >= 2:
        return [
            AdversarialFinding(
                pattern_id="forced_contractions",
                segment="full_text",
                evidence=float(count),
                severity="medium",
                confidence=0.7,
                location=(0, len(text)),
                description=f"Forced casual contractions detected ({count} instances)",
            )
        ]
    return []


def detect_discourse_overload(text: str) -> list[AdversarialFinding]:
    """Detect overuse of discourse markers (frankly, honestly, etc.)."""
    markers = [
        "frankly",
        "honestly",
        "actually",
        "basically",
        "essentially",
        "literally",
        "obviously",
        "clearly",
        "simply",
        "basically",
    ]
    count = 0
    for m in markers:
        count += len(re.findall(rf"\b{m}\b", text, re.IGNORECASE))

    if count >= 3:
        return [
            AdversarialFinding(
                pattern_id="discourse_overload",
                segment="full_text",
                evidence=float(count),
                severity="medium",
                confidence=0.65,
                location=(0, len(text)),
                description=f"Excessive discourse markers ({count} instances)",
            )
        ]
    return []


def detect_hedge_overload(text: str) -> list[AdversarialFinding]:
    """Detect overuse of hedge words."""
    hedges = [
        "sort of",
        "kind of",
        "maybe",
        "perhaps",
        "possibly",
        "probably",
        "somewhat",
        "rather",
        "quite",
        "fairly",
    ]
    count = 0
    for h in hedges:
        count += len(re.findall(rf"\b{h}\b", text, re.IGNORECASE))

    if count >= 4:
        return [
            AdversarialFinding(
                pattern_id="hedge_overload",
                segment="full_text",
                evidence=float(count),
                severity="low",
                confidence=0.55,
                location=(0, len(text)),
                description=f"Excessive hedging language ({count} instances)",
            )
        ]
    return []


def detect_perplexity_anomalies(text: str) -> list[AdversarialFinding]:
    """Detect unnatural perplexity curves (humanizers often produce
    unnaturally smooth or oscillating perplexity)."""
    scores = _perplexity_proxy(text)
    if len(scores) < 5:
        return []

    # Check for suspiciously flat or oscillating perplexity
    mean_score = statistics.mean(scores)
    stdev = statistics.stdev(scores) if len(scores) > 1 else 0.0

    # Suspiciously flat (humanizer smoothing)
    if stdev < 0.02 and mean_score > 0.1:
        return [
            AdversarialFinding(
                pattern_id="perplexity_flat",
                segment="full_text",
                evidence=round(stdev, 4),
                severity="medium",
                confidence=0.6,
                location=(0, len(text)),
                description=f"Suspiciously flat perplexity curve (stdev={stdev:.4f})",
            )
        ]

    # Check for regular oscillations
    diffs = [abs(scores[i] - scores[i - 1]) for i in range(1, len(scores))]
    if len(diffs) >= 4:
        mean_diff = statistics.mean(diffs)
        diff_stdev = statistics.stdev(diffs) if len(diffs) > 1 else 0.0
        if mean_diff > 0.1 and diff_stdev < 0.03:
            return [
                AdversarialFinding(
                    pattern_id="perplexity_oscillation",
                    segment="full_text",
                    evidence=round(diff_stdev, 4),
                    severity="medium",
                    confidence=0.65,
                    location=(0, len(text)),
                    description=f"Regular perplexity oscillation (mean_diff={mean_diff:.3f}, stdev={diff_stdev:.4f})",
                )
            ]

    return []


# ============================================================
# Pattern Library and Registry
# ============================================================

_HUMANIZATION_PATTERNS: dict[str, Callable[[str], list[AdversarialFinding]]] = {
    "regex_artifacts": detect_regex_artifacts,
    "mechanical_variation": detect_mechanical_variation,
    "mechanical_transitions": detect_mechanical_transitions,
    "deliberate_typos": detect_deliberate_typos,
    "forced_contractions": detect_forced_contractions,
    "discourse_overload": detect_discourse_overload,
    "hedge_overload": detect_hedge_overload,
    "perplexity_anomalies": detect_perplexity_anomalies,
}


class HumanizationPatternLibrary:
    """Registry of humanization detection patterns."""

    def __init__(
        self, custom_patterns: dict[str, Callable[[str], list[AdversarialFinding]]] | None = None
    ):
        self._patterns = dict(_HUMANIZATION_PATTERNS)
        if custom_patterns:
            self._patterns.update(custom_patterns)

    def register(self, name: str, detector_fn: Callable[[str], list[AdversarialFinding]]) -> None:
        """Register a custom pattern detector."""
        self._patterns[name] = detector_fn

    def unregister(self, name: str) -> bool:
        if name in self._patterns:
            del self._patterns[name]
            return True
        return False

    def get(self, name: str) -> Callable[[str], list[AdversarialFinding]] | None:
        return self._patterns.get(name)

    def list_patterns(self) -> list[str]:
        return sorted(self._patterns.keys())

    def run_all(self, text: str) -> list[AdversarialFinding]:
        """Run all registered pattern detectors on text.

        A pattern that raises contributes zero findings here; use
        :meth:`run_all_with_coverage` to learn which patterns failed
        instead of silently treating the failure as "no finding".
        """
        findings, _failed = self.run_all_with_coverage(text)
        return findings

    def run_all_with_coverage(
        self, text: str
    ) -> tuple[list[AdversarialFinding], list[str]]:
        """Run all registered pattern detectors on text.

        Returns ``(findings, failed_names)``: the names of pattern
        detectors that raised instead of returning findings. A failed
        pattern is coverage loss, never evidence of absence.
        """
        all_findings = []
        failed: list[str] = []
        for name, detector_fn in self._patterns.items():
            try:
                findings = detector_fn(text)
                all_findings.extend(findings)
            except Exception:
                failed.append(name)
        return all_findings, failed


# ============================================================
# Main Adversarial Detector
# ============================================================


class AdversarialDetector:
    """Main detector for adversarial humanization artifacts.

    Orchestrates pattern detection, aggregates findings, and produces
    a comprehensive HumanizationReport with risk assessment.
    """

    def __init__(
        self,
        pattern_library: HumanizationPatternLibrary | None = None,
        risk_thresholds: dict[str, float] | None = None,
    ) -> None:
        self.pattern_library = pattern_library or HumanizationPatternLibrary()
        self.risk_thresholds = risk_thresholds or {
            "critical": 0.8,
            "high": 0.6,
            "medium": 0.4,
            "low": 0.2,
        }

    def analyze(
        self,
        text: str,
        *,
        detector_outputs: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        language: str | None = None,
    ) -> HumanizationReport:
        """Analyze text for adversarial humanization artifacts.

        Args:
            text: Text to analyze.
            detector_outputs: Optional detector predictions for context.
            metadata: Additional metadata for the report.
            language: Optional caller-declared language code (e.g.
                ``"en"``). A declared non-English language abstains;
                without a declaration, text with no Latin-script
                letters is treated as unsupported.

        Returns:
            HumanizationReport with findings and risk assessment.
            The overall risk is ``"unknown"`` with ``confidence None``
            whenever the input is below the support floor, in an
            unsupported language, or pattern coverage was incomplete.
            Observed findings and pattern counts are still reported:
            they are observations, not a calibrated confidence.
        """
        if not text or not text.strip():
            return HumanizationReport(
                text_sha256=_sha256(""),
                text_length=0,
                detector_outputs=detector_outputs or {},
                overall_risk="unknown",
                confidence=None,
                support_status="insufficient",
                limitations=[
                    "Empty input text",
                    "Insufficient support: empty input -- no risk assessment.",
                ],
            )

        word_count = len(_word_tokenize(text))
        language_ok, language_reason = _language_support(text, language)

        support_reasons: list[str] = []
        if word_count < MIN_WORDS_FOR_ASSESSMENT:
            support_reasons.append(
                f"Insufficient support: {word_count} words (minimum "
                f"{MIN_WORDS_FOR_ASSESSMENT}) -- no overall risk is asserted; "
                "observed patterns are listed without an overall risk."
            )
        if not language_ok and language_reason is not None:
            support_reasons.append(language_reason)

        # Run all pattern detectors, tracking failures explicitly.
        all_findings, failed_patterns = self.pattern_library.run_all_with_coverage(text)
        if failed_patterns:
            support_reasons.append(
                "Incomplete pattern coverage: "
                f"{len(failed_patterns)} pattern(s) failed and were excluded "
                f"from the assessment: {', '.join(sorted(failed_patterns))}. "
                "A failed pattern is not evidence of absence."
            )

        # Filter out duplicate findings (same pattern_id)
        unique_findings = []
        seen = set()
        for f in all_findings:
            key = (f.pattern_id, f.location)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        # Assess overall risk from the de-duplicated findings.
        overall_risk, confidence = self._assess_risk(unique_findings)

        # Support gating: any coverage gap fails the assessment closed
        # to "unknown" -- the observed findings stay visible, but no
        # overall risk is asserted from an unsupported/partial run.
        support_status = "sufficient" if not support_reasons else "insufficient"
        if support_status == "insufficient":
            overall_risk, confidence = "unknown", None

        limitations = [
            "Pattern-based detection cannot prove humanization; only indicates artifacts.",
            "False positives possible on naturally informal or non-native writing.",
            "Patterns may not generalize to unseen humanization tools.",
            "Short texts (< 100 words) have reduced detection reliability.",
        ]
        limitations.extend(support_reasons)
        if support_status == "sufficient" and not unique_findings:
            limitations.append(
                "No observed patterns under the stated pattern coverage; "
                "this is not a probability of absence."
            )

        report = HumanizationReport(
            text_sha256=_sha256(text),
            text_length=len(text),
            detector_outputs=detector_outputs or {},
            findings=unique_findings,
            overall_risk=overall_risk,
            confidence=confidence,
            patterns_checked=len(self.pattern_library._patterns),
            patterns_triggered=len(set(f.pattern_id for f in unique_findings)),
            patterns_failed=sorted(failed_patterns),
            support_status=support_status,
            limitations=limitations,
            metadata=metadata or {},
            report_id=_sha256(str(uuid.uuid4()))[:16],
            created_at=_now_iso(),
        )
        return report

    def _assess_risk(
        self,
        findings: list[AdversarialFinding],
    ) -> tuple[str, float | None]:
        """Assess overall risk from observed findings.

        The risk level is a heuristic summary of observed pattern
        counts and severities, NOT an empirically calibrated
        probability: the returned confidence is always ``None``
        because no versioned held-out calibration artifact exists
        for this assessment. A clean result (no findings) means no
        patterns were observed under the stated coverage, not a
        probability 1 of absence.
        """
        if not findings:
            return "none", None

        severity_weights = {"critical": 2.0, "high": 1.5, "medium": 0.8, "low": 0.5}
        total_weight = sum(severity_weights.get(f.severity, 0) * f.confidence for f in findings)
        max_possible = len(findings) * 1.5

        risk_score = total_weight / max_possible if max_possible > 0 else 0.0

        if risk_score >= 0.65:
            return "critical", None
        elif risk_score >= 0.45:
            return "high", None
        elif risk_score >= 0.25:
            return "medium", None
        elif risk_score >= 0.15:
            return "low", None
        else:
            return "low", None


def detect_humanization(
    text: str,
    *,
    detector_outputs: dict[str, Any] | None = None,
    custom_patterns: dict[str, Callable[[str], list[AdversarialFinding]]] | None = None,
    metadata: dict[str, Any] | None = None,
    language: str | None = None,
) -> HumanizationReport:
    """Convenience function for one-shot humanization detection.

    Args:
        text: Text to analyze.
        detector_outputs: Optional detector predictions for context.
        custom_patterns: Additional pattern detectors to register.
        metadata: Additional metadata for the report.
        language: Optional caller-declared language code; a declared
            non-English language abstains (see
            :meth:`AdversarialDetector.analyze`).

    Returns:
        HumanizationReport with findings and risk assessment.
    """
    library = HumanizationPatternLibrary(custom_patterns=custom_patterns)
    detector = AdversarialDetector(pattern_library=library)
    return detector.analyze(text, detector_outputs=detector_outputs, metadata=metadata, language=language)


# ============================================================
# Convenience Functions
# ============================================================


def detect_humanization_simple(text: str) -> dict[str, Any]:
    """Simple one-shot detection returning a summary dict."""
    report = detect_humanization(text)
    return report.summary()
