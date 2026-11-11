"""Mixed-origin / co-authorship report (U4).

A mixed-origin report answers a narrower question than the document
verdict: *which parts of this text carry AI-consistent evidence, which
carry human-consistent evidence, and what, if anything, can be said
about how the two were combined?*

Design constraints (Phase 3 research §8.6, AGENTS.md rules 18/19/22/24):

* Segment methods are WEAK. A segment score is an *evidence score*,
  never a sentence authorship probability (rule 18), and a segment
  under ~20 words never carries a verdict (rule 19).
* No raw text appears anywhere in the report (rule 22): segments are
  identified by ``sha256:<hex>`` of the segment text plus char offsets.
* Text-only detection cannot prove authorship (rule 24): the report
  carries that limitation in plain language, and the idea-provenance
  note states that prose evidence cannot determine who originated the
  ideas.
* The binary verdict is WITHHELD whenever the evidence is mixed or
  the input regime has no mixed-origin validation slice (§8.6 (b)).
  A withheld verdict still reports all segment evidence — the report
  *is* the output.
* The ``mixed`` verdict value exists in the schema but is NEVER
  emitted by the v1.0 builder: any document with verdicted segments
  on both sides is ``withheld`` by condition (i) below, and a
  positive "mixed" claim would need the 8-condition bar of §8.6 (d),
  which no v1.0 cell meets. The value is reserved for a future
  calibration that defines the bar for a positive mixed claim.
* The ``condense`` operation and the ``AH`` HART type are likewise
  in the schema but never emitted by the v1.0 builder: compression
  cannot be inferred from segments without a source to compare
  against, and AI-content/human-expression cannot be separated from
  prose evidence alone.

Segment method (v1.0, declared not fitted): sentences, scored with
the builtin heuristic detector (``engine.analyze_text``,
``include_robustness=False``) at the document operating point
(0.68 / 0.32). ``methods_agreeing`` lists the builtin analyzer
families (``structural_uniformity``, ``formulaic_language``,
``lexical_profile``) whose individual scores fall on the same side
as the segment label. Degree-of-change tiers use Pangram's
0.25 / 0.5 / 0.75 boundaries ONLY as a reference scale — the
``estimate`` is ``null`` and ``calibration`` is ``"unknown"`` until
TextForensics validates its own thresholds.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from .detectors import BuiltinHeuristicDetector
from .engine import analyze_text
from .features import SENTENCE_RE, WORD_RE

REPORT_SCHEMA = "textforensics.mixed-origin-report/v1"

#: Segments shorter than this never carry a verdict (rule 19).
MIN_WORDS_FOR_VERDICT = 20

#: Declared segment operating point: the document thresholds 0.68 /
#: 0.32, reused — not fitted on the validation sample.
AI_THRESHOLD = 0.68
HUMAN_THRESHOLD = 0.32

#: Degree-of-change tier boundaries (Pangram reference scale only).
TIER_LIGHTLY = 0.25
TIER_MODERATELY = 0.5
TIER_AI = 0.75

#: The declared validation bar for segment coverage (audit W2,
#: CORE-01/CORE-11). A segment record lifts withholding only when it
#: meets ALL of these: exact detector id and version; effective status
#: ``"supported"`` (fresh, undemoted, complete — computed, never trusted
#: from the stored status); held-out ``split_role`` ``"test"``;
#: ``contamination_flag`` ``"no"``; the CORE-01 sample floor (100 human
#: + 100 AI samples); a verifying record signature; a segment-level
#: editing regime; and a known segment slice id. Partial, below-chance,
#: expired, demoted, contaminated, thin, wrong-detector or tampered
#: segment evidence stays available in the report — it never lifts
#: withholding and never authorizes a categorical verdict. Record
#: existence is not coverage.
SEGMENT_VALIDATION_BAR: tuple[str, ...] = (
    "exact detector id and version",
    "effective status 'supported' (fresh, undemoted, complete)",
    "held-out split_role 'test'",
    "contamination_flag 'no'",
    "sample floor 100 human + 100 AI",
    "verifying record signature",
    "segment-level editing regime",
    "known segment slice id",
)

NON_MONOTONICITY_WARNING = (
    "Intermediate mixtures are the hardest regime to detect "
    "(OpAI-Bench 2026); a low AI score here does not mean human."
)
IDEA_PROVENANCE_NOTE = "Prose evidence cannot determine who originated the ideas (IdeaLens 2026)."
SCORE_MEANING = "segment evidence score, NOT a sentence authorship probability"

#: Expression-only operations: the wording changed, the content did not.
EXPRESSION_ONLY_OPERATIONS = ("polish", "rewrite")
#: Content-changing operations: the content itself was added or reworked.
CONTENT_CHANGING_OPERATIONS = ("expand", "rewrite", "condense")

_SEGMENT_REFERENCE_RE = re.compile(r"^(full_text|sha256:[0-9a-f]{64})$")


#: Segment slice IDs the CLI treats as mixed-origin validation
#: coverage. A new segment-level U1 record must register its slice
#: ID here (see scripts/seed_validation.py) before the CLI will
#: treat its (language, domain) pairs as covered. The ID follows the
#: seed convention ``<key>-builtin-heuristic`` with the loader key
#: ``opai_bench_segments`` — underscores and all.
SEGMENT_SLICE_IDS: tuple[str, ...] = ("opai_bench_segments-builtin-heuristic",)

#: Editing regimes that mark a validation record as segment-level
#: mixed-origin evidence (as opposed to a document-level record).
SEGMENT_EDITING_REGIMES: tuple[str, ...] = ("LLM-edited", "mixed-origin")


def segment_covered_regimes(
    registry: Any,
    *,
    slice_ids: tuple[str, ...] | None = None,
    detector_version: str | None = None,
    detector_id: str | None = None,
    now: datetime | str | None = None,
    word_count: int | None = None,
) -> set[tuple[str, str]]:
    """(language, domain) pairs a segment-level validation record covers.

    A record counts ONLY when it clears the declared validation bar
    (:data:`SEGMENT_VALIDATION_BAR`): the exact builtin detector id and
    version, effective status ``"supported"`` (fresh, undemoted,
    complete — computed with the CURRENT version and ``now``, never
    trusted from the stored status), held-out ``split_role`` ``"test"``,
    ``contamination_flag`` ``"no"``, at least 100 human and 100 AI
    samples, a verifying record signature, a segment-level editing
    regime (``LLM-edited`` / ``mixed-origin``), and one of its metric
    slice IDs is a known segment slice. ``registry`` is a
    ``ValidationRegistry`` (or any object with a ``.records`` attribute
    of record-like objects exposing ``to_dict()`` or a mapping — a
    record without a verifiable signature cannot establish coverage).
    When ``word_count`` is supplied, the record's length bucket must
    also admit it. Date staleness, demotion, contamination, thin
    samples, a wrong detector, a non-held-out split and a tampered
    signature each independently block coverage; partial or
    below-chance experimental segment evidence stays available in the
    report but never lifts withholding.
    """
    from .validation import (
        MIN_AI_SAMPLES,
        MIN_HUMAN_SAMPLES,
        effective_status,
        verify_signature,
    )

    version = detector_version or BuiltinHeuristicDetector.detector_version
    expected_id = detector_id or BuiltinHeuristicDetector.detector_id
    ids = slice_ids if slice_ids is not None else SEGMENT_SLICE_IDS
    covered: set[tuple[str, str]] = set()
    for record in getattr(registry, "records", ()):
        if hasattr(record, "to_dict"):
            payload = record.to_dict()
        elif isinstance(record, Mapping):
            payload = record
        else:
            # No verifiable signed payload: record existence is not
            # coverage.
            continue
        if not isinstance(payload, Mapping):
            continue
        if payload.get("detector_id") != expected_id:
            continue
        if payload.get("detector_version") != version:
            continue
        if effective_status(payload, detector_version=version, now=now) != "supported":
            continue
        data = payload.get("data")
        if not isinstance(data, Mapping):
            continue
        if data.get("split_role") != "test":
            continue
        if data.get("contamination_flag") != "no":
            continue
        n_human = data.get("n_human")
        n_ai = data.get("n_ai")
        if (
            isinstance(n_human, bool)
            or not isinstance(n_human, int)
            or n_human < MIN_HUMAN_SAMPLES
            or isinstance(n_ai, bool)
            or not isinstance(n_ai, int)
            or n_ai < MIN_AI_SAMPLES
        ):
            continue
        if not verify_signature(payload):
            continue
        regime = payload.get("regime")
        if not isinstance(regime, Mapping):
            continue
        if regime.get("editing_regime") not in SEGMENT_EDITING_REGIMES:
            continue
        metrics = payload.get("metrics", [])
        if not any(isinstance(item, Mapping) and item.get("slice_id") in ids for item in metrics):
            continue
        if word_count is not None:
            bucket = regime.get("length_bucket")
            if not isinstance(bucket, Mapping):
                continue
            floor = bucket.get("floor_words")
            maximum = bucket.get("max_words")
            if (
                isinstance(floor, bool)
                or not isinstance(floor, int)
                or word_count < floor
                or (
                    maximum is not None
                    and (isinstance(maximum, bool) or not isinstance(maximum, int))
                )
                or (isinstance(maximum, int) and word_count > maximum)
            ):
                continue
        language = regime.get("language")
        for domain in regime.get("domain") or []:
            if language is not None and domain:
                covered.add((language, domain))
    return covered


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def split_sentences_with_offsets(text: str) -> list[tuple[str, int, int]]:
    """Split ``text`` into sentences with char offsets.

    Uses the shared ``SENTENCE_RE`` splitter (same as ``features`` /
    ``localize``). Offsets are found sequentially so repeated identical
    sentences resolve to their own occurrence, in order.
    """
    clean = text.strip()
    parts = [s.strip() for s in SENTENCE_RE.split(clean) if s.strip()]
    if not parts and clean:
        parts = [clean]
    sentences: list[tuple[str, int, int]] = []
    cursor = 0
    for part in parts:
        start = text.find(part, cursor)
        if start < 0:  # pragma: no cover - defensive; split output comes from text
            start = cursor
        end = start + len(part)
        sentences.append((part, start, end))
        cursor = end
    return sentences


def _segment_evidence(score: float, n_words: int) -> str:
    """Evidence label for one segment at the declared operating point."""
    if n_words < MIN_WORDS_FOR_VERDICT:
        return "insufficient"
    if score >= AI_THRESHOLD:
        return "ai-consistent"
    if score <= HUMAN_THRESHOLD:
        return "human-consistent"
    return "insufficient"


def segment_verdict(score: float, n_words: int) -> str:
    """Native-style verdict for one segment (``ai_like``/``human_like``/``abstain``).

    This mirrors :func:`_segment_evidence` — the segment-level
    operating point the report builder uses. It deliberately does
    NOT call ``BuiltinHeuristicDetector.detect()`` on the segment:
    the engine's verdict first applies a diagnostic-reliability gate
    (``length_reliability = word_count / 250``), which abstains on
    ALL short text by construction, so the detector's document
    verdict would zero out every segment-level native metric. The
    segment verdict is defined by the declared operating point
    instead; the U1 segment record states this explicitly.
    """
    return {
        "ai-consistent": "ai_like",
        "human-consistent": "human_like",
        "insufficient": "abstain",
    }[_segment_evidence(score, n_words)]


def _methods_agreeing(result: Any, evidence: str) -> list[str]:
    """Builtin analyzer families agreeing with the segment direction."""
    if evidence == "ai-consistent":
        return [a.name for a in result.analyzers if a.score >= AI_THRESHOLD]
    if evidence == "human-consistent":
        return [a.name for a in result.analyzers if a.score <= HUMAN_THRESHOLD]
    return []


def _score_segment(sentence: str) -> dict[str, Any]:
    """Score one sentence segment; never raises on short text."""
    result = analyze_text(sentence, include_robustness=False)
    n_words = len(WORD_RE.findall(sentence))
    evidence = _segment_evidence(result.score, n_words)
    return {
        "text": sentence,
        "score": result.score,
        "evidence": evidence,
        "methods_agreeing": _methods_agreeing(result, evidence),
        "diagnostic_reliability": result.diagnostic_reliability,
        "n_words": n_words,
    }


def _alternations(verdicts: list[str]) -> int:
    """Human/AI transitions between consecutive verdicted segments."""
    count = 0
    previous: str | None = None
    for verdict in verdicts:
        if verdict in ("ai-consistent", "human-consistent"):
            if previous is not None and verdict != previous:
                count += 1
            previous = verdict
    return count


def _longest_ai_run(verdicts: list[str]) -> int:
    """Longest run of consecutive AI-consistent segments."""
    longest = current = 0
    for verdict in verdicts:
        if verdict == "ai-consistent":
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest


def _hypothesise_operation(
    segments: list[dict[str, Any]],
    *,
    adversarial_findings: list[Any] | None,
) -> dict[str, Any]:
    """Derive the operation hypothesis from segment pattern + findings.

    Evidence families: (F1) the segment pattern — AI word share,
    alternation count, AI run structure; (F3) adversarial
    humanisation artifacts. (F2, document-level analyzer
    disagreement/stability, is reported in the limitations, not used
    to name an operation.) Confidence is LOW by default; MEDIUM when
    one family shows a strong, specific pattern; HIGH is unreachable
    in v1.0 — it requires two independent families agreeing on the
    same operation, and no second family independently identifies an
    operation in v1.0.
    """
    verdicts = [s["evidence"] for s in segments]
    ai_segments = [s for s in segments if s["evidence"] == "ai-consistent"]
    human_segments = [s for s in segments if s["evidence"] == "human-consistent"]
    ai_words = sum(s["n_words"] for s in ai_segments)
    human_words = sum(s["n_words"] for s in human_segments)
    verdicted_words = ai_words + human_words
    ai_share = ai_words / verdicted_words if verdicted_words else None
    alternation_count = _alternations(verdicts)

    # F3: humanisation artifacts — deliberate typos, forced
    # contractions and friends are the humaniser's fingerprints.
    high_severity_patterns: list[str] = []
    if adversarial_findings:
        high_severity_patterns = sorted(
            {f.pattern_id for f in adversarial_findings if getattr(f, "severity", None) == "high"}
        )
    if high_severity_patterns:
        evidence = [
            "adversarial humanisation artifacts: " + ", ".join(high_severity_patterns),
        ]
        confidence = "low"
        if ai_segments:
            evidence.append(f"{len(ai_segments)} AI-consistent segment(s) corroborate an AI origin")
            confidence = "medium"
        return {
            "operation": "humanise",
            "direction": "ai→human",
            "confidence": confidence,
            "evidence": evidence,
        }

    if not ai_segments:
        return {
            "operation": "unknown",
            "direction": "unknown",
            "confidence": "low",
            "evidence": ["no AI-consistent segment observed"],
        }

    direction = "human→ai" if human_segments else "unknown"
    if ai_share is not None and ai_share < TIER_LIGHTLY:
        return {
            "operation": "polish",
            "direction": direction,
            "confidence": "low",
            "evidence": [
                f"AI-consistent word share {ai_share:.2f} (below {TIER_LIGHTLY})",
                f"{len(ai_segments)} AI-consistent segment(s) among "
                f"{len(human_segments)} human-consistent segment(s)",
            ],
        }
    if alternation_count >= 3:
        return {
            "operation": "rewrite",
            "direction": direction,
            "confidence": "medium",
            "evidence": [
                f"{alternation_count} human/AI alternations across verdicted segments",
                f"AI-consistent word share {ai_share:.2f}"
                if ai_share is not None
                else "AI-consistent word share unknown",
            ],
        }
    if ai_share is not None and ai_share >= TIER_AI:
        if _longest_ai_run(verdicts) >= 3:
            operation = "expand"
            reason = (
                f"AI-consistent run of {_longest_ai_run(verdicts)} segments (share {ai_share:.2f})"
            )
        else:
            operation = "rewrite"
            reason = f"AI-consistent word share {ai_share:.2f} in scattered segments"
        return {
            "operation": operation,
            "direction": direction,
            "confidence": "low",
            "evidence": [reason],
        }
    return {
        "operation": "rewrite",
        "direction": direction,
        "confidence": "low",
        "evidence": [
            f"AI-consistent word share {ai_share:.2f}"
            if ai_share is not None
            else "AI-consistent word share unknown",
            f"{alternation_count} human/AI alternation(s) across verdicted segments",
        ],
    }


def _degree_of_change(ai_words: int, human_words: int) -> tuple[str | None, str]:
    """Degree-of-change tier from the AI-consistent word share.

    Returns (tier, method). The tier boundaries are Pangram's
    0.25 / 0.5 / 0.75 as a REFERENCE SCALE ONLY — no estimate is
    fitted in v1.0, so the numeric estimate is always null and the
    calibration is always "unknown".
    """
    verdicted_words = ai_words + human_words
    if verdicted_words == 0:
        return None, (
            "no segment carries a verdict, so no AI-consistent word share can be computed"
        )
    share = ai_words / verdicted_words
    if share <= TIER_LIGHTLY:
        tier = "human"
    elif share <= TIER_MODERATELY:
        tier = "lightly"
    elif share <= TIER_AI:
        tier = "moderately"
    else:
        tier = "ai"
    return tier, (
        f"AI-consistent word share {share:.2f} ({ai_words} of {verdicted_words} "
        f"verdicted words); tiers use Pangram's 0.25/0.5/0.75 boundaries as a "
        "reference scale only, not a TextForensics calibration"
    )


def _hart_type(segments: list[dict[str, Any]], operation: dict[str, Any]) -> tuple[str, str]:
    """HART collaboration type (Bao et al. 2025, arXiv:2503.00258).

    HH = human content + human expression; AA = AI content + AI
    expression; HA = human content + AI expression; AH = AI content +
    human expression. The v1.0 rule: single-origin evidence gives HH
    or AA; mixed evidence with an expression-only operation and a
    human word-share majority gives HA at LOW confidence; mixed
    evidence with a content-changing operation gives "unknown"
    (content and expression cannot be separated from prose evidence
    alone); AH is never emitted in v1.0 for the mirror reason.
    """
    ai_segments = [s for s in segments if s["evidence"] == "ai-consistent"]
    human_segments = [s for s in segments if s["evidence"] == "human-consistent"]
    if ai_segments and not human_segments:
        return "AA", "low"
    if human_segments and not ai_segments:
        return "HH", "low"
    if not ai_segments and not human_segments:
        return "unknown", "low"
    ai_words = sum(s["n_words"] for s in ai_segments)
    human_words = sum(s["n_words"] for s in human_segments)
    if operation["operation"] in EXPRESSION_ONLY_OPERATIONS and human_words > ai_words:
        return "HA", "low"
    return "unknown", "low"


def _decide_verdict(
    segments: list[dict[str, Any]],
    operation: dict[str, Any],
    tier: str | None,
    *,
    regime_covered: bool,
) -> tuple[str, list[str]]:
    """Apply the four §8.6 (b) withholding conditions (+ two safety rules).

    (i) segments disagree — at least one verdicted AI-consistent and
    one verdicted human-consistent segment; (ii) the operation
    hypothesis is polish/expand/condense on human-origin text
    (human-consistent segments exist); (iii) the degree-of-change
    tier is intermediate (lightly / moderately); (iv) no
    mixed-origin validation slice covers the input regime. Two
    additional safety rules, not in §8.6 but required by the same
    logic: no segment carries a verdict at all, and the operation
    direction contradicts the segment evidence (humanised AI text
    scores human on every segment — that is what humanisation does).
    A withheld verdict still reports all segment evidence.
    """
    reasons: list[str] = []
    ai_segments = [s for s in segments if s["evidence"] == "ai-consistent"]
    human_segments = [s for s in segments if s["evidence"] == "human-consistent"]
    if ai_segments and human_segments:
        reasons.append(
            "segments_disagree: at least one AI-consistent and one "
            "human-consistent segment with non-trivial length"
        )
    if operation["operation"] in ("polish", "expand", "condense") and human_segments:
        reasons.append(
            f"operation_{operation['operation']}_on_human_origin: the operation "
            "hypothesis is polish/expand/condense on human-origin text "
            "(ARB H2L regime)"
        )
    if tier in ("lightly", "moderately"):
        reasons.append(
            f"intermediate_degree_of_change: tier {tier!r} is inside the "
            "0.25-0.75 intermediate band"
        )
    if not regime_covered:
        reasons.append(
            "no_validation_slice: no mixed-origin validation slice covers the input regime"
        )
    if not ai_segments and not human_segments:
        reasons.append("insufficient_segment_evidence: no segment carries a verdict")
    if operation["direction"] == "ai→human" and human_segments and not ai_segments:
        reasons.append(
            "operation_direction_conflicts_with_segments: humanisation "
            "artifacts suggest an AI origin while every verdicted segment "
            "scores human-consistent"
        )
    if reasons:
        return "withheld", reasons
    if ai_segments:
        return "ai", []
    return "human", []


def build_mixed_origin_report(
    text: str,
    *,
    language: str | None = None,
    domain: str | None = None,
    covered_regimes: Any | None = None,
    adversarial_findings: list[Any] | None = None,
    document_analysis: Any | None = None,
) -> dict[str, Any]:
    """Build a mixed-origin report for ``text``.

    Args:
        text: The input text. Never stored — only its SHA-256 hash
            and per-segment hashes/offsets appear in the report.
        language: Input language code (e.g. ``"en"``) or ``None`` when
            undetermined. ``None`` means no validation slice can be
            shown to cover the regime (condition (iv)).
        domain: Input domain/genre (e.g. ``"news"``) or ``None``.
        covered_regimes: Iterable of ``(language, domain)`` pairs a
            mixed-origin validation slice covers, or ``None`` when no
            coverage information is available (condition (iv) fires).
        adversarial_findings: Findings from
            ``AdversarialDetector().analyze(text)`` (family F3), or
            ``None`` to skip that evidence family.
        document_analysis: ``engine.analyze_text(text)`` result
            (family F2: disagreement / stability), or ``None``.

    Returns:
        A dict conforming to ``textforensics.mixed-origin-report/v1``.
    """
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Text must not be empty.")
    scored = [
        {**_score_segment(sentence), "span": (start, end)}
        for sentence, start, end in split_sentences_with_offsets(text)
    ]
    segments = [
        {
            "span": [s["span"][0], s["span"][1]],
            "text_hash": f"sha256:{_sha256(s['text'])}",
            "evidence": s["evidence"],
            "score": round(s["score"], 4),
            "score_meaning": SCORE_MEANING,
            "methods_agreeing": s["methods_agreeing"],
            "n_words": s["n_words"],
        }
        for s in scored
    ]
    ai_words = sum(s["n_words"] for s in scored if s["evidence"] == "ai-consistent")
    human_words = sum(s["n_words"] for s in scored if s["evidence"] == "human-consistent")
    tier, tier_method = _degree_of_change(ai_words, human_words)
    operation = _hypothesise_operation(scored, adversarial_findings=adversarial_findings)
    collaboration_type, collaboration_confidence = _hart_type(scored, operation)
    regime_covered = bool(
        covered_regimes is not None
        and language is not None
        and domain is not None
        and (language, domain) in set(covered_regimes)
    )
    verdict, withheld_reasons = _decide_verdict(
        scored, operation, tier, regime_covered=regime_covered
    )

    limitations = [
        "Text-only detection cannot prove authorship.",
        "Segment scores are evidence scores, not sentence authorship probabilities.",
        f"Segments under {MIN_WORDS_FOR_VERDICT} words carry no verdict.",
        "Degree-of-change tiers use Pangram's 0.25/0.5/0.75 boundaries as a "
        "reference scale only; TextForensics has not validated its own thresholds.",
        "The operation hypothesis is an inference from segment patterns, "
        "not a measurement; confidence is low unless stated otherwise.",
    ]
    if operation["confidence"] == "low":
        limitations.append(
            "The operation hypothesis is low-confidence: segment methods are "
            "weak and no per-operation calibration set exists in v1.0."
        )
    if not regime_covered:
        limitations.append(
            "No mixed-origin validation slice covers this input regime "
            f"(language={language!r}, domain={domain!r}); the verdict is "
            "withheld for that reason alone."
        )
    if document_analysis is not None:
        limitations.append(
            "Document-level analyzer disagreement "
            f"{document_analysis.disagreement:.2f} and benign-transformation "
            f"stability {document_analysis.robustness_stability:.2f} are "
            "reported alongside, not fused into, the segment evidence."
        )

    return {
        "schema": REPORT_SCHEMA,
        "input": {
            "content_hash": f"sha256:{_sha256(text)}",
            "char_count": len(text),
            "word_count": len(WORD_RE.findall(text)),
            "segment_count": len(segments),
        },
        "detector": {
            "id": BuiltinHeuristicDetector.detector_id,
            "version": BuiltinHeuristicDetector.detector_version,
        },
        "verdict": verdict,
        "withheld_reasons": withheld_reasons,
        "collaboration_type": collaboration_type,
        "collaboration_confidence": collaboration_confidence,
        "degree_of_change": {
            "estimate": None,
            "tiers": tier,
            "method": tier_method,
            "calibration": "unknown",
        },
        "operation_hypothesis": operation,
        "segments": segments,
        "non_monotonicity_warning": NON_MONOTONICITY_WARNING,
        "idea_provenance_note": IDEA_PROVENANCE_NOTE,
        "regime": {
            "language": language,
            "domain": domain,
            "validation_slice_covered": regime_covered,
        },
        "limitations": limitations,
    }
