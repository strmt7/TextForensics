from __future__ import annotations

import difflib
import html
import math
import statistics
from dataclasses import asdict, dataclass
from typing import Any

from .engine import analyze_text
from .features import SENTENCE_RE, WORD_RE, extract_features


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


# ---------------------------------------------------------------------------
# Visual diff
# ---------------------------------------------------------------------------

def visual_diff(
    text1: str,
    text2: str,
    *,
    style: str = "side_by_side",
) -> str:
    """Generate a diff between two texts in the requested style.

    Supported styles:
    - **side_by_side**: two-column comparison with ``+``/``-``/``~`` markers.
    - **unified**: standard unified diff format.
    - **inline**: HTML with ``<ins>``/``<del>`` tags for changed spans.
    """
    if style not in ("side_by_side", "unified", "inline"):
        raise ValueError(
            f"Unknown diff style {style!r}. "
            "Expected one of: side_by_side, unified, inline."
        )

    lines1 = text1.splitlines(keepends=False)
    lines2 = text2.splitlines(keepends=False)

    if style == "unified":
        return _diff_unified(lines1, lines2)
    if style == "inline":
        return _diff_inline(text1, text2)
    return _diff_side_by_side(lines1, lines2)


def _diff_unified(lines1: list[str], lines2: list[str]) -> str:
    """Return a unified diff string."""
    diff = difflib.unified_diff(
        lines1, lines2, fromfile="text1", tofile="text2", lineterm=""
    )
    return "\n".join(diff)


def _diff_side_by_side(lines1: list[str], lines2: list[str]) -> str:
    """Return a side-by-side diff string with alignment markers."""
    matcher = difflib.SequenceMatcher(None, lines1, lines2, autojunk=False)
    blocks = matcher.get_opcodes()

    rows: list[str] = []
    header = f"{'Line':>6}  {'Original':<40}  |  {'Modified':<40}"
    rows.append(header)
    rows.append("-" * len(header))

    for tag, i1, i2, j1, j2 in blocks:
        left_lines = lines1[i1:i2]
        right_lines = lines2[j1:j2]

        if tag == "equal":
            for k, (l_line, r_line) in enumerate(
                zip(left_lines, right_lines, strict=False)
            ):
                left_display = _truncate(l_line, 40)
                right_display = _truncate(r_line, 40)
                rows.append(
                    f"{i1 + k + 1:>6}  {left_display:<40}  |  {right_display:<40}"
                )
        else:
            # Align changed/inserted/deleted lines
            for k, l_line in enumerate(left_lines):
                left_display = _truncate(l_line, 40)
                right_idx = j1 + k if j1 + k < j2 else None
                if right_idx is not None:
                    right_display = _truncate(lines2[right_idx], 40)
                    rows.append(
                        f"{i1 + k + 1:>6}  -{left_display:<39}  |  +{right_display:<39}"
                    )
                else:
                    rows.append(
                        f"{i1 + k + 1:>6}  -{left_display:<39}  |  "
                    )
            for k in range(len(left_lines), len(right_lines)):
                rows.append(
                    f"{'':>6}  {'':<40}  |  +{_truncate(right_lines[k], 40):<39}"
                )

    return "\n".join(rows)


def _diff_inline(text1: str, text2: str) -> str:
    """Return HTML with <del> and <ins> tags around changed spans."""
    matcher = difflib.SequenceMatcher(None, text1, text2, autojunk=False)
    parts: list[str] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            parts.append(html.escape(text1[i1:i2]))
        elif tag == "replace":
            parts.append(
                f"<del>{html.escape(text1[i1:i2])}</del>"
                f"<ins>{html.escape(text2[j1:j2])}</ins>"
            )
        elif tag == "delete":
            parts.append(f"<del>{html.escape(text1[i1:i2])}</del>")
        elif tag == "insert":
            parts.append(f"<ins>{html.escape(text2[j1:j2])}</ins>")
    return "".join(parts)


def _truncate(s: str, maxlen: int) -> str:
    if len(s) <= maxlen:
        return s
    return s[: maxlen - 1] + "…"


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------

def detect_anomalous_segments(
    text: str,
    *,
    threshold: float = 2.0,
) -> list[dict[str, Any]]:
    """Find text segments whose feature z-scores exceed *threshold*.

    Features analysed:
    - **word_entropy**: Shannon entropy of word types per segment.
    - **burstiness**: coefficient of variation of sentence length within each
      segment (computed over sub-sentences).
    - **type_token_ratio**: vocabulary richness per segment.

    Returns a list of dicts describing anomalous segments.
    """
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Text must not be empty.")
    if threshold < 0:
        raise ValueError("threshold must be non-negative.")

    sentences = [
        s.strip() for s in SENTENCE_RE.split(text.strip()) if s.strip()
    ]
    if not sentences:
        return []

    # Use a minimum of 2 sentences per segment so we can compute intra-segment
    # burstiness; but never fewer than 1.
    n = max(1, len(sentences) // 4)
    if n < 2:
        n = max(1, len(sentences))

    segment_features: list[dict[str, float]] = []
    segment_texts: list[str] = []

    for start in range(0, max(1, len(sentences)), n):
        chunk_sents = sentences[start : start + n]
        chunk = " ".join(chunk_sents)
        feats = extract_features(chunk)
        segment_features.append(feats)
        segment_texts.append(chunk)

    num_segments = len(segment_features)
    if num_segments < 1:
        return []

    anomalous: list[dict[str, Any]] = []
    feature_names = ["word_entropy", "burstiness", "type_token_ratio"]

    # Build per-feature z-scores
    feature_values: dict[str, list[float]] = {fn: [] for fn in feature_names}
    for feats in segment_features:
        ent = feats.get("word_entropy", 0.0)
        burst = feats.get("sentence_length_cv", 0.0)
        ttr = feats.get("type_token_ratio", 0.0)
        feature_values["word_entropy"].append(ent)
        feature_values["burstiness"].append(burst)
        feature_values["type_token_ratio"].append(ttr)

    means: dict[str, float] = {}
    stds: dict[str, float] = {}
    for fn in feature_names:
        vals = feature_values[fn]
        means[fn] = statistics.mean(vals)
        stds[fn] = statistics.pstdev(vals) if len(vals) >= 2 else 0.0

    for idx, feats in enumerate(segment_features):
        ent = feature_values["word_entropy"][idx]
        burst = feature_values["burstiness"][idx]
        ttr = feature_values["type_token_ratio"][idx]

        z_scores: dict[str, float] = {}
        for fn in feature_names:
            sd = stds[fn]
            z_scores[fn] = (
                0.0 if sd == 0 else abs(feature_values[fn][idx] - means[fn]) / sd
            )

        max_z = max(z_scores.values())
        flag = max_z >= threshold

        anomalous.append({
            "segment_index": idx,
            "text": segment_texts[idx],
            "word_count": feats.get("word_count", 0),
            "features": {
                "word_entropy": round(ent, 4),
                "burstiness": round(burst, 4),
                "type_token_ratio": round(ttr, 4),
            },
            "z_scores": {fn: round(z, 4) for fn, z in z_scores.items()},
            "max_z_score": round(max_z, 4),
            "is_anomalous": flag,
        })

    # Return only flagged segments
    return [seg for seg in anomalous if seg["is_anomalous"]]


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def segment_to_dict(segment: SegmentResult) -> dict[str, Any]:
    """Serialize a ``SegmentResult`` to a JSON-serialisable dict."""
    return segment.to_dict()
