"""Tests for explainable detection (counterfactual feature attribution)."""

from __future__ import annotations

import json

import pytest

from textforensics.explain import (
    CounterfactualExplainer,
    ExplanationReport,
    SegmentAttribution,
    explain_verdict,
    load_explanation_report,
    save_explanation_report,
    split_sentences,
)

EXPLANATION_LIMITATIONS = [
    "Counterfactual attribution measures score sensitivity, not causal proof of authorship.",
]


class TestSplitSentences:
    def test_basic_split(self):
        text = "First sentence. Second sentence. Third sentence."
        result = split_sentences(text)
        assert len(result) == 3
        assert result[0] == "First sentence."
        assert result[1] == "Second sentence."

    def test_question_and_exclamation(self):
        text = "Is this real? Yes it is! Unbelievable."
        result = split_sentences(text)
        # "Unbelievable." (1 word) merges with previous segment
        assert len(result) == 2
        assert result[0] == "Is this real?"
        assert "Unbelievable." in result[1]

    def test_empty_text(self):
        assert split_sentences("") == []
        assert split_sentences("   ") == []

    def test_single_sentence(self):
        result = split_sentences("Only one sentence here.")
        assert len(result) == 1

    def test_short_fragments_merged(self):
        # "e.g." is only 1 word -> merged with previous
        text = "This is a long sentence. e.g. something else. Another sentence."
        result = split_sentences(text, min_words=2)
        # "e.g." (1 word) merges into the previous segment; the rest stand alone
        assert all(s.strip() for s in result)
        assert len(result) == 3
        assert "e.g." in result[0]
        assert result[1] == "something else."

    def test_no_terminal_punctuation(self):
        text = "One sentence without punctuation and another"
        result = split_sentences(text)
        assert len(result) == 1

    def test_whitespace_normalised(self):
        text = "Sentence one.   Sentence two.  \n Sentence three."
        result = split_sentences(text)
        assert len(result) == 3
        assert all("  " not in s for s in result)


class TestCounterfactualExplainer:
    def test_basic_attribution(self):
        """Removing the AI-driving sentence should lower the score."""
        calls: list[str] = []

        def score_fn(text: str) -> float | None:
            calls.append(text)
            # Simulated detector: higher when formulaic phrases present
            if "furthermore" in text.lower() or "in conclusion" in text.lower():
                return 0.9
            return 0.2

        explainer = CounterfactualExplainer(score_fn, detector_id="test", detector_version="1.0")
        text = "The weather was nice. Furthermore, the results were conclusive. I enjoyed it."
        report = explainer.explain(text)

        assert report.detector_id == "test"
        assert report.original_score == 0.9
        assert report.n_segments == 3
        assert report.n_scored == 3
        assert len(report.segment_attribution) == 3

        # Removing the "Furthermore" sentence should drop score to 0.2 -> delta = -0.7
        furthermore_attr = next(
            a for a in report.segment_attribution if "Furthermore" in a.segment_text
        )
        assert furthermore_attr.delta < 0
        assert furthermore_attr.direction == "pushes_ai"

    def test_human_driving_segment(self):
        """Removing a humanising sentence should raise the score."""

        def score_fn(text: str) -> float | None:
            if "honestly" in text.lower():
                return 0.1
            return 0.8

        explainer = CounterfactualExplainer(score_fn, detector_id="test", detector_version="1.0")
        text = "Data shows trends. Honestly, I was surprised. More data follows."
        report = explainer.explain(text)

        assert report.original_score == 0.1
        honest_attr = next(
            a for a in report.segment_attribution if "Honestly" in a.segment_text
        )
        # Removing "honestly" -> score rises to 0.8 -> delta = +0.7
        assert honest_attr.delta > 0
        assert honest_attr.direction == "pushes_human"
        assert len(report.top_human_driving) >= 1

    def test_abstain_on_perturbation_skipped(self):
        """If detector abstains on perturbed text, that segment is skipped."""

        def score_fn(text: str) -> float | None:
            if len(text.split()) < 5:
                return None  # Abstain on short text
            return 0.5

        explainer = CounterfactualExplainer(score_fn, detector_id="test", detector_version="1.0")
        text = "This is a reasonably long sentence here. Short one. Another longer sentence follows."
        report = explainer.explain(text)

        # "Short one." removal leaves 8 words -> scored. But segments where the
        # removal leaves < 5 words should be skipped.
        assert report.n_scored >= 1
        for attr in report.segment_attribution:
            assert attr.perturbed_score is not None

    def test_original_abstain_returns_empty(self):
        """If detector abstains on the full text, no attribution is possible."""

        def score_fn(text: str) -> float | None:
            return None

        explainer = CounterfactualExplainer(score_fn)
        report = explainer.explain("Some text here.")

        assert report.original_score is None
        assert report.n_scored == 0
        assert report.segment_attribution == []

    def test_single_segment_no_attribution(self):
        """A single-segment text cannot be explained by removal."""

        def score_fn(text: str) -> float | None:
            return 0.5

        explainer = CounterfactualExplainer(score_fn)
        report = explainer.explain("Only one sentence.")

        assert report.n_segments == 1
        assert report.segment_attribution == []

    def test_top_k_limiting(self):
        """top_k limits the number of reported driving segments."""

        def score_fn(text: str) -> float | None:
            # Each "KEY{i}" sentence contributes
            n_keys = sum(1 for i in range(10) if f"KEY{i}" in text)
            return 0.1 * n_keys

        explainer = CounterfactualExplainer(score_fn, top_k=2)
        text = " ".join(f"KEY{i} sentence number {i} with padding words." for i in range(10))
        report = explainer.explain(text)

        assert len(report.top_ai_driving) <= 2
        assert len(report.top_human_driving) <= 2

    def test_deterministic_explanation_id(self):
        """Same input and score_fn must produce the same explanation_id."""

        def score_fn(text: str) -> float | None:
            return 0.5 if len(text) % 2 == 0 else 0.7

        explainer = CounterfactualExplainer(score_fn, detector_id="d", detector_version="1")
        text = "Alpha sentence one. Beta sentence two. Gamma sentence three."

        r1 = explainer.explain(text)
        r2 = explainer.explain(text)
        assert r1.explanation_id == r2.explanation_id
        assert len(r1.explanation_id) == 16

    def test_text_hash_recorded(self):
        """Report must record the text hash, not raw text at top level."""

        def score_fn(text: str) -> float | None:
            return 0.5

        explainer = CounterfactualExplainer(score_fn)
        text = "Sentence one here. Sentence two here."
        report = explainer.explain(text)
        d = report.to_dict()

        assert len(d["text_sha256"]) == 64
        # Raw full text must NOT appear in the serialized dict
        assert text not in json.dumps(d)

    def test_progress_callback(self):
        """Progress callback receives monotonically increasing counts."""
        events: list[tuple[int, int]] = []

        def score_fn(text: str) -> float | None:
            return 0.5

        explainer = CounterfactualExplainer(score_fn)
        text = "First segment here. Second segment here. Third segment here. Fourth segment here."
        explainer.explain(text, progress=lambda c, t: events.append((c, t)))

        assert len(events) == 4
        assert events[0] == (1, 4)
        assert events[-1] == (4, 4)

    def test_explain_ranked(self):
        """explain_ranked returns segments sorted by |delta| descending."""

        def score_fn(text: str) -> float | None:
            if "IMPORTANT" in text:
                return 0.95
            return 0.3

        explainer = CounterfactualExplainer(score_fn)
        text = "Filler one here. IMPORTANT finding stated here. Filler two here."
        ranked = explainer.explain_ranked(text)

        assert len(ranked) >= 2
        assert ranked[0].abs_delta >= ranked[-1].abs_delta

    def test_invalid_score_fn_raises(self):
        with pytest.raises(ValueError):
            CounterfactualExplainer("not callable")

    def test_limitations_present(self):
        """Report must carry limitations (AGENTS.md: keep limitations visible)."""

        def score_fn(text: str) -> float | None:
            return 0.5

        explainer = CounterfactualExplainer(score_fn)
        report = explainer.explain("First sentence. Second sentence.")
        assert len(report.limitations) > 0
        assert any("not causal proof" in lim for lim in report.limitations)


class TestExplainVerdict:
    def test_one_shot(self):
        """explain_verdict produces a complete report with verdict recorded."""

        def score_fn(text: str) -> float | None:
            if "algorithm" in text.lower():
                return 0.9
            return 0.2

        text = "Personal note here. The algorithm converged quickly. Final thought."
        report = explain_verdict(
            text, score_fn, detector_id="det", detector_version="2.0", verdict="ai_like"
        )

        assert report.verdict == "ai_like"
        assert report.detector_id == "det"
        assert report.detector_version == "2.0"
        assert len(report.segment_attribution) == 3
        assert report.summary()["verdict"] == "ai_like"

    def test_summary_structure(self):
        def score_fn(text: str) -> float | None:
            return 0.5

        report = explain_verdict("One. Two.", score_fn)
        summary = report.summary()
        assert "detector_id" in summary
        assert "n_segments" in summary
        assert "most_ai_driving_segment" in summary or summary["top_ai_driving_count"] == 0


class TestSegmentAttribution:
    def test_to_dict_roundtrip(self):
        attr = SegmentAttribution(
            segment_index=0,
            segment_text="Test segment.",
            original_score=0.5,
            perturbed_score=0.7,
            delta=0.2,
            abs_delta=0.2,
            direction="pushes_human",
        )
        d = attr.to_dict()
        assert d["segment_index"] == 0
        assert d["direction"] == "pushes_human"
        assert d["delta"] == pytest.approx(0.2)


class TestExplanationReport:
    def test_report_serialization(self):
        """Report serialization must be JSON-safe and include limitations."""
        report = ExplanationReport(
            detector_id="d",
            detector_version="1.0",
            text_sha256="a" * 64,
            original_score=0.5,
            verdict="ai_like",
            n_segments=2,
            n_scored=2,
            limitations=EXPLANATION_LIMITATIONS,
        )
        d = report.to_dict()
        # Must be JSON-serializable
        json.dumps(d)
        assert "limitations" in d
        assert len(d["limitations"]) > 0

    def test_save_load_roundtrip(self, tmp_path):
        def score_fn(text: str) -> float | None:
            if "KEY" in text:
                return 0.9
            return 0.2

        text = "Normal sentence here. KEY finding present. Another normal one."
        report = explain_verdict(text, score_fn, detector_id="d", detector_version="1.0")

        path = tmp_path / "explanation.json"
        save_explanation_report(report, str(path))
        loaded = load_explanation_report(str(path))

        assert loaded.detector_id == report.detector_id
        assert loaded.text_sha256 == report.text_sha256
        assert loaded.explanation_id == report.explanation_id
        assert len(loaded.segment_attribution) == len(report.segment_attribution)
        assert loaded.limitations == report.limitations


class TestExplainabilityInvariants:
    def test_no_raw_text_in_report_dict(self):
        """The full raw text must never appear at the top level of the report."""
        secret_text = "SENSITIVE-CONTENT-XYZ should not leak into the report top level. Second sentence."

        def score_fn(text: str) -> float | None:
            return 0.5

        report = explain_verdict(secret_text, score_fn)
        d = report.to_dict()
        # text_sha256 is present; the *full* raw text must not be a top-level key
        assert "text" not in d
        assert "raw_text" not in d
        # But individual segment texts ARE present (user's own input, needed for review)
        segment_texts = [s["segment_text"] for s in d["segment_attribution"]]
        assert any("SENSITIVE-CONTENT-XYZ" in st for st in segment_texts)

    def test_attribution_sums_sensible(self):
        """Attribution deltas should be bounded within [-1, 1] for [0,1] scores."""

        def score_fn(text: str) -> float | None:
            return min(1.0, max(0.0, len(text) / 100))

        explainer = CounterfactualExplainer(score_fn)
        text = "A" * 50 + ". " + "B" * 30 + ". " + "C" * 20 + "."
        report = explainer.explain(text)

        for attr in report.segment_attribution:
            assert -1.0 <= attr.delta <= 1.0
            assert attr.abs_delta <= 1.0

    def test_attribution_direction_consistent(self):
        """Direction must be consistent with delta sign."""

        def score_fn(text: str) -> float | None:
            return 0.5

        explainer = CounterfactualExplainer(score_fn)
        report = explainer.explain("First. Second. Third.")
        for attr in report.segment_attribution:
            if attr.delta < 0:
                assert attr.direction == "pushes_ai"
            elif attr.delta > 0:
                assert attr.direction == "pushes_human"
            else:
                assert attr.direction == "neutral"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
