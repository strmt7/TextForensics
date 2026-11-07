"""Tests for the U4 mixed-origin / co-authorship report."""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path
from types import SimpleNamespace

import jsonschema

from textforensics.mixed_origin import (
    NON_MONOTONICITY_WARNING,
    SCORE_MEANING,
    _decide_verdict,
    _degree_of_change,
    _hart_type,
    _segment_evidence,
    build_mixed_origin_report,
)
from textforensics.models import AnalyzerResult

SCHEMA = json.loads(
    (
        Path(__file__).parent.parent
        / "src"
        / "textforensics"
        / "schemas"
        / "mixed-origin-report.schema.json"
    ).read_text(encoding="utf-8")
)

CANARY = "CANARY-5e8b2-ORCHID-TUNGSTEN-7731"


def _sentence(marker: str, n_words: int = 25) -> str:
    """A filler sentence of exactly ``n_words`` words, ending in ``marker``.

    Starts with a capital so the shared ``SENTENCE_RE`` splitter (which
    only splits before an uppercase/digit/quote) sees the boundary.
    """
    return " ".join(["Filler"] + ["filler"] * (n_words - 2) + [marker]) + "."


def _fake_analyzer(name: str, score: float) -> AnalyzerResult:
    return AnalyzerResult(name=name, score=score, reliability=0.9)


def _fake_result(score: float, analyzer_scores: tuple[float, float, float]):
    names = ("structural_uniformity", "formulaic_language", "lexical_profile")
    return SimpleNamespace(
        score=score,
        analyzers=[_fake_analyzer(n, s) for n, s in zip(names, analyzer_scores, strict=True)],
        diagnostic_reliability=0.9,
    )


def _all_string_leaves(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        leaves = []
        for key, item in value.items():
            leaves.append(str(key))
            leaves.extend(_all_string_leaves(item))
        return leaves
    if isinstance(value, (list, tuple)):
        leaves = []
        for item in value:
            leaves.extend(_all_string_leaves(item))
        return leaves
    return []


class MixedOriginLogicTest(unittest.TestCase):
    """Deterministic logic tests with a mocked segment scorer."""

    def test_short_segments_always_insufficient(self):
        self.assertEqual(_segment_evidence(0.95, 5), "insufficient")
        self.assertEqual(_segment_evidence(0.05, 19), "insufficient")
        self.assertEqual(_segment_evidence(0.95, 20), "ai-consistent")
        self.assertEqual(_segment_evidence(0.05, 20), "human-consistent")
        self.assertEqual(_segment_evidence(0.5, 30), "insufficient")

    def test_degree_tier_boundaries(self):
        self.assertEqual(_degree_of_change(25, 75)[0], "human")  # share 0.25
        self.assertEqual(_degree_of_change(26, 74)[0], "lightly")
        self.assertEqual(_degree_of_change(50, 50)[0], "lightly")  # share 0.50
        self.assertEqual(_degree_of_change(51, 49)[0], "moderately")
        self.assertEqual(_degree_of_change(75, 25)[0], "moderately")  # share 0.75
        self.assertEqual(_degree_of_change(76, 24)[0], "ai")
        self.assertEqual(_degree_of_change(0, 0)[0], None)

    def test_pure_human_document(self):
        import textforensics.mixed_origin as mo

        sentences = [_sentence(f"human{i}") for i in range(4)]
        scores = {s: 0.1 for s in sentences}
        original = mo.analyze_text
        try:
            mo.analyze_text = lambda text, *, include_robustness=True: _fake_result(
                scores[text], (0.1, 0.2, 0.5)
            )
            report = build_mixed_origin_report(
                " ".join(sentences),
                language="en",
                domain="news",
                covered_regimes=[("en", "news")],
            )
        finally:
            mo.analyze_text = original
        jsonschema.validate(report, SCHEMA)
        self.assertEqual(report["verdict"], "human")
        self.assertEqual(report["withheld_reasons"], [])
        self.assertEqual(report["collaboration_type"], "HH")
        self.assertEqual(report["degree_of_change"]["tiers"], "human")
        self.assertIsNone(report["degree_of_change"]["estimate"])
        self.assertEqual(report["degree_of_change"]["calibration"], "unknown")
        self.assertEqual(report["operation_hypothesis"]["operation"], "unknown")
        self.assertTrue(all(s["evidence"] == "human-consistent" for s in report["segments"]))
        self.assertEqual(
            report["segments"][0]["methods_agreeing"],
            ["structural_uniformity", "formulaic_language"],
        )

    def test_pure_ai_document(self):
        import textforensics.mixed_origin as mo

        sentences = [_sentence(f"machine{i}") for i in range(4)]
        scores = {s: 0.9 for s in sentences}
        original = mo.analyze_text
        try:
            mo.analyze_text = lambda text, *, include_robustness=True: _fake_result(
                scores[text], (0.9, 0.85, 0.4)
            )
            report = build_mixed_origin_report(
                " ".join(sentences),
                language="en",
                domain="essays",
                covered_regimes=[("en", "essays")],
            )
        finally:
            mo.analyze_text = original
        jsonschema.validate(report, SCHEMA)
        self.assertEqual(report["verdict"], "ai")
        self.assertEqual(report["collaboration_type"], "AA")
        self.assertEqual(report["degree_of_change"]["tiers"], "ai")

    def test_mixed_evidence_is_withheld_not_mixed(self):
        """§8.6 (b)(i): any mixed evidence withholds the verdict."""
        import textforensics.mixed_origin as mo

        human = [_sentence(f"human{i}") for i in range(3)]
        machine = [_sentence(f"machine{i}") for i in range(3)]
        scores = {**{s: 0.1 for s in human}, **{s: 0.9 for s in machine}}
        original = mo.analyze_text
        try:
            mo.analyze_text = lambda text, *, include_robustness=True: _fake_result(
                scores[text],
                (0.9, 0.85, 0.4) if scores[text] >= 0.68 else (0.1, 0.2, 0.5),
            )
            report = build_mixed_origin_report(
                " ".join(human + machine),
                language="en",
                domain="news",
                covered_regimes=[("en", "news")],
            )
        finally:
            mo.analyze_text = original
        jsonschema.validate(report, SCHEMA)
        self.assertEqual(report["verdict"], "withheld")
        self.assertNotEqual(report["verdict"], "mixed")
        reasons = " ".join(report["withheld_reasons"])
        self.assertIn("segments_disagree", reasons)
        # All segment evidence is still reported.
        self.assertEqual(len(report["segments"]), 6)
        self.assertEqual(sum(1 for s in report["segments"] if s["evidence"] == "ai-consistent"), 3)
        self.assertEqual(
            sum(1 for s in report["segments"] if s["evidence"] == "human-consistent"),
            3,
        )

    def test_uncovered_regime_withholds(self):
        import textforensics.mixed_origin as mo

        sentences = [_sentence(f"human{i}") for i in range(3)]
        original = mo.analyze_text
        try:
            mo.analyze_text = lambda text, *, include_robustness=True: _fake_result(
                0.1, (0.1, 0.2, 0.5)
            )
            report = build_mixed_origin_report(
                " ".join(sentences),
                language="de",
                domain="news",
                covered_regimes=[("en", "news")],
            )
        finally:
            mo.analyze_text = original
        self.assertEqual(report["verdict"], "withheld")
        self.assertIn("no_validation_slice", " ".join(report["withheld_reasons"]))
        self.assertFalse(report["regime"]["validation_slice_covered"])

    def test_undetermined_language_withholds(self):
        import textforensics.mixed_origin as mo

        sentences = [_sentence(f"human{i}") for i in range(3)]
        original = mo.analyze_text
        try:
            mo.analyze_text = lambda text, *, include_robustness=True: _fake_result(
                0.1, (0.1, 0.2, 0.5)
            )
            report = build_mixed_origin_report(" ".join(sentences))
        finally:
            mo.analyze_text = original
        self.assertEqual(report["verdict"], "withheld")
        self.assertIn("no_validation_slice", " ".join(report["withheld_reasons"]))

    def test_withhold_conditions_unit(self):
        ai = {"evidence": "ai-consistent", "n_words": 30}
        human = {"evidence": "human-consistent", "n_words": 30}
        short = {"evidence": "insufficient", "n_words": 5}
        unknown_op = {"operation": "unknown", "direction": "unknown"}
        polish_op = {"operation": "polish", "direction": "human→ai"}
        # (i) disagreement
        verdict, reasons = _decide_verdict([ai, human], unknown_op, "human", regime_covered=True)
        self.assertEqual(verdict, "withheld")
        self.assertTrue(any("segments_disagree" in r for r in reasons))
        # (ii) polish on human-origin text (no AI segment: operation from
        # another source — the builder never emits this alone in v1.0)
        verdict, reasons = _decide_verdict([human], polish_op, "human", regime_covered=True)
        self.assertEqual(verdict, "withheld")
        self.assertTrue(any("operation_polish_on_human_origin" in r for r in reasons))
        # (iii) intermediate degree tier
        verdict, reasons = _decide_verdict([ai], unknown_op, "lightly", regime_covered=True)
        self.assertEqual(verdict, "withheld")
        self.assertTrue(any("intermediate_degree_of_change" in r for r in reasons))
        # (iv) uncovered regime
        verdict, reasons = _decide_verdict([human], unknown_op, "human", regime_covered=False)
        self.assertEqual(verdict, "withheld")
        self.assertTrue(any("no_validation_slice" in r for r in reasons))
        # No evidence at all
        verdict, reasons = _decide_verdict([short], unknown_op, None, regime_covered=True)
        self.assertEqual(verdict, "withheld")
        self.assertTrue(any("insufficient_segment_evidence" in r for r in reasons))
        # Clean single-origin, covered regime: a verdict is given.
        verdict, reasons = _decide_verdict([human], unknown_op, "human", regime_covered=True)
        self.assertEqual(verdict, "human")
        self.assertEqual(reasons, [])

    def test_hart_types(self):
        ai = {"evidence": "ai-consistent", "n_words": 30}
        human = {"evidence": "human-consistent", "n_words": 30}
        self.assertEqual(_hart_type([ai], {"operation": "unknown"})[0], "AA")
        self.assertEqual(_hart_type([human], {"operation": "unknown"})[0], "HH")
        self.assertEqual(_hart_type([], {"operation": "unknown"})[0], "unknown")
        # Mixed + expression-only op + human majority -> HA.
        self.assertEqual(_hart_type([human, human, ai], {"operation": "polish"})[0], "HA")
        # Mixed + content-changing op -> unknown (cannot be separated).
        self.assertEqual(_hart_type([human, human, ai], {"operation": "expand"})[0], "unknown")
        self.assertEqual(_hart_type([human, ai], {"operation": "rewrite"})[0], "unknown")

    def test_humanise_hypothesis_from_adversarial_findings(self):
        import textforensics.mixed_origin as mo

        sentences = [_sentence(f"human{i}") for i in range(3)]
        original = mo.analyze_text
        try:
            mo.analyze_text = lambda text, *, include_robustness=True: _fake_result(
                0.1, (0.1, 0.2, 0.5)
            )
            findings = [SimpleNamespace(pattern_id="regex_deliberate_typo", severity="high")]
            report = build_mixed_origin_report(
                " ".join(sentences),
                language="en",
                domain="news",
                covered_regimes=[("en", "news")],
                adversarial_findings=findings,
            )
        finally:
            mo.analyze_text = original
        jsonschema.validate(report, SCHEMA)
        self.assertEqual(report["operation_hypothesis"]["operation"], "humanise")
        self.assertEqual(report["operation_hypothesis"]["direction"], "ai→human")
        self.assertEqual(report["operation_hypothesis"]["confidence"], "low")
        # The direction contradicts all-human segment evidence: withheld.
        self.assertEqual(report["verdict"], "withheld")
        self.assertTrue(
            any(
                "operation_direction_conflicts_with_segments" in r
                for r in report["withheld_reasons"]
            )
        )

    def test_rewrite_hypothesis_from_alternation(self):
        import textforensics.mixed_origin as mo

        human = [_sentence(f"human{i}") for i in range(3)]
        machine = [_sentence(f"machine{i}") for i in range(3)]
        ordered = [human[0], machine[0], human[1], machine[1], human[2], machine[2]]
        scores = {**{s: 0.1 for s in human}, **{s: 0.9 for s in machine}}
        original = mo.analyze_text
        try:
            mo.analyze_text = lambda text, *, include_robustness=True: _fake_result(
                scores[text],
                (0.9, 0.85, 0.4) if scores[text] >= 0.68 else (0.1, 0.2, 0.5),
            )
            report = build_mixed_origin_report(
                " ".join(ordered),
                language="en",
                domain="news",
                covered_regimes=[("en", "news")],
            )
        finally:
            mo.analyze_text = original
        # 5 alternations -> rewrite at medium confidence.
        self.assertEqual(report["operation_hypothesis"]["operation"], "rewrite")
        self.assertEqual(report["operation_hypothesis"]["confidence"], "medium")
        self.assertEqual(report["operation_hypothesis"]["direction"], "human→ai")

    def test_determinism(self):
        import textforensics.mixed_origin as mo

        sentences = [_sentence(f"human{i}") for i in range(2)]
        original = mo.analyze_text
        try:
            mo.analyze_text = lambda text, *, include_robustness=True: _fake_result(
                0.1, (0.1, 0.2, 0.5)
            )
            first = build_mixed_origin_report(
                " ".join(sentences),
                language="en",
                domain="news",
                covered_regimes=[("en", "news")],
            )
            second = build_mixed_origin_report(
                " ".join(sentences),
                language="en",
                domain="news",
                covered_regimes=[("en", "news")],
            )
        finally:
            mo.analyze_text = original
        self.assertEqual(first, second)
        self.assertEqual(
            hashlib.sha256(json.dumps(first, sort_keys=True).encode()).hexdigest(),
            hashlib.sha256(json.dumps(second, sort_keys=True).encode()).hexdigest(),
        )

    def test_empty_text_raises(self):
        with self.assertRaises(ValueError):
            build_mixed_origin_report("   ")


class SegmentCoveredRegimesTest(unittest.TestCase):
    """The registry-coverage helper: only segment records count."""

    def _record(self, **overrides):
        regime = SimpleNamespace(
            language="en",
            domain=["news", "essays"],
            editing_regime="LLM-edited",
        )
        record = SimpleNamespace(
            status="partial",
            detector_version="0.1.0",
            regime=regime,
            metrics=[SimpleNamespace(slice_id="opai-bench-segments-builtin-heuristic")],
        )
        for key, value in overrides.items():
            if key in ("language", "domain", "editing_regime"):
                setattr(regime, key, value)
            else:
                setattr(record, key, value)
        return record

    def test_segment_record_covers_its_domains(self):
        from textforensics.mixed_origin import segment_covered_regimes

        registry = SimpleNamespace(records=(self._record(),))
        self.assertEqual(
            segment_covered_regimes(registry),
            {("en", "news"), ("en", "essays")},
        )

    def test_document_record_does_not_cover(self):
        from textforensics.mixed_origin import segment_covered_regimes

        registry = SimpleNamespace(records=(self._record(editing_regime="raw"),))
        self.assertEqual(segment_covered_regimes(registry), set())

    def test_wrong_version_wrong_status_wrong_slice_do_not_cover(self):
        from textforensics.mixed_origin import segment_covered_regimes

        cases = [
            self._record(detector_version="0.2.0"),
            self._record(status="rejected"),
            self._record(metrics=[SimpleNamespace(slice_id="opai-bench-builtin-heuristic")]),
        ]
        for record in cases:
            registry = SimpleNamespace(records=(record,))
            self.assertEqual(segment_covered_regimes(registry), set())

    def test_explicit_slice_ids(self):
        from textforensics.mixed_origin import segment_covered_regimes

        registry = SimpleNamespace(records=(self._record(),))
        self.assertEqual(
            segment_covered_regimes(registry, slice_ids=("other-segments-x",)),
            set(),
        )
        self.assertEqual(
            segment_covered_regimes(
                registry,
                slice_ids=(
                    "other-segments-x",
                    "opai-bench-segments-builtin-heuristic",
                ),
            ),
            {("en", "news"), ("en", "essays")},
        )


class MixedOriginRealTextTest(unittest.TestCase):
    """Smoke tests on real (unmocked) detector output."""

    TEXT = (
        "The committee reviewed the annual report in detail and asked for "
        "clarification on three points before approving the budget. "
        "Furthermore, in conclusion, the results demonstrate significant "
        "improvements across all metrics, moreover the outcomes are "
        "clearly transformative for the organisation going forward. "
        "Members noted that the proposal required further discussion "
        "before any vote could take place in the spring session."
    )

    def test_real_text_report_validates_and_has_shape(self):
        report = build_mixed_origin_report(
            self.TEXT, language="en", domain="news", covered_regimes=[("en", "news")]
        )
        jsonschema.validate(report, SCHEMA)
        self.assertEqual(report["schema"], "textforensics.mixed-origin-report/v1")
        self.assertEqual(report["non_monotonicity_warning"], NON_MONOTONICITY_WARNING)
        self.assertIn("IdeaLens 2026", report["idea_provenance_note"])
        self.assertEqual(
            report["input"]["content_hash"],
            "sha256:" + hashlib.sha256(self.TEXT.encode()).hexdigest(),
        )
        self.assertEqual(report["input"]["segment_count"], len(report["segments"]))
        # Offsets slice back to the sentences.
        for segment in report["segments"]:
            start, end = segment["span"]
            self.assertEqual(
                segment["text_hash"],
                "sha256:" + hashlib.sha256(self.TEXT[start:end].encode()).hexdigest(),
            )
            self.assertRegex(segment["text_hash"], r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(segment["score_meaning"], SCORE_MEANING)
        self.assertIn("Text-only detection cannot prove authorship.", report["limitations"])

    def test_no_raw_text_in_report(self):
        text = (
            "The committee reviewed the annual report in detail and the "
            f"{CANARY} reference was filed with the minutes for the record. "
            "Members asked several questions about the budget and the "
            "timeline before the chair closed the session for the day."
        )
        report = build_mixed_origin_report(text)
        dumped = json.dumps(report)
        self.assertNotIn(CANARY, dumped)
        for leaf in _all_string_leaves(report):
            self.assertNotIn(CANARY, leaf)
            self.assertNotIn("annual report in detail", leaf)
        # "probability" appears ONLY inside score_meaning (once per segment).
        self.assertEqual(
            dumped.count("probability"),
            len(report["segments"]),
            "a probability must never be asserted anywhere but score_meaning",
        )


if __name__ == "__main__":
    unittest.main()
