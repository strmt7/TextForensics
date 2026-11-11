"""W2 Worker E regression tests: IF-12 (adversarial + semantic certainty).

Written from the stated expected results (plan rule 3) before the source
fix. Every test uses disposable synthetic data; no real user text,
accounts or keys.

Audit vectors reproduced here:
- IF-12 ``unsupported_confidence``: ``AdversarialDetector().analyze(
  'ordinary')`` must not return risk ``none`` with confidence 1.0, and
  one-word ``teh`` must not produce medium risk / confidence 0.7.
- IF-12 semantic: ``analyze_semantic_consistency('ordinary')`` has one
  segment yet must not return score 0.0 (documented as human-like),
  risk ``none``, confidence 1.0.

Expected contract after the fix:
- Inputs below the support floor (fewer than 10 words for the
  adversarial detector; fewer than 3 segments for the semantic
  checker), empty inputs, and unsupported languages report
  ``unknown`` risk and ``None`` confidence. Observed pattern counts /
  severities stay visible separately -- they are observations, not a
  calibrated confidence.
- A clean result on a supported input means "no observed patterns
  under the stated coverage", so its confidence is ``None`` (no
  versioned held-out calibration exists), never 1.0.
- A pattern detector that raises is recorded in ``patterns_failed`` /
  ``checks_failed`` and named in the limitations; it is never silently
  treated as "no finding".
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from textforensics.adversarial import (
    AdversarialDetector,
    HumanizationPatternLibrary,
    detect_humanization,
)
from textforensics.semantic import (
    SemanticConsistencyChecker,
    analyze_semantic_consistency,
)

# A clean English passage comfortably above the 10-word support floor.
CLEAN_LONG = (
    "The committee reviewed the annual report in detail and discussed the "
    "budget, the timeline, and the proposal before any vote was taken."
)
assert len(CLEAN_LONG.split()) >= 10

# A long, varied English passage that splits into at least 3 segments at
# a 20-word target: deliberately uneven sentences and vocabulary.
LONG_VARIED = (
    "The committee reviewed the annual report in detail and asked several "
    "questions about the budget. Members discussed the timeline at length, "
    "while the chair noted that the proposal required further discussion. "
    "Outside, rain fell steadily on the empty square as a bus passed slowly. "
    "The treasurer presented a revised forecast with lower revenue and "
    "higher costs for the coming year, which surprised several members. "
    "After a short break, the group returned to consider amendments one by one."
)


class TestIF12AdversarialUnsupported:
    def test_empty_input_is_unknown_not_none(self):
        report = AdversarialDetector().analyze("")
        assert report.overall_risk == "unknown"
        assert report.confidence is None
        assert report.support_status == "insufficient"
        assert report.findings == []

    def test_one_word_ordinary_is_unknown_not_fully_confident_clean(self):
        report = AdversarialDetector().analyze("ordinary")
        assert report.overall_risk == "unknown"
        assert report.confidence is None
        assert report.support_status == "insufficient"

    def test_one_word_teh_is_unknown_but_observations_stay_visible(self):
        report = AdversarialDetector().analyze("teh")
        # The audit case: two triggered patterns must stay observable
        # as counts, but must not become a medium-risk / 0.7 conclusion.
        assert report.patterns_triggered == 2
        assert len(report.findings) == 2
        assert report.overall_risk == "unknown"
        assert report.confidence is None
        assert report.support_status == "insufficient"

    def test_short_clean_text_is_unknown_not_none_with_confidence_one(self):
        report = AdversarialDetector().analyze("Clean text here.")
        assert report.overall_risk == "unknown"
        assert report.confidence is None
        assert report.support_status == "insufficient"

    def test_clean_supported_text_is_none_risk_with_no_calibrated_confidence(self):
        report = AdversarialDetector().analyze(CLEAN_LONG)
        assert report.findings == []
        assert report.overall_risk == "none"
        # No observed patterns under stated coverage -- not a
        # probability 1 of absence, so no calibrated confidence.
        assert report.confidence is None
        assert report.support_status == "sufficient"
        assert any("no observed patterns" in lim.lower() for lim in report.limitations)

    def test_supported_text_with_artifacts_reports_observed_risk_without_confidence(self):
        text = (
            "I'm gonna go now. Teh recieve was good, frankly, honestly, "
            "basically it was sort of amazing. Additionally, furthermore, "
            "moreover the results were definately recieveing attention."
        )
        report = AdversarialDetector().analyze(text)
        assert report.support_status == "sufficient"
        assert report.overall_risk in {"low", "medium", "high", "critical"}
        assert report.patterns_triggered >= 1
        assert report.confidence is None

    def test_declared_unsupported_language_abstains(self):
        report = AdversarialDetector().analyze(CLEAN_LONG, language="de")
        assert report.overall_risk == "unknown"
        assert report.confidence is None
        assert report.support_status == "insufficient"
        assert any("language" in lim.lower() for lim in report.limitations)

    def test_non_latin_script_abstains(self):
        text = "这是一个很长的中文段落，用于测试不支持语言的行为是否正确触发并返回未知风险。"
        report = AdversarialDetector().analyze(text)
        assert report.overall_risk == "unknown"
        assert report.confidence is None
        assert report.support_status == "insufficient"
        assert any("language" in lim.lower() for lim in report.limitations)

    def test_failed_pattern_is_recorded_not_silently_ignored(self):
        def boom(text):
            raise RuntimeError("synthetic pattern failure")

        library = HumanizationPatternLibrary(custom_patterns={"boom": boom})
        report = AdversarialDetector(pattern_library=library).analyze(CLEAN_LONG)
        assert "boom" in report.patterns_failed
        assert report.patterns_checked == len(library.list_patterns())
        assert any("boom" in lim for lim in report.limitations)
        # The failure is coverage loss, not a clean bill of health.
        assert report.confidence is None
        assert report.overall_risk in {"none", "unknown"}
        assert report.support_status == "insufficient"

    def test_failed_pattern_does_not_block_other_patterns(self):
        def boom(text):
            raise RuntimeError("synthetic pattern failure")

        library = HumanizationPatternLibrary(custom_patterns={"boom": boom})
        text = "Teh recieve was noted. I'm gonna go now, frankly, honestly, basically."
        report = AdversarialDetector(pattern_library=library).analyze(text)
        assert "boom" in report.patterns_failed
        # The other patterns still ran, so their observations stay
        # visible -- but coverage is incomplete, so no overall risk
        # is asserted from the partial run.
        assert report.patterns_triggered >= 1
        assert report.overall_risk == "unknown"
        assert report.confidence is None

    def test_summary_and_dict_expose_counts_with_null_confidence(self):
        report = AdversarialDetector().analyze("teh")
        assert report.to_dict()["confidence"] is None
        assert report.to_dict()["overall_risk"] == "unknown"
        assert report.to_dict()["patterns_triggered"] == 2
        assert report.summary()["confidence"] is None
        assert report.summary()["patterns_triggered"] == 2

    def test_detect_humanization_convenience_abstains_on_short_input(self):
        report = detect_humanization("ordinary")
        assert report.overall_risk == "unknown"
        assert report.confidence is None


class TestIF12SemanticUnsupported:
    def test_empty_input_is_unknown_with_null_score(self):
        report = analyze_semantic_consistency("")
        assert report.risk_level == "unknown"
        assert report.overall_consistency_score is None
        assert report.confidence is None
        assert report.support_status == "insufficient"

    def test_one_segment_ordinary_is_unknown_with_null_score(self):
        report = analyze_semantic_consistency("ordinary")
        assert report.n_segments == 1
        assert report.overall_consistency_score is None
        assert report.risk_level == "unknown"
        assert report.confidence is None
        assert report.support_status == "insufficient"

    def test_two_segments_are_unknown_with_null_score(self):
        text = (
            "The committee reviewed the annual report in detail and asked "
            "several questions about the budget and the timeline. Members "
            "discussed the proposal at length before any vote was taken."
        )
        report = analyze_semantic_consistency(text, segment_word_target=20)
        assert report.n_segments == 2
        assert report.overall_consistency_score is None
        assert report.risk_level == "unknown"
        assert report.confidence is None

    def test_supported_multi_segment_text_has_defined_score_without_confidence(self):
        report = analyze_semantic_consistency(LONG_VARIED, segment_word_target=20)
        assert report.n_segments >= 3
        assert report.support_status == "sufficient"
        assert report.overall_consistency_score is not None
        assert 0.0 <= report.overall_consistency_score <= 1.0
        # No calibrated confidence exists for this heuristic aggregate.
        assert report.confidence is None
        if not report.findings:
            assert report.risk_level == "none"
            assert any("no " in lim.lower() and "observed" in lim.lower() for lim in report.limitations)

    def test_declared_unsupported_language_abstains(self):
        report = analyze_semantic_consistency(LONG_VARIED, segment_word_target=20, language="fr")
        assert report.risk_level == "unknown"
        assert report.overall_consistency_score is None
        assert report.confidence is None
        assert any("language" in lim.lower() for lim in report.limitations)

    def test_non_latin_script_abstains(self):
        text = "这是一个很长的中文段落，用于测试不支持语言的行为是否正确触发并返回未知风险。"
        report = analyze_semantic_consistency(text)
        assert report.risk_level == "unknown"
        assert report.overall_consistency_score is None
        assert report.confidence is None

    def test_failed_consistency_check_is_recorded(self):
        checker = SemanticConsistencyChecker(segment_word_target=20)
        import textforensics.semantic as semantic

        original = semantic._detect_excessive_coherence

        def boom(segments):
            raise RuntimeError("synthetic check failure")

        semantic._detect_excessive_coherence = boom
        try:
            report = checker.analyze(LONG_VARIED)
        finally:
            semantic._detect_excessive_coherence = original
        assert "excessive_coherence" in report.checks_failed
        assert any("excessive_coherence" in lim for lim in report.limitations)
        assert report.confidence is None
        assert report.support_status == "insufficient"

    def test_summary_and_dict_carry_null_score_for_undefined_aggregate(self):
        report = analyze_semantic_consistency("ordinary")
        assert report.to_dict()["overall_consistency_score"] is None
        assert report.to_dict()["risk_level"] == "unknown"
        assert report.summary()["consistency_score"] is None
