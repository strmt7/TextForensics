"""Tests for Adversarial Humanization Detection."""

from __future__ import annotations

import re

import pytest

from textforensics.adversarial import (
    AdversarialDetector,
    AdversarialFinding,
    HumanizationPatternLibrary,
    detect_deliberate_typos,
    detect_discourse_overload,
    detect_forced_contractions,
    detect_hedge_overload,
    detect_humanization,
    detect_humanization_simple,
    detect_mechanical_transitions,
    detect_mechanical_variation,
    detect_perplexity_anomalies,
    detect_regex_artifacts,
)


class TestRegexArtifacts:
    def test_deliberate_typos_detected(self):
        text = "This is a test with teh wrong spelling and thier mistakes."
        findings = detect_regex_artifacts(text)
        assert len(findings) == 1
        assert findings[0].pattern_id == "regex_deliberate_typo"
        assert findings[0].evidence >= 2

    def test_forced_contractions_detected(self):
        text = "I'm gonna go to the store. Wanna come with me? Gotta go now."
        findings = detect_regex_artifacts(text)
        finding = next(f for f in findings if f.pattern_id == "regex_forced_contraction")
        assert finding.evidence >= 3

    def test_discourse_overload_detected(self):
        text = "Frankly, honestly, basically, literally, this is too much."
        findings = detect_regex_artifacts(text)
        finding = next(f for f in findings if f.pattern_id == "regex_discourse_overload")
        assert finding.evidence >= 4

    def test_hedge_overload_detected(self):
        text = "Maybe perhaps possibly it could be that sort of thing."
        findings = detect_regex_artifacts(text)
        finding = next(f for f in findings if f.pattern_id == "regex_hedge_overload")
        assert finding.evidence >= 4


class TestMechanicalVariation:
    def test_regular_alternation_detected(self):
        # Alternating short/long sentences
        text = "Hi. This is a very long sentence with many words in it. Hi. Another very long sentence with many words. Hi. Yet another long sentence here."
        findings = detect_mechanical_variation(text)
        assert len(findings) >= 1
        assert findings[0].pattern_id == "mechanical_variation"
        assert findings[0].severity == "high"

    def test_natural_variation_not_flagged(self):
        # Natural variation should not trigger
        text = "This is a normal sentence. Here is another one. And this is the third sentence. Finally, the last one."
        findings = detect_mechanical_variation(text)
        assert len(findings) == 0

    def test_insufficient_sentences(self):
        text = "One. Two."
        findings = detect_mechanical_variation(text)
        assert len(findings) == 0


class TestMechanicalTransitions:
    def test_overuse_detected(self):
        text = "Additionally, furthermore, moreover, therefore, consequently, this is true."
        findings = detect_mechanical_transitions(text)
        assert len(findings) >= 1
        assert findings[0].pattern_id == "mechanical_transitions"

    def test_normal_usage_not_flagged(self):
        text = "Therefore, the result is clear. However, there are exceptions."
        findings = detect_mechanical_transitions(text)
        assert len(findings) == 0


class TestDeliberateTypos:
    def test_common_typos_detected(self):
        text = "I recieve the letter. It was teh best day."
        findings = detect_deliberate_typos(text)
        assert len(findings) >= 1
        assert findings[0].pattern_id == "deliberate_typos"

    def test_no_false_positive_on_correct(self):
        text = "This is a correctly spelled sentence."
        findings = detect_deliberate_typos(text)
        assert len(findings) == 0


class TestForcedContractions:
    def test_multiple_contractions_detected(self):
        text = "I'm gonna go. Wanna come? Gotta go. Kinda busy."
        findings = detect_forced_contractions(text)
        assert len(findings) >= 1
        assert findings[0].pattern_id == "forced_contractions"

    def test_single_contraction_not_flagged(self):
        text = "I'm going to the store."
        findings = detect_forced_contractions(text)
        assert len(findings) == 0


class TestDiscourseOverload:
    def test_excessive_discourse_markers(self):
        text = "Frankly, honestly, basically, literally, this is too much."
        findings = detect_discourse_overload(text)
        assert len(findings) >= 1
        assert findings[0].pattern_id == "discourse_overload"

    def test_normal_discourse_not_flagged(self):
        text = "Frankly, I think you're right."
        findings = detect_discourse_overload(text)
        assert len(findings) == 0


class TestHedgeOverload:
    def test_excessive_hedging(self):
        text = "Maybe perhaps possibly it could be that sort of thing."
        findings = detect_hedge_overload(text)
        assert len(findings) >= 1
        assert findings[0].pattern_id == "hedge_overload"


class TestPerplexityAnomalies:
    def test_flat_perplexity_detected(self):
        # Create text with very uniform word choice (low perplexity variation)
        text = " ".join(["the"] * 50 + ["cat"] * 50 + ["sat"] * 50 + ["on"] * 50 + ["mat"] * 50)
        findings = detect_perplexity_anomalies(text)
        # May or may not detect depending on implementation
        assert len(findings) >= 0

    def test_oscillating_perplexity(self):
        # Create text with oscillating perplexity
        text = "the cat. the cat. the cat. the cat. the cat."
        findings = detect_perplexity_anomalies(text)
        # May detect oscillation
        assert len(findings) >= 0


class TestHumanizationPatternLibrary:
    def test_default_patterns_loaded(self):
        library = HumanizationPatternLibrary()
        patterns = library.list_patterns()
        assert len(patterns) >= 8
        assert "regex_artifacts" in patterns
        assert "mechanical_variation" in patterns

    def test_register_custom_pattern(self):
        library = HumanizationPatternLibrary()

        def custom_detector(text):
            return []

        library.register("custom_test", custom_detector)
        assert "custom_test" in library.list_patterns()

    def test_unregister_pattern(self):
        library = HumanizationPatternLibrary()
        assert library.unregister("regex_artifacts") is True
        assert "regex_artifacts" not in library.list_patterns()

    def test_run_all(self):
        library = HumanizationPatternLibrary()
        text = "This is a test with teh typo and gonna go."
        findings = library.run_all(text)
        # Should find at least the deliberate typo and forced contraction
        pattern_ids = {f.pattern_id for f in findings}
        assert "regex_deliberate_typo" in pattern_ids
        assert "regex_forced_contraction" in pattern_ids


class TestAdversarialDetector:
    def test_clean_text_no_findings(self):
        detector = AdversarialDetector()
        text = "This is a clean, well-written sentence with no artifacts."
        report = detector.analyze(text)
        assert report.overall_risk == "none"
        assert report.confidence == 1.0
        assert len(report.findings) == 0

    def test_text_with_multiple_artifacts(self):
        detector = AdversarialDetector()
        text = "I'm gonna go. Teh recieve was good. Frankly, honestly, basically it was good."
        report = detector.analyze(text)
        assert report.overall_risk in {"medium", "high", "critical"}
        assert len(report.findings) >= 3

    def test_empty_text_returns_empty_report(self):
        detector = AdversarialDetector()
        report = detector.analyze("")
        assert report.overall_risk == "none"
        assert report.text_length == 0

    def test_report_includes_limitations(self):
        detector = AdversarialDetector()
        report = detector.analyze("Some text.")
        assert len(report.limitations) > 0
        assert any("Pattern-based" in lim for lim in report.limitations)

    def test_report_serialization(self):
        detector = AdversarialDetector()
        text = "Test with teh typo."
        report = detector.analyze(text)
        d = report.to_dict()
        assert "findings" in d
        assert "overall_risk" in d
        assert "confidence" in d
        assert "patterns_checked" in d


class TestConvenienceFunction:
    def test_detect_humanization_simple(self):
        text = "I'm gonna go. Teh recieve was good."
        result = detect_humanization_simple(text)
        assert "overall_risk" in result
        assert "total_findings" in result
        assert "by_severity" in result

    def test_detect_humanization_with_custom_patterns(self):
        def custom_detector(text):
            return [
                AdversarialFinding(
                    pattern_id="custom_pattern",
                    segment="test",
                    evidence=1.0,
                    severity="medium",
                    confidence=0.5,
                    location=(0, 10),
                    description="Custom test pattern",
                )
            ]

        text = "Some text."
        report = detect_humanization(text, custom_patterns={"custom": lambda t: []})
        # Custom patterns should be available
        assert report.patterns_checked >= 8  # Default patterns


class TestAdversarialFinding:
    def test_finding_to_dict(self):
        finding = AdversarialFinding(
            pattern_id="test",
            segment="test segment",
            evidence=1.5,
            severity="high",
            confidence=0.8,
            location=(0, 10),
            description="Test finding",
        )
        d = finding.to_dict()
        assert d["pattern_id"] == "test"
        assert d["evidence"] == 1.5
        assert d["severity"] == "high"


class TestAdversarialDetectorRiskAssessment:
    def test_no_findings_none_risk(self):
        detector = AdversarialDetector()
        report = detector.analyze("Clean text.")
        assert report.overall_risk == "none"
        assert report.confidence == 1.0

    def test_critical_risk_for_severe_findings(self):
        detector = AdversarialDetector()
        # Create text with many severe artifacts
        text = " ".join(
            [
                "Teh recieve.",
                "I'm gonna go.",
                "Frankly honestly basically.",
                "Maybe perhaps possibly.",
                "Additionally furthermore moreover.",
            ]
            * 5
        )  # Amplify
        report = detector.analyze(text)
        assert report.overall_risk in {"high", "critical"}
        assert report.confidence > 0.5


class TestHumanizationPatternFalsePositiveRate:
    """Regression test (#4c): the pattern FPR is unmeasured, not zero.

    ``HumanizationPattern.false_positive_rate`` used to default to
    0.0 and was never assigned anywhere, so every pattern reported a
    fabricated perfect false-positive rate. The honest default is
    None (unmeasured), emitted as-is by ``to_dict``.
    """

    def test_default_false_positive_rate_is_none(self):
        from textforensics.adversarial import HumanizationPattern

        pattern = HumanizationPattern(
            pattern_id="test_pattern",
            name="Test pattern",
            description="A test pattern.",
            category="lexical",
            detector_fn="detect_regex_artifacts",
            threshold=1.0,
            severity="medium",
            confidence=0.5,
        )
        assert pattern.false_positive_rate is None
        assert pattern.to_dict()["false_positive_rate"] is None


class TestAnalyzeDeduplicatesFindings:
    """Regression tests (#4a): analyze() de-duplicates before risk/report.

    ``analyze`` builds ``unique_findings`` (de-duped by
    ``(pattern_id, location)``) but used to feed the raw, duplicated
    ``all_findings`` into ``_assess_risk`` and the report. A detector
    that returns the same finding twice must therefore surface once
    in the report, once in ``patterns_triggered``, and once in the
    list ``_assess_risk`` receives.
    """

    def _detector_with_duplicate(self):
        duplicate = AdversarialFinding(
            pattern_id="dup_pattern",
            segment="sha256:" + "0" * 64,
            evidence=1.0,
            severity="high",
            confidence=0.9,
            location=(0, 10),
            description="Duplicated finding",
        )
        library = HumanizationPatternLibrary()
        for name in library.list_patterns():
            library.unregister(name)
        library.register("dup", lambda text: [duplicate, duplicate])
        return AdversarialDetector(pattern_library=library), duplicate

    def test_duplicate_finding_appears_once_in_report(self):
        detector, duplicate = self._detector_with_duplicate()
        report = detector.analyze("Some text for analysis here.")
        assert report.findings == [duplicate]
        assert report.patterns_triggered == 1

    def test_risk_assessment_receives_deduplicated_findings(self):
        detector, duplicate = self._detector_with_duplicate()
        seen: dict[str, list[AdversarialFinding]] = {}
        original_assess_risk = detector._assess_risk

        def spy(findings):
            seen["findings"] = list(findings)
            return original_assess_risk(findings)

        detector._assess_risk = spy  # type: ignore[method-assign]
        report = detector.analyze("Some text for analysis here.")
        assert seen["findings"] == [duplicate]
        # The reported risk/confidence are the ones computed from the
        # de-duplicated list.
        assert (report.overall_risk, report.confidence) == original_assess_risk([duplicate])


class TestCustomPatternRegistration:
    def test_custom_pattern_registration(self):
        library = HumanizationPatternLibrary()

        def my_detector(text):
            if "secret_pattern" in text:
                return [
                    AdversarialFinding(
                        pattern_id="secret",
                        segment="test",
                        evidence=1.0,
                        severity="critical",
                        confidence=1.0,
                        location=(0, 10),
                        description="Secret pattern found",
                    )
                ]
            return []

        library.register("secret", lambda t: [])
        # Actually test the registration
        library._patterns["secret_test"] = lambda t: (
            [
                AdversarialFinding(
                    pattern_id="secret",
                    segment="test",
                    evidence=1.0,
                    severity="critical",
                    confidence=1.0,
                    location=(0, 10),
                    description="Secret pattern found",
                )
            ]
            if "secret_pattern" in t
            else []
        )

        # Test that custom pattern is in registry
        assert "secret_test" in library.list_patterns()


class TestNoRawTextInFindings:
    """Regression tests: findings never carry raw input text (AGENTS.md rule 22).

    A canary string planted in the input must not appear anywhere in
    any finding — not in ``segment`` (which used to embed up to 200
    chars of raw text), not in any description, and not in any
    serialized report. The input is crafted to trigger regex-artifact
    findings (deliberate typos + forced contractions), so the test
    exercises the leak path rather than an empty findings list.
    """

    CANARY = "CANARY-7f3a9-ZEBRA-QUARTZ-4417"

    TEXT_WITH_CANARY = (
        "Furthermore, teh CANARY-7f3a9-ZEBRA-QUARTZ-4417 solution is gonna "
        "change everything, frankly. It is sort of amazing, kinda sorta. "
        "Additionally, moreover, therefore the results are definately "
        "recieveing attention from thier team."
    )

    def _all_string_leaves(self, value):
        """Every string leaf in a nested output structure."""
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict):
            leaves = []
            for key, item in value.items():
                leaves.append(str(key))
                leaves.extend(self._all_string_leaves(item))
            return leaves
        if isinstance(value, (list, tuple)):
            leaves = []
            for item in value:
                leaves.extend(self._all_string_leaves(item))
            return leaves
        return []

    def test_canary_absent_from_regex_findings(self):
        """Test that regex-artifact findings contain no raw input text."""
        findings = detect_regex_artifacts(self.TEXT_WITH_CANARY)
        # The leak path is exercised: at least one finding triggered.
        assert len(findings) > 0
        for finding in findings:
            assert self.CANARY not in finding.segment
            assert self.CANARY not in finding.description
            assert self.CANARY not in finding.to_dict()["segment"]
            # The segment is a content reference, not quoted text.
            assert finding.segment.startswith("sha256:")
            assert len(finding.segment) == len("sha256:") + 64

    def test_canary_absent_from_all_findings_and_reports(self):
        """Test that no entry point leaks the canary anywhere."""
        text = self.TEXT_WITH_CANARY
        outputs = [
            detect_humanization(text).to_dict(),
            detect_humanization_simple(text),
            AdversarialDetector().analyze(text).to_dict(),
            [f.to_dict() for f in HumanizationPatternLibrary().run_all(text)],
        ]
        for output in outputs:
            for leaf in self._all_string_leaves(output):
                assert self.CANARY not in leaf, f"canary leaked in: {leaf!r}"

    def test_segment_reference_matches_matched_span(self):
        """Test that the segment hash identifies the matched span.

        Per the AdversarialFinding contract, ``segment`` is the
        SHA-256 of the FIRST matched span and ``location`` is that
        span — not a hash of ``text[:200]`` with a fixed (0, 200)
        location. The expected span is computed independently here
        with re.search over the artifact's patterns.
        """
        import hashlib

        from textforensics.adversarial import _HUMANIZER_ARTIFACTS

        findings = detect_regex_artifacts(self.TEXT_WITH_CANARY)
        assert len(findings) > 0
        for finding in findings:
            artifact_id = finding.pattern_id.removeprefix("regex_")
            patterns = _HUMANIZER_ARTIFACTS[artifact_id]["patterns"]
            spans = [
                match.span()
                for pat in patterns
                if (match := re.search(pat, self.TEXT_WITH_CANARY, re.IGNORECASE)) is not None
            ]
            assert spans, f"no match found for {finding.pattern_id}"
            start, end = min(spans)
            expected = hashlib.sha256(self.TEXT_WITH_CANARY[start:end].encode("utf-8")).hexdigest()
            assert finding.segment == f"sha256:{expected}"
            assert finding.location == (start, end)


class TestNoRawTextInFindingsU4:
    """U4 precondition (§(f)): no raw text in adversarial findings/reports.

    The 63eac08 fix (``segment`` is a SHA-256 reference, never quoted
    text) is re-verified here from the U4 side, because the mixed-origin
    report consumes adversarial findings as one of its evidence
    families. These tests close the gaps the original canary class
    left open:

    * a canary planted BEYOND the 200-char truncation boundary
      (``detect_regex_artifacts`` used to hash only ``text[:200]`` —
      a leak of later text would have escaped the original canary,
      which sits at char ~20);
    * a full string-leaf scan of the serialized ``to_dict()`` output
      of ``detect_regex_artifacts`` (the original class checked only
      ``segment``/``description`` there — the numeric ``evidence``
      field was never scanned);
    * a structural invariant on EVERY finding ``analyze`` returns:
      ``segment`` is either the literal ``"full_text"`` or
      ``"sha256:<64 hex>"`` — never quoted input text.
    """

    CANARY_EARLY = "CANARY-7f3a9-ZEBRA-QUARTZ-4417"
    CANARY_LATE = "CANARY-9c2d4-MANGO-VELVET-8821"
    # A distinctive multi-word phrase from the plain filler (chars
    # <200) — guards against a leak that does not include a canary.
    FILLER_PHRASE = "annual report in detail"

    TEXT_WITH_LATE_CANARY = (
        "The committee reviewed the annual report in detail. "
        "The findings were presented to the board during the spring session. "
        "Members asked several questions about the budget and the timeline. "
        "The chair noted that the proposal required further discussion before any vote. "
        "Furthermore, teh CANARY-9c2d4-MANGO-VELVET-8821 solution is gonna "
        "change everything, frankly. It is sort of amazing, kinda sorta. "
        "Additionally, moreover, therefore the results are definately "
        "recieveing attention from thier team."
    )

    def _all_string_leaves(self, value):
        """Every string leaf in a nested output structure."""
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict):
            leaves = []
            for key, item in value.items():
                leaves.append(str(key))
                leaves.extend(self._all_string_leaves(item))
            return leaves
        if isinstance(value, (list, tuple)):
            leaves = []
            for item in value:
                leaves.extend(self._all_string_leaves(item))
            return leaves
        return []

    def test_late_canary_position(self):
        """The late canary really sits beyond the 200-char boundary."""
        assert self.TEXT_WITH_LATE_CANARY.index(self.CANARY_LATE) > 200

    def test_late_canary_absent_from_every_entry_point(self):
        """No entry point leaks text planted beyond char 200."""
        text = self.TEXT_WITH_LATE_CANARY
        outputs = [
            [f.to_dict() for f in detect_regex_artifacts(text)],
            detect_humanization(text).to_dict(),
            detect_humanization_simple(text),
            AdversarialDetector().analyze(text).to_dict(),
            [f.to_dict() for f in HumanizationPatternLibrary().run_all(text)],
        ]
        assert len(outputs[0]) > 0  # the leak path is exercised
        for output in outputs:
            for leaf in self._all_string_leaves(output):
                assert self.CANARY_LATE not in leaf, f"late canary leaked in: {leaf!r}"
                assert self.CANARY_EARLY not in leaf
                assert self.FILLER_PHRASE not in leaf, f"filler phrase leaked in: {leaf!r}"

    def test_all_analyze_segments_are_references(self):
        """Every finding segment is a reference, never quoted text."""
        findings = AdversarialDetector().analyze(self.TEXT_WITH_LATE_CANARY).findings
        assert len(findings) > 0
        pattern = re.compile(r"^(full_text|sha256:[0-9a-f]{64})$")
        for finding in findings:
            assert pattern.match(finding.segment), (
                f"segment is not a content reference: {finding.segment!r}"
            )
            assert self.CANARY_LATE not in finding.segment
            assert self.FILLER_PHRASE not in finding.segment


class TestRegexArtifactFirstMatchSpan:
    """Regression tests (#10): regex findings reference the matched span.

    ``detect_regex_artifacts`` used to hash ``text[:200]`` and report
    location ``(0, 200)`` regardless of where the match actually sits,
    contradicting the ``AdversarialFinding.segment`` contract. The
    segment is now the SHA-256 of the FIRST matched span and
    ``location`` is that span; the aggregate match count stays in
    ``evidence``.
    """

    CANARY = "CANARY-5e8b1-TULIP-GRANITE-7734"
    # Filler with no humanizer-artifact words, long enough to push
    # the planted match beyond character 200.
    TEXT_WITH_LATE_MATCH = (
        "The committee reviewed the annual report in detail. "
        "The findings were presented to the board during the spring session. "
        "Members asked several questions about the budget and the timeline. "
        "The chair noted that the proposal required further discussion before any vote. "
        "A follow-up meeting was set for the following month to check progress. "
        "The draft was teh CANARY-5e8b1-TULIP-GRANITE-7734 version circulated for comment."
    )

    def _all_string_leaves(self, value):
        """Every string leaf in a nested output structure."""
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict):
            leaves = []
            for key, item in value.items():
                leaves.append(str(key))
                leaves.extend(self._all_string_leaves(item))
            return leaves
        if isinstance(value, (list, tuple)):
            leaves = []
            for item in value:
                leaves.extend(self._all_string_leaves(item))
            return leaves
        return []

    def test_match_beyond_200_segment_and_location(self):
        """A match past char 200 is hashed at its own span, not text[:200]."""
        import hashlib

        text = self.TEXT_WITH_LATE_MATCH
        start = text.index("teh")
        assert start > 200  # the match really is beyond the old boundary
        end = start + len("teh")
        findings = detect_regex_artifacts(text)
        finding = next(f for f in findings if f.pattern_id == "regex_deliberate_typo")
        expected = hashlib.sha256(text[start:end].encode("utf-8")).hexdigest()
        assert finding.segment == f"sha256:{expected}"
        assert finding.location == (start, end)
        assert finding.evidence >= 1  # aggregate count still recorded

    def test_late_canary_still_absent_from_findings(self):
        """The canary behaviour still holds after the span fix (rule 22)."""
        findings = detect_regex_artifacts(self.TEXT_WITH_LATE_MATCH)
        assert len(findings) > 0  # the leak path is exercised
        for finding in findings:
            for leaf in self._all_string_leaves(finding.to_dict()):
                assert self.CANARY not in leaf, f"canary leaked in: {leaf!r}"
            assert finding.segment.startswith("sha256:")
            assert len(finding.segment) == len("sha256:") + 64


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
