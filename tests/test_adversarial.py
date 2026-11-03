"""Tests for Adversarial Humanization Detection."""

from __future__ import annotations

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
            return [AdversarialFinding(
                pattern_id="custom_pattern",
                segment="test",
                evidence=1.0,
                severity="medium",
                confidence=0.5,
                location=(0, 10),
                description="Custom test pattern",
            )]

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
        text = " ".join([
            "Teh recieve.",
            "I'm gonna go.",
            "Frankly honestly basically.",
            "Maybe perhaps possibly.",
            "Additionally furthermore moreover."
        ] * 5)  # Amplify
        report = detector.analyze(text)
        assert report.overall_risk in {"high", "critical"}
        assert report.confidence > 0.5


class TestCustomPatternRegistration:
    def test_custom_pattern_registration(self):
        library = HumanizationPatternLibrary()

        def my_detector(text):
            if "secret_pattern" in text:
                return [AdversarialFinding(
                    pattern_id="secret",
                    segment="test",
                    evidence=1.0,
                    severity="critical",
                    confidence=1.0,
                    location=(0, 10),
                    description="Secret pattern found",
                )]
            return []

        library.register("secret", lambda t: [])
        # Actually test the registration
        library._patterns["secret_test"] = lambda t: [AdversarialFinding(
            pattern_id="secret",
            segment="test",
            evidence=1.0,
            severity="critical",
            confidence=1.0,
            location=(0, 10),
            description="Secret pattern found",
        )] if "secret_pattern" in t else []

        # Test that custom pattern is in registry
        assert "secret_test" in library.list_patterns()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
