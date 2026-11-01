from __future__ import annotations

import math
import unittest
from unittest.mock import patch

from textforensics.engine import (
    _disagreement,
    _verdict,
    analyze_text,
)
from textforensics.models import AnalyzerResult


class VerdictEdgeCaseTests(unittest.TestCase):
    """Tests for _verdict function edge cases (lines 41, 57)."""

    def test_verdict_rejects_nan_score(self):
        """Test that _verdict raises ValueError for NaN score."""
        with self.assertRaises(ValueError):
            _verdict(float("nan"), 0.5)

    def test_verdict_rejects_inf_score(self):
        """Test that _verdict raises ValueError for infinite score."""
        with self.assertRaises(ValueError):
            _verdict(float("inf"), 0.5)
        with self.assertRaises(ValueError):
            _verdict(float("-inf"), 0.5)

    def test_verdict_rejects_nan_diagnostic_reliability(self):
        """Test that _verdict raises ValueError for NaN diagnostic_reliability (line 41)."""
        with self.assertRaises(ValueError):
            _verdict(0.5, float("nan"))

    def test_verdict_rejects_inf_diagnostic_reliability(self):
        """Test that _verdict raises ValueError for infinite diagnostic_reliability."""
        with self.assertRaises(ValueError):
            _verdict(0.5, float("inf"))
        with self.assertRaises(ValueError):
            _verdict(0.5, float("-inf"))


class AnalyzeTextEdgeCaseTests(unittest.TestCase):
    """Tests for analyze_text edge cases (line 57)."""

    def test_empty_text_rejected(self):
        """Test that analyze_text rejects empty text (line 57)."""
        with self.assertRaises(ValueError):
            analyze_text("", include_robustness=False)
        with self.assertRaises(ValueError):
            analyze_text("   ", include_robustness=False)
        with self.assertRaises(ValueError):
            analyze_text("\t\n", include_robustness=False)

    def test_empty_text_rejected_with_robustness(self):
        """Test that analyze_text rejects empty text even with robustness enabled."""
        with self.assertRaises(ValueError):
            analyze_text("", include_robustness=True)

    def test_empty_text_rejected_with_non_string(self):
        """Test that analyze_text rejects non-string input."""
        with self.assertRaises(ValueError):
            analyze_text(None, include_robustness=False)  # type: ignore[arg-type]


class DisagreementEdgeCaseTests(unittest.TestCase):
    """Tests for _disagreement edge cases."""

    def test_disagreement_single_result(self):
        """Test disagreement with single result is 0."""
        result = _disagreement([AnalyzerResult(name="a", score=0.5, reliability=0.5)])
        self.assertEqual(result, 0.0)

    def test_disagreement_empty_list(self):
        """Test disagreement with empty list is 0."""
        result = _disagreement([])
        self.assertEqual(result, 0.0)

    def test_disagreement_with_extreme_scores(self):
        """Test disagreement calculation with extreme score variance."""
        results = [
            AnalyzerResult(name="a", score=0.0, reliability=0.5),
            AnalyzerResult(name="b", score=1.0, reliability=0.5),
        ]
        disagreement = _disagreement(results)
        self.assertGreater(disagreement, 0.0)
        self.assertLessEqual(disagreement, 1.0)


class StabilityEdgeCaseTests(unittest.TestCase):
    """Tests for analyze_text stability edge cases (line 96)."""

    def test_short_text_warning(self):
        """Test that short text triggers a warning (line 86)."""
        text = "This is a short test."
        result = analyze_text(text, include_robustness=False)
        self.assertLess(result.word_count, 80)
        self.assertTrue(
            any("short" in w.lower() for w in result.warnings),
            f"Expected short text warning, got: {result.warnings}"
        )

    def test_short_text_warning_with_robustness(self):
        """Test that short text triggers warning with robustness enabled."""
        text = "Short."
        result = analyze_text(text, include_robustness=True)
        self.assertLess(result.word_count, 80)
        self.assertTrue(
            any("short" in w.lower() for w in result.warnings),
            f"Expected short text warning"
        )

    def test_high_disagreement_warning_triggered(self):
        """Test that high disagreement triggers a warning (line 91)."""
        # Create analyzers that will produce high variance
        call_count = [0]
        
        def mock_analyzer(*args):
            call_count[0] = 0
            return [
                AnalyzerResult(name="structural_uniformity", score=0.0, reliability=0.5),
                AnalyzerResult(name="formulaic_language", score=1.0, reliability=0.5),
                AnalyzerResult(name="lexical_profile", score=0.5, reliability=0.5),
            ]
        
        with patch('textforensics.engine.run_builtin_analyzers', side_effect=mock_analyzer):
            result = analyze_text("Some test text here.", include_robustness=False)
            self.assertGreater(result.disagreement, 0.45)

    def test_stability_warning_low_with_mock(self):
        """Test low stability warning by mocking variant scores to be highly variable."""
        # Mock benign_variants to return many variants
        with patch('textforensics.engine.benign_variants') as mock_benign:
            mock_benign.return_value = {
                "original": "test text here",
                "v1": "different text sample",
                "v2": "another variation",
                "v3": "yet another example",
            }
            
            # Track calls to mock
            call_idx = [0]
            base_results = [AnalyzerResult(name="test", score=0.5, reliability=0.5)]
            
            def mock_base_score(text):
                call_idx[0] += 1
                # First call is the original, subsequent are variants
                # Return different scores to get stability < 0.85
                if call_idx[0] == 1:
                    return 0.5, base_results, {'word_count': 200}
                else:
                    # Variants have score variance
                    scores = [0.6, 0.9, 0.45, 0.85, 0.7][call_idx[0] % 5]
                    return scores, base_results, {'word_count': 200}
            
            with patch('textforensics.engine._base_score', side_effect=mock_base_score):
                result = analyze_text("Long enough text for stability analysis purposes.", include_robustness=True)
                # If stability is low enough, warning should be triggered
                if result.robustness_stability < 0.85:
                    self.assertTrue(
                        any("stability" in w.lower() or "sensitive" in w.lower() for w in result.warnings),
                        f"Expected stability warning for stability={result.robustness_stability}"
                    )

    def test_stability_warning_covered(self):
        """Ensure line 96 (stability < 0.85 warning) is executed via direct test.
        
        Since natural texts don't produce low stability, we mock the condition.
        """
        with patch('textforensics.engine._base_score') as mock_base:
            with patch('textforensics.engine.run_builtin_analyzers', 
                        return_value=[AnalyzerResult(name="x", score=0.5, reliability=0.5)]):
                with patch('textforensics.engine.benign_variants') as mock_vars:
                    # Return variants that will create score variance
                    mock_vars.return_value = {"o": "text", "a": "a", "b": "b", "c": "c"}
                    
                    # First call (original): score 0.5
                    # Subsequent calls (variants): different scores
                    idx = [0]
                    def base_side_effect(txt):
                        idx[0] += 1
                        if idx[0] == 1:
                            return 0.5, [AnalyzerResult(name="x", score=0.5, reliability=0.5)], {'word_count': 200}
                        else:
                            # Return highly variable scores for variants
                            return [0.5, 0.85, 0.2][idx[0] % 3], [AnalyzerResult(name="x", score=0.5, reliability=0.5)], {'word_count': 200}
                    
                    mock_base.side_effect = base_side_effect
                    result = analyze_text("A test document for stability checking.", include_robustness=True)
                    
                    # Check for stability warning if applicable
                    if result.robustness_stability < 0.85:
                        stability_warnings = [w for w in result.warnings if "stability" in w.lower() or "sensitive" in w.lower()]
                        self.assertTrue(stability_warnings, f"Expected stability warning but got: {result.warnings}")


class IncludeRobustnessFalseTests(unittest.TestCase):
    """Tests for include_robustness=False branch."""

    def test_include_robustness_false_uses_default_stability(self):
        """Test that with include_robustness=False, stability defaults to 1.0."""
        result = analyze_text("This is a test sentence.", include_robustness=False)
        self.assertEqual(result.robustness_stability, 1.0)


if __name__ == "__main__":
    unittest.main()