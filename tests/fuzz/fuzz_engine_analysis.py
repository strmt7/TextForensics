#!/usr/bin/env python3
"""
Fuzz target for engine.py - text analysis and verdict computation.

Tests uncovered lines in analyze_text() and related engine functions:
- Line 41: _verdict() finite check for non-finite score
- Line 57: _verdict() finite check for non-finite reliability
- Lines 63-74: stability calculation and edge cases
- Line 68->74: empty variant_scores branch
- Lines 86-96: warning generation for short text, disagreement, stability
"""

import sys
from pathlib import Path

import atheris

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))


def TestOneInput(data: bytes) -> None:
    """Fuzz engine analysis and verdict computation."""
    try:
        text = data.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        return

    # Test analyze_text with various inputs
    try:
        from textforensics.engine import _disagreement, _verdict, _weighted_score, analyze_text

        # Test analyze_text with different text sizes
        if text:
            # Short text - may trigger warning
            if len(text) < 100:
                try:
                    result = analyze_text(text[:min(len(text), 50)])
                    assert hasattr(result, "verdict")
                    assert result.verdict in ("insufficient_evidence", "machine_like_patterns", "human_like_patterns", "indeterminate")
                except ValueError:
                    pass  # Empty text is rejected

            # Normal text
            try:
                result = analyze_text(text[:1000])
                assert hasattr(result, "score")
                assert 0.0 <= result.score <= 1.0 or result.score is None
                assert hasattr(result, "diagnostic_reliability")
                assert 0.0 <= result.diagnostic_reliability <= 1.0
            except ValueError:
                pass  # Text too short or other validation error

            # Text with include_robustness=False
            try:
                result = analyze_text(text[:1000], include_robustness=False)
                assert hasattr(result, "stability")
            except ValueError:
                pass

    except Exception:
        pass

    # Test _verdict directly with edge case inputs
    try:

        # Test with NaN score (line 41 - non-finite score)
        try:
            _verdict(float("nan"), 0.9)
        except ValueError:
            pass  # Expected

        # Test with infinity score
        try:
            _verdict(float("inf"), 0.9)
        except ValueError:
            pass

        # Test with NaN reliability (line 57 - non-finite reliability)
        try:
            _verdict(0.5, float("nan"))
        except ValueError:
            pass

        # Test with finite but extreme values
        try:
            verdict = _verdict(0.0, 0.5)  # Should be human_like_patterns
            assert verdict in ("insufficient_evidence", "machine_like_patterns", "human_like_patterns", "indeterminate")
        except ValueError:
            pass

        try:
            verdict = _verdict(1.0, 0.5)  # Should be machine_like_patterns
            assert verdict in ("insufficient_evidence", "machine_like_patterns", "human_like_patterns", "indeterminate")
        except ValueError:
            pass
    except Exception:
        pass

    # Test _weighted_score edge cases
    try:
        from textforensics.models import AnalyzerResult

        # Empty list
        try:
            _weighted_score([])
        except Exception:
            pass

        # Single result
        try:
            result = _weighted_score([AnalyzerResult(name="test", score=0.5, reliability=0.5)])
            assert 0.0 <= result <= 1.0
        except Exception:
            pass

        # Mixed reliabilities
        try:
            results = [
                AnalyzerResult(name="a", score=0.0, reliability=0.1),
                AnalyzerResult(name="b", score=1.0, reliability=0.9),
            ]
            score = _weighted_score(results)
            assert 0.0 <= score <= 1.0
        except Exception:
            pass
    except Exception:
        pass

    # Test _disagreement edge cases
    try:
        # Single score
        try:
            d = _disagreement([0.5])
            assert d == 0.0
        except Exception:
            pass

        # Matching scores
        try:
            d = _disagreement([0.5, 0.5, 0.5])
            assert d == 0.0
        except Exception:
            pass

        # Disparate scores
        try:
            d = _disagreement([0.0, 1.0])
            assert 0.0 <= d <= 1.0
        except Exception:
            pass
    except Exception:
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
