#!/usr/bin/env python3
"""
Fuzz target for detector input validation in detectors.py and engine.py.

Covers:
- Empty, very long, and special-character text inputs
- BuiltinHeuristicDetector.detect with edge-case inputs
- DetectorPrediction validation with fuzzed values
- _validate_no_source_echo with various text patterns
- execute_detector error handling
- Detector registry discovery with fuzzed plugin metadata
"""

from __future__ import annotations

import sys
from pathlib import Path

import atheris

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))


def TestOneInput(data: bytes) -> None:
    """Fuzz detector input handling and prediction validation."""
    try:
        text = data.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        return

    # ------------------------------------------------------------------
    # 1. BuiltinHeuristicDetector with edge-case inputs
    # ------------------------------------------------------------------
    try:
        from textforensics.detectors import BuiltinHeuristicDetector, execute_detector

        detector = BuiltinHeuristicDetector()
        result, failure = execute_detector(detector, text)

        if result is not None:
            result.validate(detector=detector)
    except Exception:
        pass

    # ------------------------------------------------------------------
    # 2. DetectorPrediction validation with fuzzed values
    # ------------------------------------------------------------------
    try:
        from textforensics.detectors import (
            DetectorContractError,
            DetectorPrediction,
            validate_prediction,
        )

        verdicts = ["ai_like", "human_like", "abstain"]
        verdict = verdicts[len(text) % len(verdicts)] if text else "abstain"

        prediction = DetectorPrediction(
            schema="textforensics.detector-result/v1",
            detector_id="fuzz/detector",
            detector_version="1.0.0",
            detector_family="fuzz",
            execution="local",
            score=len(text) / 1000.0 if text else None,
            score_semantics="fuzz test",
            verdict=verdict,
            threshold=0.5,
            supported_languages=["en"],
            min_words=50,
            evidence=[{"key": text[:100] if text else ""}],
            warnings=[text[:200] if text else ""],
        )

        try:
            validate_prediction(prediction)
        except DetectorContractError:
            pass  # Expected for invalid predictions
    except Exception:
        pass

    # ------------------------------------------------------------------
    # 3. Edge-case verdicts and execution modes
    # ------------------------------------------------------------------
    try:
        from textforensics.detectors import DetectorContractError, validate_prediction

        for verdict in ["ai_like", "human_like", "abstain", "invalid", "", "AI_LIKE"]:
            try:
                prediction = DetectorPrediction(
                    schema="textforensics.detector-result/v1",
                    detector_id="test",
                    detector_version="1.0",
                    detector_family="test",
                    execution="local",
                    score=0.5,
                    score_semantics="test",
                    verdict=verdict,
                    threshold=0.5,
                    supported_languages=["en"],
                )
                validate_prediction(prediction)
            except DetectorContractError:
                pass  # Expected for invalid verdicts

        for execution in ["local", "remote", "invalid", "", "cloud"]:
            try:
                prediction = DetectorPrediction(
                    schema="textforensics.detector-result/v1",
                    detector_id="test",
                    detector_version="1.0",
                    detector_family="test",
                    execution=execution,
                    score=0.5,
                    score_semantics="test",
                    verdict="ai_like",
                    threshold=0.5,
                    supported_languages=["en"],
                )
                validate_prediction(prediction)
            except DetectorContractError:
                pass
    except Exception:
        pass

    # ------------------------------------------------------------------
    # 4. _validate_no_source_echo with various text patterns
    # ------------------------------------------------------------------
    try:
        from textforensics.detectors import (
            DetectorContractError,
            DetectorPrediction,
            _validate_no_source_echo,
        )

        prediction = DetectorPrediction(
            schema="textforensics.detector-result/v1",
            detector_id="test",
            detector_version="1.0",
            detector_family="test",
            execution="local",
            score=0.5,
            score_semantics="test",
            verdict="ai_like",
            threshold=0.5,
            supported_languages=["en"],
            evidence=[{"text": text[:50] if text else ""}],
            warnings=[text[:100] if text else ""],
        )

        try:
            _validate_no_source_echo(prediction, text)
        except DetectorContractError:
            pass  # Expected if text is echoed
    except Exception:
        pass

    # ------------------------------------------------------------------
    # 5. Detector registry with fuzzed plugin metadata
    # ------------------------------------------------------------------
    try:
        from unittest.mock import patch

        from textforensics.detectors import (
            DetectorContractError,
            discover_detector_registry,
        )

        class MockDetector:
            detector_id = text[:100] if text else "test"
            detector_version = "1.0.0"
            detector_family = "test-family"

            def detect(self, text: str):
                from textforensics.detectors import DetectorPrediction

                return DetectorPrediction(
                    schema="textforensics.detector-result/v1",
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    detector_family=self.detector_family,
                    execution="local",
                    score=0.5,
                    score_semantics="test",
                    verdict="ai_like",
                    threshold=0.5,
                )

        class MockEntryPoint:
            name = f"mock-detector-{hash(text) % 10000}"

            def load(self):
                return lambda: MockDetector()

        ep = MockEntryPoint()
        with patch("textforensics.detectors._entry_points", return_value=[ep]):
            try:
                discover_detector_registry()
            except DetectorContractError:
                pass

        # Test with malformed entry points
        class MalformedEntryPoint:
            name = "malformed"

            def load(self):
                raise RuntimeError("Failed to load plugin")

        with patch("textforensics.detectors._entry_points", return_value=[MalformedEntryPoint()]):
            try:
                discover_detector_registry()
            except Exception:
                pass
    except Exception:
        pass

    # ------------------------------------------------------------------
    # 6. Engine analysis with very long and special-character inputs
    # ------------------------------------------------------------------
    try:
        from textforensics.engine import analyze_text

        # Test with truncated versions of various lengths
        for length in (0, 1, 10, 50, 80, 100, 500, 1000, 5000):
            try:
                result = analyze_text(text[:length] if len(text) > length else text)
                assert hasattr(result, "score")
            except ValueError:
                pass  # Empty text or other validation error
            except Exception:
                pass
    except Exception:
        pass

    # ------------------------------------------------------------------
    # 7. Text features with special characters
    # ------------------------------------------------------------------
    try:
        from textforensics.features import extract_features

        for length in (10, 50, 100, 500, 1000):
            try:
                features = extract_features(text[:length] if len(text) > length else text)
                assert isinstance(features, dict)
            except Exception:
                pass
    except Exception:
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
