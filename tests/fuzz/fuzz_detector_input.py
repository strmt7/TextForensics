#!/usr/bin/env python3
"""
Fuzz target for detector input handling in detectors.py
"""

import sys
import atheris


def TestOneInput(data: bytes) -> None:
    """Fuzz detector input handling and prediction validation."""
    try:
        text = data.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        return

    # Test BuiltinHeuristicDetector
    try:
        from textforensics.detectors import BuiltinHeuristicDetector, execute_detector

        detector = BuiltinHeuristicDetector()
        result, failure = execute_detector(detector, text)

        if result is not None:
            # Verify the prediction
            result.validate(detector=detector)
    except Exception:
        pass

    # Test DetectorPrediction validation with various inputs
    try:
        from textforensics.detectors import DetectorPrediction, validate_prediction, DetectorContractError

        # Create predictions with fuzzer-derived values
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

    # Test validate_prediction with edge cases
    try:
        from textforensics.detectors import validate_prediction, DetectorContractError

        # Test with various verdict values
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
    except Exception:
        pass

    # Test _validate_no_source_echo
    try:
        from textforensics.detectors import _validate_no_source_echo, DetectorContractError

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


def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()