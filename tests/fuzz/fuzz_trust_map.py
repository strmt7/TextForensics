#!/usr/bin/env python3
"""
Fuzz target for trust map computation in trust.py
"""

import sys
import json

import atheris

from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))


def TestOneInput(data: bytes) -> None:
    """Fuzz trust map computation and dimension calculations."""
    try:
        text = data.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        return

    from textforensics.trust import (
        build_trust_map,
        TrustMap,
        TrustDimension,
        TRUST_STATES,
    )
    from textforensics.detectors import DetectorPrediction

    # Test with fuzzed prediction inputs
    try:
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
            supported_languages=["en"] if text else [],
            min_words=len(text) if text else None,
            evidence=[{"analyzer": "test", "score": 0.5, "reliability": 0.8}],
            warnings=[text[:100] if text else ""],
        )

        # Test build_trust_map
        robust_data = [
            {
                "detector_id": "test",
                "verdict_stability": 1.0,
                "native_score_range": [0.3, 0.7],
            }
        ]

        result = build_trust_map(
            [prediction],
            word_count=len(text.split()) if text else 100,
            robustness=robust_data,
            failure_count=0,
        )

        # Verify the result
        _ = result.to_dict()
    except Exception:
        pass

    # Test with empty predictions
    try:
        result = build_trust_map(
            [],
            word_count=100,
            robustness=[],
            failure_count=0,
        )
        _ = result.to_dict()
    except Exception:
        pass

    # Test with multiple predictions of different detector families
    try:
        predictions = []
        for i in range(5):
            verdict = verdicts[i % len(verdicts)]
            pred = DetectorPrediction(
                schema="textforensics.detector-result/v1",
                detector_id=f"test/detector{i}",
                detector_version="1.0.0",
                detector_family=f"family{i % 3}",
                execution="local",
                score=0.5 + i * 0.1,
                score_semantics="test",
                verdict=verdict,
                threshold=0.5,
                supported_languages=["en"],
                min_words=50,
                evidence=[],
                warnings=[],
            )
            predictions.append(pred)

        result = build_trust_map(
            predictions,
            word_count=100,
            robustness=robust_data,
            failure_count=0,
        )

        _ = result.to_dict()
    except Exception:
        pass

    # Test TrustDimension creation with fuzzed values
    try:
        dimensions = [
            TrustDimension(
                dimension=d if isinstance(d, str) else str(d)[:50],
                state=s if s in TRUST_STATES else "unknown",
                reason=text[:200] if text else "test reason",
                evidence_refs=[],
                observed={},
                limitations=[],
            )
            for d in ["language", "text_length", "domain_genre", "editing_revision", "human_false_positive_evidence", "detector_diversity", "benign_stability", "temporal_version_stability"]
            for s in TRUST_STATES
        ]

        trust_map = TrustMap(
            schema="textforensics.trust-map/v1",
            overall="mixed",
            dimensions=dimensions,
            limitations=[],
        )

        _ = trust_map.to_dict()
    except Exception:
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()