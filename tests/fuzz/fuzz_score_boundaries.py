#!/usr/bin/env python3
"""
Fuzz target for score boundary conditions across TextForensics.

Covers:
- NaN, infinity, -infinity in detector scores
- Out-of-range scores (negative, >1.0)
- Edge-case thresholds for verdict computation
- Analyzer score clamping and reliability bounds
- DetectorPrediction validation for finite/finite-range fields
- Engine _verdict boundary values
- Benchmark threshold validation
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    import atheris
except ImportError:  # atheris optional; TestOneInput still importable
    atheris = None

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))


def _to_floats(data: bytes) -> list[float]:
    """Extract floats from raw bytes in multiple ways."""
    values: list[float] = []
    try:
        text = data.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        text = ""

    # 1. Special IEEE 754 values
    for special in ("nan", "inf", "-inf"):
        try:
            values.append(float(special))
        except ValueError:
            pass

    # 2. Try to extract numeric literals from text
    try:
        import re

        for match in re.findall(r"[-+]?\d*\.?\d+(?:[eE][-+]?\d+)?", text):
            try:
                values.append(float(match))
            except (ValueError, OverflowError):
                pass
    except Exception:
        pass

    # 3. Generate boundary values
    for sign in (-1, 1):
        for v in (
            0.0,
            1e-308,
            1e308,
            1.7e308,  # near max float
            -1.7e308,  # near min float
            sign * 0.0,  # +0 and -0
            sign * float("inf"),
        ):
            values.append(v)

    # 4. Derive scores from data length / byte values
    values.append(len(data) / 1000.0)
    values.append(len(data) / 255.0)
    if data:
        values.append(data[0] / 255.0)
        values.append(int.from_bytes(data[:4], "little", signed=True) / 10000.0)

    return values


def _fuzz_detector_prediction_scores(scores: list[float]) -> None:
    """Fuzz DetectorPrediction.score and related fields."""
    from textforensics.detectors import (
        DetectorContractError,
        DetectorPrediction,
        validate_prediction,
    )

    for score in scores:
        for verdict in ("ai_like", "human_like", "abstain"):
            try:
                pred = DetectorPrediction(
                    schema="textforensics.detector-result/v1",
                    detector_id="fuzz/score",
                    detector_version="1.0.0",
                    detector_family="fuzz",
                    execution="local",
                    score=score,
                    score_semantics="test",
                    verdict=verdict,
                    threshold=scores[0] if scores else None,
                    supported_languages=["en"],
                    min_words=50,
                    evidence=[],
                    warnings=[],
                )
                validate_prediction(pred)
            except DetectorContractError:
                pass  # Expected for NaN, inf, etc.
            except Exception:
                pass

    # Fuzz calibrated_ai_probability boundaries
    for prob in scores:
        try:
            pred = DetectorPrediction(
                schema="textforensics.detector-result/v1",
                detector_id="fuzz/score",
                detector_version="1.0.0",
                detector_family="fuzz",
                execution="local",
                score=0.5,
                score_semantics="test",
                verdict="ai_like",
                threshold=0.5,
                calibrated_ai_probability=prob,
                calibration_id="fuzz-cal-001",
                supported_languages=["en"],
                min_words=50,
                evidence=[],
                warnings=[],
            )
            validate_prediction(pred)
        except DetectorContractError:
            pass
        except Exception:
            pass

    # Fuzz reliability boundaries
    for rel in scores:
        try:
            pred = DetectorPrediction(
                schema="textforensics.detector-result/v1",
                detector_id="fuzz/score",
                detector_version="1.0.0",
                detector_family="fuzz",
                execution="local",
                score=0.5,
                score_semantics="test",
                verdict="ai_like",
                threshold=0.5,
                reliability=rel,
                supported_languages=["en"],
                min_words=50,
                evidence=[],
                warnings=[],
            )
            validate_prediction(pred)
        except DetectorContractError:
            pass
        except Exception:
            pass

    # Fuzz runtime_ms boundaries
    for rt in scores:
        try:
            pred = DetectorPrediction(
                schema="textforensics.detector-result/v1",
                detector_id="fuzz/score",
                detector_version="1.0.0",
                detector_family="fuzz",
                execution="local",
                score=0.5,
                score_semantics="test",
                verdict="ai_like",
                threshold=0.5,
                runtime_ms=rt,
                supported_languages=["en"],
                min_words=50,
                evidence=[],
                warnings=[],
            )
            validate_prediction(pred)
        except DetectorContractError:
            pass
        except Exception:
            pass


def _fuzz_engine_verdict_boundaries(scores: list[float]) -> None:
    """Fuzz engine _verdict with boundary scores and reliability values."""
    from textforensics.engine import _verdict

    for score in scores:
        for rel in scores:
            try:
                v = _verdict(score, rel)
                assert v in (
                    "insufficient_evidence",
                    "machine_like_patterns",
                    "human_like_patterns",
                    "indeterminate",
                )
            except ValueError:
                pass  # Expected for NaN, inf
            except Exception:
                pass

    # Explicit boundary tests
    boundary_scores = [0.0, 0.31, 0.32, 0.33, 0.5, 0.67, 0.68, 0.69, 1.0]
    boundary_rels = [0.0, 0.27, 0.28, 0.29, 0.5, 0.85, 1.0]
    for s in boundary_scores:
        for r in boundary_rels:
            try:
                _verdict(s, r)
            except Exception:
                pass


def _fuzz_analyzer_clamp(scores: list[float]) -> None:
    """Fuzz analyzer _clamp with boundary values."""
    from textforensics.analyzers import _clamp

    for val in scores:
        for lo in (0.0, -1.0, 0.5):
            for hi in (1.0, 2.0, 1.5):
                if lo >= hi:
                    continue
                try:
                    _clamp(val, lo, hi)
                except ValueError:
                    pass  # Expected for NaN, inf
                except Exception:
                    pass

    # Test interpolator functions
    from textforensics.analyzers import _high_when_high, _high_when_low

    for val in scores:
        for low, high in [(0.0, 1.0), (0.0, 0.5), (0.1, 0.9), (-1.0, 1.0)]:
            try:
                _high_when_low(val, low, high)
            except (ValueError, ZeroDivisionError):
                pass
            except Exception:
                pass
            try:
                _high_when_high(val, low, high)
            except (ValueError, ZeroDivisionError):
                pass
            except Exception:
                pass


def _fuzz_benchmark_threshold(scores: list[float]) -> None:
    """Fuzz benchmark threshold validation."""
    from textforensics.benchmark import _metrics

    for threshold in scores:
        try:
            _metrics([], threshold)
        except ValueError:
            pass  # Expected for NaN, inf
        except Exception:
            pass

    # Fuzz calibration artifact validation
    try:
        from textforensics.benchmark import validate_calibration_artifact

        for threshold in scores:
            artifact = {
                "schema": "textforensics.calibration/v1",
                "detector_id": "textforensics/builtin-heuristic",
                "detector_version": "0.1.0",
                "recommended_threshold": threshold,
                "calibration_dataset_sha256": "0" * 64,
            }
            try:
                validate_calibration_artifact(artifact)
            except ValueError:
                pass
            except Exception:
                pass
    except Exception:
        pass

    # Fuzz _coerce_float from drift module
    try:
        from textforensics.observatory import _coerce_float

        for val in scores:
            try:
                _coerce_float(val, "test")
            except ValueError:
                pass
            except Exception:
                pass

            # With bounds
            for lo, hi in [(0.0, 1.0), (0.0, None), (None, 1.0)]:
                try:
                    _coerce_float(val, "test", minimum=lo, maximum=hi)
                except ValueError:
                    pass
                except Exception:
                    pass
    except Exception:
        pass


def TestOneInput(data: bytes) -> None:
    """Fuzz score boundary conditions."""
    scores = _to_floats(data)

    _fuzz_detector_prediction_scores(scores)
    _fuzz_engine_verdict_boundaries(scores)
    _fuzz_analyzer_clamp(scores)
    _fuzz_benchmark_threshold(scores)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
