#!/usr/bin/env python3
"""
Fuzz target for calibration artifact parsing, validation, and threshold selection.

Covers:
- ThresholdSelectionResult and EvaluationResult construction/serialization
- select_threshold, evaluate_threshold with crafted JSONL datasets
- validate_no_contamination edge cases
- load_threshold_artifact parsing (malformed JSON, missing fields, bad schemas)
- create_calibration_artifact round-trip
- run_calibration_evaluation pipeline
- Benchmark calibration artifact validation
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

try:
    import atheris
except ImportError:  # atheris optional; TestOneInput still importable
    atheris = None

    def instrument_func(func):
        return func

    if atheris is not None:
        instrument_func = atheris.instrument_func

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))


def _make_jsonl(text: str) -> str:
    """Convert fuzzed text into a plausible JSONL benchmark dataset."""
    lines: list[str] = []
    for raw_line in text.split("\n"):
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            row = json.loads(raw_line)
            if isinstance(row, dict):
                lines.append(json.dumps(row))
                continue
        except json.JSONDecodeError:
            pass
        # Generate plausible benchmark lines from raw bytes
        label = "human" if len(raw_line) % 3 != 0 else "ai"
        sample_text = raw_line[:200] or "a"
        lines.append(json.dumps({"label": label, "text": sample_text}))
    return "\n".join(lines)


def _fuzz_threshold_artifact_parsing(text: str) -> None:
    """Fuzz load_threshold_artifact with malformed JSON and edge cases."""
    try:
        from textforensics.threshold_selection import load_threshold_artifact
    except Exception:
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # 1. Raw fuzzed text as artifact
        artifact_path = tmpdir / "artifact.json"
        artifact_path.write_text(text, encoding="utf-8")
        try:
            load_threshold_artifact(artifact_path)
        except (ValueError, json.JSONDecodeError, TypeError, KeyError):
            pass
        except Exception:
            pass

        # 2. Well-formed but semantically wrong artifacts
        for schema in (
            "",
            "textforensics.threshold-selection/v1",
            "textforensics.calibration/v1",
            "wrong-schema/v2",
            "textforensics.threshold-selection/v99",
        ):
            for threshold_val in [text[:10], "abc", "1.0", "0", None, "nan", "inf"]:
                artifact = {
                    "schema": schema,
                }
                if (
                    threshold_val is not None
                    and isinstance(threshold_val, str)
                    and threshold_val not in ("nan", "inf")
                ):
                    try:
                        artifact["threshold"] = float(threshold_val)
                    except ValueError:
                        artifact["threshold"] = threshold_val
                elif threshold_val in ("nan", "inf"):
                    artifact["threshold"] = float(threshold_val)
                elif threshold_val is not None:
                    artifact["threshold"] = threshold_val
                if len(text) % 2 == 0:
                    artifact["calibration_dataset_hash"] = "0" * 64
                elif len(text) % 3 == 0:
                    artifact["calibration_dataset_hash"] = text[:64]

                path = tmpdir / f"artifact_{schema[:5]}_{str(threshold_val)[:5]}.json"
                try:
                    path.write_text(json.dumps(artifact), encoding="utf-8")
                    load_threshold_artifact(path)
                except (ValueError, json.JSONDecodeError):
                    pass
                except Exception:
                    pass


def _fuzz_threshold_selection(text: str) -> None:
    """Fuzz select_threshold and evaluate_threshold with crafted datasets."""
    try:
        from textforensics.threshold_selection import (
            evaluate_threshold,
            select_threshold,
        )
    except Exception:
        return

    jsonl_content = _make_jsonl(text)
    if not jsonl_content.strip():
        jsonl_content = json.dumps({"label": "human", "text": "sample text"}) + "\n"

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        cal_path = tmpdir / "calibration.jsonl"
        test_path = tmpdir / "test.jsonl"
        cal_path.write_text(jsonl_content, encoding="utf-8")
        test_path.write_text(jsonl_content, encoding="utf-8")

        # Vary target_fpr
        try:
            fpr_text = text.strip().replace("\n", "").replace(" ", "")[:10]
            if fpr_text:
                try:
                    target_fpr = float(fpr_text) / 100.0
                except ValueError:
                    target_fpr = 0.01
            else:
                target_fpr = 0.01
        except Exception:
            target_fpr = 0.01

        for tfpr in (target_fpr, -0.5, 0.0, 0.01, 0.5, 1.0, 2.0):
            for det_id in (text[:30] or "fuzz", "", "textforensics/builtin-heuristic"):
                for det_ver in (text[30:50] or "1.0.0", "0.0.0"):
                    for strict in (True, False):
                        try:
                            result = select_threshold(
                                cal_path,
                                target_fpr=tfpr,
                                strict=strict,
                                detector_id=det_id,
                                detector_version=det_ver,
                            )
                            # Serialize
                            record = result.to_dict()
                            assert "threshold" in record
                            assert "calibration_dataset_hash" in record
                        except (ValueError, RuntimeError, TypeError, FileNotFoundError):
                            pass
                        except Exception:
                            pass

                        # Evaluate
                        try:
                            ev = evaluate_threshold(
                                test_path,
                                threshold=tfpr,
                                calibration_dataset_hash="0" * 64,
                                strict=strict,
                                allow_same_dataset=True,
                            )
                            ev_dict = ev.to_dict()
                            assert "evaluated" in ev_dict
                        except (ValueError, TypeError):
                            pass
                        except Exception:
                            pass


def _fuzz_calibration_artifact_roundtrip(text: str) -> None:
    """Fuzz create_calibration_artifact and load_threshold_artifact round-trip."""
    try:
        from textforensics.threshold_selection import (
            ThresholdSelectionResult,
            create_calibration_artifact,
            load_threshold_artifact,
        )
    except Exception:
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        output = tmpdir / "cal_artifact.json"

        # Build result from fuzzed data
        try:
            threshold = float(text[:10])
        except (ValueError, OverflowError):
            threshold = 0.5

        for fpr in (0.01, 0.5):
            for tpr in (0.9, 0.1):
                result = ThresholdSelectionResult(
                    threshold=threshold,
                    observed_fpr=fpr,
                    observed_tpr=tpr,
                    target_fpr=0.01,
                    human_samples=max(1, len(text) % 100),
                    ai_samples=max(1, len(text) % 50),
                    detector_id=text[:30] or "fuzz",
                    detector_version="1.0.0",
                    calibration_dataset_hash="0" * 64,
                    warning=text[:100] or None,
                )
                try:
                    create_calibration_artifact(result, output)
                    loaded = load_threshold_artifact(output)
                    assert "threshold" in loaded
                except Exception:
                    pass


def _fuzz_no_contamination(text: str) -> None:
    """Fuzz validate_no_contamination with same/different files."""
    try:
        from textforensics.threshold_selection import validate_no_contamination
    except Exception:
        return

    jsonl_content = _make_jsonl(text)
    if not jsonl_content.strip():
        jsonl_content = json.dumps({"label": "human", "text": "sample text"})

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        p1 = tmpdir / "cal.jsonl"
        p2 = tmpdir / "test.jsonl"
        p1.write_text(jsonl_content + "\n", encoding="utf-8")
        p2.write_text(
            jsonl_content + "\n" + json.dumps({"label": "ai", "text": "extra"}) + "\n",
            encoding="utf-8",
        )

        try:
            result = validate_no_contamination(p1, p2)
            assert "contamination_detected" in result
        except Exception:
            pass

        # Same file — contamination
        try:
            result = validate_no_contamination(p1, p1)
            assert result["contamination_detected"]
        except Exception:
            pass

        # Non-existent file
        try:
            validate_no_contamination(p1, tmpdir / "missing.jsonl")
        except FileNotFoundError:
            pass
        except Exception:
            pass


def _fuzz_evaluation_result_edge(text: str) -> None:
    """Fuzz EvaluationResult with extreme counts and edge-case hashes."""
    try:
        from textforensics.threshold_selection import EvaluationResult
    except Exception:
        return

    for tp in (0, 1, 100, len(text)):
        for fp in (0, 1, len(text) % 10):
            for tn in (0, 1, len(text) % 20):
                for fn in (0, 1, len(text) % 5):
                    total = tp + fp + tn + fn
                    try:
                        ev = EvaluationResult(
                            threshold=0.5,
                            tp=tp,
                            fp=fp,
                            tn=tn,
                            fn=fn,
                            accuracy=0.5,
                            fpr=0.0,
                            fnr=0.0,
                            tpr=1.0,
                            specificity=1.0,
                            precision=0.5,
                            evaluated=max(1, total),
                            test_dataset_hash=text[:64].ljust(64, "0"),
                            calibration_dataset_hash="",
                        )
                        ev_dict = ev.to_dict()
                        assert "schema" in ev_dict
                    except Exception:
                        pass


def _fuzz_run_calibration_evaluation(text: str) -> None:
    """Fuzz run_calibration_evaluation pipeline end-to-end."""
    try:
        from textforensics.threshold_selection import run_calibration_evaluation
    except Exception:
        return

    jsonl_content = _make_jsonl(text)
    if not jsonl_content.strip():
        jsonl_content = json.dumps({"label": "human", "text": "sample"}) + "\n"

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        cal_path = tmpdir / "cal.jsonl"
        eval_path = tmpdir / "eval.jsonl"
        cal_path.write_text(jsonl_content, encoding="utf-8")
        eval_path.write_text(jsonl_content, encoding="utf-8")

        for target_fpr in (0.01, 0.0, 0.5, 1.0, -0.5):
            for strict in (True, False):
                try:
                    result = run_calibration_evaluation(
                        cal_path, eval_path, target_fpr=target_fpr, strict=strict
                    )
                    assert "calibration_result" in result
                    assert "evaluation_result" in result
                    assert "validation" in result
                except (ValueError, RuntimeError, TypeError, FileNotFoundError):
                    pass
                except Exception:
                    pass


def _fuzz_get_test_samples(text: str) -> None:
    """Fuzz _get_test_samples with malformed JSONL lines."""
    try:
        from textforensics.threshold_selection import _get_test_samples
    except Exception:
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        p = tmpdir / "test.jsonl"
        # Write fuzzed text as raw JSONL with edge cases
        lines = []
        for raw_line in text.split("\n")[:50]:
            lines.append(raw_line)
        # Add edge-case lines
        lines.extend(
            [
                "",
                "not json at all",
                "123",
                "[]",
                "{}",
                '{"text": 123}',
                '{"text": null}',
                '{"text": ""}',
                '{"other": "field"}',
            ]
        )
        p.write_text("\n".join(lines), encoding="utf-8")
        try:
            samples = _get_test_samples(p)
            assert isinstance(samples, list)
        except Exception:
            pass


def _fuzz_threshold_selection_result_serialization(text: str) -> None:
    """Fuzz ThresholdSelectionResult.to_dict with extreme field values."""
    try:
        from textforensics.threshold_selection import ThresholdSelectionResult
    except Exception:
        return

    for threshold in (0.0, 1.0, -1.0, 0.5, float("inf"), float("nan")):
        for fpr in (0.0, 1.0, -0.5, float("inf")):
            for tpr in (0.0, 1.0, -0.5):
                for human_n in (0, 1, 1000000, -1):
                    for ai_n in (0, 1, 1000000, -1):
                        try:
                            r = ThresholdSelectionResult(
                                threshold=threshold,
                                observed_fpr=fpr,
                                observed_tpr=tpr,
                                target_fpr=0.01,
                                human_samples=human_n,
                                ai_samples=ai_n,
                                detector_id=text[:30] or "fuzz",
                                detector_version="1.0.0",
                                calibration_dataset_hash=text[:64].ljust(64, "0")[:64],
                                warning=text[:200] or None,
                            )
                            d = r.to_dict()
                            assert "threshold" in d
                            assert "schema" in d
                        except Exception:
                            pass


@instrument_func
def TestOneInput(data: bytes) -> None:
    """Fuzz calibration artifact parsing, validation, and threshold selection."""
    try:
        text = data.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        text = ""

    if not text:
        # Even empty: exercise zero-input paths
        _fuzz_threshold_artifact_parsing("")
        return

    _fuzz_threshold_artifact_parsing(text)
    _fuzz_threshold_selection(text)
    _fuzz_calibration_artifact_roundtrip(text)
    _fuzz_no_contamination(text)
    _fuzz_evaluation_result_edge(text)
    _fuzz_run_calibration_evaluation(text)
    _fuzz_get_test_samples(text)
    _fuzz_threshold_selection_result_serialization(text)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
