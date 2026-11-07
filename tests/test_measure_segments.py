"""Tests for scripts/measure_segments.py slice metrics.

No network is used here: only the pure slice functions are tested
on synthetic segment dicts. The live run is covered by the script's
own run, whose artifact is the evidence.
"""

import importlib.util
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"


def _load_segments_module():
    spec = importlib.util.spec_from_file_location(
        "measure_segments", SCRIPTS_DIR / "measure_segments.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["measure_segments"] = module
    spec.loader.exec_module(module)
    return module


def _seg(label, score, verdict):
    return {"label": label, "score": score, "verdict": verdict}


def test_single_class_all_human_slice():
    """v0 is all-human by construction: AUROC undefined, native FPR 0.0."""
    measure = _load_segments_module()
    segments = [
        _seg(0, 0.2, "human_like"),
        _seg(0, 0.4, "abstain"),
        _seg(0, 0.1, "human_like"),
    ]
    result = measure._slice_metrics(segments)
    assert result["n_segments"] == 3
    assert result["n_human_segments"] == 3
    assert result["n_ai_segments"] == 0
    assert result["auroc"]["value"] is None
    assert "single-class" in result["auroc"]["note"]
    assert result["tpr_at_1pct_fpr"]["value"] is None
    assert result["fpr_native"]["value"] == 0.0
    assert result["tpr_native"]["value"] is None
    assert result["coverage"] == 0.6667
    assert result["prf1_at_operating_point"]["recall"] is None


def test_single_class_all_ai_slice():
    """v8 is all-AI by construction: AUROC undefined, native TPR 0.0."""
    measure = _load_segments_module()
    segments = [
        _seg(1, 0.5, "abstain"),
        _seg(1, 0.4, "abstain"),
        _seg(1, 0.2, "human_like"),
    ]
    result = measure._slice_metrics(segments)
    assert result["auroc"]["value"] is None
    assert result["tpr_native"]["value"] == 0.0
    assert result["fpr_native"]["value"] is None
    assert result["prf1_at_operating_point"]["recall"] == 0.0
    assert result["prf1_at_operating_point"]["precision"] is None
    assert result["prf1_at_operating_point"]["f1"] is None


def test_f1_undefined_when_no_ai_prediction():
    """Mixed labels but no ai_like verdict: F1 undefined, AUROC defined."""
    measure = _load_segments_module()
    segments = [
        _seg(0, 0.2, "human_like"),
        _seg(0, 0.4, "abstain"),
        _seg(1, 0.5, "abstain"),
        _seg(1, 0.3, "human_like"),
    ]
    result = measure._slice_metrics(segments)
    assert result["auroc"]["value"] is not None
    prf1 = result["prf1_at_operating_point"]
    assert prf1["precision"] is None
    assert prf1["recall"] == 0.0
    assert prf1["f1"] is None
    assert prf1["f1_ci_lower"] is None
    assert "0.68 operating point" in prf1["f1_ci_note"]
