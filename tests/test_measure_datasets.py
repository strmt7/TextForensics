"""Tests for scripts/measure_datasets.py metric helpers and sample plan.

No network is used here: only the pure functions (AUROC, TPR@FPR, score
summary) and the static sample plan are tested. Live fetching is
covered by the script's own runs, whose artifacts are the evidence.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"


def _load_measure_module():
    spec = importlib.util.spec_from_file_location(
        "measure_datasets", SCRIPTS_DIR / "measure_datasets.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["measure_datasets"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def measure():
    return _load_measure_module()


def test_auroc_perfect_and_inverted(measure):
    assert measure.auroc([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9]) == 1.0
    assert measure.auroc([0, 0, 1, 1], [0.8, 0.9, 0.1, 0.2]) == 0.0


def test_auroc_ties_count_half(measure):
    assert measure.auroc([0, 1], [0.5, 0.5]) == 0.5
    # One win, one tie out of four pairs.
    assert measure.auroc([0, 0, 1, 1], [0.1, 0.5, 0.5, 0.9]) == 0.875


def test_auroc_needs_both_classes(measure):
    with pytest.raises(ValueError):
        measure.auroc([1, 1], [0.5, 0.6])


def test_tpr_at_fpr_perfect_separation(measure):
    labels = [0, 0, 1, 1]
    scores = [0.1, 0.2, 0.8, 0.9]
    assert measure.tpr_at_fpr(labels, scores, 0.01) == 1.0
    assert measure.tpr_at_fpr(labels, scores, 0.05) == 1.0


def test_tpr_at_fpr_unattainable_target_is_zero(measure):
    # The top score belongs to a human row, so no threshold keeps
    # FPR <= 1% with any true positive.
    labels = [0, 0, 0, 1, 1]
    scores = [0.9, 0.2, 0.1, 0.8, 0.3]
    assert measure.tpr_at_fpr(labels, scores, 0.01) == 0.0
    assert measure.tpr_at_fpr(labels, scores, 0.05) == 0.0
    # At FPR <= 50% the threshold 0.3 catches both machine rows.
    assert measure.tpr_at_fpr(labels, scores, 0.5) == 1.0


def test_tpr_at_fpr_needs_both_classes(measure):
    with pytest.raises(ValueError):
        measure.tpr_at_fpr([0, 0], [0.1, 0.2], 0.05)


def test_score_summary(measure):
    summary = measure._score_summary([0.1, 0.2, 0.3])
    assert summary == {"n": 3, "mean": 0.2, "median": 0.2, "min": 0.1, "max": 0.3}
    # A one-sided sample must not crash the measurement: it is recorded
    # with n=0 and null statistics (RAID first-200 was all-human).
    assert measure._score_summary([]) == {
        "n": 0,
        "mean": None,
        "median": None,
        "min": None,
        "max": None,
    }


def test_sample_plan_covers_verified_datasets_only(measure):
    plan = measure.SAMPLE_PLAN
    assert sorted(plan) == ["beemo", "ghostwriter", "mage", "opai_bench", "raid"]
    # MixSet is absent by design (licence unresolved).
    assert "mixset" not in plan
    # Split totals are the verified datasets-server /size figures.
    assert plan["raid"]["total"] == 2_270_000
    assert plan["mage"]["total"] == 319_071
    assert plan["beemo"]["total"] == 2_187
    assert plan["opai_bench"]["total"] == 196_029
    # GhostWriter counts verified 2026-11-07 (total 474,904).
    assert plan["ghostwriter"]["total"] == 332_224
    assert plan["ghostwriter"]["disjoint"]["total"] == 47_548
    assert plan["ghostwriter"]["n"] == 500
    assert plan["ghostwriter"]["disjoint"]["n"] == 50
    # U1 grown sample sizes (plan change, 2026-11-06): RAID 3000 strided
    # for ~100 humans, MAGE 400, OpAI-Bench 500; Beemo unchanged.
    assert plan["raid"]["n"] == 3000
    assert plan["mage"]["n"] == 400
    assert plan["beemo"]["n"] == 100
    assert plan["opai_bench"]["n"] == 500
    for entry in plan.values():
        assert entry["method"] in ("first", "strided")
        assert entry["n"] > 0
