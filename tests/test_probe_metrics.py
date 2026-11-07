"""Tests for the pure per-run drift metrics (U3, corpus half).

All fixtures are synthetic with hand-computed expectations — no live
data, no network, no cache. Where a value is derived by hand, the
arithmetic is in the comment next to it.
"""

from __future__ import annotations

import pytest

from textforensics import probe_metrics as pm


def test_wilson_ci_known_values():
    # 0/50: upper = z^2 / (n + z^2) = 3.8416 / 53.8416 ≈ 0.07135.
    lo, hi = pm.wilson_ci(0, 50)
    assert lo == 0.0
    assert hi == pytest.approx(0.07135, abs=1e-4)
    # 25/50: centre 0.5, half-width ≈ 0.1336.
    lo, hi = pm.wilson_ci(25, 50)
    assert lo == pytest.approx(0.3664, abs=1e-3)
    assert hi == pytest.approx(0.6336, abs=1e-3)
    # 50/50: lower = n / (n + z^2) = 50 / 53.8416 ≈ 0.92865.
    lo, hi = pm.wilson_ci(50, 50)
    assert lo == pytest.approx(0.92865, abs=1e-4)
    assert hi == 1.0
    with pytest.raises(ValueError):
        pm.wilson_ci(3, 2)
    with pytest.raises(ValueError):
        pm.wilson_ci(0, 0)


def test_ks_statistic_and_pvalue():
    assert pm.ks_statistic([1, 2, 3], [1, 2, 3]) == 0.0
    assert pm.ks_pvalue(0.0, 10, 10) == 1.0
    # Fully separated samples: max CDF gap is 1.
    assert pm.ks_statistic([0, 0, 0], [1, 1, 1]) == 1.0
    assert pm.ks_pvalue(1.0, 50, 50) == pytest.approx(0.0, abs=1e-9)
    # Half the mass differs: samples [0]*5+[1]*5 vs [0]*10 → D = 0.5.
    assert pm.ks_statistic([0] * 5 + [1] * 5, [0] * 10) == pytest.approx(0.5)
    # A large D on decent samples must be significant.
    assert pm.ks_pvalue(0.5, 50, 50) < 0.001
    # A tiny D on small samples must not be significant.
    assert pm.ks_pvalue(0.05, 20, 20) > 0.5
    with pytest.raises(ValueError):
        pm.ks_statistic([], [1.0])
    with pytest.raises(ValueError):
        pm.ks_pvalue(1.5, 10, 10)


def test_psi_identical_is_zero_and_shift_is_positive():
    ref = [float(i) for i in range(100)]
    assert pm.psi(ref, list(ref)) == pytest.approx(0.0, abs=1e-9)
    shifted = [x + 50.0 for x in ref]
    assert pm.psi(ref, shifted) > 0.2  # a large shift breaches "investigate"
    # A small shift stays below the 0.1 "stable" line.
    nudged = [x + 2.0 for x in ref]
    assert pm.psi(ref, nudged) < 0.1
    with pytest.raises(ValueError):
        pm.psi([], [1.0])


def test_flip_summary_direction_breakdown():
    prev = ["human_like", "human_like", "ai_like", "ai_like", "human_like", "abstain"]
    curr = ["ai_like", "human_like", "human_like", "ai_like", "abstain", "human_like"]
    out = pm.flip_summary(prev, curr)
    assert out["n"] == 6
    assert out["flips"] == 4
    assert out["flip_rate"] == pytest.approx(4 / 6)
    assert out["human_to_ai"] == 1  # the FPR-direction flip
    assert out["ai_to_human"] == 1
    assert out["to_abstain"] == 1
    assert out["from_abstain"] == 1
    lo, hi = out["flip_rate_ci"]
    assert 0.0 <= lo < float(out["flip_rate"]) < hi <= 1.0
    # No flips at all.
    same = pm.flip_summary(["ai_like"] * 5, ["ai_like"] * 5)
    assert same["flips"] == 0 and same["flip_rate"] == 0.0
    with pytest.raises(ValueError):
        pm.flip_summary(["ai_like"], ["ai_like", "human_like"])
    with pytest.raises(ValueError):
        pm.flip_summary(["weird"], ["ai_like"])


def test_ece_and_brier():
    # Perfect calibration: probs 0/1 matching labels exactly.
    assert pm.ece([0.0, 0.0, 1.0, 1.0], [0, 0, 1, 1]) == pytest.approx(0.0)
    assert pm.brier([0.0, 0.0, 1.0, 1.0], [0, 0, 1, 1]) == pytest.approx(0.0)
    # Constant 0.5 on a balanced set: Brier = 0.25, ECE = 0.
    assert pm.brier([0.5] * 4, [0, 0, 1, 1]) == pytest.approx(0.25)
    assert pm.ece([0.5] * 4, [0, 0, 1, 1]) == pytest.approx(0.0)
    # Fully wrong confident predictions: Brier = 1, ECE = 1.
    assert pm.brier([1.0, 1.0, 0.0, 0.0], [0, 0, 1, 1]) == pytest.approx(1.0)
    assert pm.ece([1.0, 1.0, 0.0, 0.0], [0, 0, 1, 1]) == pytest.approx(1.0)
    with pytest.raises(ValueError):
        pm.ece([1.5], [1])
    with pytest.raises(ValueError):
        pm.brier([0.5], [2])


def test_set_coverage_and_shortfall():
    sets = [{0}, {0, 1}, {1}, set()]
    out = pm.set_coverage(sets, [0, 1, 1, 0])
    assert out == {"covered": 3, "n": 4, "rate": 0.75}
    assert pm.coverage_shortfall_pp(0.75, 0.90) == pytest.approx(15.0)
    assert pm.coverage_shortfall_pp(0.95, 0.90) == pytest.approx(-5.0)


def test_fpr_at_threshold_and_worst_slice():
    scores = [0.1, 0.2, 0.9, 0.95]  # humans first two, machines last two
    labels = [0, 0, 1, 1]
    out = pm.fpr_at_threshold(scores, labels, 0.5)
    assert out == {
        "n_human": 2,
        "false_positives": 0,
        "fpr": 0.0,
        "fpr_ci": pm.wilson_ci(0, 2),
    }
    out = pm.fpr_at_threshold(scores, labels, 0.15)
    assert out["false_positives"] == 1 and out["fpr"] == pytest.approx(0.5)
    worst = pm.worst_slice_fpr(
        {
            "human-native": pm.fpr_at_threshold(scores, labels, 0.5),
            "human-short": pm.fpr_at_threshold(scores, labels, 0.15),
        }
    )
    assert worst["slice"] == "human-short"
    assert worst["fpr"] == pytest.approx(0.5)
    with pytest.raises(ValueError):
        pm.fpr_at_threshold([0.1], [1], 0.5)  # no human items
    with pytest.raises(ValueError):
        pm.worst_slice_fpr({})


def test_tpr_at_fpr_matches_repo_convention():
    # Perfectly separated: every machine score above every human score.
    # Target 1% FPR on 100 humans → threshold = the top human score
    # (1 human at/above it → FPR exactly 0.01), TPR 1.0.
    humans = [i / 100.0 for i in range(100)]
    machines = [1.0 + i / 100.0 for i in range(100)]
    out = pm.tpr_at_fpr(humans + machines, [0] * 100 + [1] * 100, target_fpr=0.01)
    assert out["achieved_fpr"] <= 0.01
    assert out["tpr"] == pytest.approx(1.0)
    # Overlapping scores: machines uniform on [0, 2], humans on [0, 1].
    # The 1% threshold sits near the top human score; TPR ≈ 0.5.
    humans = [i / 99.0 for i in range(100)]
    machines = [2.0 * i / 99.0 for i in range(100)]
    out = pm.tpr_at_fpr(humans + machines, [0] * 100 + [1] * 100, target_fpr=0.01)
    assert out["achieved_fpr"] <= 0.01
    assert out["tpr"] == pytest.approx(0.5, abs=0.02)
    with pytest.raises(ValueError):
        pm.tpr_at_fpr([0.1], [0], target_fpr=0.01)  # no machine items


def test_abstention_rate_and_metadata_diff():
    out = pm.abstention_rate(["ai_like", "abstain", "human_like", "abstain"])
    assert out == {"n": 4, "abstained": 2, "rate": 0.5}
    diff = pm.metadata_diff(
        {"detector_version": "0.1.0", "model_id": "a", "api_version": "v1"},
        {"detector_version": "0.2.0", "model_id": "a", "api_version": "v1"},
    )
    assert diff == {"detector_version": ("0.1.0", "0.2.0")}
    assert pm.metadata_diff({"a": 1}, {"a": 1}) == {}
    # A removed key is a diff (None on the missing side).
    assert pm.metadata_diff({"a": 1, "b": 2}, {"a": 1}) == {"b": (2, None)}


def test_holm_adjusted_known_values():
    # p = [0.01, 0.04, 0.03] → sorted [0.01, 0.03, 0.04];
    # adjusted sorted: 0.01*3=0.03, max(0.03, 0.03*2)=0.06,
    # max(0.06, 0.04*1)=0.06 → back in input order [0.03, 0.06, 0.06].
    assert pm.holm_adjusted([0.01, 0.04, 0.03]) == pytest.approx([0.03, 0.06, 0.06])
    assert pm.holm_adjusted([0.5]) == [0.5]
    with pytest.raises(ValueError):
        pm.holm_adjusted([])
    with pytest.raises(ValueError):
        pm.holm_adjusted([1.2])
