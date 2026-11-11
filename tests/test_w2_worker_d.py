"""W2 Worker D regression tests — S07/S09/S10/S21/S22 (audit wave W2).

All fixtures are synthetic. Expected values come from the audit digest's
independent oracles and the stated acceptance criteria, not from current
product output. Written red-first against main f1d8c83.
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from textforensics import probe_metrics as pm
from textforensics.model_card import ModelCard
from textforensics.probe_runs import (
    ProbeRunError,
    _records_from_series,
    _series_from_records,
    compute_run_metrics,
    evaluate_tiers,
)
from textforensics.result_codec import (
    CodecError,
    ResultCodec,
    decode_result,
    encode_result,
    validate_result,
)

# ---------------------------------------------------------------------------
# Shared synthetic builders
# ---------------------------------------------------------------------------


def _rec(item_id, *, score, verdict, cal=None, cal_id=None, direction=None):
    record = {
        "sample_id": item_id,
        "score": score,
        "verdict": verdict,
        "calibrated_ai_probability": cal,
        "calibration_id": cal_id,
    }
    if direction is not None:
        record["native_score_direction"] = direction
    return record


def _human_slice(n, *, flipped=0, score=0.3, flipped_score=0.9):
    """n human-labelled items; ``flipped`` of them flip human->AI."""
    prev, curr, labels, slices = [], [], {}, {}
    for i in range(n):
        item_id = f"h-{i:03d}"
        is_flipped = i < flipped
        prev.append(_rec(item_id, score=score, verdict="human_like"))
        curr.append(
            _rec(
                item_id,
                score=flipped_score if is_flipped else score,
                verdict="ai_like" if is_flipped else "human_like",
            )
        )
        labels[item_id] = 0
        slices[item_id] = "human-native"
    return prev, curr, labels, slices


def _tier_metrics_for_flips(*, n_paired, n_human_paired, human_to_ai_human, flips_total=None):
    """Hand-built evaluate_tiers metrics with explicit paired denominators."""
    flips_total = n_paired if flips_total is None else flips_total
    return {
        "detector_id": "d",
        "slices": {
            "human-native": {
                "n": n_paired,
                "is_human_slice": True,
                "drift_signal_allowed": n_paired >= 50,
                "score_shift": {"ks_statistic": None, "psi": None, "n_paired": None},
                "flips": {
                    "n": n_paired,
                    "flips": flips_total,
                    "flip_rate": (flips_total / n_paired) if n_paired else 0.0,
                    "flip_rate_ci": [0.01, 0.5],
                    "human_to_ai": human_to_ai_human,
                    "ai_to_human": 0,
                    "to_abstain": 0,
                    "from_abstain": 0,
                    "n_human_paired": n_human_paired,
                    "human_to_ai_human": human_to_ai_human,
                },
                "calibration": {"ece": None, "baseline_ece": None},
                "human_fpr": None,
            }
        },
        "overall": {"flips": None},
        "worst_slice_fpr": None,
        "holm": {"alpha_per_run": 0.05, "family": "per-slice KS tests", "adjusted_pvalues": {}},
    }


# ---------------------------------------------------------------------------
# S07 — sample floor on the ACTUAL paired denominator
# ---------------------------------------------------------------------------


class TestS07PairedSampleFloor:
    def test_one_paired_flip_does_not_demote(self):
        prev, curr, labels, slices = _human_slice(1, flipped=1)
        metrics = compute_run_metrics(
            current_records=curr,
            baseline_records=prev,
            previous_records=prev,
            labels=labels,
            slices=slices,
            detector_id="d",
        )
        result = evaluate_tiers(metrics=metrics, detector_version="0.1.0")
        assert result["demote"] is False
        assert not any(a["tier"] == 1 and a["rule"] == "flip_rate" for a in result["alerts"])
        assert not any(a["rule"] == "flip_rate" for a in result["alerts"])

    def test_49_paired_flips_do_not_demote(self):
        prev, curr, labels, slices = _human_slice(49, flipped=49)
        metrics = compute_run_metrics(
            current_records=curr,
            baseline_records=prev,
            previous_records=prev,
            labels=labels,
            slices=slices,
            detector_id="d",
        )
        result = evaluate_tiers(metrics=metrics, detector_version="0.1.0")
        assert result["demote"] is False
        assert not any(a["rule"] == "flip_rate" for a in result["alerts"])

    def test_50_paired_flips_above_5pct_demotes(self):
        prev, curr, labels, slices = _human_slice(50, flipped=3)  # 3/50 = 6%
        metrics = compute_run_metrics(
            current_records=curr,
            baseline_records=prev,
            previous_records=prev,
            labels=labels,
            slices=slices,
            detector_id="d",
        )
        result = evaluate_tiers(metrics=metrics, detector_version="0.1.0")
        assert result["demote"] is True
        assert any(a["tier"] == 1 and a["rule"] == "flip_rate" for a in result["alerts"])

    def test_current_50_but_paired_1_does_not_demote(self):
        # 50 current records, but the previous run only scored 1 of them.
        prev, curr, labels, slices = _human_slice(50, flipped=0)
        prev = prev[:1]
        curr[0] = _rec("h-000", score=0.9, verdict="ai_like")
        metrics = compute_run_metrics(
            current_records=curr,
            baseline_records=prev,
            previous_records=prev,
            labels=labels,
            slices=slices,
            detector_id="d",
        )
        assert metrics["slices"]["human-native"]["n"] == 50
        assert metrics["slices"]["human-native"]["flips"]["n"] == 1
        result = evaluate_tiers(metrics=metrics, detector_version="0.1.0")
        assert result["demote"] is False
        assert not any(a["rule"] == "flip_rate" for a in result["alerts"])

    def test_exact_5pct_flip_rate_does_not_demote(self):
        # 3/60 = exactly 0.05; the rule is strictly greater than 5%.
        metrics = _tier_metrics_for_flips(
            n_paired=60, n_human_paired=60, human_to_ai_human=3, flips_total=3
        )
        result = evaluate_tiers(metrics=metrics, detector_version="0.1.0")
        assert result["demote"] is False
        assert not any(a["tier"] == 1 and a["rule"] == "flip_rate" for a in result["alerts"])

    def test_just_above_5pct_flip_rate_demotes(self):
        # 4/60 ≈ 0.0667 > 0.05 at an adequately sampled paired n.
        metrics = _tier_metrics_for_flips(
            n_paired=60, n_human_paired=60, human_to_ai_human=4, flips_total=4
        )
        result = evaluate_tiers(metrics=metrics, detector_version="0.1.0")
        assert result["demote"] is True
        assert any(a["tier"] == 1 and a["rule"] == "flip_rate" for a in result["alerts"])

    def test_mixed_label_slice_uses_human_denominator(self):
        # 50 human-labelled items with no flips + 50 AI-labelled items
        # whose verdicts flip human_like -> ai_like. The verdict-based
        # count is 10/100 = 10%, but the human-labelled rate is 0/50.
        prev, curr, labels, slices = [], [], {}, {}
        for i in range(50):
            item_id = f"h-{i:03d}"
            prev.append(_rec(item_id, score=0.3, verdict="human_like"))
            curr.append(_rec(item_id, score=0.3, verdict="human_like"))
            labels[item_id] = 0
            slices[item_id] = "human-native"
        for i in range(50):
            item_id = f"a-{i:03d}"
            flipped = i < 10
            prev.append(_rec(item_id, score=0.3, verdict="human_like"))
            curr.append(
                _rec(
                    item_id,
                    score=0.9 if flipped else 0.3,
                    verdict="ai_like" if flipped else "human_like",
                )
            )
            labels[item_id] = 1
            slices[item_id] = "human-native"
        metrics = compute_run_metrics(
            current_records=curr,
            baseline_records=prev,
            previous_records=prev,
            labels=labels,
            slices=slices,
            detector_id="d",
        )
        flips = metrics["slices"]["human-native"]["flips"]
        assert flips["human_to_ai"] == 10
        assert flips["n_human_paired"] == 50
        assert flips["human_to_ai_human"] == 0
        result = evaluate_tiers(metrics=metrics, detector_version="0.1.0")
        assert result["demote"] is False
        assert not any(a["tier"] == 1 and a["rule"] == "flip_rate" for a in result["alerts"])

    def test_one_sample_ece_jump_does_not_watch(self):
        prev = [_rec("h-000", score=0.3, verdict="human_like", cal=0.2, cal_id="c1")]
        curr = [_rec("h-000", score=0.3, verdict="human_like", cal=0.9, cal_id="c1")]
        labels, slices = {"h-000": 0}, {"h-000": "human-native"}
        metrics = compute_run_metrics(
            current_records=curr,
            baseline_records=prev,
            previous_records=None,
            labels=labels,
            slices=slices,
            detector_id="d",
        )
        calibration = metrics["slices"]["human-native"]["calibration"]
        assert calibration["ece"] == pytest.approx(0.9)
        assert calibration["baseline_ece"] == pytest.approx(0.2)
        assert calibration["n_calibrated_paired"] == 1
        result = evaluate_tiers(metrics=metrics, detector_version="0.1.0")
        assert result["watch"] is False
        assert not any(a["rule"] == "calibration_drift" for a in result["alerts"])

    def test_50_paired_ece_jump_watches(self):
        prev, curr, labels, slices = [], [], {}, {}
        for i in range(50):
            item_id = f"h-{i:03d}"
            prev.append(_rec(item_id, score=0.3, verdict="human_like", cal=0.2, cal_id="c1"))
            curr.append(_rec(item_id, score=0.3, verdict="human_like", cal=0.9, cal_id="c1"))
            labels[item_id] = 0
            slices[item_id] = "human-native"
        metrics = compute_run_metrics(
            current_records=curr,
            baseline_records=prev,
            previous_records=None,
            labels=labels,
            slices=slices,
            detector_id="d",
        )
        calibration = metrics["slices"]["human-native"]["calibration"]
        assert calibration["n_calibrated_paired"] == 50
        result = evaluate_tiers(metrics=metrics, detector_version="0.1.0")
        assert result["watch"] is True
        assert any(a["tier"] == 2 and a["rule"] == "calibration_drift" for a in result["alerts"])

    def test_drift_statistic_below_paired_floor_is_recorded_not_escalated(self):
        # 50 current items, but only 1 paired baseline score with a huge
        # shift: the KS/PSI values are recorded, never escalated.
        prev = [_rec("h-000", score=0.1, verdict="human_like")]
        curr = [_rec(f"h-{i:03d}", score=0.9, verdict="ai_like") for i in range(50)]
        labels = {f"h-{i:03d}": 0 for i in range(50)}
        slices = {f"h-{i:03d}": "human-native" for i in range(50)}
        metrics = compute_run_metrics(
            current_records=curr,
            baseline_records=prev,
            previous_records=None,
            labels=labels,
            slices=slices,
            detector_id="d",
        )
        shift = metrics["slices"]["human-native"]["score_shift"]
        assert shift["n_paired"] == 1
        assert shift["ks_statistic"] is not None
        assert shift["psi"] is not None
        result = evaluate_tiers(metrics=metrics, detector_version="0.1.0")
        assert not any(a["rule"] == "drift_statistic" for a in result["alerts"])
        assert result["breaches"] == []

    def test_fpr_cap_first_run_policy_preserved_at_n100(self):
        # Deliberate absolute-FPR rule: a first run CAN demote when the
        # human slice is claimable (n_human >= 100) and the Wilson CI
        # lower bound is above the cap. Below 100 it never demotes.
        metrics = {
            "detector_id": "d",
            "slices": {
                "human-native": {
                    "n": 120,
                    "is_human_slice": True,
                    "drift_signal_allowed": True,
                    "score_shift": {"ks_statistic": None, "psi": None, "n_paired": None},
                    "flips": None,
                    "calibration": {"ece": None, "baseline_ece": None},
                    "human_fpr": {
                        "n_human": 120,
                        "false_positives": 10,
                        "fpr": 0.08,
                        "fpr_ci": [0.06, 0.10],
                        "fpr_claim_allowed": True,
                        "cap": 0.05,
                    },
                }
            },
            "overall": {"flips": None},
            "worst_slice_fpr": None,
            "holm": {"alpha_per_run": 0.05, "family": "per-slice KS tests", "adjusted_pvalues": {}},
        }
        result = evaluate_tiers(metrics=metrics, detector_version="0.1.0")
        assert result["demote"] is True
        assert any(a["tier"] == 1 and a["rule"] == "human_fpr_cap" for a in result["alerts"])
        # CI lower bound exactly at the cap does not breach (strict >).
        metrics["slices"]["human-native"]["human_fpr"]["fpr_ci"] = [0.05, 0.10]
        metrics["slices"]["human-native"]["human_fpr"]["fpr"] = 0.07
        result = evaluate_tiers(metrics=metrics, detector_version="0.1.0")
        assert result["demote"] is False
        # Unclaimable slice (n_human = 50) never demotes on FPR alone.
        metrics["slices"]["human-native"]["human_fpr"]["fpr_claim_allowed"] = False
        metrics["slices"]["human-native"]["human_fpr"]["fpr_ci"] = [0.90, 1.0]
        metrics["slices"]["human-native"]["human_fpr"]["fpr"] = 1.0
        result = evaluate_tiers(metrics=metrics, detector_version="0.1.0")
        assert result["demote"] is False


# ---------------------------------------------------------------------------
# S09 — score direction is preserved and orients ROC/TPR
# ---------------------------------------------------------------------------


class TestS09ScoreDirection:
    def test_tpr_at_fpr_lower_means_ai(self):
        # Audit case: human 0.9 / AI 0.1 with lower-means-AI yields
        # TPR 1 at FPR 0 under the lower-tail decision.
        out = pm.tpr_at_fpr([0.9, 0.1], [0, 1], target_fpr=0.01, direction="lower_means_ai")
        assert out["tpr"] == pytest.approx(1.0)
        assert out["achieved_fpr"] == pytest.approx(0.0)

    def test_fpr_at_threshold_lower_means_ai(self):
        out = pm.fpr_at_threshold([0.9, 0.1], [0, 1], 0.5, direction="lower_means_ai")
        assert out["false_positives"] == 0
        assert out["fpr"] == pytest.approx(0.0)
        out_higher = pm.fpr_at_threshold([0.9, 0.1], [0, 1], 0.5)
        assert out_higher["false_positives"] == 1

    def test_affine_equivalent_detectors_identical(self):
        # Higher-tail scores and their negation (lower-tail) must yield
        # identical TPR/FPR: direction is orientation, not evidence.
        humans = [i / 99.0 for i in range(100)]
        machines = [1.0 + i / 99.0 for i in range(100)]
        scores_h = humans + machines
        labels = [0] * 100 + [1] * 100
        higher = pm.tpr_at_fpr(scores_h, labels, target_fpr=0.01)
        lower = pm.tpr_at_fpr(
            [-s for s in scores_h], labels, target_fpr=0.01, direction="lower_means_ai"
        )
        assert higher["tpr"] == pytest.approx(lower["tpr"])
        assert higher["achieved_fpr"] == pytest.approx(lower["achieved_fpr"])
        # Also for FPR at a fixed threshold.
        f_h = pm.fpr_at_threshold(scores_h, labels, 0.5)
        f_l = pm.fpr_at_threshold([-s for s in scores_h], labels, -0.5, direction="lower_means_ai")
        assert f_h["fpr"] == pytest.approx(f_l["fpr"])

    def test_tied_scores_identical_both_directions(self):
        scores = [0.5, 0.5, 0.5, 0.5]
        labels = [0, 0, 1, 1]
        higher = pm.tpr_at_fpr(scores, labels, target_fpr=0.01)
        lower = pm.tpr_at_fpr(scores, labels, target_fpr=0.01, direction="lower_means_ai")
        assert higher["tpr"] == pytest.approx(lower["tpr"])
        assert higher["achieved_fpr"] == pytest.approx(lower["achieved_fpr"])

    def test_unbounded_native_ranges(self):
        # Native scores far outside [0, 1] orient the same way.
        higher = pm.tpr_at_fpr([-100.0, 100.0], [0, 1], target_fpr=0.01)
        lower = pm.tpr_at_fpr([100.0, -100.0], [0, 1], target_fpr=0.01, direction="lower_means_ai")
        assert higher["tpr"] == pytest.approx(1.0)
        assert lower["tpr"] == pytest.approx(1.0)
        assert higher["achieved_fpr"] == pytest.approx(lower["achieved_fpr"])

    def test_unknown_and_not_applicable_direction_unavailable(self):
        with pytest.raises(ValueError, match="direction"):
            pm.tpr_at_fpr([0.9, 0.1], [0, 1], target_fpr=0.01, direction="unknown")
        with pytest.raises(ValueError, match="direction"):
            pm.tpr_at_fpr([0.9, 0.1], [0, 1], target_fpr=0.01, direction="not_applicable")
        with pytest.raises(ValueError, match="direction"):
            pm.fpr_at_threshold([0.9], [0], 0.5, direction="unknown")
        with pytest.raises(ValueError, match="direction"):
            pm.normalize_score_direction("sideways")

    def test_attacked_tpr_lower_direction_via_run_metrics(self):
        # 60 human reference items (score 0.9, lower-means-AI) and 60
        # paraphrased AI items (score 0.1): TPR must be 1, not 0.
        curr, labels, slices = [], {}, {}
        for i in range(60):
            item_id = f"hn-{i:03d}"
            curr.append(_rec(item_id, score=0.9, verdict="human_like", direction="lower_means_ai"))
            labels[item_id] = 0
            slices[item_id] = "human-native"
        for i in range(60):
            item_id = f"ap-{i:03d}"
            curr.append(_rec(item_id, score=0.1, verdict="ai_like", direction="lower_means_ai"))
            labels[item_id] = 1
            slices[item_id] = "ai-paraphrased"
        metrics = compute_run_metrics(
            current_records=curr,
            baseline_records=None,
            previous_records=None,
            labels=labels,
            slices=slices,
            detector_id="d",
        )
        assert metrics["score_direction"] == "lower_means_ai"
        attacked = metrics["slices"]["ai-paraphrased"]["attacked_tpr"]
        assert attacked["tpr_at_1pct_fpr"] == pytest.approx(1.0)
        assert attacked["achieved_fpr"] == pytest.approx(0.0)
        assert attacked["score_direction"] == "lower_means_ai"

    def test_attacked_tpr_unknown_direction_unavailable(self):
        curr, labels, slices = [], {}, {}
        for i in range(60):
            item_id = f"hn-{i:03d}"
            curr.append(_rec(item_id, score=0.9, verdict="human_like"))
            labels[item_id] = 0
            slices[item_id] = "human-native"
        for i in range(60):
            item_id = f"ap-{i:03d}"
            curr.append(_rec(item_id, score=0.1, verdict="ai_like"))
            labels[item_id] = 1
            slices[item_id] = "ai-paraphrased"
        metrics = compute_run_metrics(
            current_records=curr,
            baseline_records=None,
            previous_records=None,
            labels=labels,
            slices=slices,
            detector_id="d",
        )
        assert metrics["score_direction"] == "unknown"
        attacked = metrics["slices"]["ai-paraphrased"]["attacked_tpr"]
        assert attacked["tpr_at_1pct_fpr"] is None
        assert "direction" in attacked["reason"]

    def test_mixed_directions_fail_closed(self):
        curr = [
            _rec("hn-000", score=0.9, verdict="human_like", direction="higher_means_ai"),
            _rec("hn-001", score=0.1, verdict="human_like", direction="lower_means_ai"),
        ]
        labels = {"hn-000": 0, "hn-001": 0}
        slices = {"hn-000": "human-native", "hn-001": "human-native"}
        with pytest.raises(ProbeRunError, match="direction"):
            compute_run_metrics(
                current_records=curr,
                baseline_records=None,
                previous_records=None,
                labels=labels,
                slices=slices,
                detector_id="d",
            )

    def test_score_series_round_trips_direction(self):
        records = [
            _rec("a", score=0.1, verdict="ai_like", direction="lower_means_ai"),
        ]
        series = _series_from_records(records)
        assert series["a"]["native_score_direction"] == "lower_means_ai"
        rebuilt = _records_from_series(series)
        assert rebuilt[0]["native_score_direction"] == "lower_means_ai"

    def test_observatory_snapshot_preserves_direction_and_range(self):
        from textforensics.observatory import DriftObservatory

        corpus = {
            "schema": "textforensics.drift-corpus/v1",
            "samples": [
                {"id": "s1", "text": "synthetic probe sentence one."},
                {"id": "s2", "text": "synthetic probe sentence two."},
            ],
        }
        obs = DriftObservatory(corpus=corpus)
        snapshot = obs.snapshot_from_observations(
            [
                {
                    "sample_id": "s1",
                    "detector_id": "d",
                    "detector_version": "0.1.0",
                    "detector_family": "f",
                    "execution": "local",
                    "score": 0.1,
                    "score_semantics": "lower means more machine-like",
                    "verdict": "ai_like",
                    "threshold": 0.2,
                    "native_score_direction": "lower_means_ai",
                    "score_range": [-5.0, 5.0],
                }
            ]
        )
        record = snapshot["records"][0]
        assert record["native_score_direction"] == "lower_means_ai"
        assert record["score_range"] == [-5.0, 5.0]
        assert record["score_semantics"] == "lower means more machine-like"

    def test_observatory_snapshot_rejects_bad_direction_and_range(self):
        from textforensics.observatory import DriftObservatory

        corpus = {
            "schema": "textforensics.drift-corpus/v1",
            "samples": [{"id": "s1", "text": "synthetic probe sentence one."}],
        }
        obs = DriftObservatory(corpus=corpus)
        base = {
            "sample_id": "s1",
            "detector_id": "d",
            "detector_version": "0.1.0",
            "detector_family": "f",
            "execution": "local",
            "score": 0.1,
            "score_semantics": "s",
            "verdict": "ai_like",
            "threshold": 0.2,
        }
        with pytest.raises(ValueError, match="direction"):
            obs.snapshot_from_observations([{**base, "native_score_direction": "sideways"}])
        with pytest.raises(ValueError, match="score_range"):
            obs.snapshot_from_observations([{**base, "score_range": [5.0, -5.0]}])
        with pytest.raises(ValueError, match="score_range"):
            obs.snapshot_from_observations([{**base, "score_range": [0.0, float("nan")]}])
        with pytest.raises(ValueError, match="score_range"):
            obs.snapshot_from_observations([{**base, "score_range": [-5.0, 5.0], "score": 9.0}])


# ---------------------------------------------------------------------------
# S10 — nonfinite rejection + independent oracles
# ---------------------------------------------------------------------------


class TestS10NonfiniteAndOracles:
    def test_ks_nan_rejects_bounded(self):
        # Runs in a subprocess so a hang fails the test instead of
        # hanging the suite (the pre-fix defect never returns).
        src_dir = str(Path(__file__).resolve().parent.parent / "src")
        code = (
            f"import sys; sys.path.insert(0, {src_dir!r});"
            "from textforensics import probe_metrics as pm;"
            "\ntry:\n"
            "    pm.ks_statistic([float('nan')], [0.0])\n"
            "    print('NO-RAISE')\n"
            "except ValueError:\n"
            "    print('RAISED')"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, timeout=10
        )
        assert proc.returncode == 0
        assert "RAISED" in proc.stdout

    @pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
    def test_rejects_nonfinite(self, bad):
        # NOTE: ks_statistic with NaN hangs pre-fix (infinite loop);
        # it is covered separately by test_ks_nan_rejects_bounded,
        # which runs it in a subprocess with a timeout.
        with pytest.raises(ValueError):
            pm.psi([bad, 0.0], [0.0, 1.0])
        with pytest.raises(ValueError):
            pm.ece([bad], [0])
        with pytest.raises(ValueError):
            pm.brier([bad], [0])
        with pytest.raises(ValueError):
            pm.fpr_at_threshold([bad], [0], 0.5)
        with pytest.raises(ValueError):
            pm.fpr_at_threshold([0.1], [0], bad)
        with pytest.raises(ValueError):
            pm.tpr_at_fpr([bad, 0.1], [0, 1], target_fpr=0.01)
        with pytest.raises(ValueError):
            pm.holm_adjusted([bad])
        with pytest.raises(ValueError):
            pm.coverage_shortfall_pp(bad, 0.9)

    def test_wilson_rejects_noninteger_and_nonfinite(self):
        with pytest.raises(ValueError):
            pm.wilson_ci(0.5, 50)
        with pytest.raises(ValueError):
            pm.wilson_ci(True, 50)
        with pytest.raises(ValueError):
            pm.wilson_ci(0, 50.0)
        with pytest.raises(ValueError):
            pm.wilson_ci(0, 50, z=float("nan"))
        with pytest.raises(ValueError):
            pm.wilson_ci(0, 50, z=float("inf"))
        with pytest.raises(ValueError):
            pm.ks_pvalue(float("nan"), 10, 10)
        with pytest.raises(ValueError):
            pm.ks_pvalue(0.5, 10.5, 10)
        with pytest.raises(ValueError):
            pm.psi([0.0, 1.0], [0.0, 1.0], bins=2.5)
        with pytest.raises(ValueError):
            pm.ece([0.5], [True])
        with pytest.raises(ValueError):
            pm.brier([0.5], [1.0])

    def test_oracles_exact(self):
        # Independent oracle values from the audit digest (S10).
        assert pm.wilson_ci(0, 50)[1] == pytest.approx(0.07135003417431873, rel=0, abs=1e-15)
        assert pm.psi([0.0] * 50 + [1.0] * 50, [0.0] * 25 + [1.0] * 75, bins=2) == pytest.approx(
            0.2746530721670274, rel=0, abs=1e-15
        )
        assert pm.ece([0.2, 0.2], [0, 1], n_bins=1) == pytest.approx(0.3)
        assert pm.brier([0.2, 0.2], [0, 1]) == pytest.approx(0.3400000000000001)
        assert pm.holm_adjusted([0.01, 0.04, 0.03]) == pytest.approx([0.03, 0.06, 0.06])

    def test_ks_exhaustive_oracle(self):
        # KS = max_t |count(a<=t)/n - count(b<=t)/m| over 225 pairs of
        # length-four discrete samples; zero mismatches for finite values.
        import random

        def oracle(a, b):
            n, m = len(a), len(b)
            best = 0.0
            for t in sorted(set(a) | set(b)):
                best = max(
                    best, abs(sum(1 for x in a if x <= t) / n - sum(1 for x in b if x <= t) / m)
                )
            return best

        rng = random.Random(20261110)
        values = [0.0, 0.25, 0.5, 0.75, 1.0]
        for _ in range(225):
            a = [rng.choice(values) for _ in range(4)]
            b = [rng.choice(values) for _ in range(4)]
            assert pm.ks_statistic(a, b) == pytest.approx(oracle(a, b), abs=1e-12)

    def test_strict_json_helper(self):
        with pytest.raises(ValueError):
            pm.strict_json_loads('{"a": NaN}')
        with pytest.raises(ValueError):
            pm.strict_json_loads('{"a": Infinity}')
        with pytest.raises(ValueError):
            pm.strict_json_loads('{"a": -Infinity}')
        with pytest.raises(ValueError):
            pm.strict_json_loads('{"a": 1e999}')  # parses to inf
        assert pm.strict_json_loads('{"a": 1.5, "b": [1, 2]}') == {"a": 1.5, "b": [1, 2]}
        with pytest.raises(ValueError):
            pm.strict_json_dumps({"a": float("nan")})
        with pytest.raises(ValueError):
            pm.strict_json_dumps({"a": [float("inf")]})
        assert json.loads(pm.strict_json_dumps({"a": 1.5})) == {"a": 1.5}
        with pytest.raises(ValueError):
            pm.reject_nonfinite_value({"a": {"b": [1.0, float("nan")]}})
        pm.reject_nonfinite_value({"a": 1.0, "b": None, "c": True, "d": "x"})

    def test_probe_run_score_rejects_nan(self):
        curr = [_rec("h-000", score=float("nan"), verdict="human_like")]
        labels, slices = {"h-000": 0}, {"h-000": "human-native"}
        with pytest.raises(ProbeRunError, match="finite"):
            compute_run_metrics(
                current_records=curr,
                baseline_records=None,
                previous_records=None,
                labels=labels,
                slices=slices,
                detector_id="d",
            )


# ---------------------------------------------------------------------------
# S21 — partial calibrated baseline
# ---------------------------------------------------------------------------


class TestS21PartialCalibratedBaseline:
    def _calibrated(self, n_current, n_baseline, *, baseline_extra=0):
        curr, base, labels, slices = [], [], {}, {}
        for i in range(n_current):
            item_id = f"h-{i:03d}"
            curr.append(_rec(item_id, score=0.3, verdict="human_like", cal=0.2, cal_id="c1"))
            labels[item_id] = 0
            slices[item_id] = "human-native"
        for i in range(n_baseline):
            item_id = f"h-{i:03d}"
            base.append(_rec(item_id, score=0.3, verdict="human_like", cal=0.2, cal_id="c1"))
        for i in range(baseline_extra):
            item_id = f"x-{i:03d}"
            base.append(_rec(item_id, score=0.3, verdict="human_like", cal=0.2, cal_id="c1"))
        return curr, base, labels, slices

    def test_partial_baseline_withholds_baseline_ece(self):
        curr, base, labels, slices = self._calibrated(2, 1)
        metrics = compute_run_metrics(
            current_records=curr,
            baseline_records=base,
            previous_records=None,
            labels=labels,
            slices=slices,
            detector_id="d",
        )
        calibration = metrics["slices"]["human-native"]["calibration"]
        assert calibration["ece"] == pytest.approx(0.2)
        assert calibration["baseline_ece"] is None
        assert calibration["n_calibrated_current"] == 2
        assert calibration["n_calibrated_paired"] == 1
        assert "1 of 2" in (calibration.get("baseline_ece_reason") or "")

    def test_baseline_superset_still_computes_baseline_ece(self):
        curr, base, labels, slices = self._calibrated(2, 2, baseline_extra=3)
        metrics = compute_run_metrics(
            current_records=curr,
            baseline_records=base,
            previous_records=None,
            labels=labels,
            slices=slices,
            detector_id="d",
        )
        calibration = metrics["slices"]["human-native"]["calibration"]
        assert calibration["baseline_ece"] == pytest.approx(0.2)
        assert calibration["n_calibrated_paired"] == 2

    def test_disjoint_baseline_withholds(self):
        curr = [
            _rec("a", score=0.3, verdict="human_like", cal=0.2, cal_id="c1"),
            _rec("b", score=0.3, verdict="human_like", cal=0.2, cal_id="c1"),
        ]
        base = [_rec("z", score=0.3, verdict="human_like", cal=0.2, cal_id="c1")]
        labels = {"a": 0, "b": 0}
        slices = {"a": "human-native", "b": "human-native"}
        metrics = compute_run_metrics(
            current_records=curr,
            baseline_records=base,
            previous_records=None,
            labels=labels,
            slices=slices,
            detector_id="d",
        )
        calibration = metrics["slices"]["human-native"]["calibration"]
        assert calibration["baseline_ece"] is None
        assert calibration["n_calibrated_paired"] == 0
        assert calibration["ece"] == pytest.approx(0.2)

    def test_mixed_calibration_availability_withholds(self):
        curr = [
            _rec("a", score=0.3, verdict="human_like", cal=0.2, cal_id="c1"),
            _rec("b", score=0.3, verdict="human_like", cal=None, cal_id=None),
        ]
        labels = {"a": 0, "b": 0}
        slices = {"a": "human-native", "b": "human-native"}
        metrics = compute_run_metrics(
            current_records=curr,
            baseline_records=None,
            previous_records=None,
            labels=labels,
            slices=slices,
            detector_id="d",
        )
        calibration = metrics["slices"]["human-native"]["calibration"]
        assert calibration["ece"] is None
        assert calibration["n_calibrated_current"] == 1

    def test_changed_calibration_id_still_matched_by_item(self):
        curr = [
            _rec("a", score=0.3, verdict="human_like", cal=0.2, cal_id="c2"),
            _rec("b", score=0.3, verdict="human_like", cal=0.2, cal_id="c2"),
        ]
        base = [
            _rec("a", score=0.3, verdict="human_like", cal=0.2, cal_id="c1"),
            _rec("b", score=0.3, verdict="human_like", cal=0.2, cal_id="c1"),
        ]
        labels = {"a": 0, "b": 0}
        slices = {"a": "human-native", "b": "human-native"}
        metrics = compute_run_metrics(
            current_records=curr,
            baseline_records=base,
            previous_records=None,
            labels=labels,
            slices=slices,
            detector_id="d",
        )
        calibration = metrics["slices"]["human-native"]["calibration"]
        assert calibration["calibration_id_changed"] is True
        assert calibration["baseline_ece"] == pytest.approx(0.2)
        assert calibration["n_calibrated_paired"] == 2


# ---------------------------------------------------------------------------
# S22 — model card + codec numeric validation
# ---------------------------------------------------------------------------


def _valid_card_dict(**overrides):
    card = {
        "schema_version": "1.0.0",
        "metadata": {
            "version": "1.0.0",
            "generated_at": "2026-11-07T00:00:00+00:00",
            "generated_by": "test",
        },
        "model_details": {
            "name": "T",
            "version": "0.1.0",
            "detector_id": "d",
            "detector_family": "f",
            "architecture": "a",
            "framework": "f",
            "license": "AGPL-3.0-or-later",
            "owner": "o",
            "contact": "c",
        },
        "intended_use": {
            "primary_use_cases": ["u"],
            "out_of_scope": ["x"],
            "target_users": ["t"],
        },
        "metrics": [{"name": "acc", "value": 0.5, "unit": "x"}],
        "quantitative_analysis": {
            "metrics": [],
            "roc_auc": 0.9,
            "pr_auc": 0.8,
            "calibration_error": 0.02,
        },
    }
    for key, value in overrides.items():
        card[key] = value
    return card


def _valid_policy():
    return {
        "revision": 1,
        "settings": {"enforce_local_first": True},
        "rules": [{"id": "r1", "description": "d", "action": "log", "scope": "all"}],
    }


class TestS22ModelCardCodec:
    @pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
    def test_model_card_rejects_nonfinite_metric(self, bad):
        card = _valid_card_dict()
        card["metrics"] = [{"name": "acc", "value": bad, "unit": "x"}]
        with pytest.raises(ValueError):
            ModelCard.from_dict(card)

    @pytest.mark.parametrize("bad", [float("nan"), float("inf")])
    def test_model_card_rejects_nonfinite_nested(self, bad):
        card = _valid_card_dict()
        card["additional_information"] = {"nested": {"v": bad}}
        with pytest.raises(ValueError):
            ModelCard.from_dict(card)
        card = _valid_card_dict()
        card["metrics"] = [{"name": "acc", "value": 0.5, "unit": "x", "metadata": {"v": bad}}]
        with pytest.raises(ValueError):
            ModelCard.from_dict(card)

    def test_model_card_ci_ordering_and_bounds(self):
        card = _valid_card_dict()
        card["metrics"] = [
            {"name": "acc", "value": 0.5, "unit": "x", "confidence_interval": [0.9, 0.1]}
        ]
        with pytest.raises(ValueError, match="confidence_interval"):
            ModelCard.from_dict(card)
        card["metrics"] = [
            {"name": "acc", "value": 0.5, "unit": "x", "confidence_interval": [0.1, float("nan")]}
        ]
        with pytest.raises(ValueError):
            ModelCard.from_dict(card)
        card["metrics"] = [
            {"name": "acc", "value": 0.5, "unit": "x", "confidence_interval": [0.4, 0.4]}
        ]
        ModelCard.from_dict(card)  # equal endpoints are valid

    @pytest.mark.parametrize("field", ["roc_auc", "pr_auc", "calibration_error"])
    @pytest.mark.parametrize("bad", [-0.1, 1.5, float("nan"), float("inf")])
    def test_model_card_bounded_fields(self, field, bad):
        card = _valid_card_dict()
        card["quantitative_analysis"][field] = bad
        with pytest.raises(ValueError):
            ModelCard.from_dict(card)

    @pytest.mark.parametrize("field", ["roc_auc", "pr_auc", "calibration_error"])
    @pytest.mark.parametrize("good", [0.0, 1.0])
    def test_model_card_bounded_endpoints_ok(self, field, good):
        card = _valid_card_dict()
        card["quantitative_analysis"][field] = good
        ModelCard.from_dict(card)

    def test_model_card_sizes_and_ratios(self):
        card = _valid_card_dict()
        card["evaluation_data"] = {
            "name": "e",
            "version": "1",
            "size": -1,
            "languages": ["en"],
            "domains": ["news"],
            "split_ratios": {"train": 0.8, "test": 0.2},
            "source": "s",
            "license": "l",
            "collection_date": "2026-01-01",
        }
        with pytest.raises(ValueError):
            ModelCard.from_dict(card)
        card["evaluation_data"]["size"] = 100
        card["evaluation_data"]["split_ratios"] = {"train": 0.8, "test": 0.1}
        with pytest.raises(ValueError, match="split_ratios"):
            ModelCard.from_dict(card)
        card["evaluation_data"]["split_ratios"] = {"train": -0.2, "test": 1.2}
        with pytest.raises(ValueError, match="split_ratios"):
            ModelCard.from_dict(card)
        card["evaluation_data"]["split_ratios"] = {"train": 0.8, "test": 0.2}
        ModelCard.from_dict(card)
        # Zero size is a valid (empty) dataset description.
        card["evaluation_data"]["size"] = 0
        ModelCard.from_dict(card)
        # Negative confusion-matrix counts are rejected.
        card = _valid_card_dict()
        card["quantitative_analysis"]["confusion_matrix"] = {"tp": -1}
        with pytest.raises(ValueError):
            ModelCard.from_dict(card)

    def test_model_card_zero_metrics_displayed_not_na(self):
        card = _valid_card_dict()
        card["quantitative_analysis"] = {
            "metrics": [],
            "roc_auc": 0.0,
            "pr_auc": 0.0,
            "calibration_error": 0.0,
        }
        md = ModelCard.from_dict(card).to_markdown()
        assert "ROC AUC: 0.0" in md
        assert "PR AUC: 0.0" in md
        assert "Calibration Error: 0.0" in md
        assert "N/A" not in md
        card["quantitative_analysis"] = {
            "metrics": [],
            "roc_auc": None,
            "pr_auc": None,
            "calibration_error": None,
        }
        md = ModelCard.from_dict(card).to_markdown()
        assert "ROC AUC: N/A" in md

    def test_model_card_to_json_strict_and_round_trip(self, tmp_path):
        card = ModelCard.from_dict(_valid_card_dict())
        text = card.to_json()
        assert "NaN" not in text and "Infinity" not in text
        restored = ModelCard.from_dict(json.loads(text))
        assert restored == card
        path = tmp_path / "card.json"
        path.write_text(text, encoding="utf-8")
        assert ModelCard.load(path) == card
        # A file containing a literal NaN token is rejected.
        bad = tmp_path / "bad.json"
        bad.write_text(text.replace('"value": 0.5', '"value": NaN'), encoding="utf-8")
        with pytest.raises(ValueError):
            ModelCard.load(bad)

    def test_model_card_to_json_rejects_constructed_nonfinite(self):
        import dataclasses

        from textforensics.model_card import QuantitativeAnalysis

        card = ModelCard.from_dict(_valid_card_dict())
        broken = dataclasses.replace(
            card,
            quantitative_analysis=QuantitativeAnalysis(
                metrics=[], roc_auc=float("nan"), pr_auc=None, calibration_error=None
            ),
        )
        with pytest.raises(ValueError):
            broken.to_json()

    @pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
    def test_codec_decode_rejects_nonfinite_tokens(self, token):
        policy = _valid_policy()
        payload = json.dumps(policy).replace(
            '"enforce_local_first": true',
            f'"enforce_local_first": true, "threshold": {token}',
        )
        with pytest.raises(CodecError):
            decode_result(payload, "enterprise-policy")
        codec = ResultCodec()
        with pytest.raises(CodecError):
            codec.decode(payload, "enterprise-policy", validate=False)

    def test_codec_decode_rejects_nonfinite_nested_and_overflow(self):
        policy = _valid_policy()
        policy["rules"][0]["conditions"] = {"x": float("nan")}
        with pytest.raises(CodecError):
            encode_result(policy, "enterprise-policy")
        payload = json.dumps(_valid_policy()).replace(
            '"enforce_local_first": true',
            '"enforce_local_first": true, "threshold": 1e999',
        )
        with pytest.raises(CodecError):
            decode_result(payload, "enterprise-policy")

    def test_codec_encode_rejects_nonfinite(self):
        policy = _valid_policy()
        policy["settings"]["threshold"] = float("inf")
        with pytest.raises(CodecError):
            encode_result(policy, "enterprise-policy")

    def test_codec_round_trip_symmetry(self):
        # Default-validation round-trip on the known-valid bundle
        # fixture (forensic-bundle accepts the "schema" key the codec
        # adds on encode).
        from test_result_codec import MINIMAL_BUNDLE

        bundle = copy.deepcopy(MINIMAL_BUNDLE)
        encoded = encode_result(bundle, "forensic-bundle")
        assert b"NaN" not in encoded
        decoded = decode_result(encoded, "forensic-bundle")
        assert decoded == bundle
        assert encode_result(decoded, "forensic-bundle") == encoded
        # Strict round-trip symmetry also holds for enterprise-policy
        # payloads when schema validation is off (that schema forbids
        # the "schema" key the codec adds — a pre-existing mismatch
        # outside this package's scope): encode(decode(x)) == x.
        from textforensics.result_codec import CodecConfig

        codec = ResultCodec(CodecConfig(validate_on_encode=False, validate_on_decode=False))
        policy = _valid_policy()
        encoded_policy = codec.encode(policy, "enterprise-policy")
        assert codec.decode(encoded_policy, "enterprise-policy") == {
            **policy,
            "schema": "textforensics.enterprise-policy/v1",
        }
        assert (
            codec.encode(codec.decode(encoded_policy, "enterprise-policy"), "enterprise-policy")
            == encoded_policy
        )

    def test_codec_validate_result_flags_nonfinite(self):
        policy = _valid_policy()
        policy["settings"]["threshold"] = float("nan")
        errors = validate_result(policy, "enterprise-policy")
        assert errors
        assert any("finite" in e.lower() for e in errors)
