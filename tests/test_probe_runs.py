"""Tests for the U3 probe-run engine (probe_runs.py).

The statistical primitives live in ``textforensics.probe_metrics``
(merged with the frozen probe corpus v1.0.0). These tests use a small
test-double object (``stub_primitives``) implementing the same function
names with the standard closed forms (Wilson, two-sample KS +
Kolmogorov asymptotic p-value, PSI over quantile bins, ECE/Brier,
Holm-Bonferroni). The double tests *this module's* aggregation, tier
and demotion logic — not the primitives themselves, which are the
corpus half's job and are covered by its own tests.
``test_load_probe_metrics_resolves_real_module`` is the contract test:
it runs the real module against the seam's names and value spot-checks.
"""

from __future__ import annotations

import math
import random
import sys
import types
from pathlib import Path

import pytest

from textforensics.probe_runs import (
    _PRIMITIVE_NAMES,
    ProbeMetricsUnavailable,
    ProbeRunError,
    apply_demotions,
    build_run_manifest,
    clear_demotions,
    compute_run_metrics,
    evaluate_tiers,
    load_probe_metrics,
    load_run,
    load_run_history,
    resolve_baseline,
    save_run,
    summarize_longitudinal,
    validate_run_manifest,
)
from textforensics.validation import (
    effective_status,
    load_validation_registry,
)

HEX64 = "a" * 64
HEX64_B = "b" * 64


# ---------------------------------------------------------------------------
# Test-double primitives (same names/signatures as probe_metrics)
# ---------------------------------------------------------------------------


def _wilson_ci(k: int, n: int, *, z: float = 1.96) -> tuple[float, float]:
    p = k / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def _ks_statistic(a: list[float], b: list[float]) -> float:
    data = sorted(set(a) | set(b))
    cdf_a = [sum(1 for x in a if x <= v) / len(a) for v in data]
    cdf_b = [sum(1 for x in b if x <= v) / len(b) for v in data]
    return max(abs(x - y) for x, y in zip(cdf_a, cdf_b, strict=True))


def _ks_pvalue(d: float, n: int, m: int) -> float:
    if d <= 0:
        return 1.0
    ne = n * m / (n + m)
    lam = (math.sqrt(ne) + 0.12 + 0.11 / math.sqrt(ne)) * d
    total = 0.0
    for k in range(1, 101):
        term = 2.0 * ((-1) ** (k - 1)) * math.exp(-2.0 * k * k * lam * lam)
        total += term
        if abs(term) < 1e-12:
            break
    return min(1.0, max(0.0, total))


def _psi(expected: list[float], actual: list[float], *, bins: int = 10) -> float:
    edges = [expected[int(i * len(expected) / bins)] for i in range(bins)]
    edges = sorted(set(edges))
    edges = [-math.inf, *edges[1:], math.inf]
    eps = 1e-4
    total = 0.0
    for i in range(len(edges) - 1):
        e = sum(1 for x in expected if edges[i] <= x < edges[i + 1]) / len(expected)
        a = sum(1 for x in actual if edges[i] <= x < edges[i + 1]) / len(actual)
        e = max(e, eps)
        a = max(a, eps)
        total += (a - e) * math.log(a / e)
    return total


def _flip_summary(previous: list[str], current: list[str]) -> dict:
    flips = human_to_ai = ai_to_human = to_abstain = from_abstain = 0
    for prev, curr in zip(previous, current, strict=True):
        if prev == curr:
            continue
        flips += 1
        if prev == "human_like" and curr == "ai_like":
            human_to_ai += 1
        elif prev == "ai_like" and curr == "human_like":
            ai_to_human += 1
        if curr == "abstain":
            to_abstain += 1
        if prev == "abstain":
            from_abstain += 1
    n = len(previous)
    return {
        "n": n,
        "flips": flips,
        "flip_rate": flips / n,
        "flip_rate_ci": _wilson_ci(flips, n),
        "human_to_ai": human_to_ai,
        "ai_to_human": ai_to_human,
        "to_abstain": to_abstain,
        "from_abstain": from_abstain,
    }


def _ece(probs: list[float], labels: list[int], *, n_bins: int = 10) -> float:
    total = 0.0
    for b in range(n_bins):
        lo, hi = b / n_bins, (b + 1) / n_bins
        members = [
            (p, y)
            for p, y in zip(probs, labels, strict=True)
            if (lo <= p < hi) or (b == n_bins - 1 and p == hi)
        ]
        if not members:
            continue
        mean_prob = sum(p for p, _ in members) / len(members)
        mean_label = sum(y for _, y in members) / len(members)
        total += abs(mean_prob - mean_label) * len(members) / len(probs)
    return total


def _brier(probs: list[float], labels: list[int]) -> float:
    return sum((p - y) ** 2 for p, y in zip(probs, labels, strict=True)) / len(probs)


def _set_coverage(prediction_sets: list[set[int]], true_labels: list[int]) -> dict:
    covered = sum(1 for s, y in zip(prediction_sets, true_labels, strict=True) if y in s)
    return {"covered": covered, "n": len(true_labels), "rate": covered / len(true_labels)}


def _coverage_shortfall_pp(empirical_rate: float, nominal_rate: float) -> float:
    return (nominal_rate - empirical_rate) * 100.0


def _fpr_at_threshold(scores: list[float], labels: list[int], threshold: float) -> dict:
    humans = [s for s, y in zip(scores, labels, strict=True) if y == 0]
    false_positives = sum(1 for s in humans if s >= threshold)
    n = len(humans)
    return {
        "n_human": n,
        "false_positives": false_positives,
        "fpr": false_positives / n,
        "fpr_ci": _wilson_ci(false_positives, n),
    }


def _worst_slice_fpr(per_slice: dict) -> dict:
    worst_name, worst = None, None
    for name, result in per_slice.items():
        if worst is None or float(result["fpr"]) > float(worst["fpr"]):
            worst_name, worst = name, result
    return {
        "slice": worst_name,
        "fpr": float(worst["fpr"]),
        "fpr_ci": worst["fpr_ci"],
        "n_human": worst["n_human"],
    }


def _tpr_at_fpr(scores: list[float], labels: list[int], *, target_fpr: float = 0.01) -> dict:
    humans = [s for s, y in zip(scores, labels, strict=True) if y == 0]
    machines = [s for s, y in zip(scores, labels, strict=True) if y == 1]
    max_score = max(scores)
    candidates = sorted(set(scores) | {math.nextafter(max_score, math.inf)})
    best = None
    for threshold in candidates:
        fpr = sum(s >= threshold for s in humans) / len(humans)
        tpr = sum(s >= threshold for s in machines) / len(machines)
        if fpr <= target_fpr:
            key = (tpr, -fpr, -threshold)
            if best is None or key > best[0]:
                best = (key, threshold, fpr, tpr)
    _, threshold, achieved_fpr, tpr = best
    return {"threshold": threshold, "achieved_fpr": achieved_fpr, "tpr": tpr}


def _abstention_rate(verdicts: list[str]) -> dict:
    abstained = sum(1 for v in verdicts if v == "abstain")
    return {"n": len(verdicts), "abstained": abstained, "rate": abstained / len(verdicts)}


def _metadata_diff(previous: dict, current: dict) -> dict:
    return {
        key: (previous.get(key), current.get(key))
        for key in sorted(set(previous) | set(current))
        if previous.get(key) != current.get(key)
    }


def _holm_adjusted(p_values: list[float]) -> list[float]:
    order = sorted(range(len(p_values)), key=lambda i: p_values[i])
    adjusted = [0.0] * len(p_values)
    running_max = 0.0
    remaining = len(p_values)
    for rank, idx in enumerate(order):
        value = p_values[idx] * (remaining - rank)
        running_max = max(running_max, value)
        adjusted[idx] = min(1.0, running_max)
    return adjusted


@pytest.fixture()
def stub_primitives() -> types.SimpleNamespace:
    return types.SimpleNamespace(
        wilson_ci=_wilson_ci,
        ks_statistic=_ks_statistic,
        ks_pvalue=_ks_pvalue,
        psi=_psi,
        flip_summary=_flip_summary,
        ece=_ece,
        brier=_brier,
        set_coverage=_set_coverage,
        coverage_shortfall_pp=_coverage_shortfall_pp,
        fpr_at_threshold=_fpr_at_threshold,
        worst_slice_fpr=_worst_slice_fpr,
        tpr_at_fpr=_tpr_at_fpr,
        abstention_rate=_abstention_rate,
        metadata_diff=_metadata_diff,
        holm_adjusted=_holm_adjusted,
    )


# ---------------------------------------------------------------------------
# Synthetic fixtures
# ---------------------------------------------------------------------------


def _make_records(
    *,
    seed: int,
    human_native: int = 120,
    human_short: int = 60,
    ai_current: int = 60,
    ai_paraphrased: int = 60,
    shift_paraphrased: float = 0.0,
    calibrated: bool = False,
    flip_human_to_ai: int = 0,
    abstain_every: int = 0,
) -> tuple[list[dict], dict[str, int], dict[str, str]]:
    """Deterministic synthetic snapshot records + labels + slices."""
    rng = random.Random(seed)
    records: list[dict] = []
    labels: dict[str, int] = {}
    slices: dict[str, str] = {}

    def _add(item_id: str, slice_name: str, label: int, score: float) -> None:
        verdict = "ai_like" if score >= 0.68 else "human_like"
        records.append(
            {
                "sample_id": item_id,
                "text_sha256": "c" * 64,
                "detector_id": "textforensics/builtin-heuristic",
                "detector_version": "0.1.0",
                "detector_family": "heuristic",
                "execution": "local",
                "score": round(score, 6),
                "score_semantics": "native heuristic score; not a probability",
                "verdict": verdict,
                "threshold": 0.68,
                "calibrated_ai_probability": round(score, 6) if calibrated else None,
                "calibration_id": "cal-2026-11-07" if calibrated else None,
                "provider_version": None,
                "observed_at": "2026-11-07T00:00:00+00:00",
            }
        )
        labels[item_id] = label
        slices[item_id] = slice_name

    for i in range(human_native):
        _add(f"hn-{i:03d}", "human-native", 0, min(0.99, max(0.01, rng.gauss(0.30, 0.10))))
    for i in range(human_short):
        _add(f"hs-{i:03d}", "human-short", 0, min(0.99, max(0.01, rng.gauss(0.32, 0.10))))
    for i in range(ai_current):
        _add(f"ac-{i:03d}", "ai-current-generator", 1, min(0.99, max(0.01, rng.gauss(0.72, 0.10))))
    for i in range(ai_paraphrased):
        score = min(0.99, max(0.01, rng.gauss(0.62, 0.10) + shift_paraphrased))
        _add(f"ap-{i:03d}", "ai-paraphrased", 1, score)

    # Optional deterministic flips: first N human-native verdicts -> ai_like.
    for record in records[:flip_human_to_ai]:
        record["verdict"] = "ai_like"
        record["score"] = 0.75
    if abstain_every:
        for j, record in enumerate(records):
            if (j + 1) % abstain_every == 0:
                record["verdict"] = "abstain"
    return records, labels, slices


def _metrics_kwargs(records, labels, slices, *, baseline=None, previous=None, **extra):
    return {
        "current_records": records,
        "baseline_records": baseline,
        "previous_records": previous,
        "labels": labels,
        "slices": slices,
        "detector_id": "textforensics/builtin-heuristic",
        **extra,
    }


# ---------------------------------------------------------------------------
# Primitives seam
# ---------------------------------------------------------------------------


def test_load_probe_metrics_accepts_injected_primitives(stub_primitives):
    assert load_probe_metrics(stub_primitives) is stub_primitives


def test_load_probe_metrics_rejects_incomplete_stub():
    with pytest.raises(ProbeRunError, match="lack"):
        load_probe_metrics(types.SimpleNamespace(wilson_ci=_wilson_ci))


def test_load_probe_metrics_missing_module_raises_unavailable(monkeypatch):
    # Block the import rather than assuming the module is absent: a None
    # entry in sys.modules makes `import` raise ImportError, and the
    # package attribute must go too or `from . import probe_metrics`
    # returns the already-imported module without importing.
    import textforensics

    monkeypatch.setitem(sys.modules, "textforensics.probe_metrics", None)
    monkeypatch.delattr(textforensics, "probe_metrics", raising=False)
    with pytest.raises(ProbeMetricsUnavailable, match="not available"):
        load_probe_metrics()


def test_load_probe_metrics_resolves_real_module():
    """Post-merge contract: the real probe_metrics satisfies the seam."""
    from textforensics import probe_metrics

    resolved = load_probe_metrics()
    assert resolved is probe_metrics
    assert all(hasattr(probe_metrics, name) for name in _PRIMITIVE_NAMES)
    # Value spot-checks (same inputs verified by hand at merge time).
    a = [0.1, 0.2, 0.3, 0.4, 0.5] * 20
    b = [0.35, 0.45, 0.55, 0.65, 0.75] * 20
    assert probe_metrics.ks_statistic(a, b) == pytest.approx(0.6)
    assert probe_metrics.psi(a, b) > 0
    assert probe_metrics.psi(a, a) == 0.0
    assert probe_metrics.wilson_ci(0, 125) == pytest.approx((0.0, 0.02982), abs=1e-4)
    assert probe_metrics.holm_adjusted([0.001, 0.02, 0.3]) == pytest.approx([0.003, 0.04, 0.3])


# ---------------------------------------------------------------------------
# Metric aggregation
# ---------------------------------------------------------------------------


def test_compute_run_metrics_baseline_run(stub_primitives):
    records, labels, slices = _make_records(seed=1)
    metrics = compute_run_metrics(
        **_metrics_kwargs(records, labels, slices), primitives=stub_primitives
    )
    assert metrics["detector_id"] == "textforensics/builtin-heuristic"
    assert set(metrics["slices"]) == {
        "human-native",
        "human-short",
        "ai-current-generator",
        "ai-paraphrased",
    }
    assert metrics["slices"]["human-native"]["n"] == 120
    assert metrics["slices"]["human-short"]["n"] == 60
    # Baseline run: no baseline to compare against, no previous run.
    assert metrics["slices"]["human-native"]["score_shift"]["status"] == "unavailable"
    assert metrics["slices"]["human-native"]["flips"] is None
    # No calibrated probabilities from the builtin: ECE/Brier unavailable,
    # conformal coverage unavailable (no conformal machinery in the repo).
    calibration = metrics["slices"]["human-native"]["calibration"]
    assert calibration["ece"] is None and calibration["brier"] is None
    assert calibration["conformal_status"] == "unavailable"
    # Human-native (n=120) carries an FPR claim; human-short (n=60) does not.
    assert metrics["slices"]["human-native"]["human_fpr"]["fpr_claim_allowed"] is True
    assert metrics["slices"]["human-short"]["human_fpr"]["fpr_claim_allowed"] is False
    # Worst-slice FPR is reported (never the mean) across claimable slices.
    assert metrics["worst_slice_fpr"]["slice"] == "human-native"
    # Abstention rate is zero on the clean fixture.
    assert metrics["overall"]["abstention_rate"] == 0.0


def test_compute_run_metrics_mixed_origin_label_none(stub_primitives):
    """Mixed-origin items (label None) are scored but never labelled."""
    records, labels, slices = _make_records(seed=11)
    # Add 50 mixed-origin items with no binary label.
    for i in range(50):
        item_id = f"mo-{i:03d}"
        records.append(
            {
                "sample_id": item_id,
                "text_sha256": "c" * 64,
                "detector_id": "textforensics/builtin-heuristic",
                "detector_version": "0.1.0",
                "detector_family": "heuristic",
                "execution": "local",
                "score": 0.55,
                "score_semantics": "native heuristic score; not a probability",
                "verdict": "human_like",
                "threshold": 0.68,
                "calibrated_ai_probability": None,
                "calibration_id": None,
                "provider_version": None,
                "observed_at": "2026-11-07T00:00:00+00:00",
            }
        )
        labels[item_id] = None
        slices[item_id] = "mixed-origin"
    metrics = compute_run_metrics(
        **_metrics_kwargs(records, labels, slices), primitives=stub_primitives
    )
    mixed = metrics["slices"]["mixed-origin"]
    assert mixed["n"] == 50
    assert mixed["n_human"] == 0 and mixed["n_ai"] == 0
    assert mixed["human_fpr"] is None
    assert mixed["attacked_tpr"] is None
    # They still count in the overall population and abstention rate.
    assert metrics["overall"]["n"] == 350
    # A bad label value (not 0/1/None) still fails closed.
    labels["mo-000"] = 2
    with pytest.raises(ProbeRunError, match="must be 0, 1, or None"):
        compute_run_metrics(**_metrics_kwargs(records, labels, slices), primitives=stub_primitives)


def test_compute_run_metrics_no_drift_vs_baseline(stub_primitives):
    records, labels, slices = _make_records(seed=2)
    metrics = compute_run_metrics(
        **_metrics_kwargs(records, labels, slices, baseline=records),
        primitives=stub_primitives,
    )
    shift = metrics["slices"]["human-native"]["score_shift"]
    assert shift["ks_statistic"] == 0.0
    assert shift["psi"] == 0.0
    assert shift["status"] == "stable"
    assert metrics["holm"]["adjusted_pvalues"]["human-native"] == 1.0


def test_compute_run_metrics_drift_injection_shows_psi_breach(stub_primitives):
    baseline, labels, slices = _make_records(seed=3)
    current, _, _ = _make_records(seed=3, shift_paraphrased=0.25)
    metrics = compute_run_metrics(
        **_metrics_kwargs(current, labels, slices, baseline=baseline),
        primitives=stub_primitives,
    )
    shift = metrics["slices"]["ai-paraphrased"]["score_shift"]
    assert shift["psi"] is not None and shift["psi"] > 0.2
    assert shift["status"] == "breach"
    assert shift["ks_statistic"] is not None and shift["ks_statistic"] >= 0.10
    # The unshifted slice stays stable.
    assert metrics["slices"]["human-native"]["score_shift"]["status"] == "stable"


def test_compute_run_metrics_ks_only_breach_shows_breach_status(stub_primitives):
    # Point-mass scores, uniformly shifted: KS = 1.0 with Holm p = 0,
    # but the test-double PSI (quantile bins over a point mass)
    # collapses to 0. The status must still say "breach" — it follows
    # the Tier-3 rule (PSI or KS), not PSI alone. (The real
    # probe_metrics.psi uses equal-width bins over the combined range
    # and would also breach here; the stub's 0.0 is a double artifact.)
    def _point_records(score: float) -> tuple[list[dict], dict, dict]:
        records: list[dict] = []
        labels: dict[str, int] = {}
        slices: dict[str, str] = {}
        for i in range(50):
            item_id = f"hn-{i:03d}"
            records.append(
                {
                    "sample_id": item_id,
                    "text_sha256": "c" * 64,
                    "detector_id": "textforensics/builtin-heuristic",
                    "detector_version": "0.1.0",
                    "detector_family": "heuristic",
                    "execution": "local",
                    "score": score,
                    "score_semantics": "native heuristic score; not a probability",
                    "verdict": "human_like",
                    "threshold": 0.68,
                    "calibrated_ai_probability": None,
                    "calibration_id": None,
                    "provider_version": None,
                    "observed_at": "2026-11-07T00:00:00+00:00",
                }
            )
            labels[item_id] = 0
            slices[item_id] = "human-native"
        return records, labels, slices

    baseline, labels, slices = _point_records(0.30)
    current, _, _ = _point_records(0.35)
    metrics = compute_run_metrics(
        **_metrics_kwargs(current, labels, slices, baseline=baseline),
        primitives=stub_primitives,
    )
    shift = metrics["slices"]["human-native"]["score_shift"]
    assert shift["ks_statistic"] == 1.0
    assert shift["ks_pvalue_holm_adjusted"] == 0.0
    assert shift["psi"] == 0.0
    assert shift["status"] == "breach"
    assert "KS statistic" in shift["reason"]


def test_compute_run_metrics_flips_directional(stub_primitives):
    baseline, labels, slices = _make_records(seed=4)
    current, _, _ = _make_records(seed=4, flip_human_to_ai=3)
    metrics = compute_run_metrics(
        **_metrics_kwargs(current, labels, slices, baseline=baseline, previous=baseline),
        primitives=stub_primitives,
    )
    flips = metrics["slices"]["human-native"]["flips"]
    assert flips["flips"] == 3
    assert flips["human_to_ai"] == 3
    assert flips["ai_to_human"] == 0
    assert flips["flip_rate_ci"][0] > 0  # Wilson CI excludes 0.
    overall = metrics["overall"]["flips"]
    assert overall["flips"] == 3


def test_compute_run_metrics_calibrated_detector_gets_ece_brier(stub_primitives):
    records, labels, slices = _make_records(seed=5, calibrated=True)
    metrics = compute_run_metrics(
        **_metrics_kwargs(records, labels, slices), primitives=stub_primitives
    )
    calibration = metrics["slices"]["human-native"]["calibration"]
    assert calibration["ece"] is not None and 0.0 <= calibration["ece"] <= 1.0
    assert calibration["brier"] is not None and 0.0 <= calibration["brier"] <= 1.0
    # Conformal coverage stays unavailable even for a calibrated detector.
    assert calibration["conformal_status"] == "unavailable"


def test_compute_run_metrics_attacked_tpr_uses_human_reference(stub_primitives):
    records, labels, slices = _make_records(seed=6)
    metrics = compute_run_metrics(
        **_metrics_kwargs(records, labels, slices), primitives=stub_primitives
    )
    attacked = metrics["slices"]["ai-paraphrased"]["attacked_tpr"]
    assert attacked["tpr_at_1pct_fpr"] is not None
    assert 0.0 <= attacked["tpr_at_1pct_fpr"] <= 1.0
    assert attacked["n_human_reference"] == 180
    # Non-attacked slices carry no attacked TPR.
    assert metrics["slices"]["human-native"]["attacked_tpr"] is None


def test_compute_run_metrics_abstention_rate(stub_primitives):
    records, labels, slices = _make_records(seed=7, abstain_every=10)
    metrics = compute_run_metrics(
        **_metrics_kwargs(records, labels, slices), primitives=stub_primitives
    )
    assert metrics["overall"]["abstention_rate"] == pytest.approx(0.1)
    assert metrics["overall"]["abstained"] == 30


def test_compute_run_metrics_missing_label_fails_closed(stub_primitives):
    records, labels, slices = _make_records(seed=8)
    del labels[records[0]["sample_id"]]
    with pytest.raises(ProbeRunError, match="no holdback label"):
        compute_run_metrics(**_metrics_kwargs(records, labels, slices), primitives=stub_primitives)


def test_compute_run_metrics_missing_slice_fails_closed(stub_primitives):
    records, labels, slices = _make_records(seed=9)
    del slices[records[0]["sample_id"]]
    with pytest.raises(ProbeRunError, match="no slice"):
        compute_run_metrics(**_metrics_kwargs(records, labels, slices), primitives=stub_primitives)


def test_compute_run_metrics_holm_family_is_per_slice_ks(stub_primitives):
    baseline, labels, slices = _make_records(seed=10)
    current, _, _ = _make_records(seed=10, shift_paraphrased=0.25)
    metrics = compute_run_metrics(
        **_metrics_kwargs(current, labels, slices, baseline=baseline),
        primitives=stub_primitives,
    )
    adjusted = metrics["holm"]["adjusted_pvalues"]
    assert set(adjusted) == {
        "human-native",
        "human-short",
        "ai-current-generator",
        "ai-paraphrased",
    }
    assert metrics["holm"]["family"] == "per-slice KS tests"
    assert metrics["holm"]["alpha_per_run"] == 0.05
    # Adjusted p-values are >= raw p-values.
    for name, adj in adjusted.items():
        raw = metrics["slices"][name]["score_shift"]["ks_pvalue"]
        assert adj >= raw


# ---------------------------------------------------------------------------
# Tier engine
# ---------------------------------------------------------------------------


def _tier_metrics(*, flip_rate=None, fpr=None, psi_breach=False, ece_increase=None):
    """Hand-built metric dicts for tier tests (no primitives needed)."""
    slices = {
        "human-native": {
            "n": 120,
            "drift_signal_allowed": True,
            "score_shift": {
                "ks_statistic": 0.30 if psi_breach else 0.02,
                "ks_pvalue": 0.001 if psi_breach else 0.6,
                "ks_pvalue_holm_adjusted": 0.004 if psi_breach else 0.6,
                "psi": 0.45 if psi_breach else 0.02,
                "status": "breach" if psi_breach else "stable",
            },
            "flips": (
                {
                    "n": 120,
                    "flips": int(flip_rate * 120),
                    "flip_rate": flip_rate,
                    "flip_rate_ci": [flip_rate / 2, flip_rate * 1.5],
                    "human_to_ai": int(flip_rate * 120),
                    "ai_to_human": 0,
                    "to_abstain": 0,
                    "from_abstain": 0,
                }
                if flip_rate is not None
                else None
            ),
            "calibration": {
                "ece": 0.10 if ece_increase is not None else 0.05,
                "baseline_ece": 0.05 if ece_increase is not None else 0.05,
            },
            "human_fpr": (
                {
                    "n_human": 120,
                    "false_positives": int(fpr * 120),
                    "fpr": fpr,
                    "fpr_ci": [fpr - 0.02, fpr + 0.02],
                    "fpr_claim_allowed": True,
                    "cap": 0.05,
                }
                if fpr is not None
                else None
            ),
        },
        "human-short": {
            "n": 60,
            "drift_signal_allowed": True,
            "score_shift": {
                "ks_statistic": 0.02,
                "ks_pvalue": 0.6,
                "ks_pvalue_holm_adjusted": 0.6,
                "psi": 0.02,
                "status": "stable",
            },
            "flips": None,
            "calibration": {"ece": None, "baseline_ece": None},
            "human_fpr": None,
        },
    }
    if ece_increase is not None:
        slices["human-native"]["calibration"]["ece"] = 0.05 + ece_increase
    return {
        "detector_id": "textforensics/builtin-heuristic",
        "slices": slices,
        "overall": {"flips": None},
        "worst_slice_fpr": None,
        "holm": {"alpha_per_run": 0.05, "family": "per-slice KS tests", "adjusted_pvalues": {}},
    }


def test_tier3_single_run_drift_statistic_records_only():
    result = evaluate_tiers(
        metrics=_tier_metrics(psi_breach=True),
        detector_version="0.1.0",
    )
    assert result["demote"] is False and result["watch"] is False
    assert len(result["alerts"]) == 1
    assert result["alerts"][0]["tier"] == 3
    assert result["alerts"][0]["action"] == "record"
    # Both breached statistics (PSI and KS) are recorded as evidence...
    assert len(result["breaches"]) == 2
    # ...but they are one drift event, hence one alert.
    assert result["alerts"][0]["rule"] == "drift_statistic"


def test_tier2_drift_statistic_on_two_consecutive_runs():
    metrics = _tier_metrics(psi_breach=True)
    first = evaluate_tiers(metrics=metrics, detector_version="0.1.0")
    second = evaluate_tiers(
        metrics=metrics,
        previous_breaches=first["breaches"],
        detector_version="0.1.0",
    )
    assert second["demote"] is False
    assert second["watch"] is True
    assert len(second["alerts"]) == 1
    assert second["alerts"][0]["tier"] == 2
    assert second["alerts"][0]["action"] == "investigate"
    assert second["alerts"][0]["consecutive_runs"] == 2


def test_drift_statistic_alone_never_demotes_even_after_three_runs():
    metrics = _tier_metrics(psi_breach=True)
    previous_breaches = None
    for _ in range(3):
        result = evaluate_tiers(
            metrics=metrics,
            previous_breaches=previous_breaches,
            detector_version="0.1.0",
        )
        assert result["demote"] is False
        previous_breaches = result["breaches"]


def test_tier2_flip_rate_above_1pct_with_ci_excluding_zero():
    result = evaluate_tiers(
        metrics=_tier_metrics(flip_rate=0.02),
        detector_version="0.1.0",
    )
    assert result["watch"] is True and result["demote"] is False
    assert result["alerts"][0]["tier"] == 2
    assert result["alerts"][0]["rule"] == "flip_rate"


def test_tier1_flip_rate_above_5pct_demotes():
    result = evaluate_tiers(
        metrics=_tier_metrics(flip_rate=0.06),
        detector_version="0.1.0",
    )
    assert result["demote"] is True
    assert any(a["tier"] == 1 and a["rule"] == "flip_rate" for a in result["alerts"])


def test_tier1_flip_rate_requires_human_to_ai_direction():
    # Same 6% flip rate, but every flip is AI->human (a recovery, or
    # a sensitivity loss on machine slices) — never a Tier-1 demotion.
    metrics = _tier_metrics(flip_rate=0.06)
    flips = metrics["slices"]["human-native"]["flips"]
    flips["human_to_ai"] = 0
    flips["ai_to_human"] = flips["flips"]
    result = evaluate_tiers(metrics=metrics, detector_version="0.1.0")
    assert result["demote"] is False
    assert not any(a["tier"] == 1 for a in result["alerts"])
    # It is still a Tier-2 watch: a 6% flip rate deserves investigation.
    assert result["watch"] is True


def test_tier1_flip_rate_ignores_machine_slice_flips():
    # Mass AI->human flips on an attacked slice are a sensitivity
    # signal, not a human-FPR event; the flip rule alone never demotes.
    metrics = _tier_metrics(flip_rate=None)
    metrics["slices"]["ai-paraphrased"] = {
        "n": 50,
        "is_human_slice": False,
        "drift_signal_allowed": True,
        "score_shift": {
            "ks_statistic": 0.02,
            "ks_pvalue": 0.6,
            "ks_pvalue_holm_adjusted": 0.6,
            "psi": 0.02,
            "status": "stable",
        },
        "flips": {
            "n": 50,
            "flips": 40,
            "flip_rate": 0.8,
            "flip_rate_ci": [0.7, 0.9],
            "human_to_ai": 0,
            "ai_to_human": 40,
            "to_abstain": 0,
            "from_abstain": 0,
        },
        "calibration": {"ece": None, "baseline_ece": None},
        "human_fpr": None,
    }
    result = evaluate_tiers(metrics=metrics, detector_version="0.1.0")
    assert result["demote"] is False
    assert not any(a["tier"] == 1 for a in result["alerts"])


def test_tier1_fpr_cap_breach_is_ci_aware():
    # FPR 0.08 with CI lower bound 0.06 > cap 0.05 -> demote.
    result = evaluate_tiers(
        metrics=_tier_metrics(fpr=0.08),
        detector_version="0.1.0",
    )
    assert result["demote"] is True
    assert any(a["tier"] == 1 and a["rule"] == "human_fpr_cap" for a in result["alerts"])


def test_fpr_below_cap_does_not_demote():
    # FPR 0.06 with CI lower bound 0.04 <= cap 0.05 -> no demotion.
    result = evaluate_tiers(
        metrics=_tier_metrics(fpr=0.06),
        detector_version="0.1.0",
    )
    assert result["demote"] is False


def test_tier2_ece_increase_above_threshold():
    result = evaluate_tiers(
        metrics=_tier_metrics(ece_increase=0.06),
        detector_version="0.1.0",
    )
    assert result["watch"] is True
    assert any(a["tier"] == 2 and a["rule"] == "calibration_drift" for a in result["alerts"])


def test_tier1_version_change_with_no_run_within_7_days():
    result = evaluate_tiers(
        metrics=_tier_metrics(),
        detector_version="0.2.0",
        previous_detector_version="0.1.0",
        previous_run_at="2026-11-01T00:00:00+00:00",
        run_at="2026-11-10T00:00:00+00:00",
    )
    assert result["demote"] is True
    assert any(
        a["tier"] == 1 and a["rule"] == "version_change_no_probe_run" for a in result["alerts"]
    )


def test_version_change_with_recent_run_does_not_demote():
    result = evaluate_tiers(
        metrics=_tier_metrics(),
        detector_version="0.2.0",
        previous_detector_version="0.1.0",
        previous_run_at="2026-11-08T00:00:00+00:00",
        run_at="2026-11-10T00:00:00+00:00",
    )
    assert result["demote"] is False


# ---------------------------------------------------------------------------
# Run manifest: build / validate / store
# ---------------------------------------------------------------------------


def _manifest(**overrides):
    kwargs = {
        "scope": "full",
        "corpus_version": "1.0.0",
        "corpus_fingerprint": HEX64,
        "corpus_manifest_sha256": HEX64_B,
        "detector_id": "textforensics/builtin-heuristic",
        "detector_version": "0.1.0",
        "provider_metadata": {},
        "code_sha": "c" * 40,
        "baseline_run_id": None,
        "is_baseline": True,
        "rebaselined_from": None,
        "previous_run_id": None,
        "metrics": {"detector_id": "textforensics/builtin-heuristic"},
        "alerts": [],
        "breaches": [],
    }
    kwargs.update(overrides)
    return build_run_manifest(**kwargs)


def test_build_run_manifest_records_thresholds_and_gaps():
    manifest = _manifest()
    assert manifest["schema"] == "textforensics.probe-run/v1"
    assert manifest["thresholds"]["psi_action"] == 0.2
    assert manifest["thresholds"]["flip_rate_tier1"] == 0.05
    assert manifest["alpha_per_run"] == 0.05
    assert any("MMD is unavailable" in gap for gap in manifest["gaps"])
    assert any("Conformal coverage is unavailable" in gap for gap in manifest["gaps"])
    assert manifest["scope_statement"].startswith("probe run:")
    validate_run_manifest(manifest)


def test_build_run_manifest_rejects_bad_scope():
    with pytest.raises(ProbeRunError, match="scope"):
        _manifest(scope="weekly")


def test_build_run_manifest_rejects_bad_fingerprint():
    with pytest.raises(ProbeRunError, match="corpus_fingerprint"):
        _manifest(corpus_fingerprint="not-a-hash")


def test_run_manifest_round_trip(tmp_path):
    manifest = _manifest()
    saved = save_run(manifest, tmp_path)
    assert saved.exists()
    loaded = load_run(saved)
    assert loaded == manifest
    assert load_run_history(tmp_path) == [manifest]


def test_run_history_orders_oldest_first(tmp_path):
    first = _manifest(run_at_utc="2026-11-01T00:00:00+00:00", run_id="a" * 32)
    second = _manifest(run_at_utc="2026-11-02T00:00:00+00:00", run_id="b" * 32)
    save_run(second, tmp_path)
    save_run(first, tmp_path)
    history = load_run_history(tmp_path)
    assert [r["run_id"] for r in history] == ["a" * 32, "b" * 32]


def test_run_history_empty_dir(tmp_path):
    assert load_run_history(tmp_path) == []


def test_validate_run_manifest_rejects_tampered_scope_statement():
    manifest = _manifest()
    manifest["scope_statement"] = "tampered"
    with pytest.raises(ProbeRunError, match="scope statement"):
        validate_run_manifest(manifest)


# ---------------------------------------------------------------------------
# Baseline management + longitudinal summary
# ---------------------------------------------------------------------------


def _history_run(run_id, at, *, baseline=False, version="0.1.0", alerts=()):
    return {
        "schema": "textforensics.probe-run/v1",
        "run_id": run_id,
        "run_at_utc": at,
        "scope": "full",
        "corpus_version": "1.0.0",
        "corpus_fingerprint": HEX64,
        "detector_id": "textforensics/builtin-heuristic",
        "detector_version": version,
        "is_baseline": baseline,
        "alerts": list(alerts),
    }


def test_resolve_baseline_ignores_partial_scope_run():
    history = [
        _history_run("r1", "2026-11-01T00:00:00+00:00", baseline=True),
    ]
    history[0]["scope"] = "monthly-attacked"
    assert (
        resolve_baseline(
            history,
            detector_id="textforensics/builtin-heuristic",
            detector_version="0.1.0",
            corpus_fingerprint=HEX64,
        )
        is None
    )


def test_resolve_baseline_first_run():
    history = [_history_run("r1", "2026-11-01T00:00:00+00:00", baseline=True)]
    assert (
        resolve_baseline(
            history,
            detector_id="textforensics/builtin-heuristic",
            detector_version="0.1.0",
            corpus_fingerprint=HEX64,
        )["run_id"]
        == "r1"
    )


def test_resolve_baseline_version_change_has_no_baseline():
    history = [_history_run("r1", "2026-11-01T00:00:00+00:00", baseline=True)]
    assert (
        resolve_baseline(
            history,
            detector_id="textforensics/builtin-heuristic",
            detector_version="0.2.0",
            corpus_fingerprint=HEX64,
        )
        is None
    )


def test_resolve_baseline_rebaseline_replaces_but_keeps_history():
    history = [
        _history_run("r1", "2026-11-01T00:00:00+00:00", baseline=True),
        _history_run("r2", "2026-11-02T00:00:00+00:00", baseline=True, version="0.2.0"),
    ]
    assert (
        resolve_baseline(
            history,
            detector_id="textforensics/builtin-heuristic",
            detector_version="0.2.0",
            corpus_fingerprint=HEX64,
        )["run_id"]
        == "r2"
    )
    # The old baseline is still in history.
    assert (
        resolve_baseline(
            history,
            detector_id="textforensics/builtin-heuristic",
            detector_version="0.1.0",
            corpus_fingerprint=HEX64,
        )["run_id"]
        == "r1"
    )


def test_longitudinal_counts_consecutive_clean_full_runs():
    history = [
        _history_run("r1", "2026-11-01T00:00:00+00:00", baseline=True),
        _history_run("r2", "2026-11-02T00:00:00+00:00"),
        _history_run("r3", "2026-11-03T00:00:00+00:00"),
    ]
    summary = summarize_longitudinal(
        history,
        detector_id="textforensics/builtin-heuristic",
        detector_version="0.1.0",
        corpus_fingerprint=HEX64,
    )
    assert summary["consecutive_clean_full_runs"] == 3
    assert summary["temporal_support"] is True
    assert summary["clean_full_run_ids"] == ["r3", "r2", "r1"]


def test_longitudinal_streak_breaks_on_tier2_alert():
    history = [
        _history_run("r1", "2026-11-01T00:00:00+00:00", baseline=True),
        _history_run(
            "r2",
            "2026-11-02T00:00:00+00:00",
            alerts=[{"tier": 2, "rule": "drift_statistic"}],
        ),
        _history_run("r3", "2026-11-03T00:00:00+00:00"),
    ]
    summary = summarize_longitudinal(
        history,
        detector_id="textforensics/builtin-heuristic",
        detector_version="0.1.0",
        corpus_fingerprint=HEX64,
    )
    assert summary["consecutive_clean_full_runs"] == 1
    assert summary["temporal_support"] is False
    assert summary["watch"]["run_id"] == "r2"


def test_longitudinal_no_runs():
    summary = summarize_longitudinal(
        [],
        detector_id="textforensics/builtin-heuristic",
        detector_version="0.1.0",
        corpus_fingerprint=HEX64,
    )
    assert summary["consecutive_clean_full_runs"] == 0
    assert summary["temporal_support"] is False
    assert summary["watch"] is None


# ---------------------------------------------------------------------------
# Demotion hook (uses the real validation registry on a temp copy)
# ---------------------------------------------------------------------------


def _registry_copy(tmp_path) -> Path:
    import shutil

    source = Path(__file__).resolve().parent.parent / "docs" / "validation" / "registry.json"
    target = tmp_path / "registry.json"
    shutil.copy(source, target)
    return target


def test_apply_demotions_sets_demoted_by_and_stale(tmp_path):
    registry_path = _registry_copy(tmp_path)
    before = load_validation_registry(registry_path)
    assert before.records, "seeded U1 registry expected"
    detector_id = before.records[0].detector_id
    result = apply_demotions(
        registry_path=registry_path,
        detector_id=detector_id,
        run_id="run-123",
        alerts=[{"tier": 1, "rule": "human_fpr_cap", "slice": "human-native"}],
    )
    assert result["demoted_record_ids"]
    assert "U3 probe run run-123" in result["reason"]
    after = load_validation_registry(registry_path)
    for record in after.records:
        if record.record_id in result["demoted_record_ids"]:
            assert record.limits.demoted_by is not None
            assert record.limits.demoted_by.startswith("U3 probe run run-123")
            assert (
                effective_status(
                    record,
                    detector_version=record.detector_version,
                    now="2026-11-07T00:00:00+00:00",
                )
                == "stale"
            )


def test_apply_demotions_no_tier1_is_noop(tmp_path):
    registry_path = _registry_copy(tmp_path)
    before = (registry_path).read_text(encoding="utf-8")
    result = apply_demotions(
        registry_path=registry_path,
        detector_id="textforensics/builtin-heuristic",
        run_id="run-123",
        alerts=[{"tier": 3, "rule": "drift_statistic"}],
    )
    assert result["demoted_record_ids"] == []
    assert (registry_path).read_text(encoding="utf-8") == before


def test_apply_demotions_no_records_is_gap(tmp_path):
    registry_path = _registry_copy(tmp_path)
    result = apply_demotions(
        registry_path=registry_path,
        detector_id="textforensics/does-not-exist",
        run_id="run-123",
        alerts=[{"tier": 1, "rule": "human_fpr_cap"}],
    )
    assert result["demoted_record_ids"] == []
    assert result["gap"] is not None and "No U1 validation records" in result["gap"]


def test_clear_demotions_after_clean_rerun(tmp_path):
    registry_path = _registry_copy(tmp_path)
    before = load_validation_registry(registry_path)
    detector_id = before.records[0].detector_id
    apply_demotions(
        registry_path=registry_path,
        detector_id=detector_id,
        run_id="run-123",
        alerts=[{"tier": 1, "rule": "flip_rate"}],
    )
    cleared = clear_demotions(
        registry_path=registry_path,
        detector_id=detector_id,
        run_id="run-124",
    )
    assert cleared["cleared_record_ids"]
    after = load_validation_registry(registry_path)
    for record in after.records:
        assert record.limits.demoted_by is None


def test_clear_demotions_leaves_foreign_demotions_alone(tmp_path):
    import dataclasses

    from textforensics.validation import ValidationRegistry, compute_signature

    registry_path = _registry_copy(tmp_path)
    registry = load_validation_registry(registry_path)
    record = registry.records[0]
    foreign_limits = dataclasses.replace(record.limits, demoted_by="manual review 2026-11-01")
    unsigned = record.to_dict()
    unsigned["limits"] = foreign_limits.to_dict()
    unsigned.pop("signature", None)
    foreign = dataclasses.replace(
        record, limits=foreign_limits, signature=compute_signature(unsigned)
    )
    replaced = [foreign if r.record_id == record.record_id else r for r in registry.records]
    ValidationRegistry(replaced, created_at_utc=registry.created_at_utc).save(registry_path)
    cleared = clear_demotions(
        registry_path=registry_path,
        detector_id=record.detector_id,
        run_id="run-125",
    )
    assert cleared["cleared_record_ids"] == []
    after = load_validation_registry(registry_path)
    assert after.record(record.record_id).limits.demoted_by == "manual review 2026-11-01"
