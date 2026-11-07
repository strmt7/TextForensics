"""Per-run drift metrics for the U3 observatory — pure functions only.

Every function here takes supplied scores / verdicts / labels and
returns numbers. Nothing here reads the probe corpus, runs a
detector, touches ``observatory.py`` or ``validation.py``, or decides
an alert tier: those are the full U3 coordinator's job (after U2
lands). These functions are the *measurement* half of §7.6 metrics
1–7, kept deliberately free of any policy so they are testable in
isolation and reusable by the observatory run.

Design notes
------------
* No scipy. The research (§7.6) says "implement the ~5 tests in
  scipy — do not take the dependency", but scipy is not a dependency
  of this repo at all, and AGENTS.md rule 14 keeps heavy dependencies
  out of the core. The tests below are small closed forms implemented
  in the standard library: two-sample KS (with the Kolmogorov
  asymptotic p-value series), PSI over quantile bins, Wilson score
  intervals, ECE/Brier, empirical ROC thresholds, Holm-Bonferroni.
  Formulas are cited in the docstrings.
* Verdict vocabulary is exactly ``observatory.VERDICTS``:
  ``{"ai_like", "human_like", "abstain"}``. Any other verdict value
  fails closed.
* Scores are native detector scores in [0, 1] where a function needs
  a probability (ECE/Brier/conformal coverage). The builtin heuristic
  detector's native score is NOT a probability (AGENTS.md rule 2);
  callers must pass calibrated probabilities to those functions, or
  record the metric as ``unavailable`` — never silently relabel a
  native score as a probability.
* Report the statistic + CI, not just a flag (research §7.2): at
  probe scale (n≈50/slice) p-values are underpowered for small
  shifts, so every function that can returns its interval alongside
  the point estimate.
"""

from __future__ import annotations

import bisect
import math
from typing import Any

VERDICTS = ("ai_like", "human_like", "abstain")
DEFAULT_Z = 1.96  # 95% two-sided normal quantile, Wilson intervals.
_PSI_EPSILON = 1e-4  # Smoothing for empty PSI bins (Evidently convention).


def wilson_ci(k: int, n: int, *, z: float = DEFAULT_Z) -> tuple[float, float]:
    """Wilson score interval for ``k`` successes in ``n`` trials.

    Returns ``(lo, hi)`` clamped to [0, 1]. The Wilson interval (not
    Wald) is used throughout: it behaves at the boundaries (k=0, k=n)
    where the FPR slices live.
    """
    if n <= 0:
        raise ValueError("wilson_ci needs n > 0")
    if k < 0 or k > n:
        raise ValueError(f"wilson_ci needs 0 <= k <= n, got k={k}, n={n}")
    if z <= 0:
        raise ValueError("wilson_ci needs z > 0")
    p = k / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def ks_statistic(sample_a: list[float], sample_b: list[float]) -> float:
    """Two-sample Kolmogorov–Smirnov statistic (max CDF gap)."""
    if not sample_a or not sample_b:
        raise ValueError("ks_statistic needs two non-empty samples")
    a = sorted(sample_a)
    b = sorted(sample_b)
    n, m = len(a), len(b)
    i = j = 0
    cdf_a = cdf_b = 0.0
    d = 0.0
    while i < n or j < m:
        if j == m or (i < n and a[i] < b[j]):
            i += 1
            cdf_a = i / n
        elif i == n or b[j] < a[i]:
            j += 1
            cdf_b = j / m
        else:  # tied values: advance both before measuring the gap
            value = a[i]
            while i < n and a[i] == value:
                i += 1
            while j < m and b[j] == value:
                j += 1
            cdf_a = i / n
            cdf_b = j / m
        d = max(d, abs(cdf_a - cdf_b))
    return d


def ks_pvalue(d: float, n: int, m: int) -> float:
    """Asymptotic two-sample KS p-value (Kolmogorov distribution).

    Uses the standard series ``Q(\\u03bb) = 2 * sum_j (-1)^(j-1)
    exp(-2 j^2 \\u03bb^2)`` with ``\\u03bb = (sqrt(ne) + 0.12 + 0.11 /
    sqrt(ne)) * d`` and ``ne = n*m/(n+m)`` (Numerical Recipes
    ``probks``). Valid for the probe scale (n, m in the tens to
    hundreds); for very small samples the asymptotic p-value is
    approximate and the statistic itself is the reported quantity.
    """
    if not 0.0 <= d <= 1.0:
        raise ValueError(f"ks_pvalue needs 0 <= d <= 1, got {d}")
    if n <= 0 or m <= 0:
        raise ValueError("ks_pvalue needs n > 0 and m > 0")
    if d == 0.0:
        return 1.0
    ne = n * m / (n + m)
    lam = (math.sqrt(ne) + 0.12 + 0.11 / math.sqrt(ne)) * d
    total = 0.0
    j = 1
    while True:
        term = 2.0 * ((-1.0) ** (j - 1)) * math.exp(-2.0 * j * j * lam * lam)
        total += term
        if abs(term) < 1e-12 or j > 100:
            break
        j += 1
    return max(0.0, min(1.0, total))


def psi(expected: list[float], actual: list[float], *, bins: int = 10) -> float:
    """Population Stability Index between two score samples.

    Bins are the quantiles of ``expected`` (the reference run);
    ``actual`` is binned on the same edges. Returns
    ``sum (actual% - expected%) * ln(actual% / expected%)`` with
    ``1e-4`` smoothing for empty bins. Thresholds (Evidently
    convention, research §7.2): <0.1 stable, 0.1–0.2 watch, >0.2
    investigate. Identical samples give exactly 0.
    """
    if not expected or not actual:
        raise ValueError("psi needs two non-empty samples")
    if bins <= 0:
        raise ValueError("psi needs bins > 0")
    ref = sorted(expected)
    n_ref = len(ref)
    # Interior cut points: the quantiles of the reference run. A value
    # equal to a cut goes to the higher bin (bisect_right) — deterministic
    # even with duplicated cut points.
    cuts = [ref[min(n_ref - 1, i * n_ref // bins)] for i in range(1, bins)]

    def _counts(sample: list[float]) -> list[int]:
        counts = [0] * bins
        for value in sample:
            counts[min(bisect.bisect_right(cuts, value), bins - 1)] += 1
        return counts

    ref_counts = _counts(expected)
    act_counts = _counts(actual)
    total = 0.0
    for e, a in zip(ref_counts, act_counts, strict=True):
        e_pct = max(e / len(expected), _PSI_EPSILON)
        a_pct = max(a / len(actual), _PSI_EPSILON)
        total += (a_pct - e_pct) * math.log(a_pct / e_pct)
    return total


def _check_verdicts(verdicts: list[str]) -> None:
    for verdict in verdicts:
        if verdict not in VERDICTS:
            raise ValueError(f"unknown verdict {verdict!r}; expected one of {VERDICTS}")


def flip_summary(
    previous: list[str], current: list[str]
) -> dict[str, int | float | tuple[float, float]]:
    """Verdict-flip rate between two runs on the same items.

    ``previous`` / ``current`` are verdicts in run order (same items,
    same order). Returns the flip count and rate with Wilson CI, plus
    the direction breakdown: ``human_to_ai`` (prev ``human_like``,
    now ``ai_like`` — an FPR event on human slices),
    ``ai_to_human``, ``to_abstain`` and ``from_abstain``. A flip
    toward AI on a human slice is an FPR event, not a symmetric
    disagreement — direction is the reported quantity.
    """
    if len(previous) != len(current):
        raise ValueError("flip_summary needs equal-length verdict lists")
    if not previous:
        raise ValueError("flip_summary needs a non-empty verdict list")
    _check_verdicts(previous)
    _check_verdicts(current)
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
        "flip_rate_ci": wilson_ci(flips, n),
        "human_to_ai": human_to_ai,
        "ai_to_human": ai_to_human,
        "to_abstain": to_abstain,
        "from_abstain": from_abstain,
    }


def ece(probs: list[float], labels: list[int], *, n_bins: int = 10) -> float:
    """Expected Calibration Error over probability/label pairs.

    ``probs`` must be calibrated probabilities in [0, 1] (rule 2:
    never pass a native uncalibrated score here); ``labels`` are
    0/1. ECE = sum over bins of |mean prob - mean label| * bin weight.
    """
    if len(probs) != len(labels):
        raise ValueError("ece needs equal-length probs and labels")
    if not probs:
        raise ValueError("ece needs a non-empty sample")
    if n_bins <= 0:
        raise ValueError("ece needs n_bins > 0")
    for prob in probs:
        if not 0.0 <= prob <= 1.0:
            raise ValueError(f"ece needs probs in [0, 1], got {prob}")
    for label in labels:
        if label not in (0, 1):
            raise ValueError(f"ece needs labels in {{0, 1}}, got {label!r}")
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


def brier(probs: list[float], labels: list[int]) -> float:
    """Brier score (mean squared error) over probability/label pairs."""
    if len(probs) != len(labels):
        raise ValueError("brier needs equal-length probs and labels")
    if not probs:
        raise ValueError("brier needs a non-empty sample")
    for prob in probs:
        if not 0.0 <= prob <= 1.0:
            raise ValueError(f"brier needs probs in [0, 1], got {prob}")
    for label in labels:
        if label not in (0, 1):
            raise ValueError(f"brier needs labels in {{0, 1}}, got {label!r}")
    return sum((p - y) ** 2 for p, y in zip(probs, labels, strict=True)) / len(probs)


def set_coverage(prediction_sets: list[set[int]], true_labels: list[int]) -> dict[str, int | float]:
    """Empirical conformal coverage: fraction of true labels in their set.

    ``prediction_sets`` are the per-item prediction sets (e.g. from a
    conformal predictor); a set containing the true label counts as
    covered. Returns covered count, n, and rate. Where no conformal
    machinery exists for a detector, the caller records coverage as
    ``unavailable`` — never as 0.
    """
    if len(prediction_sets) != len(true_labels):
        raise ValueError("set_coverage needs equal-length sets and labels")
    if not prediction_sets:
        raise ValueError("set_coverage needs a non-empty sample")
    covered = sum(1 for s, y in zip(prediction_sets, true_labels, strict=True) if y in s)
    return {"covered": covered, "n": len(true_labels), "rate": covered / len(true_labels)}


def coverage_shortfall_pp(empirical_rate: float, nominal_rate: float) -> float:
    """Conformal coverage shortfall in percentage points (nominal - empirical)."""
    if not 0.0 <= empirical_rate <= 1.0:
        raise ValueError("coverage_shortfall_pp needs empirical_rate in [0, 1]")
    if not 0.0 <= nominal_rate <= 1.0:
        raise ValueError("coverage_shortfall_pp needs nominal_rate in [0, 1]")
    return (nominal_rate - empirical_rate) * 100.0


def fpr_at_threshold(
    scores: list[float], labels: list[int], threshold: float
) -> dict[str, int | float | tuple[float, float]]:
    """Human-slice FPR at a declared operating point + Wilson CI.

    ``labels`` are 0 (human) / 1 (machine); FPR = fraction of human
    items with ``score >= threshold``. The declared threshold is an
    input, never fitted here.
    """
    if len(scores) != len(labels):
        raise ValueError("fpr_at_threshold needs equal-length scores and labels")
    if not scores:
        raise ValueError("fpr_at_threshold needs a non-empty sample")
    humans = [s for s, y in zip(scores, labels, strict=True) if y == 0]
    if not humans:
        raise ValueError("fpr_at_threshold needs at least one human item")
    if any(y not in (0, 1) for y in labels):
        raise ValueError("fpr_at_threshold needs labels in {0, 1}")
    false_positives = sum(1 for s in humans if s >= threshold)
    n = len(humans)
    return {
        "n_human": n,
        "false_positives": false_positives,
        "fpr": false_positives / n,
        "fpr_ci": wilson_ci(false_positives, n),
    }


def worst_slice_fpr(
    per_slice: dict[str, dict[str, int | float | tuple[float, float]]],
) -> dict[str, str | float | tuple[float, float]]:
    """Worst human-slice FPR: the maximum, never the mean.

    ``per_slice`` maps slice name -> ``fpr_at_threshold`` result.
    Ties break toward the first slice in dict order (deterministic).
    """
    if not per_slice:
        raise ValueError("worst_slice_fpr needs at least one slice")
    worst_name, worst = None, None
    for name, result in per_slice.items():
        if worst is None or float(result["fpr"]) > float(worst["fpr"]):
            worst_name, worst = name, result
    assert worst is not None and worst_name is not None
    return {
        "slice": worst_name,
        "fpr": float(worst["fpr"]),
        "fpr_ci": worst["fpr_ci"],
        "n_human": worst["n_human"],
    }


def tpr_at_fpr(
    scores: list[float], labels: list[int], *, target_fpr: float = 0.01
) -> dict[str, float]:
    """TPR at a target FPR, from empirical scores (no fitting).

    Same convention as ``benchmark.calibrate_threshold_jsonl``:
    candidate thresholds are the observed scores plus just above the
    maximum; among candidates with empirical FPR <= ``target_fpr``,
    the one with the highest TPR wins (ties: lower FPR, then lower
    threshold). The just-above-max candidate always satisfies the
    FPR bound (FPR 0, TPR 0), so a result always exists. Returns the
    threshold, the achieved FPR (always <= target), and the TPR.
    """
    if len(scores) != len(labels):
        raise ValueError("tpr_at_fpr needs equal-length scores and labels")
    if not scores:
        raise ValueError("tpr_at_fpr needs a non-empty sample")
    if not 0.0 < target_fpr < 1.0:
        raise ValueError("tpr_at_fpr needs 0 < target_fpr < 1")
    if any(y not in (0, 1) for y in labels):
        raise ValueError("tpr_at_fpr needs labels in {0, 1}")
    humans = [s for s, y in zip(scores, labels, strict=True) if y == 0]
    machines = [s for s, y in zip(scores, labels, strict=True) if y == 1]
    if not humans or not machines:
        raise ValueError("tpr_at_fpr needs at least one human and one machine item")
    max_score = max(scores)
    candidates = sorted(set(scores) | {math.nextafter(max_score, math.inf)})
    best: tuple[tuple[float, float, float], float, float, float] | None = None
    for threshold in candidates:
        fpr = sum(s >= threshold for s in humans) / len(humans)
        tpr = sum(s >= threshold for s in machines) / len(machines)
        if fpr <= target_fpr:
            key = (tpr, -fpr, -threshold)
            if best is None or key > best[0]:
                best = (key, threshold, fpr, tpr)
    assert best is not None  # the just-above-max candidate always qualifies
    _, threshold, achieved_fpr, tpr = best
    return {"threshold": threshold, "achieved_fpr": achieved_fpr, "tpr": tpr}


def abstention_rate(verdicts: list[str]) -> dict[str, int | float]:
    """Fraction of verdicts that abstained (a rising rate is itself drift)."""
    if not verdicts:
        raise ValueError("abstention_rate needs a non-empty verdict list")
    _check_verdicts(verdicts)
    abstained = sum(1 for v in verdicts if v == "abstain")
    return {"n": len(verdicts), "abstained": abstained, "rate": abstained / len(verdicts)}


def metadata_diff(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, tuple[Any, Any]]:
    """Provider/version metadata diff between two runs.

    Any key whose value changed (or appeared/disappeared) is
    reported as ``key -> (previous, current)`` with ``None`` for a
    missing side. A detector/provider version change is itself a
    reportable event (measurement drift) — the caller decides the
    consequence; this function only reports the diff.
    """
    diff: dict[str, tuple[Any, Any]] = {}
    for key in sorted(set(previous) | set(current)):
        prev, curr = previous.get(key), current.get(key)
        if prev != curr:
            diff[key] = (prev, curr)
    return diff


def holm_adjusted(p_values: list[float]) -> list[float]:
    """Holm-Bonferroni adjusted p-values, in the input order.

    Pre-registered per-run alpha with Holm correction is the
    multiple-testing control for a run's slices/metrics (research
    §7.5): watching dozens of metrics at alpha=0.05 without it
    guarantees false alarms.
    """
    if not p_values:
        raise ValueError("holm_adjusted needs a non-empty p-value list")
    for p in p_values:
        if not 0.0 <= p <= 1.0:
            raise ValueError(f"holm_adjusted needs p-values in [0, 1], got {p}")
    order = sorted(range(len(p_values)), key=lambda i: p_values[i])
    adjusted = [0.0] * len(p_values)
    running_max = 0.0
    remaining = len(p_values)
    for rank, idx in enumerate(order):
        value = p_values[idx] * (remaining - rank)
        running_max = max(running_max, value)
        adjusted[idx] = min(1.0, running_max)
    return adjusted
