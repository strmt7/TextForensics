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

Shared contracts defined here (audit W2, findings S09/S10/S22)
-------------------------------------------------------------
This module is the ONE home of two shared contracts, so the three
consumers (``observatory.py``, ``probe_runs.py``, ``probe_metrics.py``
itself) and the transport/model-card surfaces (``result_codec.py``,
``model_card.py``) cannot define them independently:

* Score direction (S09): ``SCORE_DIRECTIONS`` is the TFDP vocabulary
  (``higher_means_ai`` / ``lower_means_ai`` / ``not_applicable`` /
  ``unknown``). ``normalize_score_direction`` canonicalises it,
  ``is_ai_like`` is the one decision predicate, and
  ``oriented_scores`` maps any known direction onto the canonical
  higher-means-AI orientation (negation for lower-means-AI, an
  affine-equivalent transform, so TPR/FPR are identical). Unknown or
  not-applicable direction never yields a metric: callers report the
  metric as ``unavailable`` instead of guessing an orientation.
* Nonfinite / strict-JSON rejection (S10/S22): ``require_finite_number``,
  ``require_integer``, ``reject_nonfinite_value``,
  ``strict_json_loads`` and ``strict_json_dumps``. Every public
  function below rejects nonfinite inputs *before* sorting or
  comparison (a NaN must raise ``ValueError``, never hang a scan or
  fabricate a finite metric), and validates integer cardinalities /
  types / bounds. ``probe_runs.py`` reuses the same helpers for
  snapshot scores; ``result_codec.py`` and ``model_card.py`` reuse
  the strict-JSON helpers; W4 reuses them for run-manifest
  validation (S20) instead of redefining them.
"""

from __future__ import annotations

import bisect
import json
import math
from collections.abc import Mapping
from typing import Any

VERDICTS = ("ai_like", "human_like", "abstain")
DEFAULT_Z = 1.96  # 95% two-sided normal quantile, Wilson intervals.
_PSI_EPSILON = 1e-4  # Smoothing for empty PSI bins (Evidently convention).

# ---------------------------------------------------------------------------
# Shared contracts (S09 score direction; S10/S22 nonfinite + strict JSON)
# ---------------------------------------------------------------------------

SCORE_DIRECTIONS = ("higher_means_ai", "lower_means_ai", "not_applicable", "unknown")


def normalize_score_direction(value: Any) -> str:
    """Canonicalise a TFDP native-score direction (S09 shared contract).

    ``None`` (a legacy record that never declared a direction) maps to
    ``"unknown"`` — it is never guessed. Any other value outside the
    TFDP vocabulary raises ``ValueError``.
    """
    if value is None:
        return "unknown"
    if isinstance(value, str) and value in SCORE_DIRECTIONS:
        return value
    raise ValueError(
        f"unknown native_score_direction {value!r}; expected one of {SCORE_DIRECTIONS}"
    )


def require_finite_number(value: Any, name: str) -> float:
    """Return ``float(value)`` or raise ``ValueError`` (S10 shared contract).

    Rejects booleans, non-numbers, NaN and ±Infinity. This is the
    choke point every numeric input in this module passes through
    *before* any sorting or comparison.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite number, got {value!r}.")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"{name} must be finite, got {value!r}.")
    return number


def require_integer(
    value: Any, name: str, *, minimum: int | None = None, maximum: int | None = None
) -> int:
    """Return ``value`` as an ``int`` count or raise ``ValueError``.

    Counts and cardinalities are integers: booleans and floats (even
    integral ones such as ``50.0``) are rejected, so a miscounted or
    mistyped denominator cannot silently pass as a valid ``n``.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer, got {value!r}.")
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {value}.")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must be <= {maximum}, got {value}.")
    return value


def reject_nonfinite_value(value: Any, name: str = "value", _path: str | None = None) -> None:
    """Recursively reject nonfinite floats anywhere in ``value``.

    Walks mappings, sequences and sets; every float must be finite.
    Booleans, ``None`` and strings are not numbers and pass. Raises
    ``ValueError`` naming the offending path, or returns ``None``.
    """
    path = _path if _path is not None else name
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"non-finite number at {path}: {value!r}.")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            reject_nonfinite_value(item, name, f"{path}[{key!r}]")
        return
    if isinstance(value, (list, tuple, set, frozenset)):
        for index, item in enumerate(value):
            reject_nonfinite_value(item, name, f"{path}[{index}]")
        return
    return None


def _reject_json_constant(token: str) -> Any:
    raise ValueError(f"non-finite JSON constant {token!r} is not valid JSON.")


def strict_json_loads(text: str | bytes | bytearray) -> Any:
    """Parse JSON, rejecting nonfinite tokens (S10/S22 shared contract).

    Python's ``json`` accepts the literal tokens ``NaN`` /
    ``Infinity`` / ``-Infinity`` and silently overflows ``1e999`` to
    ``inf``. Both are rejected here: a nonfinite token is never valid
    JSON, so it raises ``ValueError`` instead of producing a float
    that later fabricates a finite metric.
    """
    result = json.loads(text, parse_constant=_reject_json_constant)
    reject_nonfinite_value(result)
    return result


def strict_json_dumps(value: Any, **kwargs: Any) -> str:
    """Serialise to JSON with ``allow_nan=False`` (S22 shared contract).

    A nonfinite float raises ``ValueError`` instead of emitting a
    literal ``NaN`` / ``Infinity`` token that no strict parser accepts.
    """
    return json.dumps(value, allow_nan=False, **kwargs)


def is_ai_like(score: float, threshold: float, *, direction: str = "higher_means_ai") -> bool:
    """The ONE score-direction decision predicate (S09 shared contract).

    ``higher_means_ai``: AI iff ``score >= threshold``.
    ``lower_means_ai``: AI iff ``score <= threshold``.
    ``unknown`` / ``not_applicable``: the decision is undefined and
    raises ``ValueError`` — callers must report the metric as
    ``unavailable``, never guess an orientation.
    """
    score = require_finite_number(score, "score")
    threshold = require_finite_number(threshold, "threshold")
    direction = normalize_score_direction(direction)
    if direction == "higher_means_ai":
        return score >= threshold
    if direction == "lower_means_ai":
        return score <= threshold
    raise ValueError(
        f"cannot decide ai_like with score direction {direction!r}: "
        "direction is unknown or not applicable; report unavailable."
    )


def oriented_scores(scores: list[float], *, direction: str = "higher_means_ai") -> list[float]:
    """Map scores onto the canonical higher-means-AI orientation (S09).

    ``lower_means_ai`` scores are negated — an affine-equivalent
    transform, so empirical TPR/FPR are identical to the higher-tail
    computation on the original scores. ``unknown`` /
    ``not_applicable`` raise ``ValueError`` (unavailable, not guessed).
    """
    direction = normalize_score_direction(direction)
    checked = [require_finite_number(s, "score") for s in scores]
    if direction == "higher_means_ai":
        return checked
    if direction == "lower_means_ai":
        return [-s for s in checked]
    raise ValueError(
        f"cannot orient scores with score direction {direction!r}: "
        "direction is unknown or not applicable; report unavailable."
    )


def wilson_ci(k: int, n: int, *, z: float = DEFAULT_Z) -> tuple[float, float]:
    """Wilson score interval for ``k`` successes in ``n`` trials.

    Returns ``(lo, hi)`` clamped to [0, 1]. The Wilson interval (not
    Wald) is used throughout: it behaves at the boundaries (k=0, k=n)
    where the FPR slices live.
    """
    k = require_integer(k, "k", minimum=0)
    n = require_integer(n, "n", minimum=1)
    if k > n:
        raise ValueError(f"wilson_ci needs 0 <= k <= n, got k={k}, n={n}")
    z = require_finite_number(z, "z")
    if z <= 0:
        raise ValueError("wilson_ci needs z > 0")
    p = k / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def ks_statistic(sample_a: list[float], sample_b: list[float]) -> float:
    """Two-sample Kolmogorov–Smirnov statistic (max CDF gap).

    Nonfinite inputs are rejected *before* sorting: with a NaN in
    either sample both ordered comparisons and NaN equality are
    false, so the tie branch advances neither cursor and the scan
    never terminates (audit S10). Rejection is bounded and emits no
    finite statistic for undefined input.
    """
    if not sample_a or not sample_b:
        raise ValueError("ks_statistic needs two non-empty samples")
    a = sorted(require_finite_number(v, "sample_a value") for v in sample_a)
    b = sorted(require_finite_number(v, "sample_b value") for v in sample_b)
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
    d = require_finite_number(d, "d")
    if not 0.0 <= d <= 1.0:
        raise ValueError(f"ks_pvalue needs 0 <= d <= 1, got {d}")
    n = require_integer(n, "n", minimum=1)
    m = require_integer(m, "m", minimum=1)
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
    bins = require_integer(bins, "bins", minimum=1)
    ref = sorted(require_finite_number(v, "expected value") for v in expected)
    expected_checked = [require_finite_number(v, "expected value") for v in expected]
    actual_checked = [require_finite_number(v, "actual value") for v in actual]
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

    ref_counts = _counts(expected_checked)
    act_counts = _counts(actual_checked)
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
    n_bins = require_integer(n_bins, "n_bins", minimum=1)
    probs = [require_finite_number(p, "prob") for p in probs]
    for prob in probs:
        if not 0.0 <= prob <= 1.0:
            raise ValueError(f"ece needs probs in [0, 1], got {prob}")
    for label in labels:
        if isinstance(label, bool) or not isinstance(label, int) or label not in (0, 1):
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
    probs = [require_finite_number(p, "prob") for p in probs]
    for prob in probs:
        if not 0.0 <= prob <= 1.0:
            raise ValueError(f"brier needs probs in [0, 1], got {prob}")
    for label in labels:
        if isinstance(label, bool) or not isinstance(label, int) or label not in (0, 1):
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
    for label in true_labels:
        if isinstance(label, bool) or not isinstance(label, int):
            raise ValueError(f"set_coverage needs integer labels, got {label!r}")
    covered = sum(1 for s, y in zip(prediction_sets, true_labels, strict=True) if y in s)
    return {"covered": covered, "n": len(true_labels), "rate": covered / len(true_labels)}


def coverage_shortfall_pp(empirical_rate: float, nominal_rate: float) -> float:
    """Conformal coverage shortfall in percentage points (nominal - empirical)."""
    empirical_rate = require_finite_number(empirical_rate, "empirical_rate")
    nominal_rate = require_finite_number(nominal_rate, "nominal_rate")
    if not 0.0 <= empirical_rate <= 1.0:
        raise ValueError("coverage_shortfall_pp needs empirical_rate in [0, 1]")
    if not 0.0 <= nominal_rate <= 1.0:
        raise ValueError("coverage_shortfall_pp needs nominal_rate in [0, 1]")
    return (nominal_rate - empirical_rate) * 100.0


def fpr_at_threshold(
    scores: list[float], labels: list[int], threshold: float, *, direction: str = "higher_means_ai"
) -> dict[str, int | float | tuple[float, float]]:
    """Human-slice FPR at a declared operating point + Wilson CI.

    ``labels`` are 0 (human) / 1 (machine). The decision follows the
    shared score-direction contract (S09): ``higher_means_ai`` counts
    a human false positive at ``score >= threshold``;
    ``lower_means_ai`` at ``score <= threshold``; ``unknown`` /
    ``not_applicable`` raise ``ValueError`` (unavailable, never a
    fabricated 0.0 — a NaN threshold previously produced FPR 0.0).
    The declared threshold is an input, never fitted here.
    """
    if len(scores) != len(labels):
        raise ValueError("fpr_at_threshold needs equal-length scores and labels")
    if not scores:
        raise ValueError("fpr_at_threshold needs a non-empty sample")
    scores = [require_finite_number(s, "score") for s in scores]
    threshold = require_finite_number(threshold, "threshold")
    for y in labels:
        if isinstance(y, bool) or not isinstance(y, int) or y not in (0, 1):
            raise ValueError(f"fpr_at_threshold needs labels in {{0, 1}}, got {y!r}")
    humans = [s for s, y in zip(scores, labels, strict=True) if y == 0]
    if not humans:
        raise ValueError("fpr_at_threshold needs at least one human item")
    false_positives = sum(1 for s in humans if is_ai_like(s, threshold, direction=direction))
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
    scores: list[float],
    labels: list[int],
    *,
    target_fpr: float = 0.01,
    direction: str = "higher_means_ai",
) -> dict[str, float]:
    """TPR at a target FPR, from empirical scores (no fitting).

    Same convention as ``benchmark.calibrate_threshold_jsonl``:
    candidate thresholds are the observed scores plus just above the
    maximum; among candidates with empirical FPR <= ``target_fpr``,
    the one with the highest TPR wins (ties: lower FPR, then lower
    threshold). The just-above-max candidate always satisfies the
    FPR bound (FPR 0, TPR 0), so a result always exists. Returns the
    threshold, the achieved FPR (always <= target), and the TPR.

    Score direction (S09) is applied through the shared contract:
    ``lower_means_ai`` scores are oriented onto the higher tail
    (negation — affine-equivalent, so TPR/FPR are identical to the
    higher-tail computation), and the returned threshold is mapped
    back to native score units. ``unknown`` / ``not_applicable``
    raise ``ValueError``: the ROC is unavailable, never computed
    under a guessed orientation.
    """
    if len(scores) != len(labels):
        raise ValueError("tpr_at_fpr needs equal-length scores and labels")
    if not scores:
        raise ValueError("tpr_at_fpr needs a non-empty sample")
    target_fpr = require_finite_number(target_fpr, "target_fpr")
    if not 0.0 < target_fpr < 1.0:
        raise ValueError("tpr_at_fpr needs 0 < target_fpr < 1")
    for y in labels:
        if isinstance(y, bool) or not isinstance(y, int) or y not in (0, 1):
            raise ValueError(f"tpr_at_fpr needs labels in {{0, 1}}, got {y!r}")
    direction = normalize_score_direction(direction)
    oriented = oriented_scores(scores, direction=direction)
    humans = [s for s, y in zip(oriented, labels, strict=True) if y == 0]
    machines = [s for s, y in zip(oriented, labels, strict=True) if y == 1]
    if not humans or not machines:
        raise ValueError("tpr_at_fpr needs at least one human and one machine item")
    max_score = max(oriented)
    candidates = sorted(set(oriented) | {math.nextafter(max_score, math.inf)})
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
    native_threshold = -threshold if direction == "lower_means_ai" else threshold
    return {
        "threshold": native_threshold,
        "achieved_fpr": achieved_fpr,
        "tpr": tpr,
        "direction": direction,
    }


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
    p_values = [require_finite_number(p, "p-value") for p in p_values]
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
