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


# ---------------------------------------------------------------------------
# Strict-JSON depth bound (CI-FIX-3, Worker B: Fuzz Regression RecursionError)
#
# The Fuzz Testing workflow crashed on Python 3.12 with
# ``RecursionError: maximum recursion depth exceeded`` in the
# ``json_parsing`` target: a deeply nested input parsed fine through
# ``json.loads`` (on 3.12 the C scanner accepts nesting far deeper
# than the Python recursion limit) and then crashed the recursive
# ``reject_nonfinite_value`` walk inside ``strict_json_loads``, and
# the same input crashed PyYAML's recursive composer via the YAML
# path. The strict-JSON helpers now enforce an explicit depth limit
# of 100 levels — the same bound ``verify.py`` (C12),
# ``_standalone_verify.py`` and ``datasets.py`` already use — and
# fail closed with ``ValueError``, never ``RecursionError``.
# ---------------------------------------------------------------------------


def _nested_list(depth: int) -> list:
    value: list = []
    for _ in range(depth - 1):
        value = [value]
    return value


def _nested_dict(depth: int) -> dict:
    value: dict | int = 1
    for _ in range(depth):
        value = {"a": value}
    return value  # type: ignore[return-value]


def test_strict_json_depth_limit_is_100():
    assert pm.MAX_JSON_DEPTH == 100


def test_strict_json_loads_accepts_depth_at_limit():
    assert pm.strict_json_loads("[" * 100 + "]" * 100) == _nested_list(100)
    assert pm.strict_json_loads('{"a": ' * 99 + "1" + "}" * 99) == _nested_dict(99)


def test_strict_json_loads_rejects_over_nested_input():
    # One level past the limit is rejected, not parsed.
    with pytest.raises(ValueError, match="depth"):
        pm.strict_json_loads("[" * 101 + "]" * 101)
    with pytest.raises(ValueError, match="depth"):
        pm.strict_json_loads('{"a": ' * 101 + "1" + "}" * 101)
    # Far past the limit — the depth that crashed the fuzzer — is a
    # structured ValueError, never a RecursionError.
    with pytest.raises(ValueError, match="depth"):
        pm.strict_json_loads("[" * 2000 + "]" * 2000)


def test_reject_nonfinite_value_is_iterative_and_depth_bounded():
    # A value nested far past the Python recursion limit must be
    # rejected with ValueError, never crash with RecursionError.
    with pytest.raises(ValueError, match="depth"):
        pm.reject_nonfinite_value(_nested_list(2000))
    with pytest.raises(ValueError, match="depth"):
        pm.reject_nonfinite_value(_nested_dict(2000))
    # At the limit it still walks fine.
    assert pm.reject_nonfinite_value(_nested_list(100)) is None
    assert pm.reject_nonfinite_value(_nested_dict(100)) is None
    # The nonfinite rejection itself is unchanged, including the path
    # in the message.
    with pytest.raises(ValueError, match=r"non-finite number at value\['a'\]\[1\]"):
        pm.reject_nonfinite_value({"a": [1.0, float("nan")]})
    assert pm.reject_nonfinite_value({"a": 1.0, "b": None, "c": True, "d": "x"}) is None


def test_strict_json_dumps_rejects_over_nested_value():
    with pytest.raises(ValueError, match="depth"):
        pm.strict_json_dumps(_nested_list(101))
    assert pm.strict_json_dumps(_nested_list(100)) == "[" * 100 + "]" * 100


# ---------------------------------------------------------------------------
# Strict-JSON depth bound — kill tests (CI-FIX-3 baseline refresh, Worker C)
#
# The mutation proof (cosmic-ray exec, 164 new items from Worker B's
# change: 117 killed, 47 survived) left 23 survivors that are genuine
# behaviour, not equivalents. Each test below kills the mutants named
# in its comment; the distinguishing inputs were verified against the
# actual mutants with cosmic_ray.mutating.mutate_code before the
# tests were written (see hidden_files/audit-cifix3-f-proof/).
# ---------------------------------------------------------------------------


def test_reject_nonfinite_value_enforces_depth_limit_at_101():
    # The iterative walk counts the root at depth 1. The `1 -> 0`
    # mutant (NumberReplacer:7) shifts every depth down by one, so a
    # value at exactly depth 101 is counted 100 and accepted — but
    # the 100/2000 tests never probe the boundary itself, and the
    # raw-text scan masks the walk through strict_json_loads, so only
    # a direct walk call at depth 101 distinguishes it.
    with pytest.raises(ValueError, match="depth"):
        pm.reject_nonfinite_value(_nested_list(101))
    with pytest.raises(ValueError, match="depth"):
        pm.reject_nonfinite_value(_nested_dict(101))


def test_strict_json_loads_rejects_unbalanced_over_nested_input():
    # The raw-text scan must reject over-nested input BEFORE decoding,
    # even when the document is truncated/malformed. The balanced
    # 101 tests never distinguish a broken scan from a working one:
    # when the scan silently passes, the iterative walk still raises
    # ValueError("depth") for the balanced input and masks the scan
    # mutants. An unbalanced 101-deep input has no decoded value for
    # the walk to check, so a broken scan surfaces as a JSONDecodeError
    # (no "depth" in the message) instead of the depth ValueError.
    # Kills: scan `depth = 0 -> -1` (NumberReplacer:13), the
    # zero-iteration for-loop (ZeroIterationForLoop:0), the negated
    # opener test (AddNot:16) and `depth += 1 -> += 0`
    # (NumberReplacer:15).
    with pytest.raises(ValueError, match="depth"):
        pm.strict_json_loads("[" * 101)


def test_strict_json_loads_scan_counts_closing_brackets():
    # The scan's close handling (`depth -= 1`) is only observable on
    # inputs where closes happen before further deep nesting: the
    # balanced depth tests have no closes before the deep run, and
    # the walk masks the scan on balanced input anyway.
    # (a) Two sequential 51-deep branches: true max depth is 51, so
    # the document parses. The `depth -= 1 -> -= 0` mutant
    # (NumberReplacer:17) never decrements, so the second branch
    # accumulates past 100 and the mutant rejects a valid document.
    branch: object = 1
    for _ in range(50):
        branch = [branch]
    assert pm.strict_json_loads(
        "[" + "[" * 50 + "1" + "]" * 50 + "," + "[" * 50 + "1" + "]" * 50 + "]"
    ) == [branch, branch]
    # (b) Two closed mappings followed by an unclosed 101-deep run:
    # true depth exceeds 100 during the run, so the scan raises
    # ValueError("depth"). The `depth -= 1 -> -= 2` mutant
    # (NumberReplacer:16) over-decrements on the closes, counts the
    # run as 99 deep and passes it, so decoding fails with a bare
    # JSONDecodeError instead.
    with pytest.raises(ValueError, match="depth"):
        pm.strict_json_loads("[{}, {}, [" + "[" * 99)


def test_strict_json_dumps_rejects_over_nested_dict():
    # The dumps depth check walks mappings and sequences in separate
    # branches, and the existing dumps tests only nest lists — so the
    # whole mapping branch was untested: every `depth + 1` replacement
    # there (Add_*:2, 11 mutants), both `depth + 1 -> +2 / +0`
    # replacements (NumberReplacer:20/21) and the `depth > max_depth`
    # replacements that only differ at exactly depth 100
    # (Gt_Eq/Gt_GtE/Gt_Is:4) survived. A 100-deep dict must dump and
    # a 101-deep dict must raise, mirroring the list tests.
    assert pm.strict_json_dumps(_nested_dict(100)) == (
        '{"a": ' * 100 + "1" + "}" * 100
    )
    with pytest.raises(ValueError, match="depth"):
        pm.strict_json_dumps(_nested_dict(101))
