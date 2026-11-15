"""Kill tests for probe_runs.py mutation survivors (audit W4, worker F2).

Each test names the surviving mutant(s) it kills as ``(line, col)
Operator#occurrence`` (positions from the W4 proof inventory). Tests
run against the integrated audit-w4 head; the re-prove script applies
each mutant in a scratch worktree and confirms the test fails.

Helpers reuse ``tests.test_probe_runs`` (``_make_records``,
``_metrics_kwargs``, ``_tier_metrics``, ``_manifest``, ``_history_run``,
``stub_primitives``). The end-to-end ``perform_probe_run`` tests use a
fake detector (``_FakeDetector``) whose scores/verdicts are keyed by
item id, so tier outcomes are fully controlled without a real corpus.
"""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from tests.test_probe_runs import (
    HEX64,
    _history_run,
    _manifest,
    _metrics_kwargs,
    _tier_metrics,
    # Imported to register the pytest fixture in this module; the
    # tests below request it by parameter name (see the F811 note
    # on test_slice_false_positives_exclude_ai_labelled_items).
    stub_primitives,  # noqa: F401
)
from textforensics.detectors import DETECTOR_SCHEMA_V2, DetectorPrediction
from textforensics.probe_runs import (
    ProbeRunError,
    _demoted_record,
    _parse_run_at_utc,
    _require_finite_json,
    _require_finite_number,
    _run_at_sort_key,
    _run_scored_count,
    _validate_completeness,
    apply_demotions,
    clear_demotions,
    compute_run_completeness,
    compute_run_metrics,
    evaluate_tiers,
    perform_probe_run,
    resolve_baseline,
    save_run,
    summarize_longitudinal,
    validate_run_manifest,
)

DET_ID = "textforensics/builtin-heuristic"
FAKE_ID = "textforensics/fake-detector"
FAKE_VERSION = "0.1.0"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rec(sample_id, score, verdict, **kw):
    """One snapshot record in the shape ``_make_records`` builds."""
    record = {
        "sample_id": sample_id,
        "text_sha256": "c" * 64,
        "detector_id": DET_ID,
        "detector_version": "0.1.0",
        "detector_family": "heuristic",
        "execution": "local",
        "score": score,
        "score_semantics": "native heuristic score; not a probability",
        "native_score_direction": "higher_means_ai",
        "verdict": verdict,
        "threshold": 0.68,
        "calibrated_ai_probability": None,
        "calibration_id": None,
        "provider_version": None,
        "observed_at": "2026-11-07T00:00:00+00:00",
    }
    record.update(kw)
    return record


class _FakeDetector:
    """A detector whose score/verdict/calibration are keyed by item id.

    Texts are ``probe-<item_id>``; the lookup is by the suffix.
    """

    detector_id = FAKE_ID
    detector_version = FAKE_VERSION
    detector_family = "fake"
    execution = "local"

    def __init__(self, by_item, default=(0.1, "human_like", None, None)):
        # by_item: item_id -> (score, verdict, calibrated, calibration_id)
        self.by_item = by_item
        self.default = default

    def detect(self, text):
        item_id = text.removeprefix("probe-")
        score, verdict, calibrated, calibration_id = self.by_item.get(item_id, self.default)
        return DetectorPrediction(
            schema=DETECTOR_SCHEMA_V2,
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            detector_family=self.detector_family,
            execution="local",
            score=score,
            score_semantics="ai_probability",
            verdict=verdict,
            threshold=0.5,
            calibrated_ai_probability=calibrated,
            calibration_id=calibration_id,
        )


def _corpus(n, *, slice_name="human-native", label=0, scores=None, prefix="i"):
    """A probe-corpus manifest + texts + holdback for ``n`` items.

    ``scores`` maps item id -> (score, verdict, calibrated, calibration_id).
    """
    items = []
    texts = {}
    holdback = {}
    for i in range(n):
        item_id = f"{prefix}{i}"
        text = f"probe-{item_id}"
        items.append(
            {
                "item_id": item_id,
                "slice": slice_name,
                "content_sha256": hashlib.sha256(text.encode()).hexdigest(),
            }
        )
        texts[item_id] = text
        holdback[item_id] = {"label": label}
    manifest = {"version": "1.0.0", "items_sha256": HEX64, "items": items}
    return manifest, texts, holdback


def _perform(manifest, texts, holdback, detector, **kwargs):
    """``perform_probe_run`` with dry_run=True unless overridden."""
    kwargs.setdefault("dry_run", True)
    return perform_probe_run(
        manifest=manifest,
        texts=texts,
        holdback_loader=lambda: holdback,
        detector=detector,
        **kwargs,
    )


def _completeness(**overrides):
    """A complete, support-eligible completeness accounting."""
    accounting = {
        "selected": 50,
        "attempted": 50,
        "succeeded": 50,
        "abstained": 0,
        "failed": 0,
        "is_complete": True,
        "support_eligible": True,
        "failed_item_ids": [],
        "missing_item_ids": [],
        "abstained_item_ids": [],
    }
    accounting.update(overrides)
    return accounting


def _alert(tier, rule="flip_rate", slice_name="human-native"):
    return {
        "tier": tier,
        "rule": rule,
        "slice": slice_name,
        "action": "demote" if tier == 1 else "investigate",
        "detail": f"test alert tier {tier}",
    }


def _registry_file(tmp_path, records):
    """Write a registry JSON for the given record dicts (valid signatures)."""
    from textforensics.validation import ValidationRecord, ValidationRegistry

    registry = ValidationRegistry([ValidationRecord.from_dict(r) for r in records])
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(registry.to_dict()), encoding="utf-8")
    return path


def _seeded_record(seed_index, detector_id, demoted_by):
    """One seeded registry record, re-pointed at a detector and demotion."""
    from textforensics.validation import compute_signature

    seed = json.loads(
        (
            Path(__file__).resolve().parent.parent / "docs" / "validation" / "registry.json"
        ).read_text(encoding="utf-8")
    )["records"][seed_index]
    record = copy.deepcopy(seed)
    record["detector_id"] = detector_id
    record["limits"]["demoted_by"] = demoted_by
    unsigned = {k: v for k, v in record.items() if k != "signature"}
    record["signature"] = compute_signature(unsigned)
    return record


def _saved_run(
    directory,
    *,
    run_id,
    at,
    detector_id=FAKE_ID,
    version="0.1.0",
    baseline=False,
    scope="full",
    fingerprint=HEX64,
    series=None,
    alerts=(),
):
    """Save a valid history run into ``directory`` and return its manifest."""
    manifest = _manifest(
        run_id=run_id,
        run_at_utc=at,
        scope=scope,
        corpus_fingerprint=fingerprint,
        detector_id=detector_id,
        detector_version=version,
        is_baseline=baseline,
        alerts=list(alerts),
        score_series=series or {},
        metrics={"detector_id": detector_id},
        completeness=_completeness(),
    )
    save_run(manifest, directory)
    return manifest


def _series_entry(score=0.3, verdict="human_like", calibrated=None, cal_id=None):
    return {
        "score": score,
        "verdict": verdict,
        "calibrated_ai_probability": calibrated,
        "calibration_id": cal_id,
    }


# ---------------------------------------------------------------------------
# _slice_metrics (via compute_run_metrics) + compute_run_completeness
# ---------------------------------------------------------------------------


def test_slice_false_positives_exclude_ai_labelled_items(
    # Fixture parameter: shadows the registration import above by
    # design (pytest injects the fixture by this name).
    stub_primitives,  # noqa: F811
):
    """(745,17) Eq_GtE#7: ``y == 0`` -> ``y >= 0`` counts AI items as
    false positives. One AI-labelled ai_like item must not count."""
    records = [
        _rec("h0", 0.2, "human_like"),
        _rec("h1", 0.2, "human_like"),
        _rec("a0", 0.9, "ai_like"),
    ]
    labels = {"h0": 0, "h1": 0, "a0": 1}
    slices = {"h0": "human-native", "h1": "human-native", "a0": "human-native"}
    result = compute_run_metrics(
        **_metrics_kwargs(records, labels, slices, primitives=stub_primitives)
    )
    human_fpr = result["slices"]["human-native"]["human_fpr"]
    assert human_fpr["false_positives"] == 0
    assert human_fpr["n_human"] == 2


def test_completeness_rejects_non_string_record_sample_id():
    """(872,42) ReplaceOrWithAnd#8: the record sample_id guard must
    raise on a non-string id (the ``and`` mutant skips it)."""
    with pytest.raises(ProbeRunError, match="sample_id"):
        compute_run_completeness(
            selected_item_ids=["i0"],
            records=[{"sample_id": 123, "verdict": "human_like"}],
        )


def test_completeness_rejects_empty_record_sample_id():
    """(872,42) ReplaceOrWithAnd#8 (second arm): an empty-string
    sample_id must raise too."""
    with pytest.raises(ProbeRunError, match="sample_id"):
        compute_run_completeness(
            selected_item_ids=["i0"],
            records=[{"sample_id": "", "verdict": "human_like"}],
        )


def test_completeness_skips_bad_failure_ids():
    """(885,42) ReplaceOrWithAnd#10: a failure with a bad sample_id is
    skipped, not counted as failed."""
    result = compute_run_completeness(
        selected_item_ids=["i0", "i1"],
        records=[_rec("i0", 0.2, "human_like")],
        failures=[{"sample_id": 123}, {"sample_id": "i1"}],
    )
    assert result["failed"] == 1
    assert result["failed_item_ids"] == ["i1"]
    assert result["missing_item_ids"] == []


def test_completeness_continues_past_bad_failure():
    """(886,12) ReplaceContinueWithBreak#0: the bad-failure ``continue``
    must not stop the loop; the good failure after it is counted."""
    result = compute_run_completeness(
        selected_item_ids=["i0", "i1"],
        records=[_rec("i0", 0.2, "human_like")],
        failures=[{"sample_id": ""}, {"sample_id": "i1"}],
    )
    assert result["failed"] == 1
    assert result["failed_item_ids"] == ["i1"]


def test_completeness_skips_duplicate_failure_ids():
    """(887,37) ReplaceOrWithAnd#11: a failure for an already-recorded
    sample is skipped (the ``and`` mutant counts it as failed)."""
    result = compute_run_completeness(
        selected_item_ids=["i0"],
        records=[_rec("i0", 0.2, "human_like")],
        failures=[{"sample_id": "i0"}],
    )
    assert result["failed"] == 0
    assert result["failed_item_ids"] == []


def test_completeness_continues_past_duplicate_failure():
    """(888,12) ReplaceContinueWithBreak#1: the duplicate-failure
    ``continue`` must not stop the loop."""
    result = compute_run_completeness(
        selected_item_ids=["i0", "i1"],
        records=[_rec("i0", 0.2, "human_like")],
        failures=[{"sample_id": "i0"}, {"sample_id": "i1"}],
    )
    assert result["failed"] == 1
    assert result["failed_item_ids"] == ["i1"]


def test_completeness_missing_excludes_unselected_attempts():
    """(892,38) Sub_BitXor#1: ``selected - attempted`` -> ``^``.
    An attempted item outside the selected set is not missing (the
    mutant lists it). attempted (2) stays <= selected (2), so the
    accounting itself does not raise."""
    result = compute_run_completeness(
        selected_item_ids=["i0", "i1"],
        records=[_rec("i0", 0.2, "human_like"), _rec("i9", 0.2, "human_like")],
    )
    assert result["missing_item_ids"] == ["i1"]
    assert result["attempted"] == 2


def test_completeness_wraps_inconsistent_accounting():
    """(904,11) ExceptionReplacer#4: an inconsistent accounting (more
    attempted than selected) raises ProbeRunError, not ValueError."""
    with pytest.raises(ProbeRunError, match="inconsistent"):
        compute_run_completeness(
            selected_item_ids=["i0"],
            records=[_rec("i0", 0.2, "human_like"), _rec("i1", 0.2, "human_like")],
        )


# ---------------------------------------------------------------------------
# _run_scored_count / _require_finite_number / _require_finite_json /
# _parse_run_at_utc / _run_at_sort_key
# ---------------------------------------------------------------------------


def test_run_scored_count_rejects_bool_overall_n():
    """(1169,34) Delete_Not#18: a bool overall ``n`` must not be
    returned as the scored count (the mutant returns True)."""
    assert _run_scored_count({"overall": {"n": True}, "slices": {}}) is None


def test_run_scored_count_returns_none_without_counts():
    """(1172,15) ReplaceFalseWithTrue#6: with no usable counts the
    function returns None (the mutant returns 0)."""
    assert _run_scored_count({"overall": {}, "slices": {}}) is None


def test_require_finite_number_rejects_bool():
    """(2195,16) ReplaceOrWithAnd#45: a bool is not a finite number
    (the ``and`` mutant accepts True)."""
    with pytest.raises(ProbeRunError, match="must be a number"):
        _require_finite_number(True, "alpha_per_run")


def test_require_finite_json_rejects_inf_in_list():
    """(2190,17) ZeroIterationForLoop#30: a non-finite value nested in
    a list must raise the finite error (the mutant skips the list)."""
    with pytest.raises(ProbeRunError, match="must be finite"):
        _require_finite_json({"alerts": [float("inf")]}, "manifest")


def test_parse_run_at_utc_rejects_negative_offset():
    """(2219,22) NotEq_Gt#13: a non-UTC offset below zero must raise
    (the ``>`` mutant accepts -05:00)."""
    with pytest.raises(ProbeRunError, match="must be a UTC timestamp"):
        _parse_run_at_utc("2026-11-01T00:00:00-05:00")


def test_run_at_sort_key_sorts_unparseable_first():
    """(2232,18) ExceptionReplacer#6: an unparseable run_at sorts
    first (datetime.min) instead of propagating ProbeRunError."""
    key = _run_at_sort_key({"run_at_utc": "not-a-timestamp"})
    assert key == datetime.min.replace(tzinfo=UTC)


# ---------------------------------------------------------------------------
# evaluate_tiers
# ---------------------------------------------------------------------------


def _fpr_metrics(*, first_claimable, second_ci_lo):
    """Two-slice metrics for the FPR-cap loop: slice ``aaa`` first
    (sorted order), slice ``zzz`` second."""
    return {
        "detector_id": DET_ID,
        "slices": {
            "aaa": {
                "n": 120,
                "human_fpr": {
                    "n_human": 120,
                    "false_positives": 0,
                    "fpr": 0.0,
                    "fpr_ci": [0.0, 0.02],
                    "fpr_claim_allowed": first_claimable,
                    "cap": 0.05,
                },
            },
            "zzz": {
                "n": 120,
                "human_fpr": {
                    "n_human": 120,
                    "false_positives": 60,
                    "fpr": 0.5,
                    "fpr_ci": [second_ci_lo, 0.6],
                    "fpr_claim_allowed": True,
                    "cap": 0.05,
                },
            },
        },
        "overall": {"flips": None},
        "worst_slice_fpr": None,
        "holm": {"alpha_per_run": 0.05, "family": "per-slice KS tests", "adjusted_pvalues": {}},
    }


def test_tiers_fpr_loop_continues_past_unclaimable_slice():
    """(1473,12) ReplaceContinueWithBreak#6: the FPR-cap loop's
    ``continue`` must not stop at the unclaimable first slice; the
    breaching second slice still demotes."""
    result = evaluate_tiers(
        metrics=_fpr_metrics(first_claimable=False, second_ci_lo=0.4),
        detector_version="0.1.0",
    )
    assert result["demote"] is True
    assert any(a["rule"] == "human_fpr_cap" for a in result["alerts"])


def _version_metrics(n_scored):
    """Metrics whose scored count is exactly ``n_scored``."""
    metrics = _tier_metrics()
    metrics["overall"] = {"n": n_scored, "flips": None}
    return metrics


def test_tiers_version_change_at_sample_floor_demotes():
    """(1504,59) GtE_Gt#9: ``n_scored >= MIN_SLICE_N`` -> ``>``.
    Exactly 50 scored observations is adequately sampled (tier 1)."""
    result = evaluate_tiers(
        metrics=_version_metrics(50),
        detector_version="0.1.0",
        previous_detector_version="0.0.9",
        previous_run_at="2026-11-01T00:00:00+00:00",
        run_at="2026-11-15T00:00:00+00:00",
    )
    assert result["demote"] is True
    alert = [a for a in result["alerts"] if a["rule"] == "version_change_no_probe_run"][0]
    assert alert["tier"] == 1
    assert alert["consecutive_runs"] == 1


def test_tiers_version_change_alert_carries_consecutive_runs_one():
    """(1545,37) NumberReplacer#154/#155: the version-change demote
    alert records ``consecutive_runs=1`` (not 2 or 0)."""
    result = evaluate_tiers(
        metrics=_version_metrics(60),
        detector_version="0.1.0",
        previous_detector_version="0.0.9",
        previous_run_at="2026-11-01T00:00:00+00:00",
        run_at="2026-11-15T00:00:00+00:00",
    )
    alert = [a for a in result["alerts"] if a["rule"] == "version_change_no_probe_run"][0]
    assert alert["consecutive_runs"] == 1


def test_tiers_below_floor_version_change_sets_watch():
    """(1545,37) NumberReplacer#154/#155: the below-floor
    version-change watch alert records ``consecutive_runs=1`` (not 2
    or 0)."""
    result = evaluate_tiers(
        metrics=_version_metrics(10),
        detector_version="0.1.0",
        previous_detector_version="0.0.9",
        previous_run_at="2026-11-01T00:00:00+00:00",
        run_at="2026-11-15T00:00:00+00:00",
    )
    assert result["watch"] is True
    assert result["demote"] is False
    assert any(a["tier"] == 2 for a in result["alerts"])
    alert = [a for a in result["alerts"] if a["rule"] == "version_change_no_probe_run"][0]
    assert alert["consecutive_runs"] == 1


def test_tiers_provider_below_floor_version_change_sets_watch():
    """(1584,24) ReplaceTrueWithFalse#17: a below-floor provider
    change records a Tier-2 watch (``watch = True``). (1595,37)
    NumberReplacer#162/#163: the provider-change watch alert records
    ``consecutive_runs=1`` (not 2 or 0)."""
    result = evaluate_tiers(
        metrics=_version_metrics(10),
        detector_version="0.1.0",
        previous_provider_metadata={"model": "v1"},
        provider_metadata={"model": "v2"},
        previous_run_at="2026-11-01T00:00:00+00:00",
        run_at="2026-11-15T00:00:00+00:00",
    )
    assert result["watch"] is True
    assert result["demote"] is False
    alert = [a for a in result["alerts"] if a["rule"] == "version_change_no_probe_run"][0]
    assert alert["tier"] == 2
    assert alert["consecutive_runs"] == 1


def test_tiers_provider_change_alert_carries_consecutive_runs_one():
    """(1595,37) NumberReplacer#162/#163: the provider-change demote
    alert records ``consecutive_runs=1`` (not 2 or 0)."""
    result = evaluate_tiers(
        metrics=_version_metrics(60),
        detector_version="0.1.0",
        previous_provider_metadata={"model": "v1"},
        provider_metadata={"model": "v2"},
        previous_run_at="2026-11-01T00:00:00+00:00",
        run_at="2026-11-15T00:00:00+00:00",
    )
    alert = [a for a in result["alerts"] if a["rule"] == "version_change_no_probe_run"][0]
    assert alert["tier"] == 1
    assert alert["consecutive_runs"] == 1


# ---------------------------------------------------------------------------
# _demoted_record / apply_demotions / clear_demotions
# ---------------------------------------------------------------------------


def test_demoted_record_accepts_keyword_reason(tmp_path):
    """(1657,46) Mul_Div#8: ``_demoted_record(record, *, reason)`` is
    keyword-only; calling it with ``reason=`` as a keyword works."""
    record = _seeded_record(0, FAKE_ID, None)
    from textforensics.validation import ValidationRecord

    parsed = ValidationRecord.from_dict(record)
    out = _demoted_record(record=parsed, reason="U3 probe run run-1")
    assert out.limits.demoted_by == "U3 probe run run-1"


def test_apply_demotions_only_matching_detector(tmp_path):
    """(1719,60) Eq_GtE#14: ``r.detector_id == detector_id`` -> ``>=``.
    A record for a detector sorting above the target is not demoted."""
    path = _registry_file(
        tmp_path,
        [
            _seeded_record(0, "det-a", None),
            _seeded_record(1, "det-b", None),
        ],
    )
    result = apply_demotions(
        registry_path=path,
        detector_id="det-a",
        run_id="run-1",
        alerts=[_alert(1)],
    )
    assert len(result["demoted_record_ids"]) == 1
    from textforensics.validation import load_validation_registry

    registry = load_validation_registry(path)
    by_id = {r.detector_id: r for r in registry.records}
    assert by_id["det-a"].limits.demoted_by is not None
    assert "U3 probe run run-1" in by_id["det-a"].limits.demoted_by
    assert by_id["det-b"].limits.demoted_by is None


def test_clear_demotions_only_matching_detector(tmp_path):
    """(1778,30) Eq_GtE#15: a record for a detector sorting above the
    target is not cleared."""
    path = _registry_file(
        tmp_path,
        [
            _seeded_record(0, "det-a", "U3 probe run run-1"),
            _seeded_record(1, "det-b", "U3 probe run run-1"),
        ],
    )
    result = clear_demotions(registry_path=path, detector_id="det-a", run_id="run-2")
    assert len(result["cleared_record_ids"]) == 1
    from textforensics.validation import load_validation_registry

    registry = load_validation_registry(path)
    by_id = {r.detector_id: r for r in registry.records}
    assert by_id["det-a"].limits.demoted_by is None
    assert by_id["det-b"].limits.demoted_by == "U3 probe run run-1"


def test_clear_demotions_distinct_detector_not_cleared(tmp_path):
    """(1778,30) Eq_IsNot#7: ``record.detector_id == detector_id`` ->
    ``is not``. A record for another detector (distinct string object
    from the registry file) is not cleared."""
    path = _registry_file(
        tmp_path,
        [
            _seeded_record(0, "det-a", "U3 probe run run-1"),
            _seeded_record(1, "det-b", "U3 probe run run-1"),
        ],
    )
    clear_demotions(registry_path=path, detector_id="det-a", run_id="run-2")
    from textforensics.validation import load_validation_registry

    registry = load_validation_registry(path)
    by_id = {r.detector_id: r for r in registry.records}
    assert by_id["det-b"].limits.demoted_by == "U3 probe run run-1"


def test_clear_demotions_lower_detector_not_cleared(tmp_path):
    """(1778,30) Eq_LtE#15: a record for a detector sorting below the
    target is not cleared."""
    path = _registry_file(
        tmp_path,
        [
            _seeded_record(0, "det-a", "U3 probe run run-1"),
            _seeded_record(1, "det-b", "U3 probe run run-1"),
        ],
    )
    result = clear_demotions(registry_path=path, detector_id="det-b", run_id="run-2")
    assert len(result["cleared_record_ids"]) == 1
    from textforensics.validation import load_validation_registry

    registry = load_validation_registry(path)
    by_id = {r.detector_id: r for r in registry.records}
    assert by_id["det-a"].limits.demoted_by == "U3 probe run run-1"
    assert by_id["det-b"].limits.demoted_by is None


def test_clear_demotions_fully_cleared_not_retained(tmp_path):
    """(1782,15) AddNot#106 + (1782,41) IsNot_Is#47: a record whose
    demotion is fully cleared (demoted_by becomes None) is not listed
    as retained; the reason carries no 'remain demoted' suffix."""
    path = _registry_file(tmp_path, [_seeded_record(0, FAKE_ID, "U3 probe run run-1")])
    result = clear_demotions(registry_path=path, detector_id=FAKE_ID, run_id="run-2")
    assert "remain demoted" not in result["reason"]


def test_clear_demotions_foreign_retained_in_reason(tmp_path):
    """(1796,7) AddNot#109: a record retaining a foreign demotion is
    reported in the reason suffix."""
    path = _registry_file(
        tmp_path,
        [_seeded_record(0, FAKE_ID, "U3 probe run run-1 || manual review: suspicious")],
    )
    result = clear_demotions(registry_path=path, detector_id=FAKE_ID, run_id="run-2")
    assert "1 record(s) remain demoted for a non-U3 reason" in result["reason"]
    from textforensics.validation import load_validation_registry

    registry = load_validation_registry(path)
    assert registry.records[0].limits.demoted_by == "manual review: suspicious"


# ---------------------------------------------------------------------------
# resolve_baseline
# ---------------------------------------------------------------------------


def _baseline_history(
    *,
    detector_id=DET_ID,
    version="0.1.0",
    fingerprint=HEX64,
    baseline=True,
    run_id="r1",
    at="2026-11-01T00:00:00+00:00",
):
    run = _history_run(run_id, at, baseline=baseline, version=version)
    run["detector_id"] = detector_id
    run["corpus_fingerprint"] = fingerprint
    return [run]


def test_resolve_baseline_accepts_keyword_arguments():
    """(1818,4) Mul_Div#11: ``resolve_baseline(history, *, ...)`` is
    keyword-only; calling it with ``history=`` as a keyword works (the
    ``*`` -> ``/`` mutant makes ``history`` positional-only)."""
    history = _baseline_history()
    out = resolve_baseline(
        history=history,
        detector_id=DET_ID,
        detector_version="0.1.0",
        corpus_fingerprint=HEX64,
    )
    assert out is not None and out["run_id"] == "r1"


def test_resolve_baseline_detector_above_target_not_candidate():
    """(1844,34) Eq_GtE#16: a run for a detector sorting above the
    target is not a baseline candidate."""
    history = _baseline_history(detector_id="det-b")
    # The history run claims det-b; resolving for det-a must find nothing.
    assert (
        resolve_baseline(
            history,
            detector_id="det-a",
            detector_version="0.1.0",
            corpus_fingerprint=HEX64,
        )
        is None
    )


def test_resolve_baseline_detector_distinct_object_not_candidate():
    """(1844,34) Eq_Is#8: ``run.get("detector_id") == detector_id`` ->
    ``is``. A matching detector id loaded from JSON (a distinct string
    object) is still a candidate."""
    history = json.loads(json.dumps(_baseline_history()))
    out = resolve_baseline(
        history,
        detector_id=DET_ID,
        detector_version="0.1.0",
        corpus_fingerprint=HEX64,
    )
    assert out is not None and out["run_id"] == "r1"


def test_resolve_baseline_detector_below_target_not_candidate():
    """(1844,34) Eq_LtE#16: a run for a detector sorting below the
    target is not a baseline candidate."""
    history = _baseline_history(detector_id="det-a")
    assert (
        resolve_baseline(
            history,
            detector_id="det-b",
            detector_version="0.1.0",
            corpus_fingerprint=HEX64,
        )
        is None
    )


def test_resolve_baseline_version_distinct_object_is_candidate():
    """(1845,40) Eq_Is#9: a matching detector version loaded from JSON
    (a distinct string object) is still a candidate."""
    history = json.loads(json.dumps(_baseline_history()))
    out = resolve_baseline(
        history,
        detector_id=DET_ID,
        detector_version="0.1.0",
        corpus_fingerprint=HEX64,
    )
    assert out is not None and out["run_id"] == "r1"


def test_resolve_baseline_fingerprint_above_target_not_candidate():
    """(1846,42) Eq_GtE#18: a run for a corpus fingerprint sorting
    above the target is not a baseline candidate."""
    history = _baseline_history(fingerprint="f" * 64)
    assert (
        resolve_baseline(
            history,
            detector_id=DET_ID,
            detector_version="0.1.0",
            corpus_fingerprint="a" * 64,
        )
        is None
    )


def test_resolve_baseline_fingerprint_distinct_object_is_candidate():
    """(1846,42) Eq_Is#10: a matching corpus fingerprint loaded from
    JSON (a distinct string object) is still a candidate."""
    history = json.loads(json.dumps(_baseline_history()))
    out = resolve_baseline(
        history,
        detector_id=DET_ID,
        detector_version="0.1.0",
        corpus_fingerprint=HEX64,
    )
    assert out is not None and out["run_id"] == "r1"


def test_resolve_baseline_fingerprint_below_target_not_candidate():
    """(1846,42) Eq_LtE#18: a run for a corpus fingerprint sorting
    below the target is not a baseline candidate."""
    history = _baseline_history(fingerprint="0" * 64)
    assert (
        resolve_baseline(
            history,
            detector_id=DET_ID,
            detector_version="0.1.0",
            corpus_fingerprint="a" * 64,
        )
        is None
    )


def test_resolve_baseline_truthy_non_true_is_baseline_excluded():
    """(1847,35) Is_Eq#0 + Is_GtE#0: ``is_baseline is True`` -> ``==``
    / ``>=``. A run with is_baseline=1 (truthy but not True) is not a
    baseline candidate."""
    history = _baseline_history()
    history[0]["is_baseline"] = 1
    assert (
        resolve_baseline(
            history,
            detector_id=DET_ID,
            detector_version="0.1.0",
            corpus_fingerprint=HEX64,
        )
        is None
    )


def test_resolve_baseline_false_is_baseline_excluded():
    """(1847,35) Is_LtE#0: ``is_baseline is True`` -> ``<=``. A run
    with is_baseline=False is not a baseline candidate."""
    history = _baseline_history(baseline=False)
    assert (
        resolve_baseline(
            history,
            detector_id=DET_ID,
            detector_version="0.1.0",
            corpus_fingerprint=HEX64,
        )
        is None
    )


def test_resolve_baseline_returns_newest_candidate():
    """(1854,52) USub_Not#1 + (1854,53) NumberReplacer#167:
    ``sorted(...)[-1]`` -> ``[not 1]`` / ``[-0]`` returns the oldest
    candidate instead of the newest."""
    history = [
        _history_run("r-old", "2026-11-01T00:00:00+00:00", baseline=True),
        _history_run("r-new", "2026-11-02T00:00:00+00:00", baseline=True),
    ]
    out = resolve_baseline(
        history,
        detector_id=DET_ID,
        detector_version="0.1.0",
        corpus_fingerprint=HEX64,
    )
    assert out is not None and out["run_id"] == "r-new"


# ---------------------------------------------------------------------------
# summarize_longitudinal
# ---------------------------------------------------------------------------


def _summary_history(runs):
    """Build a history list from (run_id, at, scope, version, alerts,
    fingerprint) tuples; completeness is support-eligible."""
    history = []
    for run_id, at, scope, version, alerts, fingerprint in runs:
        run = _history_run(run_id, at, baseline=False, version=version)
        run["scope"] = scope
        run["alerts"] = list(alerts)
        run["corpus_fingerprint"] = fingerprint
        history.append(run)
    return history


def _summarize(history, *, detector_id=DET_ID, version="0.1.0", fingerprint=HEX64):
    return summarize_longitudinal(
        history=history,
        detector_id=detector_id,
        detector_version=version,
        corpus_fingerprint=fingerprint,
    )


def test_summarize_accepts_keyword_arguments():
    """(1859,4) Mul_Div#12: ``summarize_longitudinal(history, *, ...)``
    is keyword-only; calling it with ``history=`` as a keyword works
    (the ``*`` -> ``/`` mutant makes ``history`` positional-only). Two
    clean full runs establish temporal support (the floor is 2)."""
    out = _summarize(
        _summary_history(
            [
                ("r2", "2026-11-02T00:00:00+00:00", "full", "0.1.0", [], HEX64),
                ("r1", "2026-11-01T00:00:00+00:00", "full", "0.1.0", [], HEX64),
            ]
        )
    )
    assert out["total_runs"] == 2
    assert out["temporal_support"] is True


def test_summarize_detector_above_target_excluded():
    """(1891,58) Eq_GtE#20: a run for a detector sorting above the
    target is not in the epoch."""
    history = _summary_history([("r1", "2026-11-01T00:00:00+00:00", "full", "0.1.0", [], HEX64)])
    out = _summarize(history, detector_id="det-a")
    # The only run is for DET_ID ("textforensics/...") which sorts above
    # "det-a"; the epoch must be empty.
    assert out["total_runs"] == 0


def test_summarize_detector_below_target_excluded():
    """(1891,58) Eq_LtE#20: a run for a detector sorting below the
    target is not in the epoch."""
    history = _summary_history([("r1", "2026-11-01T00:00:00+00:00", "full", "0.1.0", [], HEX64)])
    out = _summarize(history, detector_id="zzz-detector")
    assert out["total_runs"] == 0


def test_summarize_older_version_breaks_epoch():
    """(1905,39) NotEq_Gt#6: a run with a detector version below the
    target ends the epoch (detector_version_change)."""
    history = _summary_history(
        [
            ("r-new", "2026-11-02T00:00:00+00:00", "full", "0.1.0", [], HEX64),
            ("r-old", "2026-11-01T00:00:00+00:00", "full", "0.0.1", [], HEX64),
        ]
    )
    out = _summarize(history)
    assert out["total_runs"] == 1
    assert out["streak_break"] == {"run_id": "r-old", "reason": "detector_version_change"}


def test_summarize_other_fingerprint_breaks_epoch():
    """(1908,41) NotEq_Gt#7: a run with a corpus fingerprint below the
    target ends the epoch (corpus_change)."""
    history = _summary_history(
        [
            ("r-new", "2026-11-02T00:00:00+00:00", "full", "0.1.0", [], HEX64),
            ("r-old", "2026-11-01T00:00:00+00:00", "full", "0.1.0", [], "0" * 64),
        ]
    )
    out = _summarize(history)
    assert out["total_runs"] == 1
    assert out["streak_break"] == {"run_id": "r-old", "reason": "corpus_change"}


def test_summarize_provider_change_ends_epoch():
    """(1916,12) ReplaceBreakWithContinue#2: a provider-identity change
    ends the epoch; the walk must not continue past it."""
    history = _summary_history(
        [
            ("r-new", "2026-11-03T00:00:00+00:00", "full", "0.1.0", [], HEX64),
            ("r-mid", "2026-11-02T00:00:00+00:00", "full", "0.1.0", [], HEX64),
            ("r-old", "2026-11-01T00:00:00+00:00", "full", "0.1.0", [], HEX64),
        ]
    )
    history[1]["provider_metadata"] = {"model": "v2"}
    out = _summarize(history)
    assert out["total_runs"] == 1
    assert out["streak_break"] == {"run_id": "r-mid", "reason": "provider_change"}


def test_summarize_event_driven_breach_is_partial():
    """(1924,28) NotEq_Gt#9: an event-driven run carrying a Tier-2
    alert is a partial-run breach, not a full-run tier alert."""
    history = _summary_history(
        [
            ("r1", "2026-11-01T00:00:00+00:00", "event-driven", "0.1.0", [_alert(2)], HEX64),
        ]
    )
    out = _summarize(history)
    assert out["streak_break"] == {"run_id": "r1", "reason": "partial_run_breach"}
    assert out["watch"] is not None


def _breach_history(*, scope, tier, n_clean_before=0):
    """History: ``n_clean_before`` clean full runs (most recent) then
    one breaching run of ``scope``/``tier`` (oldest)."""
    runs = []
    for i in range(n_clean_before):
        runs.append((f"c{i}", f"2026-11-0{3 + i}T00:00:00+00:00", "full", "0.1.0", [], HEX64))
    runs.append(("b0", "2026-11-01T00:00:00+00:00", scope, "0.1.0", [_alert(tier)], HEX64))
    return _summary_history(runs)


def test_summarize_partial_tier1_alert_sets_no_watch():
    """(1927,75) Eq_Lt#21 + Eq_LtE#21 + Eq_NotEq#21: a Tier-1 alert on
    a partial run is not a Tier-2 watch."""
    out = _summarize(_breach_history(scope="monthly-attacked", tier=1))
    assert out["watch"] is None


def test_summarize_partial_tier3_alert_sets_no_watch():
    """(1927,75) Eq_Gt#21 + Eq_GtE#21: a Tier-3 alert on a partial run
    is not a Tier-2 watch."""
    out = _summarize(_breach_history(scope="monthly-attacked", tier=3))
    assert out["watch"] is None


def test_summarize_partial_watch_excludes_tier3_alert():
    """(1927,75) Eq_GtE#21: a Tier-3 alert coexisting with a Tier-2
    alert on a partial run is not in the watch (the ``>=`` mutant
    includes it). The Tier-2 alert alone sets the watch."""
    runs = [
        (
            "b0",
            "2026-11-01T00:00:00+00:00",
            "monthly-attacked",
            "0.1.0",
            [_alert(2), _alert(3, rule="drift_statistic")],
            HEX64,
        ),
    ]
    out = _summarize(_summary_history(runs))
    assert out["watch"] is not None
    assert len(out["watch"]["alerts"]) == 1
    assert out["watch"]["alerts"][0]["tier"] == 2


def test_summarize_full_watch_excludes_tier3_alert():
    """(1938,71) Eq_GtE#22: a Tier-3 alert coexisting with a Tier-2
    alert on a full run is not in the watch."""
    runs = [
        (
            "b0",
            "2026-11-01T00:00:00+00:00",
            "full",
            "0.1.0",
            [_alert(2), _alert(3, rule="drift_statistic")],
            HEX64,
        ),
    ]
    out = _summarize(_summary_history(runs))
    assert out["watch"] is not None
    assert len(out["watch"]["alerts"]) == 1
    assert out["watch"]["alerts"][0]["tier"] == 2


def test_summarize_partial_tier2_alert_sets_watch():
    """(1927,78) NumberReplacer#172/#173 + (1928,19) AddNot#117: a
    Tier-2 alert on a partial run with no clean runs after it sets a
    watch."""
    out = _summarize(_breach_history(scope="monthly-attacked", tier=2))
    assert out["watch"] is not None
    assert out["watch"]["run_id"] == "b0"


def test_summarize_partial_tier1_only_sets_no_watch():
    """(1928,25) ReplaceAndWithOr#55: ``tier2 and len < MIN`` -> ``or``.
    With no Tier-2 alert (Tier-1 only) there is no watch even when the
    clean-run count is below the floor."""
    out = _summarize(_breach_history(scope="monthly-attacked", tier=1))
    assert out["watch"] is None


def test_summarize_partial_watch_needs_below_floor():
    """(1928,48) Lt_Eq#3 + Lt_Gt#3 + Lt_GtE#3 + Lt_Is#3: with zero
    clean runs before the breach the watch is set (len 0 < 2)."""
    out = _summarize(_breach_history(scope="monthly-attacked", tier=2, n_clean_before=0))
    assert out["watch"] is not None


def test_summarize_partial_watch_expires_after_two_clean_runs():
    """(1928,48) Lt_LtE#3: with two clean runs before the breach the
    watch has expired (len 2 is not < 2)."""
    out = _summarize(_breach_history(scope="monthly-attacked", tier=2, n_clean_before=2))
    assert out["watch"] is None


def test_summarize_partial_watch_expires_after_three_clean_runs():
    """(1928,48) Lt_IsNot#3 + Lt_NotEq#3: with three clean runs
    before the breach the watch has expired (len 3 is not < 2)."""
    out = _summarize(_breach_history(scope="monthly-attacked", tier=2, n_clean_before=3))
    assert out["watch"] is None


def test_summarize_full_tier3_alert_sets_no_watch():
    """(1938,71) Eq_GtE#22: a Tier-3 alert on a full run is not a
    Tier-2 watch."""
    out = _summarize(_breach_history(scope="full", tier=3))
    assert out["watch"] is None


def test_summarize_full_tier1_alert_sets_no_watch():
    """(1938,71) Eq_LtE#22: a Tier-1 alert on a full run is not a
    Tier-2 watch."""
    out = _summarize(_breach_history(scope="full", tier=1))
    assert out["watch"] is None


def test_summarize_full_watch_expires_after_three_clean_runs():
    """(1939,44) Lt_IsNot#4 + Lt_NotEq#4: with three clean runs before
    a full-run Tier-2 breach the watch has expired."""
    out = _summarize(_breach_history(scope="full", tier=2, n_clean_before=3))
    assert out["watch"] is None


def test_summarize_last_run_at_is_most_recent():
    """(1960,42) NumberReplacer#177: ``epoch_runs[0]`` -> ``[-1]``.
    last_run_at_utc is the most recent run in the epoch."""
    history = _summary_history(
        [
            ("r-new", "2026-11-03T00:00:00+00:00", "full", "0.1.0", [], HEX64),
            ("r-old", "2026-11-01T00:00:00+00:00", "full", "0.1.0", [], HEX64),
        ]
    )
    out = _summarize(history)
    assert out["last_run_at_utc"] == "2026-11-03T00:00:00+00:00"


# ---------------------------------------------------------------------------
# _validate_completeness
# ---------------------------------------------------------------------------


def _valid_completeness(**overrides):
    accounting = _completeness()
    accounting.update(overrides)
    return accounting


def test_validate_completeness_rejects_bad_field():
    """(1980,17) ZeroIterationForLoop#27: a non-integer count field
    must raise (the skipped loop accepts it)."""
    with pytest.raises(ProbeRunError, match="non-negative integer"):
        _validate_completeness(_valid_completeness(selected="50"))


def test_validate_completeness_rejects_bool_field():
    """(1982,35) ReplaceOrWithAnd#33: a bool count must raise (the
    ``and`` mutant accepts True)."""
    with pytest.raises(ProbeRunError, match="non-negative integer"):
        _validate_completeness(_valid_completeness(selected=True))


def test_validate_completeness_rejects_negative_field():
    """(1982,65) ReplaceOrWithAnd#34 + (1982,76) NumberReplacer#179:
    a negative count must raise (both mutants accept -1)."""
    with pytest.raises(ProbeRunError, match="non-negative integer"):
        _validate_completeness(_valid_completeness(selected=-1))


def test_validate_completeness_accepts_attempted_below_selected():
    """(1991,17) Gt_Lt#13 + Gt_NotEq#13: attempted below selected is
    valid (the mutants raise on it)."""
    _validate_completeness(
        _valid_completeness(
            selected=50,
            attempted=40,
            succeeded=40,
            is_complete=False,
            support_eligible=False,
        )
    )


def test_validate_completeness_rejects_short_partition():
    """(1993,38) NotEq_Lt#10: a partition summing below attempted
    must raise (the ``<`` mutant accepts it)."""
    with pytest.raises(ProbeRunError, match="partition"):
        _validate_completeness(_valid_completeness(attempted=50, succeeded=40))


def test_validate_completeness_rejects_long_partition():
    """(1993,38) NotEq_Gt#10: a partition summing above attempted
    must raise (the ``>`` mutant accepts it)."""
    with pytest.raises(ProbeRunError, match="partition"):
        _validate_completeness(_valid_completeness(attempted=50, succeeded=50, failed=1))


def test_validate_completeness_none_is_complete_is_valid():
    """(2000,7) AddNot#125 + (2000,19) IsNot_Is#48: a missing
    is_complete (None) is valid on a complete run (the mutants raise)."""
    accounting = _valid_completeness(is_complete=None)
    _validate_completeness(accounting)


def test_validate_completeness_false_is_complete_on_complete_run_raises():
    """(2000,53) NotEq_Gt#11: is_complete=False on a complete run
    must raise (the ``>`` mutant accepts it)."""
    with pytest.raises(ProbeRunError, match="is_complete disagrees"):
        _validate_completeness(_valid_completeness(is_complete=False))


def test_validate_completeness_true_is_complete_on_partial_run_raises():
    """(2000,53) NotEq_Lt#11: is_complete=True on a partial run must
    raise (the ``<`` mutant accepts it)."""
    with pytest.raises(ProbeRunError, match="is_complete disagrees"):
        _validate_completeness(
            _valid_completeness(selected=50, attempted=40, succeeded=40, is_complete=True)
        )


def test_validate_completeness_attempted_below_selected_is_complete_raises():
    """(2000,67) Eq_LtE#23: ``attempted == selected`` -> ``<=``.
    is_complete=True with attempted below selected must raise (the
    mutant treats ``<=`` as agreeing)."""
    with pytest.raises(ProbeRunError, match="is_complete disagrees"):
        _validate_completeness(
            _valid_completeness(selected=50, attempted=40, succeeded=40, is_complete=True)
        )


def test_validate_completeness_none_support_eligible_is_valid():
    """(2002,7) AddNot#126 + (2002,24) IsNot_Is#49: a missing
    support_eligible (None) is valid on a clean complete run."""
    accounting = _valid_completeness(support_eligible=None)
    _validate_completeness(accounting)


def test_validate_completeness_false_support_on_clean_run_raises():
    """(2002,63) NotEq_Gt#12: support_eligible=False on a clean
    complete run must raise (the ``>`` mutant accepts it)."""
    with pytest.raises(ProbeRunError, match="support_eligible disagrees"):
        _validate_completeness(_valid_completeness(support_eligible=False))


def test_validate_completeness_true_support_on_partial_run_raises():
    """(2002,63) NotEq_Lt#12: support_eligible=True on a partial run
    must raise (the ``<`` mutant accepts it)."""
    with pytest.raises(ProbeRunError, match="support_eligible disagrees"):
        _validate_completeness(
            _valid_completeness(
                selected=50,
                attempted=40,
                succeeded=40,
                is_complete=False,
                support_eligible=True,
            )
        )


def test_validate_completeness_large_equal_counts_agree():
    """(2003,18) Eq_Is#14 + (2003,60) Eq_Is#15: ``attempted ==
    selected`` / ``succeeded == selected`` -> ``is``. Equal counts of
    300 (distinct int objects, outside the small-int cache) agree."""
    accounting = _valid_completeness(
        selected=int("300"),
        attempted=int("300"),
        succeeded=int("300"),
        is_complete=True,
        support_eligible=True,
    )
    _validate_completeness(accounting)


def test_validate_completeness_rejects_non_list_ids():
    """(2006,17) ZeroIterationForLoop#28: a non-list id field must
    raise (the skipped loop accepts it)."""
    with pytest.raises(ProbeRunError, match="list of strings"):
        _validate_completeness(_valid_completeness(failed_item_ids="not-a-list"))


def test_validate_completeness_none_ids_are_valid():
    """(2008,11) AddNot#127 + (2008,15) IsNot_Is#50: a missing id list
    (None) is valid (the mutants raise on it)."""
    accounting = _valid_completeness(failed_item_ids=None)
    _validate_completeness(accounting)


def test_validate_completeness_rejects_string_ids():
    """(2009,38) ReplaceOrWithAnd#35: a string id field must raise
    (the ``and`` mutant accepts a string of single characters)."""
    with pytest.raises(ProbeRunError, match="list of strings"):
        _validate_completeness(_valid_completeness(failed_item_ids="x"))


# ---------------------------------------------------------------------------
# validate_run_manifest
# ---------------------------------------------------------------------------


def _valid_manifest(**overrides):
    manifest = _manifest()
    manifest.update(overrides)
    return manifest


def test_validate_manifest_unknown_field_reports_missing_field():
    """(2250,35) Sub_BitXor#8: ``set(manifest) - KNOWN`` -> ``^``. A
    manifest missing a required field (no unknown fields) must raise
    the missing-field error, not the unknown-field error."""
    manifest = _valid_manifest()
    del manifest["metrics"]
    with pytest.raises(ProbeRunError, match="missing required field"):
        validate_run_manifest(manifest)


def test_validate_manifest_rejects_empty_required_string():
    """(2261,17) ZeroIterationForLoop#32: an empty required string
    (corpus_version) must raise (the skipped loop accepts it)."""
    manifest = _valid_manifest(corpus_version="")
    with pytest.raises(ProbeRunError, match="corpus_version"):
        validate_run_manifest(manifest)


def test_validate_manifest_rejects_non_string_link():
    """(2275,17) ZeroIterationForLoop#33: a non-string link
    (previous_run_id) must raise (the skipped loop accepts it)."""
    manifest = _valid_manifest(previous_run_id=123)
    with pytest.raises(ProbeRunError, match="previous_run_id"):
        validate_run_manifest(manifest)


def _alpha_manifest(alpha):
    manifest = _valid_manifest()
    manifest["alpha_per_run"] = alpha
    return manifest


def test_validate_manifest_alpha_zero_rejected():
    """(2280,15) Lt_LtE#6: alpha=0.0 is outside (0, 1] (the ``<=``
    mutant accepts it)."""
    with pytest.raises(ProbeRunError, match="alpha_per_run"):
        validate_run_manifest(_alpha_manifest(0.0))


def test_validate_manifest_alpha_negative_rejected():
    """(2280,15) Lt_NotEq#6 + (2280,11) NumberReplacer#193: alpha=-0.5
    is outside (0, 1] (both mutants accept it)."""
    with pytest.raises(ProbeRunError, match="alpha_per_run"):
        validate_run_manifest(_alpha_manifest(-0.5))


def test_validate_manifest_alpha_one_accepted():
    """(2280,23) LtE_Lt#2 + LtE_NotEq#2: alpha=1.0 is inside (0, 1]
    (both mutants reject it)."""
    validate_run_manifest(_alpha_manifest(1.0))


def test_validate_manifest_alpha_above_one_rejected():
    """(2280,26) NumberReplacer#194: alpha=1.5 is outside (0, 1]
    (the mutant accepts up to 2.0)."""
    with pytest.raises(ProbeRunError, match="alpha_per_run"):
        validate_run_manifest(_alpha_manifest(1.5))


def test_validate_manifest_thresholds_missing_field_rejected():
    """(2293,24) ZeroIterationForLoop#35: a thresholds object missing
    a required field must raise (the skipped loop accepts it)."""
    manifest = _valid_manifest()
    del manifest["thresholds"]["min_slice_n"]
    with pytest.raises(ProbeRunError, match="thresholds is missing"):
        validate_run_manifest(manifest)


def test_validate_manifest_thresholds_non_finite_rejected():
    """(2295,26) ZeroIterationForLoop#36: a non-finite threshold value
    must raise (the skipped loop accepts it)."""
    manifest = _valid_manifest()
    manifest["thresholds"]["fpr_cap"] = float("inf")
    with pytest.raises(ProbeRunError, match="must be finite"):
        validate_run_manifest(manifest)


def _threshold_manifest(field, value):
    manifest = _valid_manifest()
    manifest["thresholds"][field] = value
    return manifest


def test_validate_manifest_threshold_bool_rejected():
    """(2293,24) ZeroIterationForLoop#35: a bool threshold value must
    raise 'must be a number' from the finite-number loop (the skipped
    loop lets it through to a different 'integer >=' error)."""
    with pytest.raises(ProbeRunError, match="must be a number"):
        validate_run_manifest(_threshold_manifest("min_slice_n", True))


def test_validate_manifest_threshold_float_rejected():
    """(2297,38) ReplaceOrWithAnd#47: a float threshold integer (1.5)
    must raise (the ``and`` mutant accepts it; a bool never reaches
    this check because the finite-number check rejects it first)."""
    with pytest.raises(ProbeRunError, match="integer >="):
        validate_run_manifest(_threshold_manifest("min_slice_n", 1.5))


def test_validate_manifest_threshold_negative_rejected():
    """(2297,65) ReplaceOrWithAnd#48: a negative threshold integer
    must raise (the ``and`` mutant accepts -1)."""
    with pytest.raises(ProbeRunError, match="integer >="):
        validate_run_manifest(_threshold_manifest("min_slice_n", -1))


def test_validate_manifest_threshold_at_minimum_accepted():
    """(2297,74) Lt_Is#6 + Lt_Eq#7 + Lt_LtE#7: a threshold integer
    equal to its minimum (1) is valid (all three mutants reject it)."""
    validate_run_manifest(_threshold_manifest("min_slice_n", 1))


def test_validate_manifest_threshold_minimums():
    """(2162-2165) NumberReplacer#182-#189: the integer minimums are
    min_clean=1, min_slice_n=1, min_slice_n_for_fpr_claim=1,
    version_change_stale_days=0. Values at the minimum pass; values
    below it raise."""
    # #182/#184/#186: minimum 1 -> 2 rejects the minimum value.
    for field in (
        "min_clean_full_runs_for_temporal_support",
        "min_slice_n",
        "min_slice_n_for_fpr_claim",
    ):
        validate_run_manifest(_threshold_manifest(field, 1))
    # #183/#185/#187: minimum 1 -> 0 accepts 0.
    for field in (
        "min_clean_full_runs_for_temporal_support",
        "min_slice_n",
        "min_slice_n_for_fpr_claim",
    ):
        with pytest.raises(ProbeRunError, match="integer >="):
            validate_run_manifest(_threshold_manifest(field, 0))
    # #188: minimum 0 -> 1 rejects 0.
    validate_run_manifest(_threshold_manifest("version_change_stale_days", 0))
    # #189: minimum 0 -> -1 accepts -1.
    with pytest.raises(ProbeRunError, match="integer >="):
        validate_run_manifest(_threshold_manifest("version_change_stale_days", -1))


def _fpr_cap_manifest(cap):
    manifest = _valid_manifest()
    manifest["thresholds"]["fpr_cap"] = cap
    return manifest


def test_validate_manifest_fpr_cap_negative_rejected():
    """(2300,11) NumberReplacer#197: fpr_cap=-0.5 is outside [0, 1]
    (the mutant accepts down to -1.0)."""
    with pytest.raises(ProbeRunError, match="fpr_cap"):
        validate_run_manifest(_fpr_cap_manifest(-0.5))


def test_validate_manifest_fpr_cap_zero_accepted():
    """(2300,15) LtE_Lt#3 + LtE_NotEq#3: fpr_cap=0.0 is inside [0, 1]
    (both mutants reject it)."""
    validate_run_manifest(_fpr_cap_manifest(0.0))


def test_validate_manifest_fpr_cap_one_accepted():
    """(2300,26) LtE_Lt#4: fpr_cap=1.0 is inside [0, 1] (the mutant
    rejects it)."""
    validate_run_manifest(_fpr_cap_manifest(1.0))


def test_validate_manifest_metrics_non_finite_is_probe_error():
    """(2309,11) ExceptionReplacer#7: a non-finite metrics value
    raises ProbeRunError, not the raw ValueError. The value hides in
    a set, which _require_finite_json does not walk (it only walks
    mappings and lists/tuples) but reject_nonfinite_value does, so the
    ValueError path is actually reached."""
    manifest = _valid_manifest()
    manifest["metrics"] = {"detector_id": DET_ID, "x": {float("inf")}}
    with pytest.raises(ProbeRunError):
        validate_run_manifest(manifest)


def test_validate_manifest_alert_missing_field_rejected():
    """(2321,21) ZeroIterationForLoop#38: an alert missing a required
    field must raise the 'must carry tier.' error (the skipped loop
    lets it through to a different 'must carry tier 1, 2, or 3'
    error)."""
    manifest = _valid_manifest(alerts=[{"rule": "flip_rate"}])
    with pytest.raises(ProbeRunError, match="must carry tier\\."):
        validate_run_manifest(manifest)


def _tier_manifest(tier):
    manifest = _valid_manifest()
    manifest["alerts"] = [_alert(tier)]
    return manifest


def test_validate_manifest_alert_tier_boundaries():
    """(2324,37) NumberReplacer#200/#201 + (2324,43) #204/#205: the
    alert tier domain is exactly (1, 2, 3)."""
    validate_run_manifest(_tier_manifest(1))
    validate_run_manifest(_tier_manifest(3))
    with pytest.raises(ProbeRunError, match="tier 1, 2, or 3"):
        validate_run_manifest(_tier_manifest(0))
    with pytest.raises(ProbeRunError, match="tier 1, 2, or 3"):
        validate_run_manifest(_tier_manifest(4))


def test_validate_manifest_alert_empty_string_field_rejected():
    """(2328,21) ZeroIterationForLoop#39: an alert with an empty
    required string field (rule) must raise (the skipped loop accepts
    it)."""
    alert = _alert(1)
    alert["rule"] = ""
    manifest = _valid_manifest(alerts=[alert])
    with pytest.raises(ProbeRunError, match="non-empty string"):
        validate_run_manifest(manifest)


def test_validate_manifest_breach_non_object_rejected():
    """(2328,21) ZeroIterationForLoop#39: a non-object breach must
    raise (the skipped loop accepts it)."""
    manifest = _valid_manifest(breaches=[123])
    with pytest.raises(ProbeRunError, match="must be objects"):
        validate_run_manifest(manifest)


def test_validate_manifest_demotions_non_object_rejected():
    """(2332,18) ZeroIterationForLoop#40: a non-object demotions
    field must raise (the skipped loop accepts it)."""
    manifest = _valid_manifest(demotions_applied=[])
    with pytest.raises(ProbeRunError, match="must be an object"):
        validate_run_manifest(manifest)


def test_validate_manifest_valid_breach_accepted():
    """(2333,11) Delete_Not#51 + AddNot#165: a valid Mapping breach
    is accepted (both mutants raise on it)."""
    validate_run_manifest(_valid_manifest(breaches=[{"rule": "x"}]))


def test_validate_manifest_watches_non_list_rejected():
    """(2335,17) ZeroIterationForLoop#41: a non-list watches field
    must raise (the skipped loop accepts it)."""
    manifest = _valid_manifest(watches="not-a-list")
    with pytest.raises(ProbeRunError, match="must be a list"):
        validate_run_manifest(manifest)


def test_validate_manifest_provider_metadata_none_accepted():
    """(2338,7) AddNot#167 + (2338,41) IsNot_Is#56: provider_metadata
    None is accepted (both mutants raise on it)."""
    validate_run_manifest(_valid_manifest(provider_metadata=None))


def test_validate_manifest_gaps_non_string_rejected():
    """(2342,17) ZeroIterationForLoop#42: a non-string gap must raise
    (the skipped loop accepts it)."""
    manifest = _valid_manifest(gaps=[123])
    with pytest.raises(ProbeRunError, match="must contain strings"):
        validate_run_manifest(manifest)


def test_validate_manifest_score_series_non_object_rejected():
    """(2346,17) ZeroIterationForLoop#43: a non-object score_series
    entry must raise (the skipped loop accepts it)."""
    manifest = _valid_manifest(score_series={"i1": "not-a-dict"})
    with pytest.raises(ProbeRunError, match="must be an object"):
        validate_run_manifest(manifest)


def test_validate_manifest_score_series_unknown_key_rejected():
    """(2347,20) ZeroIterationForLoop#44: a score_series entry missing
    a required field must raise (the skipped loop accepts it)."""
    manifest = _valid_manifest(score_series={"i1": {"score": 0.5}})
    with pytest.raises(ProbeRunError, match="must carry"):
        validate_run_manifest(manifest)


def test_validate_manifest_score_series_minimal_entry_accepted():
    """(2359,16) Sub_BitXor#10: ``set(entry) - allowed`` -> ``^``. A
    minimal entry carrying only score + verdict is accepted (the
    mutant reports the absent allowed keys as unknown)."""
    manifest = _valid_manifest(score_series={"i1": {"score": 0.5, "verdict": "human_like"}})
    validate_run_manifest(manifest)


def test_validate_manifest_score_direction_none_accepted():
    """(2374,15) AddNot#174 + (2374,25) IsNot_Is#58: a score_series
    entry without a direction is accepted (both mutants raise)."""
    manifest = _valid_manifest(
        score_series={"i1": {"score": 0.5, "verdict": "human_like", "native_score_direction": None}}
    )
    validate_run_manifest(manifest)


def test_validate_manifest_score_direction_bogus_is_probe_error():
    """(2377,23) ExceptionReplacer#8: an unknown score direction
    raises ProbeRunError, not the raw ValueError."""
    manifest = _valid_manifest(
        score_series={
            "i1": {"score": 0.5, "verdict": "human_like", "native_score_direction": "bogus"}
        }
    )
    with pytest.raises(ProbeRunError, match="unknown"):
        validate_run_manifest(manifest)


def _range_manifest(score_range):
    return _valid_manifest(
        score_series={"i1": {"score": 0.5, "verdict": "human_like", "score_range": score_range}}
    )


def test_validate_manifest_score_range_not_sequence_rejected():
    """(2385,16) ReplaceOrWithAnd#49: a non-list/tuple score_range
    with length 2 and numeric endpoints (range(2)) must raise (the
    ``and`` mutant accepts it)."""
    with pytest.raises(ProbeRunError, match="score_range"):
        validate_run_manifest(_range_manifest(range(2)))


def test_validate_manifest_score_range_length_one_rejected():
    """(2385,36) NotEq_Gt#15 + (2386,16) ReplaceOrWithAnd#50: a
    one-element score_range must raise (both mutants accept it)."""
    with pytest.raises(ProbeRunError, match="score_range"):
        validate_run_manifest(_range_manifest([1.0]))


def test_validate_manifest_score_range_length_three_rejected():
    """(2385,36) NotEq_Lt#15 + (2392,16) ReplaceOrWithAnd#53: a
    three-element score_range with numeric endpoints and lo < hi
    must raise (both mutants accept it)."""
    with pytest.raises(ProbeRunError, match="score_range"):
        validate_run_manifest(_range_manifest([0.0, 1.0, 2.0]))


def test_validate_manifest_score_range_string_endpoints_rejected():
    """(2388,20) ReplaceOrWithAnd#51: string endpoints must raise
    (the ``and`` mutant accepts them)."""
    with pytest.raises(ProbeRunError, match="score_range"):
        validate_run_manifest(_range_manifest(["x", "y"]))


def test_validate_manifest_score_range_equal_distinct_rejected():
    """(2392,38) Lt_IsNot#7: a score_range with equal endpoints that
    are distinct float objects must raise (the ``is not`` mutant
    accepts it)."""
    with pytest.raises(ProbeRunError, match="score_range"):
        validate_run_manifest(_range_manifest([float("0.5"), 0.5]))


def test_validate_manifest_score_range_equal_rejected():
    """(2392,38) Lt_LtE#8: a score_range with equal endpoints must
    raise (the mutant accepts it)."""
    with pytest.raises(ProbeRunError, match="score_range"):
        validate_run_manifest(_range_manifest([0.5, 0.5]))


def test_validate_manifest_score_range_reversed_rejected():
    """(2392,38) Lt_NotEq#8: a score_range with lo > hi must raise
    (the ``!=`` mutant accepts it: ``not (1.0 != 0.5)`` is False)."""
    with pytest.raises(ProbeRunError, match="score_range"):
        validate_run_manifest(_range_manifest([1.0, 0.5]))


def test_validate_manifest_score_series_missing_score_rejected():
    """(2397,25) ZeroIterationForLoop#46: a score_series entry missing
    ``score`` must raise the 'must carry' error (the skipped loop lets
    the entry through to a different 'must be a number' error)."""
    manifest = _valid_manifest(score_series={"i1": {"verdict": "human_like"}})
    with pytest.raises(ProbeRunError, match="must carry"):
        validate_run_manifest(manifest)


def test_validate_manifest_calibration_id_non_string_rejected():
    """A score_series entry with a non-string calibration_id must
    raise (a guard the entry loop enforces)."""
    manifest = _valid_manifest(
        score_series={
            "i1": {
                "score": 0.5,
                "verdict": "human_like",
                "calibrated_ai_probability": 0.5,
                "calibration_id": 123,
            }
        }
    )
    with pytest.raises(ProbeRunError, match="must be a string"):
        validate_run_manifest(manifest)


def _prob_manifest(prob):
    return _valid_manifest(
        score_series={
            "i1": {"score": 0.5, "verdict": "human_like", "calibrated_ai_probability": prob}
        }
    )


def test_validate_manifest_probability_negative_rejected():
    """(2408,23) NumberReplacer#213: a calibrated probability of -0.5
    is outside [0, 1] (the mutant accepts down to -1.0)."""
    with pytest.raises(ProbeRunError, match="calibrated_ai_probability"):
        validate_run_manifest(_prob_manifest(-0.5))


def test_validate_manifest_probability_zero_accepted():
    """(2408,27) LtE_Lt#5 + LtE_NotEq#5: a calibrated probability of
    0.0 is inside [0, 1] (both mutants reject it)."""
    validate_run_manifest(_prob_manifest(0.0))


def test_validate_manifest_probability_one_accepted():
    """(2408,42) LtE_Lt#6: a calibrated probability of 1.0 is inside
    [0, 1] (the mutant rejects it)."""
    validate_run_manifest(_prob_manifest(1.0))


def test_validate_manifest_scope_statement_mismatch_rejected():
    """(2418,39) NotEq_Lt#16: a scope statement sorting below the
    canonical text must raise (the ``<`` mutant accepts it)."""
    manifest = _valid_manifest(scope_statement="a")
    with pytest.raises(ProbeRunError, match="scope statement"):
        validate_run_manifest(manifest)


def test_validate_manifest_previous_run_id_equal_rejected():
    """(2424,63) Eq_Is#16: a previous_run_id equal to run_id as a
    value (but a distinct string object) must raise (the ``is``
    mutant accepts it)."""
    manifest = _valid_manifest()
    manifest["previous_run_id"] = "".join(manifest["run_id"])
    with pytest.raises(ProbeRunError, match="must not equal run_id"):
        validate_run_manifest(manifest)


def test_validate_manifest_baseline_link_equal_non_baseline_rejected():
    """(2427,7) AddNot#183 + (2427,21) IsNot_Is#63: a baseline_run_id
    equal to run_id on a non-baseline run must raise (both mutants
    accept it)."""
    manifest = _valid_manifest(is_baseline=False)
    manifest["baseline_run_id"] = manifest["run_id"]
    with pytest.raises(ProbeRunError, match="must not equal run_id"):
        validate_run_manifest(manifest)


def test_validate_manifest_baseline_link_equal_distinct_rejected():
    """(2427,51) Eq_Is#17: a baseline_run_id equal to run_id as a
    value (distinct string object) on a non-baseline run must raise."""
    manifest = _valid_manifest(is_baseline=False)
    manifest["baseline_run_id"] = "".join(manifest["run_id"])
    with pytest.raises(ProbeRunError, match="must not equal run_id"):
        validate_run_manifest(manifest)


def test_validate_manifest_metrics_detector_mismatch_rejected():
    """(2437,57) NotEq_Lt#17: a metrics detector sorting above the run
    detector must raise (the ``<`` mutant accepts it)."""
    manifest = _valid_manifest()
    manifest["metrics"] = {"detector_id": "zzz-detector"}
    with pytest.raises(ProbeRunError, match="does not match"):
        validate_run_manifest(manifest)


def test_validate_manifest_holm_alpha_mismatch_rejected():
    """(2442,22) NotEq_Lt#18: a Holm alpha above this run's alpha must
    raise (the ``<`` mutant accepts it)."""
    manifest = _valid_manifest()
    manifest["metrics"] = {
        "detector_id": DET_ID,
        "holm": {"alpha_per_run": 0.06},
    }
    with pytest.raises(ProbeRunError, match="does not match"):
        validate_run_manifest(manifest)


def _overall_manifest(overall_n, series_len):
    manifest = _valid_manifest(
        score_series={f"i{k}": {"score": 0.5, "verdict": "human_like"} for k in range(series_len)}
    )
    manifest["metrics"] = {"detector_id": DET_ID, "overall": {"n": overall_n}}
    return manifest


def test_validate_manifest_overall_n_bool_rejected():
    """(2451,46) ReplaceOrWithAnd#54: a bool overall n must raise
    (the ``and`` mutant accepts True)."""
    with pytest.raises(ProbeRunError, match="non-negative integer"):
        validate_run_manifest(_overall_manifest(True, 1))


def test_validate_manifest_overall_n_negative_rejected():
    """(2451,77) ReplaceOrWithAnd#55 + (2451,92) NumberReplacer#217:
    a negative overall n must raise (both mutants accept -1)."""
    with pytest.raises(ProbeRunError, match="non-negative integer"):
        validate_run_manifest(_overall_manifest(-1, 1))


def test_validate_manifest_overall_n_zero_accepted():
    """(2451,90) Lt_Eq#9 + Lt_LtE#9 + (2451,92) NumberReplacer#216:
    an overall n of 0 is valid (all three mutants reject it)."""
    validate_run_manifest(_overall_manifest(0, 0))


def test_validate_manifest_overall_n_below_series_rejected():
    """(2455,25) NotEq_Gt#19: an overall n below the series length
    must raise (the ``>`` mutant accepts it)."""
    with pytest.raises(ProbeRunError, match="does not match"):
        validate_run_manifest(_overall_manifest(1, 2))


def test_validate_manifest_overall_n_equal_large_agrees():
    """(2455,25) NotEq_IsNot#17: an overall n equal to the series
    length (300, a distinct int object) agrees."""
    validate_run_manifest(_overall_manifest(int("300"), 300))


def test_validate_manifest_slice_without_n_skipped():
    """(2463,58) ReplaceOrWithAnd#56: a slice entry that is a Mapping
    without ``n`` is skipped (the ``and`` mutant reads ``n`` and
    raises KeyError)."""
    manifest = _overall_manifest(0, 0)
    manifest["metrics"]["slices"] = {"human-native": {"note": "no n here"}}
    validate_run_manifest(manifest)


def test_validate_manifest_bad_slice_validated_after_skipped():
    """(2464,20) ReplaceContinueWithBreak#8: the slice loop's
    ``continue`` must not stop at a skipped entry; a later slice with
    a negative n still raises."""
    manifest = _overall_manifest(1, 1)
    manifest["metrics"]["slices"] = {
        "aaa": "not-a-mapping",
        "zzz": {"n": -1},
    }
    with pytest.raises(ProbeRunError, match="non-negative integer"):
        validate_run_manifest(manifest)


def _slice_n_manifest(slice_n):
    manifest = _overall_manifest(0, 0)
    manifest["metrics"]["slices"] = {"human-native": {"n": slice_n}}
    return manifest


def test_validate_manifest_slice_n_bool_rejected():
    """(2466,48) ReplaceOrWithAnd#57: a bool slice n must raise (the
    ``and`` mutant accepts True)."""
    with pytest.raises(ProbeRunError, match="non-negative integer"):
        validate_run_manifest(_slice_n_manifest(True))


def test_validate_manifest_slice_n_negative_rejected():
    """(2466,77) ReplaceOrWithAnd#58 + (2466,90) NumberReplacer#221:
    a negative slice n must raise (both mutants accept -1)."""
    with pytest.raises(ProbeRunError, match="non-negative integer"):
        validate_run_manifest(_slice_n_manifest(-1))


def test_validate_manifest_slice_n_zero_accepted():
    """(2466,88) Lt_Eq#10 + Lt_LtE#10 + (2466,90) NumberReplacer#220:
    a slice n of 0 is valid (all three mutants reject it)."""
    validate_run_manifest(_slice_n_manifest(0))


def test_validate_manifest_slice_total_below_overall_rejected():
    """(2472,53) NotEq_Gt#20: slice ns summing below the overall n
    must raise (the ``>`` mutant accepts it)."""
    manifest = _overall_manifest(2, 2)
    manifest["metrics"]["slices"] = {"human-native": {"n": 1}}
    with pytest.raises(ProbeRunError, match="do not sum"):
        validate_run_manifest(manifest)


def test_validate_manifest_slice_total_equal_large_agrees():
    """(2472,53) NotEq_IsNot#18: slice ns summing to the overall n
    (300, distinct int objects) agree."""
    manifest = _overall_manifest(int("300"), 300)
    manifest["metrics"]["slices"] = {"human-native": {"n": int("300")}}
    validate_run_manifest(manifest)


# ---------------------------------------------------------------------------
# save_run
# ---------------------------------------------------------------------------


def test_save_run_creates_nested_directory(tmp_path):
    """(2488,29) ReplaceTrueWithFalse#20: ``mkdir(parents=True)`` ->
    False. Saving into a nested non-existent directory works."""
    manifest = _manifest(run_id="run-nested-1")
    target = save_run(manifest, tmp_path / "deep" / "deeper")
    assert target.exists()
    assert json.loads(target.read_text(encoding="utf-8"))["run_id"] == "run-nested-1"


def test_save_run_indent_two():
    """(2490,38) NumberReplacer#222/#223: ``indent=2`` -> 3/1. The
    saved file starts with the two-space indent."""
    import tempfile

    manifest = _manifest(run_id="run-indent-1")
    with tempfile.TemporaryDirectory() as directory:
        target = save_run(manifest, directory)
        content = target.read_text(encoding="utf-8")
    assert content.startswith('{\n  "schema": "textforensics.probe-run/v1"')


def test_save_run_writes_raw_utf8(tmp_path):
    """(2490,54) ReplaceFalseWithTrue#9: ``ensure_ascii=False`` ->
    True. Non-ASCII content is written as raw UTF-8, not escaped."""
    manifest = _manifest(gaps=["café — ünïcode gap"])
    target = save_run(manifest, tmp_path)
    assert "café".encode() in target.read_bytes()
    assert b"caf\\u00e9" not in target.read_bytes()


def test_save_run_unreadable_existing_is_probe_error(tmp_path):
    """(2511,19) ExceptionReplacer#10: an existing run that cannot be
    read (a directory at the target path) raises ProbeRunError, not
    the raw OSError."""
    manifest = _manifest(run_id="run-exists-1")
    target = tmp_path / "run-run-exists-1.json"
    target.mkdir()
    with pytest.raises(ProbeRunError, match="cannot be read"):
        save_run(manifest, tmp_path)


def test_save_run_different_existing_bytes_refused(tmp_path):
    """(2516,24) Eq_GtE#29: ``existing == rendered_bytes`` -> ``>=``.
    Pre-existing bytes sorting above the rendered bytes ('~' > '{')
    must not be treated as identical; the save is refused instead of
    silently returning the target."""
    manifest = _manifest(run_id="run-diff-1")
    target = tmp_path / "run-run-diff-1.json"
    target.write_bytes(b"~~~~not-json")
    with pytest.raises(ProbeRunError, match="different content"):
        save_run(manifest, tmp_path)


# ---------------------------------------------------------------------------
# perform_probe_run
# ---------------------------------------------------------------------------


def test_perform_rejects_non_list_items():
    """(2632,35) ReplaceOrWithAnd#59: a non-list ``items`` must raise
    the 'has no items' error (the ``and`` mutant proceeds to a
    different error)."""
    manifest, texts, holdback = _corpus(1)
    manifest["items"] = "not-a-list"
    with pytest.raises(ProbeRunError, match="has no items"):
        _perform(manifest, texts, holdback, _FakeDetector({}))


def test_perform_converts_non_utc_run_at_to_z():
    """(2636,7) Delete_Not#72 + AddNot#202: a run_at with a non-UTC
    offset is converted to UTC 'Z' (both mutants skip the conversion)."""
    manifest, texts, holdback = _corpus(1)
    out = _perform(
        manifest,
        texts,
        holdback,
        _FakeDetector({}),
        run_at=datetime(2026, 11, 15, 12, 0, tzinfo=timezone(timedelta(hours=5))),
    )
    assert out["run_at_utc"].endswith("Z")
    assert out["run_at_utc"] == "2026-11-15T07:00:00+00:00".replace("+00:00", "Z")


def test_perform_monthly_current_generator_scope_selects_only_its_slice(tmp_path):
    """(2642,13) Eq_Gt#30 + Eq_GtE#30: ``scope == "monthly-attacked"``
    -> ``>`` / ``>=``. A monthly-current-generator run must score
    only ai-current-generator items (both mutants select the attacked
    slices instead and find none)."""
    manifest, texts, holdback = _corpus(2, slice_name="ai-current-generator", label=1)
    out = _perform(manifest, texts, holdback, _FakeDetector({}), scope="monthly-current-generator")
    assert out["metrics"]["overall"]["n"] == 2
    assert out["scope"] == "monthly-current-generator"


def test_perform_scope_filter_continues_past_out_of_scope_item():
    """(2655,12) ReplaceContinueWithBreak#9: the scope-filter
    ``continue`` must not stop at the first out-of-scope item; the
    in-scope item after it is scored."""
    items = []
    texts = {}
    holdback = {}
    for item_id, slice_name, label in (
        ("i0", "human-native", 0),
        ("i1", "ai-paraphrased", 1),
    ):
        text = f"probe-{item_id}"
        items.append(
            {
                "item_id": item_id,
                "slice": slice_name,
                "content_sha256": hashlib.sha256(text.encode()).hexdigest(),
            }
        )
        texts[item_id] = text
        holdback[item_id] = {"label": label}
    manifest = {"version": "1.0.0", "items_sha256": HEX64, "items": items}
    out = _perform(manifest, texts, holdback, _FakeDetector({}), scope="monthly-attacked")
    assert out["metrics"]["overall"]["n"] == 1
    assert out["completeness"]["selected"] == 1


def test_perform_rejects_non_mapping_holdback_entry():
    """(2720,42) ReplaceOrWithAnd#63: a holdback entry that is not a
    Mapping (but contains 'label') must raise ProbeRunError, not
    TypeError."""
    manifest, texts, holdback = _corpus(1)
    holdback["i0"] = ["label"]
    with pytest.raises(ProbeRunError, match="has no label"):
        _perform(manifest, texts, holdback, _FakeDetector({}))


def _history_dir(tmp_path, runs):
    """A runs directory populated with the given saved-run manifests."""
    directory = tmp_path / "runs"
    directory.mkdir()
    for kwargs in runs:
        _saved_run(directory, **kwargs)
    return directory


def test_perform_history_filter_excludes_other_detector(tmp_path):
    """(2735,67) Eq_GtE#32: a history run for a detector sorting above
    the target is not the previous run (no rebaseline)."""
    directory = _history_dir(
        tmp_path,
        [
            {
                "run_id": "a" * 32,
                "at": "2026-11-01T00:00:00+00:00",
                "detector_id": "zzz-detector",
                "version": "0.2.0",
                "baseline": True,
            },
        ],
    )
    manifest, texts, holdback = _corpus(3)
    out = _perform(manifest, texts, holdback, _FakeDetector({}), runs_dir=directory)
    assert out["previous_run_id"] is None
    assert out["is_baseline"] is True


def test_perform_history_filter_excludes_lower_detector(tmp_path):
    """(2735,67) Eq_LtE#32: a history run for a detector sorting below
    the target is not the previous run."""
    directory = _history_dir(
        tmp_path,
        [
            {
                "run_id": "a" * 32,
                "at": "2026-11-01T00:00:00+00:00",
                "detector_id": "aaa-detector",
                "version": "0.2.0",
                "baseline": True,
            },
        ],
    )
    manifest, texts, holdback = _corpus(3)
    out = _perform(manifest, texts, holdback, _FakeDetector({}), runs_dir=directory)
    assert out["previous_run_id"] is None


def test_perform_history_filter_matches_distinct_detector_id(tmp_path):
    """(2735,67) Eq_IsNot#21: a history run whose detector id equals
    the target as a value (distinct string object, loaded from JSON)
    is the previous run."""
    directory = _history_dir(
        tmp_path,
        [
            {
                "run_id": "a" * 32,
                "at": "2026-11-01T00:00:00+00:00",
                "detector_id": FAKE_ID,
                "version": FAKE_VERSION,
                "baseline": True,
            },
        ],
    )
    manifest, texts, holdback = _corpus(3)
    out = _perform(manifest, texts, holdback, _FakeDetector({}), runs_dir=directory)
    assert out["previous_run_id"] == "a" * 32
    assert out["is_baseline"] is False


def test_perform_previous_is_newest_history_run(tmp_path):
    """(2736,32) USub_Not#2 + (2736,33) NumberReplacer#229:
    ``detector_history[-1]`` -> ``[not 1]`` / ``[-0]`` returns the
    oldest run instead of the newest."""
    directory = _history_dir(
        tmp_path,
        [
            {
                "run_id": "a" * 32,
                "at": "2026-11-01T00:00:00+00:00",
                "detector_id": FAKE_ID,
                "version": FAKE_VERSION,
                "baseline": True,
            },
            {
                "run_id": "b" * 32,
                "at": "2026-11-02T00:00:00+00:00",
                "detector_id": FAKE_ID,
                "version": FAKE_VERSION,
                "baseline": False,
            },
        ],
    )
    manifest, texts, holdback = _corpus(3)
    out = _perform(manifest, texts, holdback, _FakeDetector({}), runs_dir=directory)
    assert out["previous_run_id"] == "b" * 32


def test_perform_version_change_below_rebaselines(tmp_path):
    """(2746,45) IsNot_Is#73 + (2747,45) NotEq_Gt#21 + NotEq_GtE#21
    + NotEq_Is#19 + NotEq_Eq#21: a previous detector version below
    the current one is a version change (rebaseline). The ``is`` /
    ``==`` mutants treat the different version as unchanged; the
    ``>`` / ``>=`` mutants treat a lower version as unchanged."""
    directory = _history_dir(
        tmp_path,
        [
            {
                "run_id": "a" * 32,
                "at": "2026-11-01T00:00:00+00:00",
                "detector_id": FAKE_ID,
                "version": "0.0.9",
                "baseline": True,
            },
        ],
    )
    manifest, texts, holdback = _corpus(3)
    out = _perform(manifest, texts, holdback, _FakeDetector({}), runs_dir=directory)
    assert out["is_baseline"] is True
    assert out["rebaselined_from"] == "a" * 32


def test_perform_version_change_above_rebaselines(tmp_path):
    """(2747,45) NotEq_Lt#21 + NotEq_LtE#21 + NotEq_Is#19 +
    NotEq_Eq#21: a previous detector version above the current one
    is a version change."""
    directory = _history_dir(
        tmp_path,
        [
            {
                "run_id": "a" * 32,
                "at": "2026-11-01T00:00:00+00:00",
                "detector_id": FAKE_ID,
                "version": "0.2.0",
                "baseline": True,
            },
        ],
    )
    manifest, texts, holdback = _corpus(3)
    out = _perform(manifest, texts, holdback, _FakeDetector({}), runs_dir=directory)
    assert out["is_baseline"] is True
    assert out["rebaselined_from"] == "a" * 32


def test_perform_same_version_no_rebaseline(tmp_path):
    """(2747,45) NotEq_IsNot#19: a previous detector version equal to
    the current one as a value (distinct string object, loaded from
    JSON) is not a version change (the ``is not`` mutant treats it
    as changed)."""
    directory = _history_dir(
        tmp_path,
        [
            {
                "run_id": "a" * 32,
                "at": "2026-11-01T00:00:00+00:00",
                "detector_id": FAKE_ID,
                "version": FAKE_VERSION,
                "baseline": True,
            },
        ],
    )
    manifest, texts, holdback = _corpus(3)
    out = _perform(manifest, texts, holdback, _FakeDetector({}), runs_dir=directory)
    assert out["is_baseline"] is False
    assert out["rebaselined_from"] is None


def test_perform_same_provider_identity_no_rebaseline(tmp_path):
    """(2751,77) NotEq_IsNot#20: provider metadata equal as a value
    (distinct dict objects) is not a provider change."""
    directory = _history_dir(
        tmp_path,
        [
            {
                "run_id": "a" * 32,
                "at": "2026-11-01T00:00:00+00:00",
                "detector_id": FAKE_ID,
                "version": FAKE_VERSION,
                "baseline": True,
            },
        ],
    )
    manifest, texts, holdback = _corpus(3)
    out = _perform(manifest, texts, holdback, _FakeDetector({}), runs_dir=directory)
    assert out["is_baseline"] is False
    assert out["rebaselined_from"] is None


def test_perform_no_identity_change_no_rebaseline(tmp_path):
    """(2759,24) ReplaceAndWithOr#79: ``identity_changed and scope in
    (...)`` -> ``or``. With no identity change a full run does not
    rebaseline even though the scope is full."""
    directory = _history_dir(
        tmp_path,
        [
            {
                "run_id": "a" * 32,
                "at": "2026-11-01T00:00:00+00:00",
                "detector_id": FAKE_ID,
                "version": FAKE_VERSION,
                "baseline": True,
            },
        ],
    )
    manifest, texts, holdback = _corpus(3)
    out = _perform(manifest, texts, holdback, _FakeDetector({}), runs_dir=directory)
    assert out["is_baseline"] is False
    assert out["rebaselined_from"] is None


def test_perform_baseline_series_drives_score_shift(tmp_path):
    """(2771,75) ReplaceOrWithAnd#65: ``baseline.get("score_series")
    or {}`` -> ``and {}``. A baseline with a score series produces a
    computed score shift (the mutant passes no baseline records)."""
    series = {f"i{k}": _series_entry(score=0.3) for k in range(3)}
    directory = _history_dir(
        tmp_path,
        [
            {
                "run_id": "a" * 32,
                "at": "2026-11-01T00:00:00+00:00",
                "detector_id": FAKE_ID,
                "version": FAKE_VERSION,
                "baseline": True,
                "series": series,
            },
        ],
    )
    manifest, texts, holdback = _corpus(3)
    out = _perform(manifest, texts, holdback, _FakeDetector({}), runs_dir=directory)
    shift = out["metrics"]["slices"]["human-native"]["score_shift"]
    assert shift["ks_statistic"] is not None


def test_perform_previous_series_drives_flips(tmp_path):
    """(2774,75) ReplaceOrWithAnd#66: ``previous.get("score_series")
    or {}`` -> ``and {}``. A previous run with a score series produces
    flip metrics (the mutant passes no previous records)."""
    series = {f"i{k}": _series_entry(score=0.3, verdict="human_like") for k in range(3)}
    directory = _history_dir(
        tmp_path,
        [
            {
                "run_id": "a" * 32,
                "at": "2026-11-01T00:00:00+00:00",
                "detector_id": FAKE_ID,
                "version": FAKE_VERSION,
                "baseline": True,
                "series": {},
            },
            {
                "run_id": "b" * 32,
                "at": "2026-11-02T00:00:00+00:00",
                "detector_id": FAKE_ID,
                "version": FAKE_VERSION,
                "baseline": False,
                "series": series,
            },
        ],
    )
    manifest, texts, holdback = _corpus(3)
    out = _perform(manifest, texts, holdback, _FakeDetector({}), runs_dir=directory)
    assert out["metrics"]["slices"]["human-native"]["flips"] is not None


def test_perform_tier1_alert_demotes_registry(tmp_path):
    """(2801,48) Eq_Lt#33 + (2801,51) NumberReplacer#231: a Tier-1
    alert is demoted (the mutants drop Tier-1 alerts from the tier1
    list)."""
    registry = _registry_file(tmp_path, [_seeded_record(0, FAKE_ID, None)])
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()
    manifest, texts, holdback = _corpus(120, slice_name="human-native", label=0)
    detector = _FakeDetector({}, default=(0.9, "ai_like", None, None))
    out = perform_probe_run(
        manifest=manifest,
        texts=texts,
        holdback_loader=lambda: holdback,
        detector=detector,
        runs_dir=runs_dir,
        registry_path=registry,
    )
    assert any(a["tier"] == 1 for a in out["alerts"])
    assert out["demotions_applied"]["demoted_record_ids"]
    assert out["watches"] == []


def test_perform_tier2_alert_becomes_watch(tmp_path):
    """(2810,28) NumberReplacer#232/#233 + (2814,17)
    ZeroIterationForLoop#53: a Tier-2 alert becomes a watch whose
    run_id is the new run's id."""
    directory = _history_dir(
        tmp_path,
        [
            {
                "run_id": "a" * 32,
                "at": "2026-11-01T00:00:00+00:00",
                "detector_id": FAKE_ID,
                "version": "0.0.9",
                "baseline": True,
            },
        ],
    )
    manifest, texts, holdback = _corpus(3)
    out = _perform(manifest, texts, holdback, _FakeDetector({}), runs_dir=directory)
    assert len(out["watches"]) == 1
    assert out["watches"][0]["run_id"] == out["run_id"]
    assert out["watches"][0]["rule"] == "version_change_no_probe_run"


def test_perform_tier1_without_registry_refused(tmp_path):
    """(2823,15) AddNot#230 + (2823,29) Is_IsNot#17: a Tier-1 alert
    with no registry path raises ProbeRunError (both mutants skip the
    refusal)."""
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()
    manifest, texts, holdback = _corpus(120, slice_name="human-native", label=0)
    detector = _FakeDetector({}, default=(0.9, "ai_like", None, None))
    with pytest.raises(ProbeRunError, match="registry"):
        perform_probe_run(
            manifest=manifest,
            texts=texts,
            holdback_loader=lambda: holdback,
            detector=detector,
            runs_dir=runs_dir,
            registry_path=None,
        )


def test_perform_monthly_run_keeps_demotions(tmp_path):
    """(2834,19) Eq_GtE#35: a monthly run does not clear demotions
    (the ``>=`` mutant clears them, treating the scope as full)."""
    registry = _registry_file(tmp_path, [_seeded_record(0, FAKE_ID, "U3 probe run run-1")])
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()
    manifest, texts, holdback = _corpus(2, slice_name="ai-paraphrased", label=1)
    out = perform_probe_run(
        manifest=manifest,
        texts=texts,
        holdback_loader=lambda: holdback,
        detector=_FakeDetector({}),
        runs_dir=runs_dir,
        registry_path=registry,
        scope="monthly-attacked",
    )
    from textforensics.validation import load_validation_registry

    reloaded = load_validation_registry(registry)
    assert reloaded.records[0].limits.demoted_by == "U3 probe run run-1"
    assert out["demotions_cleared"] == {}


def test_perform_event_driven_run_keeps_demotions(tmp_path):
    """(2834,19) Eq_LtE#35: an event-driven run does not clear
    demotions (the ``<=`` mutant clears them)."""
    registry = _registry_file(tmp_path, [_seeded_record(0, FAKE_ID, "U3 probe run run-1")])
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()
    manifest, texts, holdback = _corpus(2, slice_name="human-native", label=0)
    out = perform_probe_run(
        manifest=manifest,
        texts=texts,
        holdback_loader=lambda: holdback,
        detector=_FakeDetector({}),
        runs_dir=runs_dir,
        registry_path=registry,
        scope="event-driven",
    )
    from textforensics.validation import load_validation_registry

    reloaded = load_validation_registry(registry)
    assert reloaded.records[0].limits.demoted_by == "U3 probe run run-1"
    assert out["demotions_cleared"] == {}


def _calibrated_run(tmp_path, *, baseline_series):
    """A run over 3 calibrated items with a partial baseline series
    (only some items carry a calibrated baseline probability)."""
    by_item = {f"i{k}": (0.3, "human_like", 0.3, "cal-1") for k in range(3)}
    directory = _history_dir(
        tmp_path,
        [
            {
                "run_id": "a" * 32,
                "at": "2026-11-01T00:00:00+00:00",
                "detector_id": FAKE_ID,
                "version": FAKE_VERSION,
                "baseline": True,
                "series": baseline_series,
            },
        ],
    )
    manifest, texts, holdback = _corpus(3)
    return _perform(manifest, texts, holdback, _FakeDetector(by_item), runs_dir=directory)


def test_perform_partial_baseline_reports_slice_gap(tmp_path):
    """(2865,36) ZeroIterationForLoop#54 + (2865,59)
    ReplaceOrWithAnd#67 + (2866,38) ReplaceOrWithAnd#68: a partial
    baseline (calibrated for only some items) produces a slice
    missing-calibration gap."""
    series = {"i0": _series_entry(score=0.3, calibrated=0.3, cal_id="cal-1")}
    out = _calibrated_run(tmp_path, baseline_series=series)
    slice_gaps = [g for g in out["gaps"] if g.startswith("Missing calibration evidence on slice")]
    assert len(slice_gaps) == 1
    assert "human-native" in slice_gaps[0]


def test_perform_partial_baseline_single_slice_gap_distinct(tmp_path):
    """(2870,30) IsNot_Lt#0 + IsNot_LtE#0 + IsNot_Gt#0 + IsNot_GtE#0
    + IsNot_Is#76: comparing the slice and overall missing-calibration
    dicts with an ordering operator raises; ``is`` is False for
    distinct dicts, so the slice gap is still reported."""
    series = {"i0": _series_entry(score=0.3, calibrated=0.3, cal_id="cal-1")}
    out = _calibrated_run(tmp_path, baseline_series=series)
    slice_gaps = [g for g in out["gaps"] if g.startswith("Missing calibration evidence on slice")]
    assert len(slice_gaps) == 1


def test_perform_partial_baseline_distinct_equal_gap_reported(tmp_path):
    """(2870,30) IsNot_NotEq#0: with a single-slice corpus the slice
    and overall missing-calibration dicts are equal as values but
    distinct objects, so the slice gap is reported."""
    series = {"i0": _series_entry(score=0.3, calibrated=0.3, cal_id="cal-1")}
    out = _calibrated_run(tmp_path, baseline_series=series)
    slice_gaps = [g for g in out["gaps"] if g.startswith("Missing calibration evidence on slice")]
    assert len(slice_gaps) == 1


def test_perform_same_missing_calibration_not_duplicated(monkeypatch, tmp_path):
    """(2870,12) ReplaceAndWithOr#83 + (2870,30) IsNot_Eq#0: when a
    slice's missing-calibration dict IS the overall one (same object),
    the slice gap is deduplicated (exactly one gap line)."""
    import textforensics.probe_runs as pr

    missing = {
        "reason": "baseline_ece unavailable: only 1 of 3 labelled items",
        "n_matched": 1,
        "n_labelled": 3,
        "missing_item_ids": ["i1", "i2"],
    }
    metrics = _tier_metrics()
    metrics["detector_id"] = FAKE_ID
    metrics["slices"]["human-native"]["n"] = 3
    metrics["slices"]["human-short"]["n"] = 0
    metrics["overall"] = {
        "n": 3,
        "flips": None,
        "calibration": {"missing_calibration": missing},
    }
    metrics["slices"]["human-native"]["calibration"] = {"missing_calibration": missing}
    monkeypatch.setattr(pr, "compute_run_metrics", lambda **kwargs: metrics)
    manifest, texts, holdback = _corpus(3)
    out = _perform(manifest, texts, holdback, _FakeDetector({}))
    gap_lines = [g for g in out["gaps"] if g.startswith("Missing calibration evidence")]
    assert len(gap_lines) == 1
