"""W5 Worker F kill tests for probe_runs (audit-w5-f).

Kill evidence for the 14 killable runtime survivors in
textforensics.probe_runs (7 more are equivalents; see
hidden_files/audit-w5-f-equiv-reasons-probe_runs.json):

* ``_registry_transaction`` (lines 1713-1716): the restore guard
  ``current != before`` must not rewrite an unmodified registry
  (AddNot on ``path.exists()`` and ``!=`` -> ``is not`` both restore
  when they must not -- killed by spying on atomic_write_bytes);
  restoring to lexicographically SMALLER bytes must happen
  (``!=`` -> ``>`` / ``>=`` both skip the restore); a failing
  restore must raise ProbeRunError, not the raw OSError
  (ExceptionReplacer).
* ``_apply_demotions_inner`` Eq_LtE (line 1751): a tier-0 alert is
  not a Tier-1 alert and must not demote.
* ``_apply_demotions_inner`` / ``_clear_demotions_inner`` reload
  checks (lines 1783, 1851): ``sorted(...) != sorted(...)`` must
  raise when the reloaded registry lost a record. Dropping the
  LARGEST record id kills ``!=`` -> ``>`` (and ``is``); dropping the
  SMALLEST kills ``!=`` -> ``<`` (and ``is``). The reload is mocked
  to return the registry minus one record.
* ``perform_probe_run`` Eq_Gt on the monthly-current-generator scope
  (line 2731): only ai-current-generator items are scored. The W4
  scope test used a single-slice corpus, so the mutant (which scores
  everything) passed it; this test mixes slices.
* ``perform_probe_run`` Eq_GtE on the watches filter (line 2897): a
  Tier-3 alert is not a watch. The tier evaluation is stubbed to
  return a Tier-3 alert (the filter, not the evaluator, is under
  test); the run's watches must stay empty.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

import textforensics.probe_runs as pr
from tests.test_probe_runs import HEX64
from textforensics.detectors import DETECTOR_SCHEMA_V2, DetectorPrediction
from textforensics.probe_runs import (
    ProbeRunError,
    _registry_transaction,
    apply_demotions,
    clear_demotions,
    perform_probe_run,
)
from textforensics.validation import ValidationRegistry, load_validation_registry

FAKE_ID = "textforensics/fake-detector"
FAKE_VERSION = "0.1.0"


def _alert(tier, rule="rule-x", slice_name="human-native"):
    return {
        "tier": tier,
        "rule": rule,
        "slice": slice_name,
        "action": "demote" if tier == 1 else "investigate",
        "detail": f"test alert tier {tier}",
    }


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


def _registry_file(tmp_path, records):
    """Write a registry JSON for the given record dicts (valid signatures)."""
    from textforensics.validation import ValidationRecord, ValidationRegistry

    registry = ValidationRegistry([ValidationRecord.from_dict(r) for r in records])
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(registry.to_dict()), encoding="utf-8")
    return path


class _FakeDetector:
    """A detector whose score/verdict/calibration are keyed by item id."""

    detector_id = FAKE_ID
    detector_version = FAKE_VERSION
    detector_family = "fake"
    execution = "local"

    def __init__(self, by_item, default=(0.1, "human_like", None, None)):
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


def _corpus(items):
    """A probe-corpus manifest + texts + holdback for (item_id, slice, label)."""
    manifest_items = []
    texts = {}
    holdback = {}
    for item_id, slice_name, label in items:
        text = f"probe-{item_id}"
        manifest_items.append(
            {
                "item_id": item_id,
                "slice": slice_name,
                "content_sha256": hashlib.sha256(text.encode()).hexdigest(),
            }
        )
        texts[item_id] = text
        holdback[item_id] = {"label": label}
    manifest = {"version": "1.0.0", "items_sha256": HEX64, "items": manifest_items}
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


# ---------------------------------------------------------------------------
# _registry_transaction
# ---------------------------------------------------------------------------


def test_transaction_does_not_rewrite_unmodified_registry(tmp_path, monkeypatch):
    """An unmodified registry is not rewritten on rollback.

    Kills AddNot (1713: ``path.exists()`` -> ``not path.exists()``)
    and NotEq_IsNot (1714: ``!=`` -> ``is not``): both mutants restore
    (rewrite identical bytes) where the original restores nothing.
    """
    path = tmp_path / "registry.json"
    path.write_bytes(b"bbb")
    calls = []
    real_write = pr.atomic_write_bytes

    def _spy(p, data):
        calls.append((str(p), data))
        return real_write(p, data)

    monkeypatch.setattr(pr, "atomic_write_bytes", _spy)
    with pytest.raises(ValueError, match="boom"), _registry_transaction(path):
        raise ValueError("boom")
    assert calls == []
    assert path.read_bytes() == b"bbb"


def test_transaction_restores_smaller_bytes(tmp_path):
    """A rollback restores bytes that sort below the modified bytes.

    Kills NotEq_Gt / NotEq_GtE (1714): with current=b"aaa" and
    before=b"bbb", ``>`` / ``>=`` are False, so both mutants skip the
    restore and leave the modified bytes in place.
    """
    path = tmp_path / "registry.json"
    path.write_bytes(b"bbb")
    with pytest.raises(ValueError, match="boom"), _registry_transaction(path):
        path.write_bytes(b"aaa")
        raise ValueError("boom")
    assert path.read_bytes() == b"bbb"


def test_transaction_restore_failure_raises_probe_run_error(tmp_path, monkeypatch):
    """A failing restore raises ProbeRunError naming both failures.

    Kills ExceptionReplacer (1716): the mutant lets the raw OSError
    from the restore propagate instead of the ProbeRunError.
    """
    path = tmp_path / "registry.json"
    path.write_bytes(b"bbb")

    def _boom(p, data):
        raise OSError("simulated disk failure")

    monkeypatch.setattr(pr, "atomic_write_bytes", _boom)
    with pytest.raises(ProbeRunError, match="could not be restored"), _registry_transaction(path):
        path.write_bytes(b"aaa")
        raise ValueError("boom")


# ---------------------------------------------------------------------------
# _apply_demotions_inner / _clear_demotions_inner reload checks
# ---------------------------------------------------------------------------


def _reload_missing(monkeypatch, drop_record_id):
    """Mock load_validation_registry: first call real, reload drops a record."""
    real_load = load_validation_registry
    calls = {"n": 0}

    def _mock(path):
        calls["n"] += 1
        registry = real_load(path)
        if calls["n"] == 1:
            return registry
        kept = [r for r in registry.records if r.record_id != drop_record_id]
        return ValidationRegistry(kept, created_at_utc=registry.created_at_utc)

    monkeypatch.setattr(pr, "load_validation_registry", _mock)


def test_apply_demotions_ignores_tier_zero_alert(tmp_path):
    """A tier-0 alert is not a Tier-1 alert and demotes nothing.

    Kills Eq_LtE (1751: ``tier == 1`` -> ``tier <= 1``), which would
    treat a tier-0 alert as Tier-1.
    """
    path = _registry_file(tmp_path, [_seeded_record(0, "det-a", None)])
    result = apply_demotions(
        registry_path=path,
        detector_id="det-a",
        run_id="run-1",
        alerts=[_alert(0)],
    )
    assert result["demoted_record_ids"] == []
    registry = load_validation_registry(path)
    assert registry.records[0].limits.demoted_by is None


def test_apply_demotions_reload_missing_largest_record_raises(tmp_path, monkeypatch):
    """A reload that lost the largest record id must raise.

    Kills NotEq_Gt (1783): ["beemo"] > ["beemo", "mage"] is False, so
    the mutant does not raise; and NotEq_Is: two distinct list objects
    are never identical, so that mutant never raises either.
    """
    path = _registry_file(
        tmp_path,
        [_seeded_record(0, "det-a", None), _seeded_record(1, "det-a", None)],
    )
    _reload_missing(monkeypatch, "evr-20261106-mage-builtin-heuristic")
    with pytest.raises(ProbeRunError, match="reload after demotion"):
        apply_demotions(
            registry_path=path,
            detector_id="det-a",
            run_id="run-1",
            alerts=[_alert(1)],
        )


def test_apply_demotions_reload_missing_smallest_record_raises(tmp_path, monkeypatch):
    """A reload that lost the smallest record id must raise.

    Kills NotEq_Lt (1783): ["mage"] < ["beemo", "mage"] is False, so
    the mutant does not raise; and NotEq_Is (same as above).
    """
    path = _registry_file(
        tmp_path,
        [_seeded_record(0, "det-a", None), _seeded_record(1, "det-a", None)],
    )
    _reload_missing(monkeypatch, "evr-20261106-beemo-builtin-heuristic")
    with pytest.raises(ProbeRunError, match="reload after demotion"):
        apply_demotions(
            registry_path=path,
            detector_id="det-a",
            run_id="run-1",
            alerts=[_alert(1)],
        )


def test_clear_demotions_reload_missing_largest_record_raises(tmp_path, monkeypatch):
    """A reload that lost the largest record id must raise (clearing).

    Kills NotEq_Gt / NotEq_Is (1851), same argument as demotion.
    """
    path = _registry_file(
        tmp_path,
        [
            _seeded_record(0, "det-a", "U3 probe run run-1"),
            _seeded_record(1, "det-a", "U3 probe run run-1"),
        ],
    )
    _reload_missing(monkeypatch, "evr-20261106-mage-builtin-heuristic")
    with pytest.raises(ProbeRunError, match="reload after clearing"):
        clear_demotions(registry_path=path, detector_id="det-a", run_id="run-2")


def test_clear_demotions_reload_missing_smallest_record_raises(tmp_path, monkeypatch):
    """A reload that lost the smallest record id must raise (clearing).

    Kills NotEq_Lt / NotEq_Is (1851), same argument as demotion.
    """
    path = _registry_file(
        tmp_path,
        [
            _seeded_record(0, "det-a", "U3 probe run run-1"),
            _seeded_record(1, "det-a", "U3 probe run run-1"),
        ],
    )
    _reload_missing(monkeypatch, "evr-20261106-beemo-builtin-heuristic")
    with pytest.raises(ProbeRunError, match="reload after clearing"):
        clear_demotions(registry_path=path, detector_id="det-a", run_id="run-2")


# ---------------------------------------------------------------------------
# perform_probe_run scope + watches
# ---------------------------------------------------------------------------


def test_monthly_current_generator_scope_scores_only_its_slice():
    """A monthly-current-generator run scores only ai-current-generator.

    Kills Eq_Gt (2731: ``scope == \"monthly-current-generator\"`` ->
    ``>``): the mutant leaves scope_slices unset, so it scores the
    human-native item too (n==2 instead of 1).
    """
    manifest, texts, holdback = _corpus(
        [("i0", "ai-current-generator", 1), ("i1", "human-native", 0)]
    )
    out = _perform(manifest, texts, holdback, _FakeDetector({}), scope="monthly-current-generator")
    assert out["metrics"]["overall"]["n"] == 1
    assert out["scope"] == "monthly-current-generator"


def test_tier3_alert_is_not_a_watch(monkeypatch):
    """A Tier-3 alert is recorded, not watched.

    Kills Eq_GtE (2897: ``tier == 2`` -> ``tier >= 2``): the mutant
    puts the Tier-3 drift alert in the watches list. The tier
    evaluation is stubbed (the watches filter, not the evaluator, is
    under test).
    """
    tier3 = {
        "tier": 3,
        "rule": "drift_statistic",
        "slice": "human-native",
        "action": "investigate",
        "detail": "Drift statistic breached on 1 run.",
    }

    def _fake_evaluate_tiers(**kwargs):
        return {"alerts": [tier3], "breaches": [], "demote": False, "watch": True}

    monkeypatch.setattr(pr, "evaluate_tiers", _fake_evaluate_tiers)
    manifest, texts, holdback = _corpus([("i0", "human-native", 0)])
    out = _perform(manifest, texts, holdback, _FakeDetector({}))
    assert out["watches"] == []
    assert out["alerts"] == [tier3]
