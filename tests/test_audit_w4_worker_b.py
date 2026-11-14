"""W4 Worker B regression tests — S01/S02/S03/S06/S07/S08 (audit wave W4).

All fixtures are synthetic. Expected values come from the audit plan's
acceptance criteria and the stated expected results, not from current
product output. Written red-first against main ``c91672a``.

- S01: U3 run completeness is an invariant against the selected item
  set. An incomplete run never clears demotions, never becomes a
  baseline, and never advances temporal support.
- S02: stale policy instances cannot lower the persisted anti-rollback
  floor (revision 10 cannot go back to revision 1).
- S03: manual/foreign demotions are independent of U3 demotions.
- S06: adapter/provider/model/config/corpus changes are evidence
  epochs; chronology is evaluated before filtering.
- S07: sample floors apply to actual paired observations (n>=50); a
  single human sample cannot cause a detector-wide demotion.
- S08: observatory execution honors an active emergency stop between
  detector calls, via the W1 ``execution_policy`` channel.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import shutil
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest

from textforensics.detectors import DetectorPrediction
from textforensics.emergency_stop import EmergencyStopError, get_sentinel
from textforensics.execution_policy import CancellationToken, ExecutionCancelled
from textforensics.observatory import DriftObservatory
from textforensics.probe_runs import (
    apply_demotions,
    build_run_manifest,
    clear_demotions,
    compute_run_metrics,
    evaluate_tiers,
    load_run_history,
    perform_probe_run,
    resolve_baseline,
    summarize_longitudinal,
    validate_run_manifest,
)
from textforensics.validation import (
    ValidationRegistry,
    compute_signature,
    effective_status,
    load_validation_registry,
)

HEX64 = "a" * 64
HEX64_B = "b" * 64
DETECTOR_ID = "test/stub-detector"


# ---------------------------------------------------------------------------
# Shared synthetic builders
# ---------------------------------------------------------------------------


def _rec(item_id, *, score, verdict):
    return {
        "sample_id": item_id,
        "score": score,
        "verdict": verdict,
        "calibrated_ai_probability": None,
        "calibration_id": None,
    }


def _complete(*, selected=50, attempted=50, succeeded=50, abstained=0, failed=0):
    return {
        "selected": selected,
        "attempted": attempted,
        "succeeded": succeeded,
        "abstained": abstained,
        "failed": failed,
        "is_complete": attempted == selected,
        "support_eligible": attempted == selected and failed == 0 and succeeded == selected,
        "failed_item_ids": [],
        "missing_item_ids": [],
        "abstained_item_ids": [],
    }


def _history_run(
    run_id,
    at,
    *,
    baseline=False,
    version="0.1.0",
    alerts=(),
    scope="full",
    provider=None,
    corpus=HEX64,
    completeness=None,
):
    run = {
        "schema": "textforensics.probe-run/v1",
        "run_id": run_id,
        "run_at_utc": at,
        "scope": scope,
        "corpus_version": "1.0.0",
        "corpus_fingerprint": corpus,
        "detector_id": DETECTOR_ID,
        "detector_version": version,
        "provider_metadata": dict(provider or {}),
        "is_baseline": baseline,
        "alerts": list(alerts),
    }
    if completeness is not None:
        run["completeness"] = dict(completeness)
    return run


def _registry_copy(tmp_path) -> Path:
    source = Path(__file__).resolve().parent.parent / "docs" / "validation" / "registry.json"
    target = tmp_path / "registry.json"
    shutil.copy(source, target)
    return target


def _corpus(n_items, *, slices=("human-native",)):
    items, texts, holdback = [], {}, {}
    for i in range(n_items):
        item_id = f"item-{i:03d}"
        text = f"ITEM-{i:03d} probe text number {i}. " + "lorem ipsum dolor sit amet. " * 12
        items.append(
            {
                "item_id": item_id,
                "slice": slices[i % len(slices)],
                "content_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            }
        )
        texts[item_id] = text
        holdback[item_id] = {"label": 0}
    manifest = {
        "format": "textforensics.probe-corpus/v1",
        "version": "1.0.0",
        "created_at_utc": "2026-11-07T00:00:00Z",
        "items": items,
        "items_sha256": hashlib.sha256(
            json.dumps(items, sort_keys=True).encode("utf-8")
        ).hexdigest(),
    }
    return manifest, texts, holdback


class _FailingDetector:
    """Scores item 0 only; raises on every other item."""

    detector_id = DETECTOR_ID
    detector_version = "0.1.0"
    detector_family = "stub"

    def detect(self, text: str) -> DetectorPrediction:
        if text.startswith("ITEM-000 "):
            return DetectorPrediction(
                schema="textforensics.detector-result/v1",
                detector_id=self.detector_id,
                detector_version=self.detector_version,
                detector_family=self.detector_family,
                execution="local",
                score=0.2,
                score_semantics="stub",
                verdict="human_like",
                threshold=0.68,
            )
        raise RuntimeError("synthetic detector failure")


class _CleanDetector:
    """Scores every item human_like."""

    detector_id = DETECTOR_ID
    detector_version = "0.1.0"
    detector_family = "stub"

    def __init__(self, *, provider_version=None, version="0.1.0"):
        self.provider_version = provider_version
        self.detector_version = version

    def detect(self, text: str) -> DetectorPrediction:
        return DetectorPrediction(
            schema="textforensics.detector-result/v1",
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            detector_family=self.detector_family,
            execution="local",
            score=0.2,
            score_semantics="stub",
            verdict="human_like",
            threshold=0.68,
        )


# ---------------------------------------------------------------------------
# S01 — run completeness invariant
# ---------------------------------------------------------------------------


class TestS01RunCompleteness:
    def test_400_item_399_failure_run_clears_nothing(self, tmp_path):
        """The audit's exact shape: 400 selected, 399 failed, twice."""
        manifest, texts, holdback = _corpus(400)
        registry_path = _registry_copy(tmp_path)
        registry = load_validation_registry(registry_path)
        record = registry.records[0]
        detector = _FailingDetector()
        detector.detector_id = record.detector_id
        apply_demotions(
            registry_path=registry_path,
            detector_id=record.detector_id,
            run_id="run-pre",
            alerts=[{"tier": 1, "rule": "flip_rate"}],
        )
        assert (
            load_validation_registry(registry_path).record(record.record_id).limits.demoted_by
            is not None
        )
        runs_dir = tmp_path / "runs"
        for day in (1, 2):
            run = perform_probe_run(
                manifest=manifest,
                texts=texts,
                holdback_loader=lambda: holdback,
                detector=detector,
                scope="full",
                runs_dir=runs_dir,
                registry_path=registry_path,
                run_at=datetime(2026, 11, day, tzinfo=UTC),
            )
            assert run["completeness"]["selected"] == 400
            assert run["completeness"]["attempted"] == 400
            assert run["completeness"]["succeeded"] == 1
            assert run["completeness"]["failed"] == 399
            assert run["completeness"]["is_complete"] is True
            assert run["completeness"]["support_eligible"] is False
            assert len(run["completeness"]["failed_item_ids"]) == 399
            assert run["completeness"]["missing_item_ids"] == []
            assert run["is_baseline"] is False
            assert run["demotions_cleared"] == {
                "cleared_record_ids": [],
                "reason": None,
                "gap": (
                    "run is incomplete: 1 of 400 selected items scored "
                    "successfully (399 failed, 0 abstained, 0 missing); "
                    "demotions are retained."
                ),
            }
            validate_run_manifest(run)
        after = load_validation_registry(registry_path).record(record.record_id)
        assert after.limits.demoted_by is not None
        assert after.limits.demoted_by.startswith("U3 probe run run-pre")
        history = load_run_history(runs_dir)
        summary = summarize_longitudinal(
            history,
            detector_id=record.detector_id,
            detector_version="0.1.0",
            corpus_fingerprint=manifest["items_sha256"],
        )
        assert summary["consecutive_clean_full_runs"] == 0
        assert summary["temporal_support"] is False

    def test_small_incomplete_run_clears_nothing(self, tmp_path):
        manifest, texts, holdback = _corpus(8)
        registry_path = _registry_copy(tmp_path)
        registry = load_validation_registry(registry_path)
        record = registry.records[0]
        detector = _FailingDetector()
        detector.detector_id = record.detector_id
        apply_demotions(
            registry_path=registry_path,
            detector_id=record.detector_id,
            run_id="run-pre",
            alerts=[{"tier": 1, "rule": "flip_rate"}],
        )
        run = perform_probe_run(
            manifest=manifest,
            texts=texts,
            holdback_loader=lambda: holdback,
            detector=detector,
            scope="full",
            runs_dir=tmp_path / "runs",
            registry_path=registry_path,
            run_at=datetime(2026, 11, 1, tzinfo=UTC),
        )
        assert run["completeness"]["selected"] == 8
        assert run["completeness"]["succeeded"] == 1
        assert run["completeness"]["failed"] == 7
        assert run["completeness"]["support_eligible"] is False
        assert run["demotions_cleared"]["cleared_record_ids"] == []
        assert (
            load_validation_registry(registry_path).record(record.record_id).limits.demoted_by
            is not None
        )

    def test_genuinely_complete_clean_run_still_clears_and_supports(self, tmp_path):
        manifest, texts, holdback = _corpus(8)
        registry_path = _registry_copy(tmp_path)
        registry = load_validation_registry(registry_path)
        record = registry.records[0]
        detector = _CleanDetector()
        detector.detector_id = record.detector_id
        apply_demotions(
            registry_path=registry_path,
            detector_id=record.detector_id,
            run_id="run-pre",
            alerts=[{"tier": 1, "rule": "flip_rate"}],
        )
        runs_dir = tmp_path / "runs"
        for day in (1, 2):
            run = perform_probe_run(
                manifest=manifest,
                texts=texts,
                holdback_loader=lambda: holdback,
                detector=detector,
                scope="full",
                runs_dir=runs_dir,
                registry_path=registry_path,
                run_at=datetime(2026, 11, day, tzinfo=UTC),
            )
            assert run["completeness"]["support_eligible"] is True
        assert (
            load_validation_registry(registry_path).record(record.record_id).limits.demoted_by
            is None
        )
        summary = summarize_longitudinal(
            load_run_history(runs_dir),
            detector_id=record.detector_id,
            detector_version="0.1.0",
            corpus_fingerprint=manifest["items_sha256"],
        )
        assert summary["consecutive_clean_full_runs"] == 2
        assert summary["temporal_support"] is True

    def test_abstained_items_make_run_incomplete(self, tmp_path):
        """An abstention is not a success: it blocks clearing/support."""
        manifest, texts, holdback = _corpus(8)
        registry_path = _registry_copy(tmp_path)
        registry = load_validation_registry(registry_path)
        record = registry.records[0]

        class _AbstainingDetector(_CleanDetector):
            def detect(self, text: str) -> DetectorPrediction:
                prediction = super().detect(text)
                if text.startswith("ITEM-000 "):
                    return dataclasses.replace(prediction, verdict="abstain")
                return prediction

        detector = _AbstainingDetector()
        detector.detector_id = record.detector_id
        apply_demotions(
            registry_path=registry_path,
            detector_id=record.detector_id,
            run_id="run-pre",
            alerts=[{"tier": 1, "rule": "flip_rate"}],
        )
        run = perform_probe_run(
            manifest=manifest,
            texts=texts,
            holdback_loader=lambda: holdback,
            detector=detector,
            scope="full",
            runs_dir=tmp_path / "runs",
            registry_path=registry_path,
            run_at=datetime(2026, 11, 1, tzinfo=UTC),
        )
        assert run["completeness"]["abstained"] == 1
        assert run["completeness"]["support_eligible"] is False
        assert run["demotions_cleared"]["cleared_record_ids"] == []
        assert (
            load_validation_registry(registry_path).record(record.record_id).limits.demoted_by
            is not None
        )

    def test_resolve_baseline_skips_incomplete_baseline(self):
        incomplete = _history_run(
            "r1",
            "2026-11-01T00:00:00+00:00",
            baseline=True,
            completeness=_complete(selected=400, attempted=400, succeeded=1, failed=399),
        )
        assert (
            resolve_baseline(
                [incomplete],
                detector_id=DETECTOR_ID,
                detector_version="0.1.0",
                corpus_fingerprint=HEX64,
            )
            is None
        )
        complete = _history_run(
            "r1",
            "2026-11-01T00:00:00+00:00",
            baseline=True,
            completeness=_complete(selected=50),
        )
        assert (
            resolve_baseline(
                [complete],
                detector_id=DETECTOR_ID,
                detector_version="0.1.0",
                corpus_fingerprint=HEX64,
            )["run_id"]
            == "r1"
        )

    def test_manifest_without_completeness_is_not_baseline_eligible(self):
        legacy = _history_run("r1", "2026-11-01T00:00:00+00:00", baseline=True)
        assert "completeness" not in legacy
        assert (
            resolve_baseline(
                [legacy],
                detector_id=DETECTOR_ID,
                detector_version="0.1.0",
                corpus_fingerprint=HEX64,
            )
            is None
        )

    def test_build_run_manifest_validates_completeness_partition(self):
        with pytest.raises(Exception, match="completeness"):
            build_run_manifest(
                scope="full",
                corpus_version="1.0.0",
                corpus_fingerprint=HEX64,
                corpus_manifest_sha256=HEX64_B,
                detector_id=DETECTOR_ID,
                detector_version="0.1.0",
                baseline_run_id=None,
                is_baseline=True,
                previous_run_id=None,
                metrics={"detector_id": DETECTOR_ID},
                alerts=[],
                breaches=[],
                completeness={
                    "selected": 10,
                    "attempted": 9,
                    "succeeded": 9,
                    "abstained": 1,
                    "failed": 0,
                    "is_complete": True,
                    "support_eligible": False,
                },
            )


# ---------------------------------------------------------------------------
# S02 — stale policy floor
# ---------------------------------------------------------------------------


class TestS02StalePolicyFloor:
    def _floor(self, tmp_path, name):
        from textforensics.policy import PolicyRevisionFloor

        state_path = tmp_path / f"{name}.enc"
        key_path = tmp_path / f"{name}.key"
        return PolicyRevisionFloor(state_path=state_path, key_path=key_path), state_path, key_path

    def _policy(self, revision):
        from textforensics.policy import EnterprisePolicy, compute_policy_digest

        draft = EnterprisePolicy(revision=revision, digest="", settings={}, rules=[])
        return EnterprisePolicy(
            revision=revision, digest=compute_policy_digest(draft), settings={}, rules=[]
        )

    def test_stale_instance_cannot_lower_floor_10_to_1(self, tmp_path):
        floor_a, state_path, key_path = self._floor(tmp_path, "a")
        from textforensics.policy import PolicyRevisionFloor

        floor_b = PolicyRevisionFloor(state_path=state_path, key_path=key_path)
        floor_a.advance_floor(self._policy(10))
        assert PolicyRevisionFloor(state_path=state_path, key_path=key_path).floor_revision == 10
        # Stale B loaded the floor at 0; it must now see the fresh floor.
        rejections = floor_b.check_policy(self._policy(1))
        assert rejections, "stale check of revision 1 against floor 10 must reject"
        assert any("ROLLBACK" in r for r in rejections)
        floor_b.advance_floor(self._policy(1))
        fresh = PolicyRevisionFloor(state_path=state_path, key_path=key_path)
        assert fresh.floor_revision == 10

    def test_check_and_advance_is_one_transaction(self, tmp_path):
        floor_a, state_path, key_path = self._floor(tmp_path, "b")
        from textforensics.policy import PolicyRevisionFloor

        floor_b = PolicyRevisionFloor(state_path=state_path, key_path=key_path)
        floor_a.advance_floor(self._policy(10))
        assert floor_b.check_and_advance(self._policy(1)) != []
        assert PolicyRevisionFloor(state_path=state_path, key_path=key_path).floor_revision == 10
        assert floor_b.check_and_advance(self._policy(11)) == []
        assert PolicyRevisionFloor(state_path=state_path, key_path=key_path).floor_revision == 11

    def test_same_revision_conflicting_digest_rejected_after_reload(self, tmp_path):
        floor_a, state_path, key_path = self._floor(tmp_path, "c")
        from textforensics.policy import PolicyRevisionFloor

        floor_b = PolicyRevisionFloor(state_path=state_path, key_path=key_path)
        floor_a.advance_floor(self._policy(10))
        other = self._policy(10)
        other = dataclasses.replace(other, digest="0" * 64)
        assert floor_b.check_policy(other) != []
        assert any("DRIFT" in r for r in floor_b.check_policy(other))

    def test_concurrent_first_key_creation_shares_key_material(self, tmp_path):
        from textforensics.policy import PolicyRevisionFloor

        state_path = tmp_path / "race.enc"
        key_path = tmp_path / "race.key"
        errors: list[BaseException] = []
        floors: list[PolicyRevisionFloor] = []

        def _make(revision):
            try:
                floor = PolicyRevisionFloor(state_path=state_path, key_path=key_path)
                floor.advance_floor(self._policy(revision))
                floors.append(floor)
            except BaseException as exc:  # noqa: BLE001 - collected, asserted below
                errors.append(exc)

        threads = [
            threading.Thread(target=_make, args=(5,)),
            threading.Thread(target=_make, args=(9,)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert errors == []
        assert len(floors) == 2
        assert floors[0].get_key() == floors[1].get_key()
        fresh = PolicyRevisionFloor(state_path=state_path, key_path=key_path)
        assert fresh.floor_revision == 9

    def test_failed_persistence_leaves_prior_state_recoverable(self, tmp_path, monkeypatch):
        floor, state_path, key_path = self._floor(tmp_path, "d")
        from textforensics.policy import PolicyRevisionFloor

        floor.advance_floor(self._policy(10))
        assert PolicyRevisionFloor(state_path=state_path, key_path=key_path).floor_revision == 10

        def _boom(*args, **kwargs):
            raise OSError("synthetic persistence failure")

        monkeypatch.setattr(PolicyRevisionFloor, "_atomic_write_bytes", staticmethod(_boom))
        with pytest.raises(OSError, match="synthetic persistence failure"):
            floor.advance_floor(self._policy(11))
        assert floor.floor_revision == 10
        # The durable state on disk is still the recoverable floor 10.
        fresh = PolicyRevisionFloor(state_path=state_path, key_path=key_path)
        assert fresh.floor_revision == 10

    def test_engine_load_policy_uses_one_transaction(self, tmp_path):
        from textforensics.policy import EnterprisePolicyEngine, PolicyRevisionFloor

        state_path = tmp_path / "eng.enc"
        key_path = tmp_path / "eng.key"
        floor = PolicyRevisionFloor(state_path=state_path, key_path=key_path)
        floor.advance_floor(self._policy(10))
        stale_engine = EnterprisePolicyEngine(
            floor=PolicyRevisionFloor(state_path=state_path, key_path=key_path)
        )
        # The stale engine's floor snapshot predates nothing here, but a
        # second engine loading revision 1 after floor 10 must reject.
        assert stale_engine.load_policy({"revision": 1, "settings": {}, "rules": []}) != []
        assert PolicyRevisionFloor(state_path=state_path, key_path=key_path).floor_revision == 10


# ---------------------------------------------------------------------------
# S03 — foreign/manual demotions stay independent
# ---------------------------------------------------------------------------


class TestS03ForeignDemotionPreserved:
    def _foreign_registry(self, tmp_path, reason="manual review 2026-11-01"):
        registry_path = _registry_copy(tmp_path)
        registry = load_validation_registry(registry_path)
        record = registry.records[0]
        foreign_limits = dataclasses.replace(record.limits, demoted_by=reason)
        unsigned = record.to_dict()
        unsigned["limits"] = foreign_limits.to_dict()
        unsigned.pop("signature", None)
        foreign = dataclasses.replace(
            record, limits=foreign_limits, signature=compute_signature(unsigned)
        )
        ValidationRegistry(
            [foreign if r.record_id == record.record_id else r for r in registry.records],
            created_at_utc=registry.created_at_utc,
        ).save(registry_path)
        return registry_path, record

    def test_manual_then_u3_then_clean_keeps_manual(self, tmp_path):
        registry_path, record = self._foreign_registry(tmp_path)
        apply_demotions(
            registry_path=registry_path,
            detector_id=record.detector_id,
            run_id="run-1",
            alerts=[{"tier": 1, "rule": "flip_rate"}],
        )
        mid = load_validation_registry(registry_path).record(record.record_id)
        assert "manual review 2026-11-01" in (mid.limits.demoted_by or "")
        assert "U3 probe run run-1" in (mid.limits.demoted_by or "")
        cleared = clear_demotions(
            registry_path=registry_path, detector_id=record.detector_id, run_id="run-2"
        )
        assert record.record_id in cleared["cleared_record_ids"]
        after = load_validation_registry(registry_path).record(record.record_id)
        assert after.limits.demoted_by == "manual review 2026-11-01"
        assert (
            effective_status(
                after, detector_version=record.detector_version, now="2026-11-07T00:00:00+00:00"
            )
            == "stale"
        )

    def test_u3_then_u3_keeps_auditable_history(self, tmp_path):
        registry_path = _registry_copy(tmp_path)
        registry = load_validation_registry(registry_path)
        record = registry.records[0]
        apply_demotions(
            registry_path=registry_path,
            detector_id=record.detector_id,
            run_id="run-1",
            alerts=[{"tier": 1, "rule": "flip_rate"}],
        )
        apply_demotions(
            registry_path=registry_path,
            detector_id=record.detector_id,
            run_id="run-2",
            alerts=[{"tier": 1, "rule": "human_fpr_cap"}],
        )
        after = load_validation_registry(registry_path).record(record.record_id)
        assert "U3 probe run run-1" in (after.limits.demoted_by or "")
        assert "U3 probe run run-2" in (after.limits.demoted_by or "")
        cleared = clear_demotions(
            registry_path=registry_path, detector_id=record.detector_id, run_id="run-3"
        )
        assert record.record_id in cleared["cleared_record_ids"]
        assert (
            load_validation_registry(registry_path).record(record.record_id).limits.demoted_by
            is None
        )

    def test_foreign_reason_is_never_rewritten_to_look_u3(self, tmp_path):
        registry_path, record = self._foreign_registry(
            tmp_path, reason="manual review: U3 probe run mentioned in prose"
        )
        apply_demotions(
            registry_path=registry_path,
            detector_id=record.detector_id,
            run_id="run-1",
            alerts=[{"tier": 1, "rule": "flip_rate"}],
        )
        mid = load_validation_registry(registry_path).record(record.record_id)
        assert (mid.limits.demoted_by or "").startswith(
            "manual review: U3 probe run mentioned in prose"
        )


# ---------------------------------------------------------------------------
# S06 — evidence epochs + chronology before filtering
# ---------------------------------------------------------------------------


class TestS06TemporalEpochs:
    def test_streak_breaks_across_version_change(self):
        history = [
            _history_run("r1", "2026-11-01T00:00:00+00:00", completeness=_complete()),
            _history_run(
                "r2", "2026-11-02T00:00:00+00:00", version="0.2.0", completeness=_complete()
            ),
            _history_run("r3", "2026-11-03T00:00:00+00:00", completeness=_complete()),
        ]
        summary = summarize_longitudinal(
            history, detector_id=DETECTOR_ID, detector_version="0.1.0", corpus_fingerprint=HEX64
        )
        assert summary["temporal_support"] is False
        assert summary["consecutive_clean_full_runs"] == 1
        assert summary["clean_full_run_ids"] == ["r3"]

    def test_total_runs_counts_whole_epoch_despite_in_epoch_break(self):
        # A streak break INSIDE the epoch (most recent run incomplete)
        # must not shrink total_runs: the epoch is r1 + r2, and the
        # break is reported separately in streak_break.
        history = [
            _history_run("r1", "2026-11-01T00:00:00+00:00", completeness=_complete()),
            _history_run(
                "r2",
                "2026-11-02T00:00:00+00:00",
                completeness=_complete(failed=1, succeeded=49),
            ),
        ]
        summary = summarize_longitudinal(
            history, detector_id=DETECTOR_ID, detector_version="0.1.0", corpus_fingerprint=HEX64
        )
        assert summary["total_runs"] == 2
        assert summary["consecutive_clean_full_runs"] == 0
        assert summary["temporal_support"] is False
        assert summary["streak_break"] == {"run_id": "r2", "reason": "incomplete_run"}

    def test_latest_partial_breach_breaks_streak(self):
        history = [
            _history_run("r1", "2026-11-01T00:00:00+00:00", completeness=_complete()),
            _history_run("r2", "2026-11-02T00:00:00+00:00", completeness=_complete()),
            _history_run(
                "r3",
                "2026-11-03T00:00:00+00:00",
                scope="monthly-attacked",
                alerts=[{"tier": 1, "rule": "flip_rate"}],
                completeness=_complete(),
            ),
        ]
        summary = summarize_longitudinal(
            history, detector_id=DETECTOR_ID, detector_version="0.1.0", corpus_fingerprint=HEX64
        )
        assert summary["temporal_support"] is False
        assert summary["consecutive_clean_full_runs"] == 0

    def test_clean_partial_run_does_not_break_streak(self):
        history = [
            _history_run("r1", "2026-11-01T00:00:00+00:00", completeness=_complete()),
            _history_run(
                "r2",
                "2026-11-02T00:00:00+00:00",
                scope="monthly-attacked",
                completeness=_complete(),
            ),
            _history_run("r3", "2026-11-03T00:00:00+00:00", completeness=_complete()),
        ]
        summary = summarize_longitudinal(
            history, detector_id=DETECTOR_ID, detector_version="0.1.0", corpus_fingerprint=HEX64
        )
        assert summary["consecutive_clean_full_runs"] == 2
        assert summary["temporal_support"] is True

    def test_provider_change_breaks_epoch(self):
        history = [
            _history_run(
                "r1",
                "2026-11-01T00:00:00+00:00",
                provider={DETECTOR_ID: "p1"},
                completeness=_complete(),
            ),
            _history_run(
                "r2",
                "2026-11-02T00:00:00+00:00",
                provider={DETECTOR_ID: "p2"},
                completeness=_complete(),
            ),
        ]
        summary = summarize_longitudinal(
            history, detector_id=DETECTOR_ID, detector_version="0.1.0", corpus_fingerprint=HEX64
        )
        assert summary["temporal_support"] is False
        assert summary["consecutive_clean_full_runs"] == 1

    def test_corpus_change_breaks_epoch(self):
        history = [
            _history_run("r1", "2026-11-01T00:00:00+00:00", completeness=_complete()),
            _history_run(
                "r2", "2026-11-02T00:00:00+00:00", corpus=HEX64_B, completeness=_complete()
            ),
            _history_run("r3", "2026-11-03T00:00:00+00:00", completeness=_complete()),
        ]
        summary = summarize_longitudinal(
            history, detector_id=DETECTOR_ID, detector_version="0.1.0", corpus_fingerprint=HEX64
        )
        assert summary["temporal_support"] is False
        assert summary["consecutive_clean_full_runs"] == 1

    def test_watch_expires_after_two_clean_full_runs(self):
        history = [
            _history_run(
                "r1",
                "2026-11-01T00:00:00+00:00",
                alerts=[{"tier": 2, "rule": "drift_statistic"}],
                completeness=_complete(),
            ),
            _history_run("r2", "2026-11-02T00:00:00+00:00", completeness=_complete()),
            _history_run("r3", "2026-11-03T00:00:00+00:00", completeness=_complete()),
        ]
        summary = summarize_longitudinal(
            history, detector_id=DETECTOR_ID, detector_version="0.1.0", corpus_fingerprint=HEX64
        )
        assert summary["watch"] is None
        assert summary["temporal_support"] is True

    def test_watch_survives_one_clean_full_run(self):
        history = [
            _history_run(
                "r1",
                "2026-11-01T00:00:00+00:00",
                alerts=[{"tier": 2, "rule": "drift_statistic"}],
                completeness=_complete(),
            ),
            _history_run("r2", "2026-11-02T00:00:00+00:00", completeness=_complete()),
        ]
        summary = summarize_longitudinal(
            history, detector_id=DETECTOR_ID, detector_version="0.1.0", corpus_fingerprint=HEX64
        )
        assert summary["watch"] is not None
        assert summary["watch"]["run_id"] == "r1"

    def test_resolve_baseline_keys_on_provider(self):
        history = [
            _history_run(
                "r1",
                "2026-11-01T00:00:00+00:00",
                baseline=True,
                provider={DETECTOR_ID: "p1"},
                completeness=_complete(),
            ),
        ]
        assert (
            resolve_baseline(
                history,
                detector_id=DETECTOR_ID,
                detector_version="0.1.0",
                corpus_fingerprint=HEX64,
                provider_metadata={DETECTOR_ID: "p2"},
            )
            is None
        )
        assert (
            resolve_baseline(
                history,
                detector_id=DETECTOR_ID,
                detector_version="0.1.0",
                corpus_fingerprint=HEX64,
                provider_metadata={DETECTOR_ID: "p1"},
            )["run_id"]
            == "r1"
        )

    def test_provider_change_rebaselines_in_perform_probe_run(self, tmp_path):
        manifest, texts, holdback = _corpus(8)
        runs_dir = tmp_path / "runs"
        first = perform_probe_run(
            manifest=manifest,
            texts=texts,
            holdback_loader=lambda: holdback,
            detector=_CleanDetector(provider_version="p1"),
            scope="full",
            runs_dir=runs_dir,
            registry_path=None,
            run_at=datetime(2026, 11, 1, tzinfo=UTC),
        )
        assert first["is_baseline"] is True
        second = perform_probe_run(
            manifest=manifest,
            texts=texts,
            holdback_loader=lambda: holdback,
            detector=_CleanDetector(provider_version="p2"),
            scope="full",
            runs_dir=runs_dir,
            registry_path=None,
            run_at=datetime(2026, 11, 2, tzinfo=UTC),
        )
        assert second["is_baseline"] is True
        assert second["rebaselined_from"] == first["run_id"]
        assert second["baseline_run_id"] == second["run_id"]


# ---------------------------------------------------------------------------
# S07 — sample floors on actual paired observations
# ---------------------------------------------------------------------------


class TestS07SampleFloors:
    def _one_sample_metrics(self):
        prev = [_rec("h-000", score=0.3, verdict="human_like")]
        curr = [_rec("h-000", score=0.9, verdict="ai_like")]
        return compute_run_metrics(
            current_records=curr,
            baseline_records=prev,
            previous_records=prev,
            labels={"h-000": 0},
            slices={"h-000": "human-native"},
            detector_id="d",
        )

    def test_one_sample_flip_does_not_demote(self):
        result = evaluate_tiers(metrics=self._one_sample_metrics(), detector_version="0.1.0")
        assert result["demote"] is False
        assert not any(a["rule"] == "flip_rate" for a in result["alerts"])

    def test_current_50_paired_1_does_not_demote(self):
        prev = [_rec("h-000", score=0.3, verdict="human_like")]
        curr = [
            _rec(
                f"h-{i:03d}",
                score=0.9 if i == 0 else 0.3,
                verdict="ai_like" if i == 0 else "human_like",
            )
            for i in range(50)
        ]
        metrics = compute_run_metrics(
            current_records=curr,
            baseline_records=prev,
            previous_records=prev,
            labels={f"h-{i:03d}": 0 for i in range(50)},
            slices={f"h-{i:03d}": "human-native" for i in range(50)},
            detector_id="d",
        )
        assert metrics["slices"]["human-native"]["flips"]["n_human_paired"] == 1
        result = evaluate_tiers(metrics=metrics, detector_version="0.1.0")
        assert result["demote"] is False

    def test_version_change_on_one_sample_run_does_not_demote(self):
        metrics = self._one_sample_metrics()
        result = evaluate_tiers(
            metrics=metrics,
            detector_version="0.2.0",
            previous_detector_version="0.1.0",
            previous_run_at="2026-11-01T00:00:00+00:00",
            run_at="2026-11-09T00:00:00+00:00",
        )
        assert result["demote"] is False
        assert any(
            a["tier"] == 2 and a["rule"] == "version_change_no_probe_run" for a in result["alerts"]
        )
        assert result["watch"] is True

    def test_provider_change_on_one_sample_run_does_not_demote(self):
        metrics = self._one_sample_metrics()
        result = evaluate_tiers(
            metrics=metrics,
            detector_version="0.1.0",
            previous_detector_version="0.1.0",
            previous_provider_metadata={"d": "p1"},
            provider_metadata={"d": "p2"},
            previous_run_at="2026-11-01T00:00:00+00:00",
            run_at="2026-11-09T00:00:00+00:00",
        )
        assert result["demote"] is False
        assert any(
            a["tier"] == 2 and a["rule"] == "version_change_no_probe_run" for a in result["alerts"]
        )

    def test_version_change_on_adequately_sampled_run_still_demotes(self):
        prev = [_rec(f"h-{i:03d}", score=0.3, verdict="human_like") for i in range(60)]
        curr = [_rec(f"h-{i:03d}", score=0.3, verdict="human_like") for i in range(60)]
        metrics = compute_run_metrics(
            current_records=curr,
            baseline_records=prev,
            previous_records=prev,
            labels={f"h-{i:03d}": 0 for i in range(60)},
            slices={f"h-{i:03d}": "human-native" for i in range(60)},
            detector_id="d",
        )
        result = evaluate_tiers(
            metrics=metrics,
            detector_version="0.2.0",
            previous_detector_version="0.1.0",
            previous_run_at="2026-11-01T00:00:00+00:00",
            run_at="2026-11-09T00:00:00+00:00",
        )
        assert result["demote"] is True
        assert any(
            a["tier"] == 1 and a["rule"] == "version_change_no_probe_run" for a in result["alerts"]
        )

    def test_one_sample_e2e_version_change_does_not_demote(self, tmp_path):
        manifest, texts, holdback = _corpus(1)
        registry_path = _registry_copy(tmp_path)
        registry = load_validation_registry(registry_path)
        record = registry.records[0]
        runs_dir = tmp_path / "runs"
        first = _CleanDetector(version="0.1.0")
        first.detector_id = record.detector_id
        perform_probe_run(
            manifest=manifest,
            texts=texts,
            holdback_loader=lambda: holdback,
            detector=first,
            scope="full",
            runs_dir=runs_dir,
            registry_path=registry_path,
            run_at=datetime(2026, 11, 1, tzinfo=UTC),
        )
        second = _CleanDetector(version="0.2.0")
        second.detector_id = record.detector_id
        run2 = perform_probe_run(
            manifest=manifest,
            texts=texts,
            holdback_loader=lambda: holdback,
            detector=second,
            scope="full",
            runs_dir=runs_dir,
            registry_path=registry_path,
            run_at=datetime(2026, 11, 9, tzinfo=UTC),
        )
        assert run2["demotions_applied"] == {}
        assert run2["alerts"] and not any(a["tier"] == 1 for a in run2["alerts"])
        assert (
            load_validation_registry(registry_path).record(record.record_id).limits.demoted_by
            is None
        )


# ---------------------------------------------------------------------------
# S08 — emergency stop honored by the observatory
# ---------------------------------------------------------------------------


class _CountingDetector:
    detector_id = "test/counting"
    detector_version = "0.1.0"
    detector_family = "stub"

    def __init__(self):
        self.calls = 0

    def detect(self, text: str) -> DetectorPrediction:
        self.calls += 1
        return DetectorPrediction(
            schema="textforensics.detector-result/v1",
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            detector_family=self.detector_family,
            execution="local",
            score=0.2,
            score_semantics="stub",
            verdict="human_like",
            threshold=0.5,
        )


def _observatory():
    return DriftObservatory(
        corpus={
            "schema": "textforensics.drift-corpus/v1",
            "samples": [
                {
                    "id": "s1",
                    "text": "hello world this is a probe sentence for testing purposes only",
                },
                {
                    "id": "s2",
                    "text": "another probe sentence with enough words to pass checks here",
                },
                {
                    "id": "s3",
                    "text": "a third probe sentence with enough words to pass checks here",
                },
            ],
        }
    )


@pytest.fixture
def _reset_singleton():
    sentinel = get_sentinel()
    previous_path = sentinel._path
    previous_env = os.environ.get("TEXTFORENSICS_EMERGENCY_STOP")
    yield sentinel
    sentinel._path = previous_path
    if previous_env is None:
        os.environ.pop("TEXTFORENSICS_EMERGENCY_STOP", None)
    else:
        os.environ["TEXTFORENSICS_EMERGENCY_STOP"] = previous_env


class TestS08EmergencyStop:
    def test_configured_sentinel_blocks_before_first_call(self, tmp_path, _reset_singleton):
        stop_path = tmp_path / "stop"
        sentinel = _reset_singleton
        sentinel.configure(stop_path)
        sentinel.activate()
        detector = _CountingDetector()
        with pytest.raises(EmergencyStopError):
            _observatory().take_snapshot(detectors=[detector])
        assert detector.calls == 0

    def test_configured_sentinel_activated_mid_run_stops_after_first_call(
        self, tmp_path, _reset_singleton
    ):
        stop_path = tmp_path / "stop"
        sentinel = _reset_singleton
        sentinel.configure(stop_path)

        class _ActivatingDetector(_CountingDetector):
            def detect(self, text: str) -> DetectorPrediction:
                prediction = super().detect(text)
                if self.calls == 1:
                    sentinel.activate()
                return prediction

        detector = _ActivatingDetector()
        with pytest.raises(EmergencyStopError):
            _observatory().take_snapshot(detectors=[detector])
        assert detector.calls == 1

    def test_cancelled_token_blocks_before_first_call(self):
        token = CancellationToken()
        token.cancel()
        detector = _CountingDetector()
        with pytest.raises(ExecutionCancelled):
            _observatory().take_snapshot(detectors=[detector], cancellation=token)
        assert detector.calls == 0

    def test_token_cancelled_mid_run_stops_after_first_call(self):
        token = CancellationToken()

        class _CancellingDetector(_CountingDetector):
            def detect(self, text: str) -> DetectorPrediction:
                prediction = super().detect(text)
                if self.calls == 1:
                    token.cancel()
                return prediction

        detector = _CancellingDetector()
        with pytest.raises(ExecutionCancelled):
            _observatory().take_snapshot(detectors=[detector], cancellation=token)
        assert detector.calls == 1

    def test_stopped_probe_run_saves_nothing_and_clears_nothing(self, tmp_path):
        manifest, texts, holdback = _corpus(8)
        registry_path = _registry_copy(tmp_path)
        registry = load_validation_registry(registry_path)
        record = registry.records[0]
        detector = _CleanDetector()
        detector.detector_id = record.detector_id
        apply_demotions(
            registry_path=registry_path,
            detector_id=record.detector_id,
            run_id="run-pre",
            alerts=[{"tier": 1, "rule": "flip_rate"}],
        )
        runs_dir = tmp_path / "runs"
        stop_path = tmp_path / "stop"
        stop_path.write_text("stop\n", encoding="utf-8")
        os.environ["TEXTFORENSICS_EMERGENCY_STOP"] = str(stop_path)
        try:
            with pytest.raises(EmergencyStopError):
                perform_probe_run(
                    manifest=manifest,
                    texts=texts,
                    holdback_loader=lambda: holdback,
                    detector=detector,
                    scope="full",
                    runs_dir=runs_dir,
                    registry_path=registry_path,
                    run_at=datetime(2026, 11, 1, tzinfo=UTC),
                )
        finally:
            del os.environ["TEXTFORENSICS_EMERGENCY_STOP"]
        assert not runs_dir.exists() or list(runs_dir.glob("run-*.json")) == []
        assert (
            load_validation_registry(registry_path).record(record.record_id).limits.demoted_by
            is not None
        )
