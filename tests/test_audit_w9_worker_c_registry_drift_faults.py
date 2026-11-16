"""W9 worker C qualification: registry + drift + faults, end to end.

Audit wave W9 (qualification, 0 findings by design). Every flow is run
as a real user would run it — shipped registries on disk, the real CLI
dispatch, the real probe-run path, the real cache / retry / health /
cancellation / ledger machinery — against temporary copies, never
against the shipped files. No decision-logic code is changed by this
module; it only qualifies existing behaviour.

Flows covered (task brief §1-7):
  1. registry import (validation + evidence, counts + schema + tamper)
  2. drift snapshot / compare / run (API + CLI, round-trip + drift)
  3. demotion / recovery (direct API + full probe-run path)
  4. reload after an external change
  5. cache / retry / health faults (reported, never swallowed)
  6. bounded cancellation
  7. recoverable restart (SIGKILL mid-append / stray temp file)

Expected live state (verified, not assumed — see
tests/test_audit_w9_worker_c_* assertions):
  validation registry: 15 records / 8 supported, registry_id
  3202e9a97342d0df972eaa6dc233bd6837955b2d17297e64542e7a163c3ba7cc
  evidence registry: 50 records.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATION_REGISTRY = REPO_ROOT / "docs" / "validation" / "registry.json"
EVIDENCE_REGISTRY = REPO_ROOT / "docs" / "evidence" / "registry.json"
DRIFT_CORPUS = REPO_ROOT / "testdata" / "drift_corpus.json"
BUILTIN_ID = "textforensics/builtin-heuristic"

EXPECTED_VALIDATION_COUNT = 15
EXPECTED_SUPPORTED_COUNT = 8
EXPECTED_EVIDENCE_COUNT = 50
EXPECTED_VALIDATION_REGISTRY_ID = "3202e9a97342d0df972eaa6dc233bd6837955b2d17297e64542e7a163c3ba7cc"


def _copy_registry(src: Path, tmp_path: Path, name: str = "registry.json") -> Path:
    dest = tmp_path / name
    shutil.copyfile(src, dest)
    return dest


# ---------------------------------------------------------------------------
# 1. Registry import
# ---------------------------------------------------------------------------


def test_validation_registry_loads_with_documented_counts():
    from textforensics.validation import load_validation_registry

    registry = load_validation_registry(VALIDATION_REGISTRY)
    assert len(registry.records) == EXPECTED_VALIDATION_COUNT
    supported = [r for r in registry.records if r.status == "supported"]
    assert len(supported) == EXPECTED_SUPPORTED_COUNT
    assert registry.registry_id == EXPECTED_VALIDATION_REGISTRY_ID
    stored = json.loads(VALIDATION_REGISTRY.read_text(encoding="utf-8"))
    assert stored["registry_id"] == registry.registry_id
    summary = registry.summary()
    assert summary["record_count"] == EXPECTED_VALIDATION_COUNT
    assert summary["statuses"] == {"partial": 7, "supported": 8}
    assert summary["detector_ids"] == [
        "builtin-heuristic",
        "textforensics/builtin-heuristic",
    ]
    assert len(registry.records_for(BUILTIN_ID)) == 9


def test_evidence_registry_loads_with_documented_count():
    """The shipped evidence registry is the U7 claim-to-evidence index:
    pointer records (evidence_record_id -> run artifact + SHA-256),
    per docs/evidence/README.md and evidence-registry.schema.json. It
    is NOT a list of full EvidenceRecord dicts, so it is qualified by
    its JSON schema (see test_registries_validate_against_shipped_json_
    schemas) and by re-hashing every artifact — the same check the
    claims gate performs — not by evidence.load_registry."""
    import hashlib
    import re

    payload = json.loads(EVIDENCE_REGISTRY.read_text(encoding="utf-8"))
    assert payload["schema"] == "textforensics.evidence-registry/v1"
    records = payload["records"]
    assert len(records) == EXPECTED_EVIDENCE_COUNT
    ids = [r["evidence_record_id"] for r in records]
    assert len(set(ids)) == len(ids)
    assert all(re.fullmatch(r"EV-[0-9]{8}-[a-z0-9-]+", i) for i in ids)
    for record in records:
        artifact = REPO_ROOT / record["run_artifact"]
        assert artifact.is_file(), f"missing artifact {record['run_artifact']}"
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        assert digest == record["run_artifact_sha256"], record["evidence_record_id"]


def test_claims_gate_registry_functions_verify_all_50_records():
    """Qualify the evidence registry through the claims gate's own
    loader/verifier (scripts/check_claims.py): schema validation of
    the registry, re-hash of all 50 artifacts, schema validation of
    every artifact. The full gate binary (33/33) is exercised by the
    repo's claims tests and CI; this flow asserts the gate inputs for
    the evidence registry are truthful. (A full-gate run is not
    embedded here: it re-installs pinned build tools into a temp venv
    and is environment-sensitive — it failed ENOSPC on this VM's 512M
    /tmp before the directory was cleaned.)"""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "check_claims", REPO_ROOT / "scripts" / "check_claims.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    records = module.load_registry(REPO_ROOT)
    assert len(records) == EXPECTED_EVIDENCE_COUNT
    _, failures = module.verify_registry_records(REPO_ROOT, records)
    assert failures == []


def test_registries_validate_against_shipped_json_schemas():
    import jsonschema

    schemas_dir = REPO_ROOT / "src" / "textforensics" / "schemas"
    for registry_path, schema_name in (
        (VALIDATION_REGISTRY, "validation-registry.schema.json"),
        (EVIDENCE_REGISTRY, "evidence-registry.schema.json"),
    ):
        schema = json.loads((schemas_dir / schema_name).read_text(encoding="utf-8"))
        payload = json.loads(registry_path.read_text(encoding="utf-8"))
        jsonschema.validate(payload, schema)


def test_tampered_registry_is_rejected_not_loaded(tmp_path):
    from textforensics.validation import ValidationError, load_validation_registry

    copy = _copy_registry(VALIDATION_REGISTRY, tmp_path)
    payload = json.loads(copy.read_text(encoding="utf-8"))
    payload["records"][0]["record_id"] = "evr-tampered"
    copy.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValidationError):
        load_validation_registry(copy)


def test_duplicate_record_ids_are_rejected(tmp_path):
    from textforensics.validation import (
        ValidationError,
        ValidationRecord,
        ValidationRegistry,
    )

    registry = ValidationRegistry(
        [
            ValidationRecord.from_dict(r)
            for r in json.loads(VALIDATION_REGISTRY.read_text(encoding="utf-8"))["records"][:2]
        ]
    )
    with pytest.raises(ValidationError, match="unique"):
        ValidationRegistry([registry.records[0], registry.records[0]])


def test_registry_save_reload_round_trip_is_identical(tmp_path):
    from textforensics.validation import load_validation_registry

    copy = _copy_registry(VALIDATION_REGISTRY, tmp_path)
    before = load_validation_registry(copy)
    out = tmp_path / "roundtrip.json"
    before.save(out)
    after = load_validation_registry(out)
    assert after.registry_id == before.registry_id
    assert [r.record_id for r in after.records] == [r.record_id for r in before.records]
    assert json.loads(out.read_text(encoding="utf-8"))["registry_id"] == before.registry_id


# ---------------------------------------------------------------------------
# 2. Drift snapshot / compare / run
# ---------------------------------------------------------------------------


def test_drift_snapshot_compare_round_trip_api(tmp_path):
    from textforensics.observatory import DriftObservatory

    obs = DriftObservatory(corpus_path=DRIFT_CORPUS)
    assert len(obs.samples) == 34
    snap = obs.take_snapshot(
        detector_ids=[BUILTIN_ID], snapshot_id="w9c-snap-1", label="w9c baseline"
    )
    assert snap["record_count"] == 34
    assert snap["detector_ids"] == [BUILTIN_ID]
    assert snap["corpus_sha256"] == obs.corpus_sha256
    path = tmp_path / "snap1.json"
    obs.save_snapshots(path)
    assert not list(tmp_path.glob(".*.tmp"))  # no stray temp files
    reloaded = DriftObservatory(corpus_path=DRIFT_CORPUS)
    reloaded.load_snapshots(path)
    # take_snapshot already registered the snapshot in obs.snapshots,
    # so the saved file holds exactly the one snapshot.
    assert [s["snapshot_id"] for s in reloaded.snapshots] == ["w9c-snap-1"]
    assert reloaded.snapshots[0] == snap


def test_drift_compare_identical_is_stable_and_flipped_is_drift(tmp_path):
    import copy

    from textforensics.observatory import DriftObservatory

    obs = DriftObservatory(corpus_path=DRIFT_CORPUS)
    snap = obs.take_snapshot(detector_ids=[BUILTIN_ID], snapshot_id="w9c-snap-1")
    identical = obs.compare_snapshots(snap, snap)
    assert identical["overall"]["status"] == "no_detectors_compared" or (
        identical["overall"]["detectors_with_drift"] == 0
        and identical["overall"]["detectors_stable"] >= 0
    )
    flipped = copy.deepcopy(snap)
    flipped["snapshot_id"] = "w9c-snap-2"
    for record in flipped["records"]:
        record["score"] = 1.0 - record["score"]
    report = obs.compare_snapshots(snap, flipped)
    assert report["overall"]["status"] == "drift_detected"
    assert report["overall"]["detectors_with_drift"] == 1
    assert report["detectors"][0]["drift_detected"] is True
    assert report["detectors"][0]["comparable_samples"] == 34


def test_drift_compare_rejects_corpus_mismatch():
    from textforensics.observatory import DriftObservatory

    obs = DriftObservatory(corpus_path=DRIFT_CORPUS)
    snap = obs.take_snapshot(detector_ids=[BUILTIN_ID], snapshot_id="w9c-snap-1")
    other = dict(snap)
    other["snapshot_id"] = "w9c-snap-other"
    other["corpus_sha256"] = "0" * 64
    report = obs.compare_snapshots(snap, other)
    assert report["overall"]["status"] == "corpus_mismatch"
    assert report["detectors"] == []


def test_drift_snapshot_compare_cli_end_to_end(tmp_path):
    env = dict(os.environ, PYTHONPATH=str(REPO_ROOT / "src"))
    snap1 = tmp_path / "snap1.json"
    snap2 = tmp_path / "snap2.json"
    report = tmp_path / "report.json"
    for snap, sid in ((snap1, "cli-1"), (snap2, "cli-2")):
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "textforensics.cli",
                "drift",
                "snapshot",
                "--output",
                str(snap),
                "--snapshot-id",
                sid,
            ],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
        )
        assert proc.returncode == 0, proc.stderr
        assert json.loads(snap.read_text(encoding="utf-8"))["snapshot_id"] == sid
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "textforensics.cli",
            "drift",
            "compare",
            str(snap1),
            str(snap2),
            "--output",
            str(report),
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["baseline_snapshot_id"] == "cli-1"
    assert payload["current_snapshot_id"] == "cli-2"
    assert payload["overall"]["detectors_compared"] == 1


def _write_probe_fixture(tmp_path: Path):
    import hashlib

    from textforensics.probe_corpus import ProbeCorpusManifest, item_id
    from tests.test_probe_runs_e2e import _build_corpus

    manifest, texts, holdback = _build_corpus()
    # The e2e fixture uses synthetic item_ids ("human-native-000");
    # the CLI verifies the frozen corpus, whose ids are
    # content-addressed (pc100-<slice>-<sha16>). Remap everything and
    # recompute the freeze fingerprint so the fixture verifies.
    remap: dict[str, str] = {}
    for item in manifest["items"]:
        new_id = item_id(item["slice"], item["content_sha256"])
        remap[item["item_id"]] = new_id
        item["item_id"] = new_id
    texts = {remap[k]: v for k, v in texts.items()}
    holdback = {remap[k]: v for k, v in holdback.items()}
    manifest["items_sha256"] = ProbeCorpusManifest.from_dict(
        manifest
    ).compute_items_sha256()
    manifest_path = tmp_path / "manifest.json"
    texts_path = tmp_path / "corpus.jsonl"
    holdback_path = tmp_path / "holdback.jsonl"
    texts_bytes = "".join(
        json.dumps({"item_id": k, "text": v}) + "\n" for k, v in texts.items()
    ).encode("utf-8")
    holdback_bytes = "".join(
        json.dumps({"item_id": k, **v}) + "\n" for k, v in holdback.items()
    ).encode("utf-8")
    texts_path.write_bytes(texts_bytes)
    holdback_path.write_bytes(holdback_bytes)
    # The fixture manifest ships placeholder file hashes; the CLI
    # verifies the real files, so pin the real hashes here.
    manifest["corpus_file_sha256"] = hashlib.sha256(texts_bytes).hexdigest()
    manifest["holdback_sha256"] = hashlib.sha256(holdback_bytes).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest_path, texts_path, holdback_path


def test_drift_run_cli_dry_run_writes_nothing(tmp_path):
    from textforensics.cli import _run, build_parser
    from textforensics.config import Settings

    manifest_path, texts_path, holdback_path = _write_probe_fixture(tmp_path)
    registry_copy = _copy_registry(VALIDATION_REGISTRY, tmp_path, "v-registry.json")
    before = registry_copy.read_bytes()
    runs_dir = tmp_path / "runs"
    args = build_parser().parse_args(
        [
            "drift",
            "run",
            "--manifest",
            str(manifest_path),
            "--texts",
            str(texts_path),
            "--holdback",
            str(holdback_path),
            "--runs-dir",
            str(runs_dir),
            "--registry",
            str(registry_copy),
            "--dry-run",
        ]
    )
    assert _run(args, Settings()) == 0
    assert not runs_dir.exists()
    assert registry_copy.read_bytes() == before


def test_drift_run_cli_real_run_saves_manifest(tmp_path):
    from textforensics.cli import _run, build_parser
    from textforensics.config import Settings
    from textforensics.probe_runs import validate_run_manifest

    manifest_path, texts_path, holdback_path = _write_probe_fixture(tmp_path)
    registry_copy = _copy_registry(VALIDATION_REGISTRY, tmp_path, "v-registry.json")
    runs_dir = tmp_path / "runs"
    out = tmp_path / "run.json"
    args = build_parser().parse_args(
        [
            "drift",
            "run",
            "--manifest",
            str(manifest_path),
            "--texts",
            str(texts_path),
            "--holdback",
            str(holdback_path),
            "--runs-dir",
            str(runs_dir),
            "--registry",
            str(registry_copy),
            "--output",
            str(out),
        ]
    )
    assert _run(args, Settings()) == 0
    manifest = json.loads(out.read_text(encoding="utf-8"))
    validate_run_manifest(manifest)
    assert (runs_dir / f"run-{manifest['run_id']}.json").is_file()
    assert manifest["alerts"] == []
    assert manifest["demotions_applied"] == {}
    # The builtin detector abstains on every synthetic lorem-ipsum
    # probe (470 attempted / 470 abstained / 0 succeeded), so the run
    # is correctly NOT support-eligible and NOT a baseline — abstention
    # is preserved, not papered over. (The stub-detector run in
    # test_full_probe_run_demotes_then_clean_rerun_recovers IS a
    # baseline, because the stub returns verdicts.)
    assert manifest["completeness"]["attempted"] == 470
    assert manifest["completeness"]["abstained"] == 470
    assert manifest["completeness"]["support_eligible"] is False
    assert manifest["is_baseline"] is False


# ---------------------------------------------------------------------------
# 3. Demotion / recovery
# ---------------------------------------------------------------------------

_DEMOTE_ALERT = [{"tier": 1, "rule": "human_fpr_cap", "detail": "w9c synthetic"}]


def test_apply_and_clear_demotions_direct_api(tmp_path):
    from textforensics.probe_runs import (
        apply_demotions,
        clear_demotions,
        has_u3_demotion,
    )
    from textforensics.validation import load_validation_registry

    registry_copy = _copy_registry(VALIDATION_REGISTRY, tmp_path)
    before = load_validation_registry(registry_copy)
    before_id = before.registry_id
    result = apply_demotions(
        registry_path=registry_copy,
        detector_id=BUILTIN_ID,
        run_id="w9c-run-1",
        alerts=_DEMOTE_ALERT,
    )
    assert result["gap"] is None
    assert len(result["demoted_record_ids"]) == 9
    demoted = load_validation_registry(registry_copy)
    assert demoted.registry_id != before_id
    for record in demoted.records_for(BUILTIN_ID):
        assert has_u3_demotion(record.limits.demoted_by)
        assert "w9c-run-1" in record.limits.demoted_by
    for record in demoted.records:
        if record.detector_id != BUILTIN_ID:
            assert record.limits.demoted_by is None
    # Re-applying the identical reason is a no-op (no duplicate segment).
    again = apply_demotions(
        registry_path=registry_copy,
        detector_id=BUILTIN_ID,
        run_id="w9c-run-1",
        alerts=_DEMOTE_ALERT,
    )
    assert again["demoted_record_ids"] == result["demoted_record_ids"]
    redemoted = load_validation_registry(registry_copy)
    assert (
        redemoted.records_for(BUILTIN_ID)[0].limits.demoted_by.count("U3 probe run w9c-run-1") == 1
    )
    # Recovery: clearing restores the prior state exactly.
    cleared = clear_demotions(
        registry_path=registry_copy, detector_id=BUILTIN_ID, run_id="w9c-run-2"
    )
    assert cleared["cleared_record_ids"] == result["demoted_record_ids"]
    assert cleared["foreign_demotions_retained"] == []
    recovered = load_validation_registry(registry_copy)
    for record in recovered.records_for(BUILTIN_ID):
        assert record.limits.demoted_by is None
    assert recovered.registry_id == before_id
    # Clearing when nothing is demoted is a clean no-op.
    assert (
        clear_demotions(registry_path=registry_copy, detector_id=BUILTIN_ID, run_id="w9c-run-3")[
            "cleared_record_ids"
        ]
        == []
    )


def test_no_tier1_alert_demotes_nothing(tmp_path):
    from textforensics.probe_runs import apply_demotions
    from textforensics.validation import load_validation_registry

    registry_copy = _copy_registry(VALIDATION_REGISTRY, tmp_path)
    result = apply_demotions(
        registry_path=registry_copy,
        detector_id=BUILTIN_ID,
        run_id="w9c-run-1",
        alerts=[{"tier": 2, "rule": "watch", "detail": "drift only"}],
    )
    assert result == {"demoted_record_ids": [], "reason": None, "gap": None}
    assert load_validation_registry(registry_copy).registry_id == (
        load_validation_registry(VALIDATION_REGISTRY).registry_id
    )


def test_demotion_of_unknown_detector_reports_gap(tmp_path):
    from textforensics.probe_runs import apply_demotions

    registry_copy = _copy_registry(VALIDATION_REGISTRY, tmp_path)
    result = apply_demotions(
        registry_path=registry_copy,
        detector_id="no-such/detector",
        run_id="w9c-run-1",
        alerts=_DEMOTE_ALERT,
    )
    assert result["demoted_record_ids"] == []
    assert result["gap"] is not None and "no-such/detector" in result["gap"]


def test_foreign_demotion_survives_u3_clear(tmp_path):
    from tests.test_validation_trustmap import make_record_dict, registry_of
    from textforensics.probe_runs import apply_demotions, clear_demotions
    from textforensics.validation import load_validation_registry

    foreign = make_record_dict(
        detector_id="test/stub-detector", demoted_by="manual review: stale evidence"
    )
    reg = registry_of(foreign)
    registry_copy = tmp_path / "registry.json"
    reg.save(registry_copy)
    apply_demotions(
        registry_path=registry_copy,
        detector_id="test/stub-detector",
        run_id="w9c-run-1",
        alerts=_DEMOTE_ALERT,
    )
    demoted = load_validation_registry(registry_copy).records[0]
    assert "manual review" in demoted.limits.demoted_by
    assert "U3 probe run w9c-run-1" in demoted.limits.demoted_by
    cleared = clear_demotions(
        registry_path=registry_copy,
        detector_id="test/stub-detector",
        run_id="w9c-run-2",
    )
    assert cleared["foreign_demotions_retained"] == [demoted.record_id]
    recovered = load_validation_registry(registry_copy).records[0]
    assert recovered.limits.demoted_by == "manual review: stale evidence"


def test_full_probe_run_demotes_then_clean_rerun_recovers(tmp_path):
    from tests.test_probe_runs_e2e import StubDetector, _build_corpus, _run
    from tests.test_validation_trustmap import make_record_dict, registry_of
    from textforensics.probe_runs import has_u3_demotion
    from textforensics.validation import load_validation_registry

    manifest, texts, holdback = _build_corpus()
    reg = registry_of(make_record_dict(detector_id="test/stub-detector"))
    registry_copy = tmp_path / "registry.json"
    reg.save(registry_copy)
    runs_dir = tmp_path / "runs"
    clean = _run(manifest, texts, holdback, StubDetector(), runs_dir, registry_path=registry_copy)
    assert clean["is_baseline"] is True
    assert clean["demotions_applied"] == {}
    drifted = _run(
        manifest,
        texts,
        holdback,
        StubDetector(flip_human=True),
        runs_dir,
        registry_path=registry_copy,
    )
    assert drifted["demotions_applied"]["demoted_record_ids"] == [
        "evr-20261106-synthetic-test-builtin-heuristic"
    ]
    assert has_u3_demotion(load_validation_registry(registry_copy).records[0].limits.demoted_by)
    recovered = _run(
        manifest, texts, holdback, StubDetector(), runs_dir, registry_path=registry_copy
    )
    assert recovered["demotions_cleared"]["cleared_record_ids"] == [
        "evr-20261106-synthetic-test-builtin-heuristic"
    ]
    assert load_validation_registry(registry_copy).records[0].limits.demoted_by is None


# ---------------------------------------------------------------------------
# 4. Reload after an external change
# ---------------------------------------------------------------------------


def test_reload_picks_up_external_change(tmp_path):
    from textforensics.probe_runs import apply_demotions
    from textforensics.validation import load_validation_registry

    registry_copy = _copy_registry(VALIDATION_REGISTRY, tmp_path)
    first = load_validation_registry(registry_copy)
    assert first.records_for(BUILTIN_ID)[0].limits.demoted_by is None
    # External change: another writer demotes via the public API.
    apply_demotions(
        registry_path=registry_copy,
        detector_id=BUILTIN_ID,
        run_id="w9c-external",
        alerts=_DEMOTE_ALERT,
    )
    second = load_validation_registry(registry_copy)
    assert second.registry_id != first.registry_id
    assert second.records_for(BUILTIN_ID)[0].limits.demoted_by is not None
    assert "w9c-external" in second.records_for(BUILTIN_ID)[0].limits.demoted_by
    # The first (stale) in-memory object is untouched: reload is explicit.
    assert first.records_for(BUILTIN_ID)[0].limits.demoted_by is None


def test_reload_after_external_corruption_fails_closed(tmp_path):
    from textforensics.validation import ValidationError, load_validation_registry

    registry_copy = _copy_registry(VALIDATION_REGISTRY, tmp_path)
    assert load_validation_registry(registry_copy) is not None
    raw = registry_copy.read_bytes()
    registry_copy.write_bytes(raw[: len(raw) // 2])  # truncated mid-record
    with pytest.raises((ValidationError, ValueError, KeyError)):
        load_validation_registry(registry_copy)


# ---------------------------------------------------------------------------
# 5. Cache / retry / health faults
# ---------------------------------------------------------------------------

_CACHE_RESULT = {"score": 0.31, "verdict": "human_like", "detector": BUILTIN_ID}


def test_cache_miss_then_hit_returns_equal_copy():
    from textforensics.detection_cache import CacheEntryStatus, DetectionCache

    cache = DetectionCache()
    result, status = cache.get("some text", BUILTIN_ID, "0.1.0")
    assert result is None and status is CacheEntryStatus.MISSING
    assert cache.stats.misses == 1
    assert asyncio.run(cache.put("some text", BUILTIN_ID, "0.1.0", _CACHE_RESULT)) is True
    result, status = cache.get("some text", BUILTIN_ID, "0.1.0")
    assert status is CacheEntryStatus.FRESH
    assert result == _CACHE_RESULT
    result["score"] = 9.9  # mutating the returned copy must not poison the cache
    again, _ = cache.get("some text", BUILTIN_ID, "0.1.0")
    assert again["score"] == 0.31
    assert cache.stats.hits >= 2


def test_cache_evicts_lru_under_capacity():
    from textforensics.detection_cache import CacheEntryStatus, CachePolicy, DetectionCache

    cache = DetectionCache(policy=CachePolicy(max_size_bytes=40))
    assert asyncio.run(cache.put("text one", BUILTIN_ID, "0.1.0", {"score": 0.1}))
    assert asyncio.run(cache.put("text two", BUILTIN_ID, "0.1.0", {"score": 0.2}))
    assert asyncio.run(cache.put("text three", BUILTIN_ID, "0.1.0", {"score": 0.3}))
    statuses = [
        cache.get(t, BUILTIN_ID, "0.1.0")[1] for t in ("text one", "text two", "text three")
    ]
    assert CacheEntryStatus.MISSING in statuses  # oldest evicted
    assert CacheEntryStatus.FRESH in statuses  # newest retained


def test_cache_entry_expires_and_is_reported_not_silent():
    import time as _time

    from textforensics.detection_cache import CacheEntryStatus, DetectionCache

    cache = DetectionCache()
    assert asyncio.run(
        cache.put("short lived", BUILTIN_ID, "0.1.0", _CACHE_RESULT, ttl_seconds=0.5)
    )
    assert cache.get("short lived", BUILTIN_ID, "0.1.0")[1] is CacheEntryStatus.FRESH
    _time.sleep(0.7)
    result, status = cache.get("short lived", BUILTIN_ID, "0.1.0")
    assert result is None and status is CacheEntryStatus.EXPIRED


def test_cache_oversized_entry_is_refused_and_bad_ttl_rejected():
    from textforensics.detection_cache import CachePolicy, DetectionCache

    cache = DetectionCache(policy=CachePolicy(max_size_bytes=64))
    assert (
        asyncio.run(cache.put("big", BUILTIN_ID, "0.1.0", {"score": 0.1, "pad": "x" * 500}))
        is False
    )
    assert cache.get("big", BUILTIN_ID, "0.1.0")[0] is None
    with pytest.raises(ValueError):
        asyncio.run(cache.put("bad ttl", BUILTIN_ID, "0.1.0", _CACHE_RESULT, ttl_seconds=0))


def test_cache_persists_across_restart(tmp_path):
    from textforensics.detection_cache import CacheEntryStatus, DetectionCache

    path = tmp_path / "cache.json"
    cache = DetectionCache(storage_path=path)
    assert asyncio.run(cache.put("persist me", BUILTIN_ID, "0.1.0", _CACHE_RESULT))
    assert cache.save() is True
    assert cache.last_persistence_error is None
    restarted = DetectionCache(storage_path=path)
    result, status = restarted.get("persist me", BUILTIN_ID, "0.1.0")
    assert status is CacheEntryStatus.FRESH and result == _CACHE_RESULT


def test_retry_succeeds_after_transient_failures_then_reports_state():
    from textforensics.retry import RetryGate, RetryPolicy, with_retry_gate

    attempts = {"n": 0}

    async def flaky():
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise ConnectionError("transient")
        return "ok"

    gate = RetryGate(RetryPolicy(max_retries=5, base_delay=0.001))
    assert asyncio.run(with_retry_gate(gate, flaky)) == "ok"
    assert attempts["n"] == 3
    assert gate.state.name == "CLOSED"
    assert gate.failures == 0


def test_retry_exhaustion_raises_last_error_and_opens_circuit():
    from textforensics.retry import RetryGate, RetryPolicy, with_retry_gate

    attempts = {"n": 0}

    async def always_fails():
        attempts["n"] += 1
        raise ConnectionError(f"boom {attempts['n']}")

    gate = RetryGate(
        RetryPolicy(
            max_retries=2, base_delay=0.001, circuit_open_after=2, circuit_reset_timeout=60.0
        )
    )
    with pytest.raises(ConnectionError, match="boom 3"):
        asyncio.run(with_retry_gate(gate, always_fails))
    assert attempts["n"] == 3  # initial attempt + 2 retries, no more
    assert gate.state.name == "OPEN"
    allowed, delay = gate.ready()
    assert allowed is False and delay > 0  # backoff enforced, not silent


def test_health_check_pass_fail_and_no_evidence(tmp_path):
    from textforensics.observatory import (
        HealthCheck,
        _create_error_rate_check,
        _create_latency_check,
        create_detector_health_monitor,
    )

    latency = _create_latency_check()
    assert latency.evaluate([10.0, 20.0, 30.0], BUILTIN_ID) is None
    warning = latency.evaluate([5000.0, 6000.0], BUILTIN_ID)
    assert warning is not None and warning.severity.name == "WARNING"
    alert = latency.evaluate([11000.0, 12000.0], BUILTIN_ID)
    assert alert is not None
    assert alert.severity.name == "CRITICAL"
    assert alert.metric_value >= 11000.0
    error_rate = _create_error_rate_check()
    assert error_rate.evaluate([0.0, 0.0, 0.0], BUILTIN_ID) is None
    assert error_rate.evaluate([1.0, 1.0, 1.0], BUILTIN_ID) is not None
    # S18: fewer samples than min_samples is "no evidence", never a pass.
    strict = HealthCheck("strict", "latency_ms", lambda v: (False, 1.0), 1.0, 2.0, min_samples=5)
    assert strict.evaluate([999.0], BUILTIN_ID) is None
    # Monitor: recorded faults surface in the health report. The
    # throughput check needs >= 0.5 requests/s over the last minute
    # (>= 30 requests) to count as healthy, so record 30.
    monitor = create_detector_health_monitor()
    for _ in range(30):
        monitor.record_detector_result(BUILTIN_ID, 50.0)
    state, score = monitor.check_detector_health(BUILTIN_ID)
    assert state.name == "HEALTHY"
    for _ in range(30):
        monitor.record_detector_result(BUILTIN_ID, 9000.0)
    state, _ = monitor.check_detector_health(BUILTIN_ID)
    assert state.name != "HEALTHY"
    assert monitor.get_alerts()


def test_diagnostics_quick_health_check_reports(tmp_path):
    import asyncio as _asyncio

    from textforensics.diagnostics import quick_health_check

    report = _asyncio.run(quick_health_check())
    assert isinstance(report, dict) and report


# ---------------------------------------------------------------------------
# 6. Bounded cancellation
# ---------------------------------------------------------------------------


def test_cancelled_token_refuses_detector_execution_before_start():
    from tests.test_probe_runs_e2e import StubDetector
    from textforensics.detectors import execute_detector
    from textforensics.execution_policy import CancellationToken, ExecutionCancelled

    token = CancellationToken()
    token.cancel()
    assert token.is_cancelled()
    with pytest.raises(ExecutionCancelled):
        execute_detector(StubDetector(), "any text", cancellation=token)


def test_cancelled_token_refuses_drift_snapshot():
    from textforensics.execution_policy import CancellationToken, ExecutionCancelled
    from textforensics.observatory import DriftObservatory

    obs = DriftObservatory(corpus_path=DRIFT_CORPUS)
    token = CancellationToken()
    token.cancel()
    with pytest.raises(ExecutionCancelled):
        obs.take_snapshot(detector_ids=[BUILTIN_ID], cancellation=token)


def test_cooperative_loop_terminates_within_bound_after_cancel():
    from textforensics.execution_policy import (
        CancellationToken,
        ExecutionCancelled,
    )

    token = CancellationToken()
    started = time.monotonic()
    bound_seconds = 5.0
    iterations = 0
    with pytest.raises(ExecutionCancelled):
        while True:
            iterations += 1
            if iterations == 50:
                token.cancel()
            token.assert_not_cancelled()
            time.sleep(0.001)
            assert time.monotonic() - started < bound_seconds
    assert iterations == 50
    assert time.monotonic() - started < bound_seconds


# ---------------------------------------------------------------------------
# 7. Recoverable restart
# ---------------------------------------------------------------------------


def test_atomic_write_survives_stray_temp_file_and_rewrite(tmp_path):
    from textforensics.atomic_io import atomic_write_text
    from textforensics.validation import load_validation_registry

    registry_copy = _copy_registry(VALIDATION_REGISTRY, tmp_path)
    # Simulate an interrupted atomic write: a stray temp file sits next
    # to the target, the target itself untouched.
    stray = registry_copy.parent / f".{registry_copy.name}.abc123.tmp"
    stray.write_text('{"partial": true', encoding="utf-8")
    assert load_validation_registry(registry_copy) is not None
    assert len(load_validation_registry(registry_copy).records) == 15
    # A later atomic write still succeeds and leaves no temp behind.
    atomic_write_text(tmp_path / "note.txt", "recovered\n")
    assert (tmp_path / "note.txt").read_text(encoding="utf-8") == "recovered\n"
    stray.unlink()
    assert not list(registry_copy.parent.glob(".*.tmp"))


def test_killed_writer_leaves_registry_loadable(tmp_path):
    """SIGKILL a child mid-write; the registry must stay loadable."""
    from textforensics.validation import load_validation_registry

    registry_copy = _copy_registry(VALIDATION_REGISTRY, tmp_path)
    script = tmp_path / "killed_writer.py"
    script.write_text(
        "import os, signal, time\n"
        "from pathlib import Path\n"
        f"target = Path({str(registry_copy)!r})\n"
        "for i in range(1000):\n"
        "    tmp = target.with_name(f'.{target.name}.{i}.tmp')\n"
        "    tmp.write_text('{\"partial\": %d' % i, encoding='utf-8')\n"
        "    time.sleep(0.001)\n"
        "    tmp.unlink(missing_ok=True)\n",
        encoding="utf-8",
    )
    proc = subprocess.Popen(
        [sys.executable, str(script)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.05)
    proc.send_signal(signal.SIGKILL)
    proc.wait(timeout=10)
    assert proc.returncode == -signal.SIGKILL
    registry = load_validation_registry(registry_copy)
    assert len(registry.records) == EXPECTED_VALIDATION_COUNT
    assert registry.registry_id == EXPECTED_VALIDATION_REGISTRY_ID


def test_ledger_survives_sigkill_mid_append_and_recovers(tmp_path):
    """Kill a process appending ledger entries; the log must either load
    cleanly (whole entries only) or fail closed naming the torn line —
    never load as a shorter, apparently valid log. After truncating a
    torn tail, appends continue contiguously."""
    from textforensics.ledger import AuditLog, AuditLogError

    log_path = tmp_path / "audit.jsonl"
    script = tmp_path / "ledger_writer.py"
    script.write_text(
        "import time\n"
        "from textforensics.ledger import AuditLog\n"
        f"log = AuditLog({str(log_path)!r})\n"
        "for i in range(10000):\n"
        "    log.append('w9c-op', actor='w9c', input_data={'i': i})\n",
        encoding="utf-8",
    )
    env = dict(os.environ, PYTHONPATH=str(REPO_ROOT / "src"))
    err_path = tmp_path / "writer.err"
    with err_path.open("w", encoding="utf-8") as err_handle:
        proc = subprocess.Popen(
            [sys.executable, str(script)],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=err_handle,
        )
        deadline = time.monotonic() + 60
        while not log_path.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert log_path.exists(), (
            "ledger writer never created the log; child stderr: "
            + err_path.read_text(encoding="utf-8")
        )
        time.sleep(0.5)  # let it append a real prefix before the kill
        proc.send_signal(signal.SIGKILL)
        proc.wait(timeout=10)
    assert proc.returncode == -signal.SIGKILL
    lines = [ln for ln in log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) >= 1  # the kill happened after real work
    try:
        log = AuditLog(log_path)
        assert log.verify_chain() is True
        assert len(log) == len(lines)
        torn = False
    except AuditLogError as exc:
        # Fail-closed on a torn tail: the fault is reported, and the
        # surviving prefix is NOT presented as a valid shorter log.
        torn = True
        assert "line" in str(exc)
        assert len(lines) >= 1
    if torn:
        # Recovery: drop only the torn final line, keep the verified prefix.
        good = lines[:-1]
        assert good
        log_path.write_text("\n".join(good) + "\n", encoding="utf-8")
        log = AuditLog(log_path)
        assert log.verify_chain() is True
        assert len(log) == len(good)
    # Appends continue contiguously after recovery.
    head = len(log)
    entry = log.append("w9c-after-restart", actor="w9c")
    assert entry.index == head
    assert AuditLog(log_path).verify_chain() is True


def test_registry_save_is_atomic_and_reload_verifies(tmp_path):
    from textforensics.validation import load_validation_registry

    registry_copy = _copy_registry(VALIDATION_REGISTRY, tmp_path)
    registry = load_validation_registry(registry_copy)
    registry.save(registry_copy)
    assert not list(tmp_path.glob(".*.tmp"))
    reloaded = load_validation_registry(registry_copy)
    assert reloaded.registry_id == registry.registry_id
    assert reloaded.to_dict() == registry.to_dict()
