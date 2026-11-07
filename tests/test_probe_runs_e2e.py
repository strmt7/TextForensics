"""End-to-end tests for perform_probe_run (U3).

These tests drive the whole run path — synthetic frozen corpus,
stub detector, real DriftObservatory scoring, real run history —
with small synthetic fixtures. No datasets are fetched and no
corpus files are touched.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tests.test_validation_trustmap import make_record_dict, registry_of
from textforensics.detectors import DetectorPrediction
from textforensics.probe_runs import (
    perform_probe_run,
    summarize_longitudinal,
    validate_run_manifest,
)
from textforensics.validation import ValidationRegistry

DETECTOR_ID = "test/stub-detector"
DETECTOR_VERSION = "0.1.0"

# slice -> (n_items, kind, label); kind is the text marker the stub
# detector keys on. human-native has 120 items so its FPR is
# claimable (MIN_SLICE_N_FOR_FPR_CLAIM = 100); the rest have 50.
SLICE_PLAN: tuple[tuple[str, int, str, int | None], ...] = (
    ("human-native", 120, "HUMAN", 0),
    ("human-short", 50, "HUMAN", 0),
    ("ai-current-generator", 50, "MACHINE", 1),
    ("ai-legacy-generator", 50, "MACHINE", 1),
    ("ai-paraphrased", 50, "MACHINE", 1),
    ("ai-humanized", 50, "MACHINE", 1),
    ("mixed-origin", 50, "MACHINE", None),
    ("benign-transformed", 50, "HUMAN", 0),
)


class StubDetector:
    """Deterministic stub: HUMAN text scores low, MACHINE text high."""

    detector_id = DETECTOR_ID
    detector_version = DETECTOR_VERSION
    detector_family = "stub"

    def __init__(self, *, shift: float = 0.0, flip_human: bool = False) -> None:
        self.shift = shift
        self.flip_human = flip_human
        self.calls = 0

    def detect(self, text: str) -> DetectorPrediction:
        self.calls += 1
        is_machine = "MACHINE" in text
        score = 0.8 if is_machine else 0.2
        if self.flip_human and not is_machine:
            score = 0.9
        score = min(0.99, max(0.01, score + self.shift))
        return DetectorPrediction(
            schema="textforensics.detector-result/v1",
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            detector_family=self.detector_family,
            execution="local",
            score=score,
            score_semantics="stub test score; not a probability",
            verdict="ai_like" if score >= 0.68 else "human_like",
            threshold=0.68,
        )


def _build_corpus() -> tuple[dict, dict[str, str], dict[str, dict]]:
    items: list[dict] = []
    texts: dict[str, str] = {}
    holdback: dict[str, dict] = {}
    for slice_name, n, kind, label in SLICE_PLAN:
        for i in range(n):
            item_id = f"{slice_name}-{i:03d}"
            text = f"{kind} probe text number {i}. " + "lorem ipsum dolor sit amet. " * 12
            items.append(
                {
                    "item_id": item_id,
                    "slice": slice_name,
                    "content_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                    "word_count": len(text.split()),
                    "char_count": len(text),
                    "lang": "en",
                    "source_dataset": "synthetic",
                    "source_config": "test",
                    "source_split": "train",
                    "source_id": item_id,
                    "transform_name": None,
                    "base_content_sha256": None,
                }
            )
            texts[item_id] = text
            holdback[item_id] = {"label": label, "regime": slice_name}
    items_json = json.dumps(items, sort_keys=True)
    manifest = {
        "schema": "textforensics.probe-corpus/v1",
        "version": "1.0.0",
        "created_at_utc": "2026-11-07T00:00:00Z",
        "items": items,
        "items_sha256": hashlib.sha256(items_json.encode("utf-8")).hexdigest(),
        "holdback_sha256": hashlib.sha256(b"holdback").hexdigest(),
        "corpus_file_sha256": hashlib.sha256(b"corpus").hexdigest(),
        "sources": ["synthetic"],
        "current_generators": [],
        "notes": "synthetic fixture corpus for perform_probe_run tests",
    }
    return manifest, texts, holdback


def _run(
    manifest: dict,
    texts: dict,
    holdback: dict,
    detector: StubDetector,
    runs_dir: Path,
    *,
    scope: str = "full",
    registry_path: Path | None = None,
    dry_run: bool = False,
    run_at: datetime | None = None,
    primitives: object = None,
) -> dict:
    return perform_probe_run(
        manifest=manifest,
        texts=texts,
        holdback_loader=lambda: holdback,
        detector=detector,
        scope=scope,
        runs_dir=runs_dir,
        registry_path=registry_path,
        dry_run=dry_run,
        primitives=primitives,
        run_at=run_at,
    )


def _make_stub_primitives():
    """Build the same closed-form test-double primitives as
    tests/test_probe_runs.py (imported helpers, one shared stub)."""
    import types

    from tests.test_probe_runs import (
        _abstention_rate,
        _brier,
        _coverage_shortfall_pp,
        _ece,
        _flip_summary,
        _fpr_at_threshold,
        _holm_adjusted,
        _ks_pvalue,
        _ks_statistic,
        _metadata_diff,
        _psi,
        _set_coverage,
        _tpr_at_fpr,
        _wilson_ci,
        _worst_slice_fpr,
    )

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


@pytest.fixture
def primitives():
    return _make_stub_primitives()


def test_first_run_is_baseline_and_clean(tmp_path, primitives):
    manifest, texts, holdback = _build_corpus()
    detector = StubDetector()
    run = _run(manifest, texts, holdback, detector, tmp_path, primitives=primitives)
    validate_run_manifest(run)
    assert run["is_baseline"] is True
    assert run["baseline_run_id"] == run["run_id"]
    assert run["previous_run_id"] is None
    assert run["alerts"] == []
    assert not any(a["tier"] == 1 for a in run["alerts"])
    assert len(run["score_series"]) == 470
    assert run["metrics"]["overall"]["n"] == 470
    assert run["metrics"]["slices"]["human-native"]["human_fpr"]["fpr"] == 0.0
    assert run["metrics"]["worst_slice_fpr"]["fpr"] == 0.0
    # No raw text anywhere in the manifest.
    assert "lorem ipsum" not in json.dumps(run)
    assert (tmp_path / f"run-{run['run_id']}.json").exists()


def test_two_clean_runs_give_two_consecutive_clean_full_runs(tmp_path, primitives):
    manifest, texts, holdback = _build_corpus()
    _run(manifest, texts, holdback, StubDetector(), tmp_path, primitives=primitives)
    second = _run(manifest, texts, holdback, StubDetector(), tmp_path, primitives=primitives)
    assert second["is_baseline"] is False
    assert second["alerts"] == []
    from textforensics.probe_runs import load_run_history

    history = load_run_history(tmp_path)
    summary = summarize_longitudinal(
        history,
        detector_id=DETECTOR_ID,
        detector_version=DETECTOR_VERSION,
        corpus_fingerprint=manifest["items_sha256"],
    )
    assert summary["consecutive_clean_full_runs"] == 2
    assert summary["temporal_support"] is True


def test_drift_tier3_then_tier2_on_consecutive_runs(tmp_path, primitives):
    manifest, texts, holdback = _build_corpus()
    _run(manifest, texts, holdback, StubDetector(), tmp_path, primitives=primitives)
    drifted = _run(
        manifest, texts, holdback, StubDetector(shift=0.25), tmp_path, primitives=primitives
    )
    tiers = {a["tier"] for a in drifted["alerts"]}
    assert tiers == {3}, drifted["alerts"]
    assert not any(a["tier"] == 1 for a in drifted["alerts"])
    assert drifted["breaches"], "drift run must record breaches for the next run"
    again = _run(
        manifest, texts, holdback, StubDetector(shift=0.25), tmp_path, primitives=primitives
    )
    tiers = {a["tier"] for a in again["alerts"]}
    assert 2 in tiers, again["alerts"]
    assert not any(a["tier"] == 1 for a in again["alerts"])
    assert any(a.get("consecutive_runs") == 2 for a in again["alerts"])


def test_tier1_fpr_demotes_and_clean_run_clears(tmp_path, primitives):
    manifest, texts, holdback = _build_corpus()
    registry_path = tmp_path / "registry.json"
    record = make_record_dict(detector_id=DETECTOR_ID, detector_version=DETECTOR_VERSION)
    registry_of(record).save(registry_path)
    _run(
        manifest,
        texts,
        holdback,
        StubDetector(),
        tmp_path,
        registry_path=registry_path,
        primitives=primitives,
    )
    bad = _run(
        manifest,
        texts,
        holdback,
        StubDetector(flip_human=True),
        tmp_path,
        registry_path=registry_path,
        primitives=primitives,
    )
    tier1 = [a for a in bad["alerts"] if a["tier"] == 1]
    assert tier1, bad["alerts"]
    assert any(a["tier"] == 1 for a in bad["alerts"])
    assert bad["demotions_applied"], "Tier 1 must write demotions"
    reloaded = ValidationRegistry.load(registry_path)
    demoted = [r for r in reloaded.records if r.limits.demoted_by]
    assert len(demoted) == 1
    assert demoted[0].limits.demoted_by.startswith("U3 probe run ")
    from textforensics.validation import effective_status

    assert (
        effective_status(demoted[0], detector_version=DETECTOR_VERSION, now=datetime.now(UTC))
        == "stale"
    )
    # A clean full run clears the U3 demotion.
    clean = _run(
        manifest,
        texts,
        holdback,
        StubDetector(),
        tmp_path,
        registry_path=registry_path,
        primitives=primitives,
    )
    assert not any(a["tier"] == 1 for a in clean["alerts"])
    assert clean["demotions_cleared"], "clean full run must clear U3 demotions"
    reloaded = ValidationRegistry.load(registry_path)
    assert all(r.limits.demoted_by is None for r in reloaded.records)


def test_holdback_loader_runs_only_after_scoring(tmp_path, primitives):
    manifest, texts, holdback = _build_corpus()
    detector = StubDetector()
    calls_at_load: list[int] = []

    def loader():
        calls_at_load.append(detector.calls)
        return holdback

    run = perform_probe_run(
        manifest=manifest,
        texts=texts,
        holdback_loader=loader,
        detector=detector,
        runs_dir=tmp_path,
        primitives=primitives,
    )
    assert run["is_baseline"] is True
    assert calls_at_load == [470], "labels must load only after all 470 items are scored"
    assert detector.calls == 470


def test_dry_run_writes_nothing(tmp_path, primitives):
    manifest, texts, holdback = _build_corpus()
    registry_path = tmp_path / "registry.json"
    record = make_record_dict(detector_id=DETECTOR_ID, detector_version=DETECTOR_VERSION)
    registry_of(record).save(registry_path)
    before = registry_path.read_bytes()
    run = _run(
        manifest,
        texts,
        holdback,
        StubDetector(flip_human=True),
        tmp_path,
        registry_path=registry_path,
        dry_run=True,
        primitives=primitives,
    )
    assert any(a["tier"] == 1 for a in run["alerts"])  # computed, not applied
    assert list(tmp_path.glob("run-*.json")) == []
    assert registry_path.read_bytes() == before


def test_monthly_scope_scores_only_attacked_slices_and_is_not_a_baseline(tmp_path, primitives):
    manifest, texts, holdback = _build_corpus()
    run = _run(
        manifest,
        texts,
        holdback,
        StubDetector(),
        tmp_path,
        scope="monthly-attacked",
        primitives=primitives,
    )
    assert run["is_baseline"] is False
    assert run["baseline_run_id"] is None
    assert set(run["metrics"]["slices"]) == {"ai-paraphrased", "ai-humanized"}
    assert run["metrics"]["overall"]["n"] == 100
    # A later full run still becomes the baseline.
    full = _run(manifest, texts, holdback, StubDetector(), tmp_path, primitives=primitives)
    assert full["is_baseline"] is True


def test_perform_probe_run_rejects_bad_scope(tmp_path, primitives):
    manifest, texts, holdback = _build_corpus()
    with pytest.raises(ValueError, match="scope must be one of"):
        _run(
            manifest,
            texts,
            holdback,
            StubDetector(),
            tmp_path,
            scope="weekly",
            primitives=primitives,
        )
