"""Tests for scripts/seed_validation.py (U1 Package C, commit 5).

No network is used here and no real cache is needed: the bootstrap
and record-builder tests synthesise (label, score, verdict) triples
in the test, and the --check test builds a synthetic cache + fake U7
artifact + fake U7 registry in a temporary directory. The one test
that touches the real repo reads only the committed
docs/validation/registry.json (no cache, no network). No dataset
text and no measured numbers appear in these tests.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
from pathlib import Path

import pytest

from textforensics.datasets import NormalizedRow, get_spec, write_sample_cache
from textforensics.schema import validate_evidence_record
from textforensics.validation import (
    ValidationRegistry,
    effective_status,
    validate_record,
    verify_signature,
)

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
REPO_ROOT = Path(__file__).parent.parent


def _load_seed_module():
    spec = importlib.util.spec_from_file_location(
        "seed_validation", SCRIPTS_DIR / "seed_validation.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["seed_validation"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def seed():
    return _load_seed_module()


def _synthetic_triples():
    """Deterministic (label, score, verdict) triples: 40 human, 40 machine.

    Scores separate the classes imperfectly; a few machine rows cross
    into ai_like, no human row does, and some rows abstain.
    """
    triples = []
    for i in range(40):
        score = round(0.15 + 0.004 * i, 4)
        verdict = "abstain" if i % 8 == 0 else "human_like"
        triples.append((0, score, verdict))
    for i in range(40):
        score = round(0.25 + 0.008 * i, 4)
        verdict = "ai_like" if score >= 0.55 else ("abstain" if i % 9 == 0 else "human_like")
        triples.append((1, score, verdict))
    return triples


def _synthetic_artifact():
    return {
        "run_id": "EV-20261106-synthetic-test",
        "run_artifact": "docs/evidence/runs/EV-20261106-synthetic-test.json",
        "run_artifact_sha256": "b" * 64,
        "run_date": "2026-11-06",
        "code_version": "a" * 40,
        "drops": [{"item": "synthetic drop", "reason": "synthetic test fixture"}],
    }


def test_bootstrap_ci_is_deterministic_given_the_seed(seed):
    items = [0, 1, 1, 0, 1, 0, 0, 1]
    stat = lambda sample: sum(sample) / len(sample)  # noqa: E731
    first = seed.bootstrap_ci(stat, items)
    second = seed.bootstrap_ci(stat, items)
    assert first == second


def test_bootstrap_ci_contains_the_point_estimate(seed):
    items = [0, 1, 1, 0, 1, 0, 0, 1, 1, 0]
    point = sum(items) / len(items)
    lower, upper = seed.bootstrap_ci(lambda sample: sum(sample) / len(sample), items)
    assert lower <= point <= upper
    assert 0.0 <= lower <= upper <= 1.0


def test_bootstrap_ci_narrows_with_n(seed):
    stat = lambda sample: sum(sample) / len(sample)  # noqa: E731
    small = [1, 0] * 5
    large = [1, 0] * 500
    small_lo, small_hi = seed.bootstrap_ci(stat, small, resamples=200)
    large_lo, large_hi = seed.bootstrap_ci(stat, large, resamples=200)
    assert (large_hi - large_lo) < (small_hi - small_lo)


def test_metric_with_ci_widens_to_include_the_point_estimate(seed):
    metric = seed.metric_with_ci(0.0, 10, (0.1, 0.2))
    assert metric.ci_lower <= 0.0 <= metric.ci_upper
    assert metric.value == 0.0


class TestRecordBuilder:
    def test_record_from_synthetic_triples_passes_both_validators(self, seed):
        record, measurements = seed.record_from_triples(
            "raid",
            _synthetic_triples(),
            word_counts=[100] * 80,
            domains=["synthetic-domain"],
            generators=["synthetic-generator"],
            artifact=_synthetic_artifact(),
            cache_file_sha256="c" * 64,
        )
        payload = record.to_dict()
        assert validate_evidence_record(payload) == []
        assert validate_record(payload) == []
        assert verify_signature(payload)
        assert record.status == "partial"
        assert effective_status(record, detector_version="0.1.0") == "partial"
        assert payload["metrics"][0]["fpr_native"]["operating_point"] == (
            "builtin-heuristic native verdict (analyze_text); no score threshold"
        )
        assert record.metrics[0].auroc.method == "bootstrap, 1000 resamples, seed 20261106"
        assert record.data.contamination_flag == "no"
        assert record.data.licence == "MIT"
        assert record.limits.next_revalidation_due == "2027-02-04"
        assert measurements["n_human"] == 40
        assert measurements["n_ai"] == 40

    def test_measure_triples_ci_contains_point_estimates(self, seed):
        measurements = seed.measure_triples(_synthetic_triples())
        for name in ("auroc", "tpr_at_fpr_0_01", "tpr_at_fpr_0_05", "fpr_native", "tpr_native"):
            metric = measurements[name]
            assert metric.ci_lower <= metric.value <= metric.ci_upper
        assert 0.0 <= measurements["abstention_rate"] <= 1.0
        assert measurements["coverage"] == pytest.approx(1.0 - measurements["abstention_rate"])

    def test_mixset_has_no_seed_record(self, seed):
        with pytest.raises(ValueError, match="no seed config"):
            seed.record_from_triples(
                "mixset",
                _synthetic_triples(),
                word_counts=[100] * 80,
                domains=["synthetic"],
                generators=["synthetic"],
                artifact=_synthetic_artifact(),
                cache_file_sha256="c" * 64,
            )

    def test_aggregate_scope_reads_meta_not_invention(self, seed):
        rows = [
            NormalizedRow(
                text="x",
                label=0,
                dataset="mage",
                config="default",
                split="train",
                source_id="s1",
                regime="mage",
                meta={"src": "sci_gen_human"},
            ),
            NormalizedRow(
                text="y",
                label=1,
                dataset="mage",
                config="default",
                split="train",
                source_id="s2",
                regime="mage",
                meta={"src": "sci_gen_machine_continuation_text-davinci-003"},
            ),
        ]
        scope = seed.aggregate_scope("mage", rows)
        assert scope["domains"] == ["sci_gen"]
        assert scope["generators"] == ["text-davinci-003"]


def _write_fake_u7_repo(tmp: Path, *, artifact_sha: str | None = None) -> Path:
    """Create a synthetic repo root with a fake U7 artifact + registry."""
    runs_dir = tmp / "docs" / "evidence" / "runs"
    runs_dir.mkdir(parents=True)
    artifact = {
        "schema": "textforensics.run-artifact/v1",
        "evidence_record_id": "EV-20261106-dataset-mage",
        "kind": "command",
        "command": "python scripts/measure_datasets.py --only mage",
        "code_version": "a" * 40,
        "run_date": "2026-11-06",
        "results": {},
        "drops": [],
        "badge": "available",
    }
    artifact_path = runs_dir / "EV-20261106-dataset-mage.json"
    artifact_path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n")
    sha = artifact_sha or hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    registry = {
        "schema": "textforensics.evidence-registry/v1",
        "records": [
            {
                "evidence_record_id": "EV-20261106-dataset-mage",
                "run_artifact": "docs/evidence/runs/EV-20261106-dataset-mage.json",
                "run_artifact_sha256": sha,
            }
        ],
    }
    (tmp / "docs" / "evidence" / "registry.json").write_text(
        json.dumps(registry, indent=2, sort_keys=True) + "\n"
    )
    return tmp


def _write_synthetic_cache(tmp: Path) -> Path:
    """Write a small synthetic MAGE cache (12 human + 12 machine rows)."""
    cache_dir = tmp / "cache"
    spec = get_spec("mage")
    human_text = " ".join(["The committee reviewed the annual report and noted the findings."] * 12)
    machine_text = " ".join(
        ["Moreover the systematic analysis demonstrates significant outcomes."] * 12
    )
    rows = [
        NormalizedRow(
            text=human_text,
            label=0,
            dataset="mage",
            config="default",
            split="train",
            source_id=f"synthetic-human-{i}",
            regime="mage",
            meta={"src": "squad_human"},
        )
        for i in range(12)
    ] + [
        NormalizedRow(
            text=machine_text,
            label=1,
            dataset="mage",
            config="default",
            split="train",
            source_id=f"synthetic-machine-{i}",
            regime="mage",
            meta={"src": "squad_machine_continuation_7B"},
        )
        for i in range(12)
    ]
    write_sample_cache(spec, "default", "train", rows, cache_dir=cache_dir)
    return cache_dir


class TestVerifyArtifact:
    def test_verify_run_artifact_success(self, seed):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = _write_fake_u7_repo(Path(tmpdir))
            proven = seed.verify_run_artifact("mage", repo_root=repo)
            assert proven["run_id"] == "EV-20261106-dataset-mage"
            assert proven["run_date"] == "2026-11-06"
            assert len(proven["run_artifact_sha256"]) == 64

    def test_verify_run_artifact_hash_mismatch_fails_loudly(self, seed):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = _write_fake_u7_repo(Path(tmpdir), artifact_sha="d" * 64)
            with pytest.raises(ValueError, match="mismatch"):
                seed.verify_run_artifact("mage", repo_root=repo)

    def test_verify_run_artifact_missing_entry_fails(self, seed):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            (repo / "docs" / "evidence" / "runs").mkdir(parents=True)
            (repo / "docs" / "evidence" / "runs" / "EV-20261106-dataset-mage.json").write_text(
                json.dumps(
                    {
                        "evidence_record_id": "EV-20261106-dataset-mage",
                        "run_date": "2026-11-06",
                        "code_version": "a" * 40,
                    }
                )
            )
            (repo / "docs" / "evidence" / "registry.json").write_text(
                json.dumps({"schema": "textforensics.evidence-registry/v1", "records": []})
            )
            with pytest.raises(ValueError, match="no entry"):
                seed.verify_run_artifact("mage", repo_root=repo)


class TestCheckMode:
    def test_check_mode_builds_from_synthetic_cache_without_network(self, seed):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            repo = _write_fake_u7_repo(tmp / "repo")
            cache_dir = _write_synthetic_cache(tmp)
            exit_code = seed.main(
                [
                    "--only",
                    "mage",
                    "--check",
                    "--cache-dir",
                    str(cache_dir),
                    "--repo-root",
                    str(repo),
                ]
            )
            assert exit_code == 0
            assert not (repo / "docs" / "validation" / "registry.json").exists()

    def test_build_record_from_synthetic_cache_dual_validates(self, seed):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            repo = _write_fake_u7_repo(tmp / "repo")
            cache_dir = _write_synthetic_cache(tmp)
            record, _measurements = seed.build_record("mage", cache_dir=cache_dir, repo_root=repo)
            assert validate_evidence_record(record.to_dict()) == []
            assert validate_record(record.to_dict()) == []
            assert record.data.dataset_name == "MAGE"
            assert record.metrics[0].n_human == 12
            assert record.metrics[0].n_ai == 12


class TestSeededRegistry:
    def test_committed_registry_loads_with_four_records_and_no_mixset(self):
        registry = ValidationRegistry.load(REPO_ROOT / "docs" / "validation" / "registry.json")
        assert len(registry.records) == 4
        assert [record.record_id for record in registry.records] == [
            "evr-20261106-beemo-builtin-heuristic",
            "evr-20261106-mage-builtin-heuristic",
            "evr-20261106-opai-bench-builtin-heuristic",
            "evr-20261106-raid-builtin-heuristic",
        ]
        for record in registry.records:
            assert record.status == "partial"
            assert effective_status(record, detector_version="0.1.0") == "partial"
            assert record.data.contamination_flag == "no"
            assert validate_evidence_record(record.to_dict()) == []
            assert validate_record(record.to_dict()) == []
            assert verify_signature(record)
        assert (
            "mixset"
            not in " ".join(
                record.record_id + record.data.dataset_name for record in registry.records
            ).lower()
        )
