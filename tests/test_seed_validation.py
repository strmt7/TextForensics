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

    def test_built_record_carries_paired_native_tpr(self, seed):
        record, measurements = seed.record_from_triples(
            "raid",
            _synthetic_triples(),
            word_counts=[100] * 80,
            domains=["synthetic-domain"],
            generators=["synthetic-generator"],
            artifact=_synthetic_artifact(),
            cache_file_sha256="c" * 64,
        )
        tpr_native = record.metrics[0].tpr_native
        assert tpr_native is not None
        assert tpr_native.value == pytest.approx(measurements["tpr_native"].value)
        assert tpr_native.ci_lower <= tpr_native.value <= tpr_native.ci_upper
        assert tpr_native.n <= record.metrics[0].n_ai
        payload = record.to_dict()
        assert payload["metrics"][0]["tpr_native"]["value"] == pytest.approx(
            measurements["tpr_native"].value
        )
        assert validate_evidence_record(payload) == []
        assert validate_record(payload) == []

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

    def test_aggregate_scope_ghostwriter_agents_are_generators(self, seed):
        rows = [
            NormalizedRow(
                text="x",
                label=0,
                dataset="ghostwriter",
                config="default",
                split="train",
                source_id="g1",
                regime="raw",
                meta={"domain": "cnn_news", "agent": "human", "lang": "en-EN"},
            ),
            NormalizedRow(
                text="y",
                label=1,
                dataset="ghostwriter",
                config="default",
                split="train",
                source_id="g2",
                regime="raw",
                meta={"domain": "bundestag", "agent": "gpt-4o-mini", "lang": "de-DE"},
            ),
            NormalizedRow(
                text="z",
                label=1,
                dataset="ghostwriter",
                config="default",
                split="train",
                source_id="g3",
                regime="raw",
                meta={"domain": "bundestag", "agent": "gemma2:9b", "lang": "de-DE"},
            ),
        ]
        scope = seed.aggregate_scope("ghostwriter", rows)
        assert scope["domains"] == ["bundestag", "cnn_news"]
        # "human" is an agent value on human rows, not a generator.
        assert scope["generators"] == ["gemma2:9b", "gpt-4o-mini"]

    def test_aggregate_scope_detectrl_x_models_are_generators(self, seed):
        rows = [
            NormalizedRow(
                text="x",
                label=0,
                dataset="detectrl_x",
                config="binary",
                split="train",
                source_id="d1",
                regime="raw",
                meta={
                    "domain": "Wiki",
                    "model": "gpt-4o",
                    "lang": "english",
                    "split": "train",
                    "file": "Binary/binary_general_open.json",
                },
            ),
            NormalizedRow(
                text="y",
                label=1,
                dataset="detectrl_x",
                config="binary",
                split="train",
                source_id="d2",
                regime="raw",
                meta={
                    "domain": "News",
                    "model": "deepseek-v3",
                    "lang": "arabic",
                    "split": "train",
                    "file": "Binary/binary_general_open.json",
                },
            ),
            NormalizedRow(
                text="z",
                label=1,
                dataset="detectrl_x",
                config="binary",
                split="train",
                source_id="d3",
                regime="raw",
                meta={
                    "domain": "Wiki",
                    "model": "qwen-max",
                    "lang": "chinese",
                    "split": "train",
                    "file": "Binary/binary_general_open.json",
                },
            ),
        ]
        scope = seed.aggregate_scope("detectrl_x", rows)
        assert scope["domains"] == ["News", "Wiki"]
        assert scope["generators"] == ["deepseek-v3", "gpt-4o", "qwen-max"]

    def test_record_from_synthetic_triples_detectrl_x_is_multilingual(self, seed):
        record, _measurements = seed.record_from_triples(
            "detectrl_x",
            _synthetic_triples(),
            word_counts=[100] * 80,
            domains=["Wiki"],
            generators=["gpt-4o"],
            artifact=_synthetic_artifact(),
            cache_file_sha256="c" * 64,
        )
        payload = record.to_dict()
        assert validate_evidence_record(payload) == []
        assert validate_record(payload) == []
        assert verify_signature(payload)
        assert record.regime.language == "mul"
        # The 8 languages span Arab, Hans, Cyrl and Latn: script is "mul".
        assert record.regime.script == "mul"
        assert "ar + zh + en + fr + de + pt + ru + es" in (record.regime.language_variety or "")

    def test_record_from_synthetic_triples_ghostwriter_is_multilingual(self, seed):
        record, _measurements = seed.record_from_triples(
            "ghostwriter",
            _synthetic_triples(),
            word_counts=[100] * 80,
            domains=["cnn_news"],
            generators=["gpt-4o-mini"],
            artifact=_synthetic_artifact(),
            cache_file_sha256="c" * 64,
        )
        payload = record.to_dict()
        assert validate_evidence_record(payload) == []
        assert validate_record(payload) == []
        assert verify_signature(payload)
        assert record.regime.language == "mul"
        assert record.regime.language_variety == "en-EN + de-DE (288 + 59 labelled rows)"
        assert record.data.dataset_name == "GhostWriter"
        assert "CC-BY-NC-SA 4.0" in record.data.licence
        assert record.limits.next_revalidation_due == "2027-02-04"


def _write_synthetic_detectrl_x_cache(tmp: Path) -> Path:
    """Write a small synthetic DetectRL-X cache (12 human + 12 machine rows)."""
    cache_dir = tmp / "cache"
    spec = get_spec("detectrl_x")
    human_text = " ".join(["The committee reviewed the annual report and noted the findings."] * 12)
    machine_text = " ".join(
        ["Moreover the systematic analysis demonstrates significant outcomes."] * 12
    )
    langs = ["english", "arabic", "chinese"]
    models = ["gpt-4o", "deepseek-v3"]
    domains = ["Wiki", "News"]
    rows = [
        NormalizedRow(
            text=human_text,
            label=0,
            dataset="detectrl_x",
            config="binary",
            split="train",
            source_id=f"detectrl-x:Binary/binary_general_open.json:{i}:human",
            regime="raw",
            meta={
                "lang": langs[i % 3],
                "model": models[i % 2],
                "split": "train",
                "domain": domains[i % 2],
                "file": "Binary/binary_general_open.json",
            },
        )
        for i in range(12)
    ] + [
        NormalizedRow(
            text=machine_text,
            label=1,
            dataset="detectrl_x",
            config="binary",
            split="train",
            source_id=f"detectrl-x:Binary/binary_general_open.json:{i}:llm",
            regime="raw",
            meta={
                "lang": langs[i % 3],
                "model": models[i % 2],
                "split": "train",
                "domain": domains[i % 2],
                "file": "Binary/binary_general_open.json",
            },
        )
        for i in range(12)
    ]
    write_sample_cache(spec, "binary", "train", rows, cache_dir=cache_dir)
    return cache_dir


def _write_fake_u7_repo(
    tmp: Path, *, key: str = "mage", run_date: str = "20261106", artifact_sha: str | None = None
) -> Path:
    """Create a synthetic repo root with a fake U7 artifact + registry."""
    slug = key.replace("_", "-")
    runs_dir = tmp / "docs" / "evidence" / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    artifact = {
        "schema": "textforensics.run-artifact/v1",
        "evidence_record_id": f"EV-{run_date}-dataset-{slug}",
        "kind": "command",
        "command": f"python scripts/measure_datasets.py --only {key}",
        "code_version": "a" * 40,
        "run_date": f"{run_date[:4]}-{run_date[4:6]}-{run_date[6:]}",
        "results": {},
        "drops": [],
        "badge": "available",
    }
    artifact_path = runs_dir / f"EV-{run_date}-dataset-{slug}.json"
    artifact_path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n")
    sha = artifact_sha or hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    registry = {
        "schema": "textforensics.evidence-registry/v1",
        "records": [
            {
                "evidence_record_id": f"EV-{run_date}-dataset-{slug}",
                "run_artifact": f"docs/evidence/runs/EV-{run_date}-dataset-{slug}.json",
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


def _write_synthetic_ghostwriter_cache(tmp: Path) -> Path:
    """Write a small synthetic GhostWriter cache (12 human + 12 machine + 4 fusion)."""
    cache_dir = tmp / "cache"
    spec = get_spec("ghostwriter")
    human_text = " ".join(["The committee reviewed the annual report and noted the findings."] * 12)
    machine_text = " ".join(
        ["Moreover the systematic analysis demonstrates significant outcomes."] * 12
    )
    fusion_text = " ".join(["The report therefore combines the earlier findings."] * 12)
    rows = (
        [
            NormalizedRow(
                text=human_text,
                label=0,
                dataset="ghostwriter",
                config="default",
                split="train",
                source_id=f"synthetic-human-{i}",
                regime="raw",
                meta={"domain": "cnn_news", "agent": "human", "lang": "en-EN", "type": "fulltext"},
            )
            for i in range(12)
        ]
        + [
            NormalizedRow(
                text=machine_text,
                label=1,
                dataset="ghostwriter",
                config="default",
                split="train",
                source_id=f"synthetic-machine-{i}",
                regime="raw",
                meta={
                    "domain": "bundestag",
                    "agent": "gpt-4o-mini",
                    "lang": "de-DE",
                    "type": "fulltext",
                },
            )
            for i in range(12)
        ]
        + [
            NormalizedRow(
                text=fusion_text,
                label=None,
                dataset="ghostwriter",
                config="default",
                split="train",
                source_id=f"synthetic-fusion-{i}",
                regime="mixed-origin",
                meta={
                    "domain": "gutenberg",
                    "agent": "gemma2:9b",
                    "lang": "en-EN",
                    "type": "chunk",
                },
            )
            for i in range(4)
        ]
    )
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

    def test_verify_run_artifact_uses_run_date_not_hardcoded_date(self, seed):
        # No EV-20261106 date is baked in: the GhostWriter artifact is
        # dated 20261107 and is found by auto-detection and by stamp.
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = _write_fake_u7_repo(Path(tmpdir), key="ghostwriter", run_date="20261107")
            proven = seed.verify_run_artifact("ghostwriter", repo_root=repo)
            assert proven["run_id"] == "EV-20261107-dataset-ghostwriter"
            assert proven["run_date"] == "2026-11-07"
            proven2 = seed.verify_run_artifact("ghostwriter", repo_root=repo, run_date="20261107")
            assert proven2["run_id"] == proven["run_id"]
            with pytest.raises(ValueError, match="missing"):
                seed.verify_run_artifact("ghostwriter", repo_root=repo, run_date="20261106")

    def test_verify_run_artifact_auto_detect_prefers_latest(self, seed):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            _write_fake_u7_repo(tmp, key="mage", run_date="20261106")
            _write_fake_u7_repo(tmp, key="mage", run_date="20261107")
            proven = seed.verify_run_artifact("mage", repo_root=tmp)
            assert proven["run_id"] == "EV-20261107-dataset-mage"


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

    def test_build_ghostwriter_record_dual_validates_and_excludes_fusion(self, seed):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            repo = _write_fake_u7_repo(tmp / "repo", key="ghostwriter", run_date="20261107")
            cache_dir = _write_synthetic_ghostwriter_cache(tmp)
            record, _measurements = seed.build_record(
                "ghostwriter", cache_dir=cache_dir, repo_root=repo
            )
            assert validate_evidence_record(record.to_dict()) == []
            assert validate_record(record.to_dict()) == []
            assert record.data.dataset_name == "GhostWriter"
            assert record.metrics[0].n_human == 12
            assert record.metrics[0].n_ai == 12
            assert record.regime.language == "mul"
            assert record.regime.domain == ("bundestag", "cnn_news")
            assert record.regime.generator.families == ("gpt-4o-mini",)
            assert record.limits.next_revalidation_due == "2027-02-05"
            assert any("fusion" in drop.item for drop in record.run.drops_manifest)

    def test_build_detectrl_x_record_dual_validates(self, seed):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            repo = _write_fake_u7_repo(tmp / "repo", key="detectrl_x", run_date="20261107")
            cache_dir = _write_synthetic_detectrl_x_cache(tmp)
            record, _measurements = seed.build_record(
                "detectrl_x", cache_dir=cache_dir, repo_root=repo
            )
            assert validate_evidence_record(record.to_dict()) == []
            assert validate_record(record.to_dict()) == []
            assert record.data.dataset_name == "DetectRL-X"
            assert record.metrics[0].n_human == 12
            assert record.metrics[0].n_ai == 12
            assert record.regime.language == "mul"
            assert record.regime.script == "mul"
            assert record.regime.domain == ("News", "Wiki")
            assert record.regime.generator.families == ("deepseek-v3", "gpt-4o")
            assert record.limits.next_revalidation_due == "2027-02-05"
            assert "non-commercial academic research only" in record.data.licence

    def test_check_mode_builds_detectrl_x_without_writing(self, seed):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            repo = _write_fake_u7_repo(tmp / "repo", key="detectrl_x", run_date="20261107")
            cache_dir = _write_synthetic_detectrl_x_cache(tmp)
            exit_code = seed.main(
                [
                    "--only",
                    "detectrl_x",
                    "--check",
                    "--cache-dir",
                    str(cache_dir),
                    "--repo-root",
                    str(repo),
                ]
            )
            assert exit_code == 0
            assert not (repo / "docs" / "validation" / "registry.json").exists()

    def test_check_mode_builds_ghostwriter_without_writing(self, seed):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            repo = _write_fake_u7_repo(tmp / "repo", key="ghostwriter", run_date="20261107")
            cache_dir = _write_synthetic_ghostwriter_cache(tmp)
            exit_code = seed.main(
                [
                    "--only",
                    "ghostwriter",
                    "--check",
                    "--cache-dir",
                    str(cache_dir),
                    "--repo-root",
                    str(repo),
                ]
            )
            assert exit_code == 0
            assert not (repo / "docs" / "validation" / "registry.json").exists()


class TestAppendMode:
    def test_append_keeps_existing_records_untouched(self, seed):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            repo = _write_fake_u7_repo(tmp / "repo", key="ghostwriter", run_date="20261107")
            cache_dir = _write_synthetic_ghostwriter_cache(tmp)
            mage_record, _ = seed.record_from_triples(
                "mage",
                _synthetic_triples(),
                word_counts=[100] * 80,
                domains=["synthetic-domain"],
                generators=["synthetic-generator"],
                artifact=_synthetic_artifact(),
                cache_file_sha256="c" * 64,
            )
            existing = ValidationRegistry([mage_record])
            registry_path = tmp / "registry.json"
            existing.save(registry_path)
            args = [
                "--only",
                "ghostwriter",
                "--append",
                "--cache-dir",
                str(cache_dir),
                "--repo-root",
                str(repo),
                "--registry",
                str(registry_path),
            ]
            assert seed.main(args) == 0
            reloaded = ValidationRegistry.load(registry_path)
            assert len(reloaded.records) == 2
            assert reloaded.record("evr-20261107-ghostwriter-builtin-heuristic") is not None
            kept = next(r for r in reloaded.records if r.record_id == mage_record.record_id)
            assert kept.to_dict() == mage_record.to_dict()
            # Appending the same record again is refused.
            assert seed.main(args) == 2
            assert len(ValidationRegistry.load(registry_path).records) == 2


class TestSeededRegistry:
    def test_committed_registry_loads_with_seven_records_and_no_mixset(self):
        registry = ValidationRegistry.load(REPO_ROOT / "docs" / "validation" / "registry.json")
        assert len(registry.records) == 7
        assert [record.record_id for record in registry.records] == [
            "evr-20261106-beemo-builtin-heuristic",
            "evr-20261106-mage-builtin-heuristic",
            "evr-20261106-opai-bench-builtin-heuristic",
            "evr-20261106-raid-builtin-heuristic",
            "evr-20261107-detectrl-x-builtin-heuristic",
            "evr-20261107-ghostwriter-builtin-heuristic",
            # Segment-level record (U4): sorted last by record_id; it
            # must never auto-match a Trust Map dimension (regime
            # LLM-edited), so the per-record assertions below apply
            # to it exactly as to the document records.
            "evr-20261107-opai-bench-builtin-heuristic",
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


# ---------------------------------------------------------------------------
# Phase 5 RAID humans-100: re-seed overrides + the supported gate
# ---------------------------------------------------------------------------


def _passing_triples():
    """100 human + 100 machine triples that pass all 8 support conditions.

    Human scores stay below machine scores (AUROC 1.0), no human row
    verdicts ai_like (native FPR 0/100), and abstentions are spread
    evenly so no metric is degenerate.
    """
    triples = []
    for i in range(100):
        score = round(0.15 + 0.002 * i, 4)
        verdict = "abstain" if i % 10 == 0 else "human_like"
        triples.append((0, score, verdict))
    for i in range(100):
        score = round(0.55 + 0.002 * i, 4)
        verdict = "abstain" if i % 10 == 0 else "ai_like"
        triples.append((1, score, verdict))
    return triples


def _high_fpr_triples():
    """100 human + 100 machine triples with native FPR 0.10 (10/100)."""
    triples = []
    for i in range(100):
        score = round(0.15 + 0.002 * i, 4)
        verdict = "ai_like" if i < 10 else "human_like"
        triples.append((0, score, verdict))
    for i in range(100):
        score = round(0.55 + 0.002 * i, 4)
        verdict = "ai_like"
        triples.append((1, score, verdict))
    return triples


def _synthetic_artifact_20261108():
    artifact = _synthetic_artifact()
    artifact["run_id"] = "EV-20261108-synthetic-test"
    artifact["run_artifact"] = "docs/evidence/runs/EV-20261108-synthetic-test.json"
    artifact["run_date"] = "2026-11-08"
    return artifact


class TestReseedOverrides:
    def test_bootstrap_seed_override_changes_method_strings(self, seed):
        record, _measurements = seed.record_from_triples(
            "raid",
            _synthetic_triples(),
            word_counts=[100] * 80,
            domains=["synthetic-domain"],
            generators=["synthetic-generator"],
            artifact=_synthetic_artifact_20261108(),
            cache_file_sha256="c" * 64,
            bootstrap_seed=20261108,
        )
        assert record.metrics[0].auroc.method == "bootstrap, 1000 resamples, seed 20261108"
        assert record.run.seeds["bootstrap_seed"] == 20261108
        assert record.run.reporting_rules.endswith("seed 20261108")
        assert record.status == "partial"

    def test_record_id_and_supersedes_overrides(self, seed):
        record, _measurements = seed.record_from_triples(
            "raid",
            _synthetic_triples(),
            word_counts=[100] * 80,
            domains=["synthetic-domain"],
            generators=["synthetic-generator"],
            artifact=_synthetic_artifact_20261108(),
            cache_file_sha256="c" * 64,
            record_id="evr-20261108-raid-builtin-heuristic",
            supersedes="evr-20261106-raid-builtin-heuristic",
        )
        assert record.record_id == "evr-20261108-raid-builtin-heuristic"
        assert record.supersedes == "evr-20261106-raid-builtin-heuristic"
        assert verify_signature(record.to_dict())

    def test_text_overrides_replace_the_config_texts(self, seed):
        record, _measurements = seed.record_from_triples(
            "raid",
            _synthetic_triples(),
            word_counts=[100] * 80,
            domains=["synthetic-domain"],
            generators=["synthetic-generator"],
            artifact=_synthetic_artifact_20261108(),
            cache_file_sha256="c" * 64,
            known_failure_modes=["custom failure mode"],
            limitations_extra=["custom limitation"],
            appeal_note="custom appeal note",
        )
        assert list(record.limits.known_failure_modes) == ["custom failure mode"]
        assert "custom limitation" in record.limits.limitations
        assert record.limits.appeal_note == "custom appeal note"


class TestSupportedGate:
    def test_allow_supported_with_passing_triples_yields_supported(self, seed):
        record, measurements = seed.record_from_triples(
            "raid",
            _passing_triples(),
            word_counts=[100] * 200,
            domains=["synthetic-domain"],
            generators=["synthetic-generator"],
            artifact=_synthetic_artifact_20261108(),
            cache_file_sha256="c" * 64,
            bootstrap_seed=20261108,
            record_id="evr-20261108-raid-builtin-heuristic",
            supersedes="evr-20261106-raid-builtin-heuristic",
            allow_supported=True,
        )
        assert record.status == "supported"
        assert measurements["support_blockers"] == []
        assert effective_status(record, detector_version="0.1.0", now="2026-11-08") == "supported"
        assert validate_evidence_record(record.to_dict()) == []
        assert validate_record(record.to_dict()) == []
        assert verify_signature(record.to_dict())
        assert record.limits.next_revalidation_due == "2027-02-06"
        assert record.metrics[0].fpr_native.value == 0.0
        assert record.metrics[0].fpr_native.ci_upper == 0.0

    def test_allow_supported_with_thin_human_slice_stays_partial(self, seed):
        _record, measurements = seed.record_from_triples(
            "raid",
            _synthetic_triples(),
            word_counts=[100] * 80,
            domains=["synthetic-domain"],
            generators=["synthetic-generator"],
            artifact=_synthetic_artifact_20261108(),
            cache_file_sha256="c" * 64,
            allow_supported=True,
        )
        assert _record.status == "partial"
        assert any("n_human=40" in blocker for blocker in measurements["support_blockers"])

    def test_allow_supported_with_high_fpr_stays_partial(self, seed):
        _record, measurements = seed.record_from_triples(
            "raid",
            _high_fpr_triples(),
            word_counts=[100] * 200,
            domains=["synthetic-domain"],
            generators=["synthetic-generator"],
            artifact=_synthetic_artifact_20261108(),
            cache_file_sha256="c" * 64,
            allow_supported=True,
        )
        assert _record.status == "partial"
        assert any("ceiling" in blocker for blocker in measurements["support_blockers"])

    def test_supported_gate_defaults_off(self, seed):
        record, _measurements = seed.record_from_triples(
            "raid",
            _passing_triples(),
            word_counts=[100] * 200,
            domains=["synthetic-domain"],
            generators=["synthetic-generator"],
            artifact=_synthetic_artifact_20261108(),
            cache_file_sha256="c" * 64,
            bootstrap_seed=20261108,
        )
        assert record.status == "partial"
        assert "support_blockers" not in _measurements


class TestVerifyArtifactRegistryHold:
    def test_verify_run_artifact_without_registry_entry(self, seed):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = _write_fake_u7_repo(Path(tmpdir), key="raid", run_date="20261108")
            # The registry hold: the artifact exists but no entry pins it yet.
            (repo / "docs" / "evidence" / "registry.json").write_text(
                json.dumps({"schema": "textforensics.evidence-registry/v1", "records": []})
            )
            with pytest.raises(ValueError, match="no entry"):
                seed.verify_run_artifact("raid", repo_root=repo, run_date="20261108")
            proven = seed.verify_run_artifact(
                "raid", repo_root=repo, run_date="20261108", require_registry_entry=False
            )
            assert proven["run_id"] == "EV-20261108-dataset-raid"
            assert proven["run_date"] == "2026-11-08"
            assert len(proven["run_artifact_sha256"]) == 64


def _write_synthetic_raid_cache(tmp: Path) -> Path:
    """Write a small synthetic RAID cache as a second sample file."""
    cache_dir = tmp / "cache"
    spec = get_spec("raid")
    human_text = " ".join(["The committee reviewed the annual report and noted the findings."] * 12)
    machine_text = " ".join(
        ["Moreover the systematic analysis demonstrates significant outcomes."] * 12
    )
    rows = [
        NormalizedRow(
            text=human_text,
            label=0,
            dataset="raid",
            config="raid",
            split="train",
            source_id=f"synthetic-human-{i}",
            regime="raid",
            meta={"domain": "news", "model": "human"},
        )
        for i in range(12)
    ] + [
        NormalizedRow(
            text=machine_text,
            label=1,
            dataset="raid",
            config="raid",
            split="train",
            source_id=f"synthetic-machine-{i}",
            regime="raid",
            meta={"domain": "news", "model": "gpt4"},
        )
        for i in range(12)
    ]
    write_sample_cache(
        spec, "raid", "train", rows, cache_dir=cache_dir, filename="train-6000.jsonl"
    )
    return cache_dir


class TestBuildRecordReseed:
    def test_build_record_with_cache_filename_and_registry_hold(self, seed):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            repo = _write_fake_u7_repo(tmp / "repo", key="raid", run_date="20261108")
            (repo / "docs" / "evidence" / "registry.json").write_text(
                json.dumps({"schema": "textforensics.evidence-registry/v1", "records": []})
            )
            cache_dir = _write_synthetic_raid_cache(tmp)
            record, measurements = seed.build_record(
                "raid",
                cache_dir=cache_dir,
                repo_root=repo,
                run_date="20261108",
                cache_filename="train-6000.jsonl",
                bootstrap_seed=20261108,
                record_id="evr-20261108-raid-builtin-heuristic",
                supersedes="evr-20261106-raid-builtin-heuristic",
                allow_supported=True,
                require_registry_entry=False,
            )
            assert record.record_id == "evr-20261108-raid-builtin-heuristic"
            assert record.supersedes == "evr-20261106-raid-builtin-heuristic"
            assert record.run.run_id == "EV-20261108-dataset-raid"
            assert record.run.seeds["bootstrap_seed"] == 20261108
            assert record.limits.next_revalidation_due == "2027-02-06"
            assert record.metrics[0].n_human == 12
            assert record.metrics[0].n_ai == 12
            # 12 humans cannot support: the gate keeps it partial and says why.
            assert record.status == "partial"
            assert any("n_human=12" in blocker for blocker in measurements["support_blockers"])
            assert validate_evidence_record(record.to_dict()) == []
            assert validate_record(record.to_dict()) == []
            assert verify_signature(record.to_dict())
