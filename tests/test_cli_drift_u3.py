"""CLI tests for ``tf drift run`` / ``tf drift status`` (U3).

The frozen probe corpus and the probe-metrics primitives live on
branch u3-corpus and have not merged yet, so these tests inject
small fake ``textforensics.probe_corpus`` / ``textforensics.probe_metrics``
modules (built from the same closed-form helpers as
tests/test_probe_runs.py) and exercise the real CLI dispatch,
including the missing-module exit path.
"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

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
from tests.test_probe_runs_e2e import StubDetector, _build_corpus
from textforensics.cli import _run, build_parser
from textforensics.config import Settings
from textforensics.validation import ValidationRegistry

BUILTIN_ID = "textforensics/builtin-heuristic"


def _write_fixture_files(tmp_path: Path):
    manifest, texts, holdback = _build_corpus()
    manifest_path = tmp_path / "manifest.json"
    texts_path = tmp_path / "corpus.jsonl"
    holdback_path = tmp_path / "holdback.jsonl"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    texts_path.write_text(
        "".join(json.dumps({"item_id": k, "text": v}) + "\n" for k, v in texts.items()),
        encoding="utf-8",
    )
    holdback_path.write_text(
        "".join(json.dumps({"item_id": k, **v}) + "\n" for k, v in holdback.items()),
        encoding="utf-8",
    )
    return manifest, manifest_path, texts_path, holdback_path


def _fake_probe_corpus_module(*, fail_verification: bool = False):
    module = types.ModuleType("textforensics.probe_corpus")

    class FakeManifest:
        def __init__(self, data):
            self._data = data
            self.version = data["version"]

        @classmethod
        def from_dict(cls, data):
            return cls(data)

    def verify_corpus_files(corpus_path, holdback_path, manifest):
        if fail_verification:
            return ["synthetic verification failure (test double)"]
        texts = load_corpus_texts(corpus_path)
        labels = load_holdback(holdback_path)
        problems = []
        for item in manifest._data["items"]:
            if item["item_id"] not in texts:
                problems.append(f"missing text for {item['item_id']}")
            if item["item_id"] not in labels:
                problems.append(f"missing holdback for {item['item_id']}")
        return problems

    def load_corpus_texts(path):
        texts = {}
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if line.strip():
                record = json.loads(line)
                texts[record["item_id"]] = record["text"]
        return texts

    def load_holdback(path):
        labels = {}
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if line.strip():
                record = json.loads(line)
                labels[record["item_id"]] = record
        return labels

    module.ProbeCorpusManifest = FakeManifest
    module.verify_corpus_files = verify_corpus_files
    module.load_corpus_texts = load_corpus_texts
    module.load_holdback = load_holdback
    return module


def _fake_probe_metrics_module():
    module = types.ModuleType("textforensics.probe_metrics")
    for name, fn in {
        "wilson_ci": _wilson_ci,
        "ks_statistic": _ks_statistic,
        "ks_pvalue": _ks_pvalue,
        "psi": _psi,
        "flip_summary": _flip_summary,
        "ece": _ece,
        "brier": _brier,
        "set_coverage": _set_coverage,
        "coverage_shortfall_pp": _coverage_shortfall_pp,
        "fpr_at_threshold": _fpr_at_threshold,
        "worst_slice_fpr": _worst_slice_fpr,
        "tpr_at_fpr": _tpr_at_fpr,
        "abstention_rate": _abstention_rate,
        "metadata_diff": _metadata_diff,
        "holm_adjusted": _holm_adjusted,
    }.items():
        setattr(module, name, fn)
    return module


@pytest.fixture
def fake_modules(monkeypatch):
    monkeypatch.setitem(sys.modules, "textforensics.probe_corpus", _fake_probe_corpus_module())
    monkeypatch.setitem(sys.modules, "textforensics.probe_metrics", _fake_probe_metrics_module())


def _cli(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    return _run(args, Settings())


def _registry_file(tmp_path: Path, detector_id: str = BUILTIN_ID) -> Path:
    from tests.test_validation_trustmap import make_record_dict, registry_of

    path = tmp_path / "registry.json"
    record = make_record_dict(detector_id=detector_id, detector_version="0.1.0")
    registry_of(record).save(path)
    return path


def test_drift_run_without_corpus_module_exits_2(tmp_path, monkeypatch, capsys):
    manifest, manifest_path, texts_path, holdback_path = _write_fixture_files(tmp_path)
    monkeypatch.delitem(sys.modules, "textforensics.probe_corpus", raising=False)
    code = _cli(
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
            str(tmp_path / "runs"),
        ]
    )
    assert code == 2
    captured = capsys.readouterr()
    assert "not available yet" in captured.err
    assert list((tmp_path / "runs").glob("run-*.json")) == []


def test_drift_run_full_succeeds(tmp_path, fake_modules, capsys):
    manifest, manifest_path, texts_path, holdback_path = _write_fixture_files(tmp_path)
    runs_dir = tmp_path / "runs"
    registry_path = _registry_file(tmp_path)
    code = _cli(
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
            str(registry_path),
        ]
    )
    assert code == 0
    runs = list(runs_dir.glob("run-*.json"))
    assert len(runs) == 1
    run = json.loads(runs[0].read_text(encoding="utf-8"))
    assert run["is_baseline"] is True
    assert run["metrics"]["overall"]["n"] == 470
    assert "lorem ipsum" not in json.dumps(run)
    captured = capsys.readouterr()
    assert "baseline: yes" in captured.out
    assert "longitudinal:" in captured.out


def test_drift_run_unknown_detector_exits_3(tmp_path, fake_modules, capsys):
    _, manifest_path, texts_path, holdback_path = _write_fixture_files(tmp_path)
    code = _cli(
        [
            "drift",
            "run",
            "--manifest",
            str(manifest_path),
            "--texts",
            str(texts_path),
            "--holdback",
            str(holdback_path),
            "--detector-id",
            "test/no-such-detector",
            "--runs-dir",
            str(tmp_path / "runs"),
        ]
    )
    assert code == 3
    assert "unknown detector" in capsys.readouterr().err


def test_drift_run_wrong_detector_version_exits_3(tmp_path, fake_modules, capsys):
    _, manifest_path, texts_path, holdback_path = _write_fixture_files(tmp_path)
    code = _cli(
        [
            "drift",
            "run",
            "--manifest",
            str(manifest_path),
            "--texts",
            str(texts_path),
            "--holdback",
            str(holdback_path),
            "--detector-version",
            "9.9.9",
            "--runs-dir",
            str(tmp_path / "runs"),
        ]
    )
    assert code == 3
    assert "not '9.9.9'" in capsys.readouterr().err


def test_drift_run_corpus_verification_failure_exits_3(tmp_path, monkeypatch, capsys):
    _, manifest_path, texts_path, holdback_path = _write_fixture_files(tmp_path)
    monkeypatch.setitem(
        sys.modules,
        "textforensics.probe_corpus",
        _fake_probe_corpus_module(fail_verification=True),
    )
    monkeypatch.setitem(sys.modules, "textforensics.probe_metrics", _fake_probe_metrics_module())
    code = _cli(
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
            str(tmp_path / "runs"),
        ]
    )
    assert code == 3
    assert "verification failed" in capsys.readouterr().err


def test_drift_run_fail_on_tier1(tmp_path, fake_modules, monkeypatch, capsys):
    """A Tier-1 run exits 0 normally and 1 with --fail-on-tier1."""
    from textforensics.detectors import DetectorRegistry

    _, manifest_path, texts_path, holdback_path = _write_fixture_files(tmp_path)
    runs_dir = tmp_path / "runs"
    registry_path = _registry_file(tmp_path, detector_id=StubDetector.detector_id)

    def fake_registry():
        return DetectorRegistry(detectors={StubDetector.detector_id: StubDetector(flip_human=True)})

    monkeypatch.setattr("textforensics.detectors.discover_detector_registry", fake_registry)
    base = [
        "drift",
        "run",
        "--manifest",
        str(manifest_path),
        "--texts",
        str(texts_path),
        "--holdback",
        str(holdback_path),
        "--detector-id",
        StubDetector.detector_id,
        "--runs-dir",
        str(runs_dir),
        "--registry",
        str(registry_path),
    ]
    # The flip detector's first run is its own baseline, but the FPR
    # cap rule is absolute: human FPR 1.0 on the claimable
    # human-native slice already fires Tier 1 and demotes. Exit 0
    # either way without --fail-on-tier1 (a Tier-1 demotion is an
    # expected outcome, not a CLI failure).
    assert _cli(base) == 0
    # Second run: human FPR 1.0 again, Tier 1 again.
    assert _cli(base) == 0
    capsys.readouterr()
    assert _cli([*base, "--fail-on-tier1"]) == 1
    captured = capsys.readouterr()
    assert "Tier-1" in captured.out


def test_drift_status_no_runs(tmp_path, capsys):
    code = _cli(
        [
            "drift",
            "status",
            "--detector-id",
            BUILTIN_ID,
            "--runs-dir",
            str(tmp_path / "runs"),
        ]
    )
    assert code == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "no_runs"
    assert payload["consecutive_clean_full_runs"] == 0


def test_drift_status_with_runs(tmp_path, fake_modules, capsys):
    _, manifest_path, texts_path, holdback_path = _write_fixture_files(tmp_path)
    runs_dir = tmp_path / "runs"
    base = [
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
        str(_registry_file(tmp_path)),
    ]
    assert _cli(base) == 0
    assert _cli(base) == 0
    capsys.readouterr()  # drain the drift-run human output
    code = _cli(["drift", "status", "--detector-id", BUILTIN_ID, "--runs-dir", str(runs_dir)])
    assert code == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["consecutive_clean_full_runs"] == 2
    assert payload["temporal_support"] is True
    assert payload["total_runs"] == 2
    assert payload["demotions"] == []
    assert "temporal support: yes" in captured.err


def test_drift_status_shows_demotions(tmp_path, fake_modules, monkeypatch, capsys):
    from textforensics.detectors import DetectorRegistry

    _, manifest_path, texts_path, holdback_path = _write_fixture_files(tmp_path)
    runs_dir = tmp_path / "runs"
    registry_path = _registry_file(tmp_path, detector_id=StubDetector.detector_id)

    def fake_registry():
        return DetectorRegistry(detectors={StubDetector.detector_id: StubDetector(flip_human=True)})

    monkeypatch.setattr("textforensics.detectors.discover_detector_registry", fake_registry)
    base = [
        "drift",
        "run",
        "--manifest",
        str(manifest_path),
        "--texts",
        str(texts_path),
        "--holdback",
        str(holdback_path),
        "--detector-id",
        StubDetector.detector_id,
        "--runs-dir",
        str(runs_dir),
        "--registry",
        str(registry_path),
    ]
    assert _cli(base) == 0
    assert _cli(base) == 0
    reloaded = ValidationRegistry.load(registry_path)
    assert any(r.limits.demoted_by for r in reloaded.records)
    capsys.readouterr()  # drain the drift-run human output
    code = _cli(
        [
            "drift",
            "status",
            "--detector-id",
            StubDetector.detector_id,
            "--runs-dir",
            str(runs_dir),
            "--registry",
            str(registry_path),
        ]
    )
    assert code == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert len(payload["demotions"]) == 1
    assert payload["demotions"][0]["effective_status"] == "stale"
    assert "Active U3 demotions: 1 record(s) stale." in captured.err
