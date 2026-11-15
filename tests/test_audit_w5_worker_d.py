"""W5 Worker D regression tests — CLI surface + state transport (audit wave W5).

Written red-first against main ``3952384`` (W4 merged).

- Item 1: ``benchmark --calibration-dataset`` — the CLI benchmark command
  can supply a calibration dataset, compute its fingerprint, prove
  disjointness, and produce a verified held-out run (or fail closed).
- Item 2: ``schema validate --type`` — the ``--type`` choices align with
  the 13-name packaged schema registry.
- Item 3: nontransactional state exports — observatory / model-card /
  codec / probe-corpus exports commit atomically, and a failed probe-run
  manifest save never leaves a demotion/clearing citing a missing run.
- Item 4: codec features — migration callbacks are actually dispatched,
  streaming is bounded, and the schema-version map matches the generic
  validator (trust-map current is v3, as the shipped schema accepts).

All fixtures are synthetic; no real user text, accounts, or keys.
"""

from __future__ import annotations

import hashlib
import json
import sys
import threading
import tracemalloc
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path

import pytest

from textforensics.cli import main as cli_main
from textforensics.constants import EXIT_ERROR, EXIT_OK

CAL_HUMAN = "I tested the device this morning and it worked as expected."
CAL_AI = "Furthermore, this robust solution seamlessly unlocks potential."
EVAL_HUMAN = "I tested the device this afternoon and it failed outright."
EVAL_AI = "Moreover, this approach is fundamentally flawed and fails badly."
SHARED_TEXT = "I tested the device this morning and it worked as expected."


def _run_cli(argv: list[str]) -> tuple[int, str, str]:
    """Run the CLI in-process; return (exit_code, stdout, stderr)."""
    old_argv, old_stdout, old_stderr = sys.argv, sys.stdout, sys.stderr
    try:
        sys.argv = ["textforensics", *argv]
        sys.stdout, sys.stderr = StringIO(), StringIO()
        try:
            code = cli_main()
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else EXIT_ERROR
        return code, sys.stdout.getvalue(), sys.stderr.getvalue()
    finally:
        sys.argv, sys.stdout, sys.stderr = old_argv, old_stdout, old_stderr


def _write_jsonl(path: Path, human: str, ai: str) -> Path:
    path.write_text(
        json.dumps({"label": "human", "text": human})
        + "\n"
        + json.dumps({"label": "ai", "text": ai})
        + "\n",
        encoding="utf-8",
    )
    return path


def _calibrate_via_cli(tmp_path: Path, dataset: Path) -> Path:
    artifact = tmp_path / "calibration.json"
    code, out, err = _run_cli(
        ["calibrate", str(dataset), "--target-fpr", "0.0", "--output", str(artifact)]
    )
    assert code == EXIT_OK, err
    assert json.loads(artifact.read_text(encoding="utf-8"))["recommended_threshold"] is not None
    return artifact


# ---------------------------------------------------------------------------
# Item 1 — benchmark --calibration-dataset
# ---------------------------------------------------------------------------


class TestBenchmarkCalibrationDataset:
    def test_disjoint_calibration_dataset_yields_verified_held_out_run(self, tmp_path):
        cal = _write_jsonl(tmp_path / "cal.jsonl", CAL_HUMAN, CAL_AI)
        ev = _write_jsonl(tmp_path / "eval.jsonl", EVAL_HUMAN, EVAL_AI)
        artifact = _calibrate_via_cli(tmp_path, cal)
        code, out, err = _run_cli(
            [
                "benchmark",
                str(ev),
                "--calibration",
                str(artifact),
                "--calibration-dataset",
                str(cal),
            ]
        )
        assert code == EXIT_OK, err
        result = json.loads(out)
        assert result["mode"] == "held_out_evaluation"
        assert result["disjointness_status"] == "verified"
        assert result["overlap_count"] == 0
        # The proof is recorded on the run, with the calibration fingerprint.
        proof = result["disjointness_proof"]
        assert proof["status"] == "verified"
        assert proof["training_hash"] == result["calibration_dataset_sha256"]
        assert proof["training_hash"] == hashlib.sha256(cal.read_bytes()).hexdigest()
        assert proof["evaluation_hash"] == result["dataset_sha256"]
        assert proof["group_overlap_count"] == 0

    def test_calibration_dataset_without_artifact_fits_then_verifies(self, tmp_path):
        cal = _write_jsonl(tmp_path / "cal.jsonl", CAL_HUMAN, CAL_AI)
        ev = _write_jsonl(tmp_path / "eval.jsonl", EVAL_HUMAN, EVAL_AI)
        code, out, err = _run_cli(["benchmark", str(ev), "--calibration-dataset", str(cal)])
        assert code == EXIT_OK, err
        result = json.loads(out)
        assert result["mode"] == "held_out_evaluation"
        assert result["disjointness_status"] == "verified"
        assert (
            result["disjointness_proof"]["training_hash"]
            == hashlib.sha256(cal.read_bytes()).hexdigest()
        )

    def test_same_dataset_fails_closed_never_verified(self, tmp_path):
        data = _write_jsonl(tmp_path / "data.jsonl", CAL_HUMAN, CAL_AI)
        artifact = _calibrate_via_cli(tmp_path, data)
        code, out, err = _run_cli(
            [
                "benchmark",
                str(data),
                "--calibration",
                str(artifact),
                "--calibration-dataset",
                str(data),
            ]
        )
        assert code == EXIT_ERROR, out
        assert "calibration dataset" in err.lower()
        assert "held_out_evaluation" not in out

    def test_contaminated_pair_fails_closed_never_verified(self, tmp_path):
        # The evaluation file reuses one calibration row verbatim.
        cal = _write_jsonl(tmp_path / "cal.jsonl", CAL_HUMAN, CAL_AI)
        ev = _write_jsonl(tmp_path / "eval.jsonl", SHARED_TEXT, EVAL_AI)
        artifact = _calibrate_via_cli(tmp_path, cal)
        code, out, err = _run_cli(
            [
                "benchmark",
                str(ev),
                "--calibration",
                str(artifact),
                "--calibration-dataset",
                str(cal),
            ]
        )
        assert code == EXIT_ERROR, out
        assert "contaminat" in err.lower()
        assert "held_out_evaluation" not in out

    def test_artifact_fingerprint_mismatch_fails_closed(self, tmp_path):
        cal_a = _write_jsonl(tmp_path / "cal-a.jsonl", CAL_HUMAN, CAL_AI)
        cal_b = _write_jsonl(tmp_path / "cal-b.jsonl", EVAL_HUMAN, EVAL_AI)
        ev = _write_jsonl(
            tmp_path / "eval.jsonl", "A third human sentence here.", "A third ai sentence here."
        )
        artifact = _calibrate_via_cli(tmp_path, cal_a)
        code, out, err = _run_cli(
            [
                "benchmark",
                str(ev),
                "--calibration",
                str(artifact),
                "--calibration-dataset",
                str(cal_b),
            ]
        )
        assert code == EXIT_ERROR, out
        assert "fingerprint" in err.lower() or "mismatch" in err.lower()
        assert "held_out_evaluation" not in out

    def test_allow_same_dataset_is_diagnostic_never_verified(self, tmp_path):
        data = _write_jsonl(tmp_path / "data.jsonl", CAL_HUMAN, CAL_AI)
        artifact = _calibrate_via_cli(tmp_path, data)
        code, out, err = _run_cli(
            [
                "benchmark",
                str(data),
                "--calibration",
                str(artifact),
                "--calibration-dataset",
                str(data),
                "--allow-same-dataset",
            ]
        )
        assert code == EXIT_OK, err
        result = json.loads(out)
        assert result["mode"] == "diagnostic"
        assert result["disjointness_status"] == "contaminated"
        assert result["disjointness_proof"]["status"] == "contaminated"

    def test_calibration_dataset_conflicts_with_fixed_threshold(self, tmp_path):
        cal = _write_jsonl(tmp_path / "cal.jsonl", CAL_HUMAN, CAL_AI)
        ev = _write_jsonl(tmp_path / "eval.jsonl", EVAL_HUMAN, EVAL_AI)
        code, out, err = _run_cli(
            ["benchmark", str(ev), "--threshold", "0.5", "--calibration-dataset", str(cal)]
        )
        assert code == EXIT_ERROR, out
        assert "threshold" in err.lower()


# ---------------------------------------------------------------------------
# Item 2 — schema validate --type covers the 13-name registry
# ---------------------------------------------------------------------------


class TestSchemaValidateAllNames:
    def test_validate_succeeds_for_every_packaged_schema(self, tmp_path):
        from test_schema import _valid_payloads, minimal_evidence_record

        from textforensics.casefile import seal_case_file
        from textforensics.report import build_forensic_bundle
        from textforensics.schema import list_schemas

        text = (
            "I tested the device twice yesterday and wrote down what changed. "
            "The second run was warmer, so I plan to repeat it before drawing conclusions."
        )
        payloads = _valid_payloads()
        payloads["evidence-record"] = minimal_evidence_record()
        bundle = build_forensic_bundle(text).to_dict()
        payloads["forensic-bundle"] = bundle
        payloads["case-file"] = seal_case_file(bundle)
        payloads["trust-map"] = bundle["trust_map"]
        payloads["detector-result"] = bundle["detector_results"][0]
        payloads["enterprise-policy"] = {
            "revision": 1,
            "settings": {},
            "rules": [
                {
                    "id": "synthetic-rule",
                    "description": "synthetic",
                    "action": "warn",
                    "scope": "global",
                }
            ],
        }
        assert set(payloads) == set(list_schemas())
        assert len(list_schemas()) == 13
        for name in sorted(payloads):
            target = tmp_path / f"{name}.json"
            target.write_text(json.dumps(payloads[name]), encoding="utf-8")
            code, out, err = _run_cli(["schema", "validate", str(target), "--type", name])
            assert code == EXIT_OK, f"{name}: {err} {out}"
            assert json.loads(out)["valid"] is True, f"{name}: {out}"

    def test_validate_unknown_type_fails_listing_valid_names(self, tmp_path):
        target = tmp_path / "x.json"
        target.write_text("{}", encoding="utf-8")
        code, out, err = _run_cli(["schema", "validate", str(target), "--type", "not-a-schema"])
        assert code != EXIT_OK
        combined = out + err
        assert "not-a-schema" in combined
        for name in ("forensic-bundle", "probe-run", "evidence-record", "trust-map"):
            assert name in combined

    def test_validate_invalid_payload_still_fails(self, tmp_path):
        target = tmp_path / "bad.json"
        target.write_text("{}", encoding="utf-8")
        code, out, err = _run_cli(["schema", "validate", str(target), "--type", "probe-run"])
        assert code != EXIT_OK
        assert json.loads(out)["valid"] is False


# ---------------------------------------------------------------------------
# Item 3 — nontransactional state exports (atomic commit + probe-run order)
# ---------------------------------------------------------------------------


def _seed(path: Path, content: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


class TestAtomicExports:
    """A failed write leaves the previous good file, never a half-written one."""

    def test_save_snapshots_failure_keeps_previous_file(self, tmp_path, monkeypatch):
        from textforensics.observatory import DriftObservatory

        corpus = {
            "schema": "textforensics.drift-corpus/v1",
            "samples": [
                {
                    "id": "s1",
                    "text": "a probe sentence with enough words to pass checks here",
                }
            ],
        }
        obs = DriftObservatory(corpus=corpus)
        store = tmp_path / "store.json"
        obs.save_snapshots(store)
        previous = store.read_bytes()
        assert previous

        def _boom(*args, **kwargs):
            raise OSError("synthetic disk failure")

        monkeypatch.setattr("os.replace", _boom)
        with pytest.raises(OSError, match="synthetic disk failure"):
            obs.save_snapshots(store)
        assert store.read_bytes() == previous
        assert list(tmp_path.glob(".store.json.*.tmp")) == []

    def test_save_snapshots_fsync_failure_keeps_previous_file(self, tmp_path, monkeypatch):
        from textforensics.observatory import DriftObservatory

        corpus = {
            "schema": "textforensics.drift-corpus/v1",
            "samples": [
                {
                    "id": "s1",
                    "text": "a probe sentence with enough words to pass checks here",
                }
            ],
        }
        obs = DriftObservatory(corpus=corpus)
        store = tmp_path / "store.json"
        obs.save_snapshots(store)
        previous = store.read_bytes()

        def _boom(fd):
            raise OSError("synthetic fsync failure")

        monkeypatch.setattr("os.fsync", _boom)
        with pytest.raises(OSError, match="synthetic fsync failure"):
            obs.save_snapshots(store)
        assert store.read_bytes() == previous

    def test_health_report_save_failure_returns_false_and_keeps_previous(
        self, tmp_path, monkeypatch
    ):
        from textforensics.observatory import DetectorHealthReport, HealthState

        report = DetectorHealthReport(
            detector_id="test/detector",
            overall_state=HealthState.HEALTHY,
            health_score=0.9,
        )
        path = _seed(tmp_path / "health.json", b'{"previous": true}\n')
        previous = path.read_bytes()

        def _boom(*args, **kwargs):
            raise OSError("synthetic disk failure")

        monkeypatch.setattr("os.replace", _boom)
        assert report.save(path) is False
        assert path.read_bytes() == previous

    def _model_card(self):
        from textforensics.model_card import (
            IntendedUse,
            ModelCard,
            ModelCardMetadata,
            ModelDetails,
        )

        return ModelCard(
            metadata=ModelCardMetadata(
                version="1.0.0",
                generated_at="2024-01-01T00:00:00+00:00",
                generated_by="Test",
                schema_version="1.0.0",
                language="en",
            ),
            model_details=ModelDetails(
                name="Test Detector",
                version="1.0.0",
                detector_id="test/detector",
                detector_family="test",
                architecture="transformer",
                framework="pytorch",
                license="Apache-2.0",
                owner="Test",
                contact="test@example.invalid",
                references=[],
                tags=[],
            ),
            intended_use=IntendedUse(
                primary_use_cases=["AI text detection"],
                out_of_scope=["Creative writing"],
                target_users=["Researchers"],
                deployment_environments=["On-premise"],
                constraints=[],
            ),
        )

    def test_model_card_save_json_failure_keeps_previous(self, tmp_path, monkeypatch):
        card = self._model_card()
        path = _seed(tmp_path / "card.json", b'{"previous": true}\n')
        previous = path.read_bytes()

        def _boom(*args, **kwargs):
            raise OSError("synthetic disk failure")

        monkeypatch.setattr("os.replace", _boom)
        assert card.save_json(path) is False
        assert path.read_bytes() == previous

    def test_model_card_save_markdown_failure_keeps_previous(self, tmp_path, monkeypatch):
        card = self._model_card()
        path = _seed(tmp_path / "card.md", b"# previous\n")
        previous = path.read_bytes()

        def _boom(*args, **kwargs):
            raise OSError("synthetic disk failure")

        monkeypatch.setattr("os.replace", _boom)
        assert card.save_markdown(path) is False
        assert path.read_bytes() == previous

    def test_codec_encode_file_failure_keeps_previous(self, tmp_path, monkeypatch):
        from test_result_codec import MINIMAL_BUNDLE

        from textforensics.result_codec import ResultCodec

        path = _seed(tmp_path / "result.json", b'{"previous": true}\n')
        previous = path.read_bytes()

        def _boom(*args, **kwargs):
            raise OSError("synthetic disk failure")

        monkeypatch.setattr("os.replace", _boom)
        with pytest.raises(OSError, match="synthetic disk failure"):
            ResultCodec().encode_file(dict(MINIMAL_BUNDLE), path, "forensic-bundle")
        assert path.read_bytes() == previous

    def test_probe_corpus_write_manifest_failure_keeps_previous(self, tmp_path, monkeypatch):
        from textforensics.probe_corpus import ProbeCorpusManifest, write_manifest

        manifest = ProbeCorpusManifest(
            version="1.0.0",
            created_at_utc="2026-11-06T00:00:00+00:00",
            items=(),
            items_sha256="a" * 64,
            holdback_sha256="b" * 64,
            corpus_file_sha256="c" * 64,
            sources={},
            current_generators={},
        )
        path = _seed(tmp_path / "manifest.json", b'{"previous": true}\n')
        previous = path.read_bytes()

        def _boom(*args, **kwargs):
            raise OSError("synthetic disk failure")

        monkeypatch.setattr("os.replace", _boom)
        with pytest.raises(OSError, match="synthetic disk failure"):
            write_manifest(path, manifest)
        assert path.read_bytes() == previous

    def test_successful_saves_still_round_trip(self, tmp_path):
        from textforensics.observatory import DriftObservatory
        from textforensics.probe_corpus import (
            ProbeCorpusManifest,
            load_manifest,
            write_manifest,
        )

        manifest = ProbeCorpusManifest(
            version="1.0.0",
            created_at_utc="2026-11-06T00:00:00+00:00",
            items=(),
            items_sha256="a" * 64,
            holdback_sha256="b" * 64,
            corpus_file_sha256="c" * 64,
            sources={},
            current_generators={},
        )
        path = tmp_path / "manifest.json"
        write_manifest(path, manifest)
        assert load_manifest(path).version == "1.0.0"
        obs = DriftObservatory(
            corpus={
                "schema": "textforensics.drift-corpus/v1",
                "samples": [
                    {
                        "id": "s1",
                        "text": "a probe sentence with enough words to pass checks here",
                    }
                ],
            }
        )
        store = tmp_path / "store.json"
        obs.save_snapshots(store)
        assert obs.load_snapshots(store) == []


class TestProbeRunRegistryTransaction:
    """Registry mutation + run save commit together or not at all."""

    def _setup(self, tmp_path, *, n_items=8):
        from test_audit_w4_worker_b import _corpus, _registry_copy

        from textforensics.validation import load_validation_registry

        manifest, texts, holdback = _corpus(n_items)
        registry_path = _registry_copy(tmp_path)
        registry = load_validation_registry(registry_path)
        record = registry.records[0]
        return manifest, texts, holdback, registry_path, record

    def test_failed_run_save_restores_cleared_demotions(self, tmp_path, monkeypatch):
        from test_audit_w4_worker_b import _CleanDetector, apply_demotions

        from textforensics.probe_runs import perform_probe_run
        from textforensics.validation import load_validation_registry

        manifest, texts, holdback, registry_path, record = self._setup(tmp_path)
        detector = _CleanDetector()
        detector.detector_id = record.detector_id
        apply_demotions(
            registry_path=registry_path,
            detector_id=record.detector_id,
            run_id="run-pre",
            alerts=[{"tier": 1, "rule": "flip_rate"}],
        )
        before = registry_path.read_bytes()
        assert (
            load_validation_registry(registry_path).record(record.record_id).limits.demoted_by
            is not None
        )

        def _boom(*args, **kwargs):
            raise OSError("synthetic run-save failure")

        monkeypatch.setattr("textforensics.probe_runs.save_run", _boom)
        with pytest.raises(Exception, match="synthetic run-save failure"):
            perform_probe_run(
                manifest=manifest,
                texts=texts,
                holdback_loader=lambda: holdback,
                detector=detector,
                scope="full",
                runs_dir=tmp_path / "runs",
                registry_path=registry_path,
                run_at=datetime(2026, 11, 1, tzinfo=UTC),
            )
        # The clearing is rolled back: the demotion still cites run-pre,
        # and no run file cites a clearing that never happened.
        assert registry_path.read_bytes() == before
        assert (
            load_validation_registry(registry_path).record(record.record_id).limits.demoted_by
            is not None
        )
        assert list((tmp_path / "runs").glob("run-*.json")) == []

    def test_failed_run_save_restores_applied_demotions(self, tmp_path, monkeypatch):
        from test_audit_w4_worker_b import _CleanDetector

        from textforensics.probe_runs import perform_probe_run
        from textforensics.validation import load_validation_registry

        # 60 items + a detector-version change fires a Tier-1 alert, so
        # perform_probe_run demotes inside the transaction (W4/S07).
        manifest, texts, holdback, registry_path, record = self._setup(tmp_path, n_items=60)
        first = _CleanDetector(version="0.1.0")
        first.detector_id = record.detector_id
        perform_probe_run(
            manifest=manifest,
            texts=texts,
            holdback_loader=lambda: holdback,
            detector=first,
            scope="full",
            runs_dir=tmp_path / "runs",
            registry_path=registry_path,
            run_at=datetime(2026, 11, 1, tzinfo=UTC),
        )
        before = registry_path.read_bytes()
        second = _CleanDetector(version="0.2.0")
        second.detector_id = record.detector_id

        def _boom(*args, **kwargs):
            raise OSError("synthetic run-save failure")

        monkeypatch.setattr("textforensics.probe_runs.save_run", _boom)
        with pytest.raises(Exception, match="synthetic run-save failure"):
            perform_probe_run(
                manifest=manifest,
                texts=texts,
                holdback_loader=lambda: holdback,
                detector=second,
                scope="full",
                runs_dir=tmp_path / "runs",
                registry_path=registry_path,
                run_at=datetime(2026, 11, 9, tzinfo=UTC),
            )
        # No demotion may cite the run that was never saved.
        assert registry_path.read_bytes() == before
        assert (
            load_validation_registry(registry_path).record(record.record_id).limits.demoted_by
            is None
        )
        assert len(list((tmp_path / "runs").glob("run-*.json"))) == 1

    def test_failed_registry_save_saves_no_run(self, tmp_path, monkeypatch):
        from test_audit_w4_worker_b import _CleanDetector, apply_demotions

        from textforensics.probe_runs import perform_probe_run
        from textforensics.validation import ValidationRegistry

        manifest, texts, holdback, registry_path, record = self._setup(tmp_path)
        detector = _CleanDetector()
        detector.detector_id = record.detector_id
        apply_demotions(
            registry_path=registry_path,
            detector_id=record.detector_id,
            run_id="run-pre",
            alerts=[{"tier": 1, "rule": "flip_rate"}],
        )
        before = registry_path.read_bytes()

        def _boom(self, path):
            raise OSError("synthetic registry-save failure")

        monkeypatch.setattr(ValidationRegistry, "save", _boom)
        with pytest.raises(Exception, match="synthetic registry-save failure"):
            perform_probe_run(
                manifest=manifest,
                texts=texts,
                holdback_loader=lambda: holdback,
                detector=detector,
                scope="full",
                runs_dir=tmp_path / "runs",
                registry_path=registry_path,
                run_at=datetime(2026, 11, 1, tzinfo=UTC),
            )
        assert registry_path.read_bytes() == before
        assert (
            not (tmp_path / "runs").exists() or list((tmp_path / "runs").glob("run-*.json")) == []
        )

    def test_failed_manifest_build_restores_registry(self, tmp_path, monkeypatch):
        from test_audit_w4_worker_b import _CleanDetector, apply_demotions

        from textforensics.probe_runs import perform_probe_run
        from textforensics.validation import load_validation_registry

        manifest, texts, holdback, registry_path, record = self._setup(tmp_path)
        detector = _CleanDetector()
        detector.detector_id = record.detector_id
        apply_demotions(
            registry_path=registry_path,
            detector_id=record.detector_id,
            run_id="run-pre",
            alerts=[{"tier": 1, "rule": "flip_rate"}],
        )
        before = registry_path.read_bytes()

        def _boom(*args, **kwargs):
            raise RuntimeError("synthetic manifest-build failure")

        monkeypatch.setattr("textforensics.probe_runs.build_run_manifest", _boom)
        with pytest.raises(Exception, match="synthetic manifest-build failure"):
            perform_probe_run(
                manifest=manifest,
                texts=texts,
                holdback_loader=lambda: holdback,
                detector=detector,
                scope="full",
                runs_dir=tmp_path / "runs",
                registry_path=registry_path,
                run_at=datetime(2026, 11, 1, tzinfo=UTC),
            )
        assert registry_path.read_bytes() == before
        assert (
            load_validation_registry(registry_path).record(record.record_id).limits.demoted_by
            is not None
        )

    def test_registry_mutation_is_serialized_across_threads(self, tmp_path):
        from test_audit_w4_worker_b import apply_demotions

        from textforensics.validation import load_validation_registry

        _, _, _, registry_path, record = self._setup(tmp_path)
        barrier = threading.Barrier(2)
        errors: list[BaseException] = []

        def _demote(run_id: str):
            try:
                barrier.wait(timeout=10)
                apply_demotions(
                    registry_path=registry_path,
                    detector_id=record.detector_id,
                    run_id=run_id,
                    alerts=[{"tier": 1, "rule": "flip_rate"}],
                )
            except BaseException as exc:  # noqa: BLE001 — collected, asserted below
                errors.append(exc)

        threads = [threading.Thread(target=_demote, args=(f"run-{i}",)) for i in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        assert errors == []
        demoted_by = (
            load_validation_registry(registry_path).record(record.record_id).limits.demoted_by
        )
        # Serialized read-modify-write: neither demotion is lost.
        assert demoted_by is not None
        assert "U3 probe run run-0" in demoted_by
        assert "U3 probe run run-1" in demoted_by

    def test_successful_run_still_commits_both_sides(self, tmp_path):
        from test_audit_w4_worker_b import _CleanDetector, apply_demotions

        from textforensics.probe_runs import load_run_history, perform_probe_run
        from textforensics.validation import load_validation_registry

        manifest, texts, holdback, registry_path, record = self._setup(tmp_path)
        detector = _CleanDetector()
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
        # apply_demotions demotes every record of this detector, so a
        # clean run clears all of them (not just records[0]).
        expected_cleared = sorted(
            r.record_id
            for r in load_validation_registry(registry_path).records
            if r.detector_id == record.detector_id
        )
        assert run["demotions_cleared"]["cleared_record_ids"] == expected_cleared
        assert (
            load_validation_registry(registry_path).record(record.record_id).limits.demoted_by
            is None
        )
        assert len(load_run_history(tmp_path / "runs")) == 1


# ---------------------------------------------------------------------------
# Item 4 — codec: real migration dispatch, bounded streaming, truthful map
# ---------------------------------------------------------------------------


def _v1_bundle() -> dict:
    return {
        "schema": "textforensics.forensic-bundle/v1",
        "content_sha256": "0" * 64,
        "input": {"word_count": 1, "raw_text_included": False},
    }


class TestCodecMigrations:
    def test_migration_callback_is_actually_invoked(self):
        from textforensics.result_codec import CodecConfig, ResultCodec

        seen: list[dict] = []

        def _migrate_v1_to_v2(data: dict) -> dict:
            seen.append(dict(data))
            migrated = dict(data)
            migrated["schema"] = "textforensics.forensic-bundle/v2"
            migrated["migrated_by_test"] = True
            return migrated

        config = CodecConfig(
            migrations={
                "textforensics.forensic-bundle/v1": {
                    "textforensics.forensic-bundle/v2": _migrate_v1_to_v2,
                }
            }
        )
        decoded = ResultCodec(config).decode(
            json.dumps(_v1_bundle()), "forensic-bundle", validate=False
        )
        assert len(seen) == 1
        assert seen[0]["schema"] == "textforensics.forensic-bundle/v1"
        assert decoded["schema"] == "textforensics.forensic-bundle/v2"
        assert decoded["migrated_by_test"] is True

    def test_migration_without_callback_fails_loudly(self):
        import warnings

        from textforensics.result_codec import ResultCodec, VersionMigrationError

        with warnings.catch_warnings():
            warnings.simplefilter("error")
            with pytest.raises(VersionMigrationError, match="No migration"):
                ResultCodec().decode(json.dumps(_v1_bundle()), "forensic-bundle", validate=False)

    def test_migration_callback_must_produce_target_version(self):
        from textforensics.result_codec import CodecConfig, ResultCodec, VersionMigrationError

        def _no_relabel(data: dict) -> dict:
            # Returns the payload unchanged: the codec must not
            # silently relabel it as v2.
            return dict(data)

        config = CodecConfig(
            migrations={
                "textforensics.forensic-bundle/v1": {
                    "textforensics.forensic-bundle/v2": _no_relabel,
                }
            }
        )
        with pytest.raises(VersionMigrationError, match="did not produce"):
            ResultCodec(config).decode(json.dumps(_v1_bundle()), "forensic-bundle", validate=False)

    def test_migration_callback_error_fails_loudly(self):
        from textforensics.result_codec import CodecConfig, ResultCodec, VersionMigrationError

        def _boom(data: dict) -> dict:
            raise ValueError("synthetic migration failure")

        config = CodecConfig(
            migrations={
                "textforensics.forensic-bundle/v1": {
                    "textforensics.forensic-bundle/v2": _boom,
                }
            }
        )
        with pytest.raises(VersionMigrationError, match="synthetic migration failure"):
            ResultCodec(config).decode(json.dumps(_v1_bundle()), "forensic-bundle", validate=False)

    def test_strict_mode_ignores_registered_callbacks(self):
        from textforensics.result_codec import CodecConfig, ResultCodec, VersionMigrationError

        def _migrate(data: dict) -> dict:
            migrated = dict(data)
            migrated["schema"] = "textforensics.forensic-bundle/v2"
            return migrated

        config = CodecConfig(
            strict_version=True,
            migrations={
                "textforensics.forensic-bundle/v1": {
                    "textforensics.forensic-bundle/v2": _migrate,
                }
            },
        )
        with pytest.raises(VersionMigrationError, match="Schema version mismatch"):
            ResultCodec(config).decode(json.dumps(_v1_bundle()), "forensic-bundle", validate=False)

    def test_accepted_legacy_version_still_needs_no_migration(self):
        # trust-map v2 is in the accepted set: kept as-is, no callback,
        # no error — the W3/C23 multi-version rule is unchanged.
        from textforensics.result_codec import ResultCodec

        data = {
            "schema": "textforensics.trust-map/v2",
            "overall": "strong",
            "dimensions": [],
            "limitations": [],
            "input_conditions": {},
            "evidence_registry": {},
            "coverage": {"supported": 0, "partial": 0, "unknown": 0, "out_of_scope": 0},
            "generated_at_utc": "2024-01-01T00:00:00+00:00",
        }
        decoded = ResultCodec().decode(json.dumps(data), "trust-map", validate=True)
        assert decoded["schema"] == "textforensics.trust-map/v2"


class TestCodecStreaming:
    def _large_payload(self) -> dict:
        from test_result_codec import MINIMAL_BUNDLE

        data = json.loads(json.dumps(MINIMAL_BUNDLE))
        data["detector_results"] = [
            {
                "detector_id": f"synthetic/detector-{i}",
                "score": 0.5,
                "note": "x" * 1024,
            }
            for i in range(5000)
        ]
        return data

    def test_iter_encode_chunks_are_bounded_and_lossless(self):
        from textforensics.result_codec import ResultCodec

        data = self._large_payload()
        codec = ResultCodec()
        chunks = list(codec.iter_encode(data, "forensic-bundle", chunk_size=8192))
        assert chunks, "streaming must yield at least one chunk"
        assert all(len(chunk) <= 8192 for chunk in chunks)
        assert len(chunks) > 1, "a multi-megabyte payload must stream in many chunks"
        assert b"".join(chunks) == codec.encode(data, "forensic-bundle")

    def test_stream_encode_is_bounded_not_materialized(self):
        from textforensics.result_codec import ResultCodec

        data = self._large_payload()
        codec = ResultCodec()
        encoded = codec.encode(data, "forensic-bundle")
        assert len(encoded) > 5_000_000, f"fixture too small: {len(encoded)}"
        stream = codec.stream_encode(data, "forensic-bundle", chunk_size=8192)
        tracemalloc.start()
        try:
            digest = hashlib.sha256()
            total = 0
            while True:
                piece = stream.read(8192)
                assert len(piece) <= 8192
                if not piece:
                    break
                # Hash incrementally: accumulating the whole payload
                # here would itself materialize it and defeat the test.
                digest.update(piece)
                total += len(piece)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert total == len(encoded)
        assert digest.hexdigest() == hashlib.sha256(encoded).hexdigest()
        # Peak working memory while streaming stays bounded by the chunk
        # size, far below the ~5 MB serialized payload.
        assert peak < 1_000_000, f"streaming peak {peak} bytes is not bounded"

    def test_stream_encode_matches_encode(self):
        from test_result_codec import MINIMAL_BUNDLE

        from textforensics.result_codec import ResultCodec

        data = dict(MINIMAL_BUNDLE)
        codec = ResultCodec()
        stream = codec.stream_encode(data, "forensic-bundle")
        assert stream.read() == codec.encode(data, "forensic-bundle")


class TestCodecVersionMap:
    def test_version_map_matches_validator_exactly(self):
        from textforensics.result_codec import _SCHEMA_VERSIONS
        from textforensics.schema import list_schemas, supported_versions

        for name, current in sorted(_SCHEMA_VERSIONS.items()):
            assert name in list_schemas(), f"{name} is advertised but has no schema"
            if current is not None:
                assert current in supported_versions(name), (
                    f"{name} advertises {current} but the validator accepts "
                    f"{sorted(supported_versions(name))}"
                )

    def test_trust_map_current_is_v3_as_shipped(self):
        from textforensics.result_codec import _SCHEMA_VERSIONS
        from textforensics.schema import supported_versions

        assert _SCHEMA_VERSIONS["trust-map"] == "textforensics.trust-map/v3"
        assert supported_versions("trust-map") == {
            "textforensics.trust-map/v1",
            "textforensics.trust-map/v2",
            "textforensics.trust-map/v3",
        }

    @pytest.mark.parametrize(
        "name", ["drift-report", "calibration", "threshold-selection", "bundle-manifest"]
    )
    def test_unadvertised_names_fail_loudly(self, name):
        from textforensics.result_codec import CodecError, ResultCodec

        codec = ResultCodec()
        with pytest.raises(CodecError, match="Unknown schema"):
            codec.encode({}, name)
        with pytest.raises(CodecError, match="Unknown schema"):
            codec.encode({}, name, validate=False)
        with pytest.raises(CodecError, match="Unknown schema"):
            codec.decode(b"{}", name)
        with pytest.raises(CodecError, match="Unknown schema"):
            codec.decode(b"{}", name, validate=False)

    def test_enterprise_policy_is_unversioned_and_encodable(self):
        from textforensics.result_codec import ResultCodec
        from textforensics.schema import supported_versions, validate

        assert supported_versions("enterprise-policy") == frozenset()
        policy = {
            "revision": 1,
            "settings": {},
            "rules": [
                {
                    "id": "synthetic-rule",
                    "description": "synthetic",
                    "action": "warn",
                    "scope": "global",
                }
            ],
        }
        assert validate(policy, "enterprise-policy") == []
        encoded = ResultCodec().encode(dict(policy), "enterprise-policy")
        decoded_payload = json.loads(encoded)
        # The codec must not stamp a version the schema forbids.
        assert "schema" not in decoded_payload
        assert ResultCodec().decode(encoded, "enterprise-policy")["revision"] == 1
