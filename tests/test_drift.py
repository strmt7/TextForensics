from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

# Ensure the package root is importable.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from textforensics.detectors import BuiltinHeuristicDetector
from textforensics.drift import (
    DriftObservatory,
    _distribution_summary,
    _index_by_sample,
    _is_human_sample,
    _now_iso,
    _percentile,
    _records_by_detector,
    _round,
    _unique_scalars,
)

CORPUS_PATH = os.path.join(os.path.dirname(__file__), "..", "testdata", "drift_corpus.json")


def _baseline_snapshot(
    sample_ids: list[str],
    *,
    detector_id: str = "test-detector",
    detector_version: str = "1.0.0",
    detector_family: str = "stylometric-heuristic",
    execution: str = "local",
    score: float = 0.5,
    verdict: str = "ai_like",
    threshold: float | None = 0.5,
    supported_languages: list[str] | None = None,
    min_words: int | None = None,
    calibration_id: str | None = None,
    calibrated_ai_probability: float | None = None,
    provider_version: str | None = None,
    snapshot_id: str | None = None,
    label: str | None = None,
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for sid in sample_ids:
        record: dict[str, Any] = {
            "sample_id": sid,
            "score": score,
            "score_semantics": "higher_means_more_machine_like; uncalibrated pattern score",
            "verdict": verdict,
            "detector_id": detector_id,
            "detector_version": detector_version,
            "detector_family": detector_family,
            "execution": execution,
            "threshold": threshold,
            "supported_languages": supported_languages or ["en"],
            "min_words": min_words,
            "observed_at": _now_iso(),
        }
        if calibrated_ai_probability is not None:
            record["calibrated_ai_probability"] = calibrated_ai_probability
        if calibration_id is not None:
            record["calibration_id"] = calibration_id
        if provider_version is not None:
            record["provider_version"] = provider_version
        records.append(record)
    return {
        "schema": "textforensics.drift-snapshot/v1",
        "snapshot_id": snapshot_id or "baseline",
        "taken_at": "2025-01-01T00:00:00+00:00",
        "corpus_sha256": None,  # filled in by the observatory
        "label": label,
        "detector_ids": [detector_id],
        "record_count": len(records),
        "failure_count": 0,
        "records": records,
        "failures": [],
    }


def _make_snapshot(
    sample_ids: list[str],
    detector_id: str = "test-detector",
    **kwargs: Any,
) -> dict[str, Any]:
    return _baseline_snapshot(sample_ids, detector_id=detector_id, **kwargs)


# ─── utility helpers ──────────────────────────────────────────────


class UtilityTests(unittest.TestCase):
    def test_distribution_summary_empty(self):
        summary = _distribution_summary([])
        self.assertEqual(summary["n"], 0)
        self.assertIsNone(summary["mean"])

    def test_distribution_summary_single_value(self):
        summary = _distribution_summary([0.5])
        self.assertEqual(summary["n"], 1)
        self.assertAlmostEqual(summary["mean"], 0.5)
        self.assertAlmostEqual(summary["stdev"], 0.0)

    def test_distribution_summary_multiple_values(self):
        values = [0.1, 0.3, 0.5, 0.7, 0.9]
        summary = _distribution_summary(values)
        self.assertEqual(summary["n"], 5)
        self.assertAlmostEqual(summary["median"], 0.5)
        self.assertEqual(summary["min"], 0.1)
        self.assertEqual(summary["max"], 0.9)

    def test_distribution_summary_ignores_non_finite(self):
        summary = _distribution_summary([0.1, float("nan"), 0.9])
        self.assertEqual(summary["n"], 2)
        self.assertEqual(summary["min"], 0.1)
        self.assertEqual(summary["max"], 0.9)

    def test_percentile_single_value(self):
        self.assertAlmostEqual(_percentile([1.0], 0.5), 1.0)

    def test_percentile_empty(self):
        self.assertIsNone(_percentile([], 0.5))

    def test_percentile_middle(self):
        values = [10.0, 20.0, 30.0, 40.0, 50.0]
        self.assertAlmostEqual(_percentile(values, 0.5), 30.0)

    def test_round_finite(self):
        self.assertAlmostEqual(_round(0.123456789), 0.123457)

    def test_round_none(self):
        self.assertIsNone(_round(None))

    def test_round_infinite_returns_none(self):
        self.assertIsNone(_round(float("inf")))

    def test_unique_scalars(self):
        result = _unique_scalars([2, 1, 1, 3, None])
        self.assertEqual(result, [None, 1, 2, 3])

    def test_is_human_sample_true(self):
        self.assertTrue(_is_human_sample({"label": "human"}))

    def test_is_human_sample_false(self):
        self.assertFalse(_is_human_sample({"label": "ai"}))

    def test_is_human_sample_unknown(self):
        self.assertFalse(_is_human_sample({}))

    def test_records_by_detector(self):
        snapshot = {
            "records": [
                {"detector_id": "a", "sample_id": "s1"},
                {"detector_id": "b", "sample_id": "s1"},
                {"detector_id": "a", "sample_id": "s2"},
            ]
        }
        groups = _records_by_detector(snapshot)
        self.assertEqual(len(groups["a"]), 2)
        self.assertEqual(len(groups["b"]), 1)

    def test_index_by_sample(self):
        records = [
            {"sample_id": "s1", "score": 0.3},
            {"sample_id": "s2", "score": 0.7},
        ]
        index = _index_by_sample(records)
        self.assertAlmostEqual(index["s1"]["score"], 0.3)
        self.assertAlmostEqual(index["s2"]["score"], 0.7)

    def test_index_by_sample_rejects_duplicate(self):
        records = [
            {"sample_id": "s1", "score": 0.3},
            {"sample_id": "s1", "score": 0.7},
        ]
        with self.assertRaises(ValueError):
            _index_by_sample(records)


# ─── corpus loading ──────────────────────────────────────────────


class CorpusLoadingTests(unittest.TestCase):
    def test_load_from_file(self):
        obs = DriftObservatory(corpus_path=CORPUS_PATH)
        self.assertGreater(len(obs.samples), 20)
        for sample in obs.samples.values():
            self.assertIsNotNone(sample.sample_id)
            self.assertIsNotNone(sample.text_sha256)
            self.assertIsNotNone(sample.metadata)

    def test_load_from_dict_corpus(self):
        corpus = {
            "schema": "textforensics.drift-corpus/v1",
            "samples": [
                {
                    "id": "s1",
                    "text_sha256": "a" * 64,
                    "metadata": {"label": "human", "domain": "general"},
                },
                {
                    "id": "s2",
                    "text_sha256": "b" * 64,
                    "metadata": {"label": "ai", "domain": "tech"},
                },
            ],
        }
        obs = DriftObservatory(corpus=corpus)
        self.assertEqual(len(obs.samples), 2)

    def test_load_from_list_corpus(self):
        samples = [
            {
                "id": "s1",
                "text_sha256": "a" * 64,
                "metadata": {},
            },
        ]
        obs = DriftObservatory(corpus=samples)
        self.assertEqual(len(obs.samples), 1)

    def test_load_empty_corpus(self):
        obs = DriftObservatory(corpus={"schema": "textforensics.drift-corpus/v1", "samples": []})
        self.assertEqual(len(obs.samples), 0)

    def test_hash_mismatch_raises(self):
        corpus = {
            "samples": [
                {
                    "id": "s1",
                    "text_sha256": "wrong" * 21 + "a",
                    "text": "hello world",
                    "metadata": {},
                },
            ]
        }
        with self.assertRaises(ValueError):
            DriftObservatory(corpus=corpus)

    def test_duplicate_sample_id_raises(self):
        corpus = {
            "samples": [
                {"id": "s1", "text_sha256": "a" * 64, "metadata": {}},
                {"id": "s1", "text_sha256": "b" * 64, "metadata": {}},
            ]
        }
        with self.assertRaises(ValueError):
            DriftObservatory(corpus=corpus)

    def test_missing_sample_id_raises(self):
        corpus = {
            "samples": [
                {"text_sha256": "a" * 64, "metadata": {}},
            ]
        }
        with self.assertRaises(ValueError):
            DriftObservatory(corpus=corpus)

    def test_text_sha256_derived_from_text(self):
        corpus = {
            "samples": [
                {
                    "id": "s1",
                    "text": "hello world",
                    "metadata": {},
                },
            ]
        }
        obs = DriftObservatory(corpus=corpus)
        # SHA256 of "hello world" is known
        expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        self.assertEqual(obs.samples["s1"].text_sha256, expected)

    def test_corpus_hash_is_deterministic(self):
        obs1 = DriftObservatory(corpus_path=CORPUS_PATH)
        obs2 = DriftObservatory(corpus_path=CORPUS_PATH)
        self.assertEqual(obs1.corpus_sha256, obs2.corpus_sha256)


# ─── snapshot creation ──────────────────────────────────────────


class SnapshotCreationTests(unittest.TestCase):
    def setUp(self):
        self.corpus = {
            "samples": [
                {"id": f"sample-{i:02d}", "text": f"This is sample text number {i} that is long enough to trigger analysis. It has more than enough words to meet minimum length requirements for drift tracking.", "metadata": {"label": "human" if i % 2 == 0 else "ai", "domain": "general"}}
                for i in range(1, 7)
            ]
        }
        self.detector = BuiltinHeuristicDetector()
        self.obs = DriftObservatory(corpus=self.corpus)

    def test_take_snapshot_creates_snapshot(self):
        snapshot = self.obs.take_snapshot(
            detectors=[self.detector],
            taken_at="2025-06-01T00:00:00+00:00",
            snapshot_id="test-snap",
        )
        self.assertIn("schema", snapshot)
        self.assertEqual(snapshot["snapshot_id"], "test-snap")
        self.assertGreater(snapshot["record_count"], 0)

    def test_take_snapshot_records_in_memory(self):
        self.obs.take_snapshot(detectors=[self.detector], snapshot_id="s1")
        self.assertEqual(len(self.obs.snapshots), 1)

    def test_take_snapshot_multiple(self):
        self.obs.take_snapshot(detectors=[self.detector], snapshot_id="s1")
        self.obs.take_snapshot(detectors=[self.detector], snapshot_id="s2")
        self.assertEqual(len(self.obs.snapshots), 2)

    def test_empty_corpus_snapshot(self):
        obs = DriftObservatory(corpus={"samples": []})
        snapshot = obs.take_snapshot(detector_ids=[])
        self.assertEqual(snapshot["record_count"], 0)

    def test_snapshot_has_corpus_hash(self):
        self.obs.take_snapshot(detectors=[self.detector])
        self.assertEqual(
            self.obs.snapshots[0]["corpus_sha256"],
            self.obs.corpus_sha256,
        )

    def test_snapshot_from_observations_manual(self):
        sample_ids = list(self.obs.samples.keys())
        observations = [
            {
                "sample_id": sid,
                "score": 0.5,
                "verdict": "ai_like",
                "detector_id": "manual-detector",
                "detector_version": "1.0",
                "detector_family": "manual",
                "execution": "local",
            }
            for sid in sample_ids
        ]
        snapshot = self.obs.snapshot_from_observations(observations)
        self.assertEqual(snapshot["record_count"], len(sample_ids))

    def test_snapshot_from_observations_with_failures(self):
        sample_ids = list(self.obs.samples.keys())[:2]
        observations = [
            {
                "sample_id": sid,
                "score": 0.5,
                "verdict": "ai_like",
                "detector_id": "test",
                "detector_version": "1.0",
                "detector_family": "test",
                "execution": "local",
            }
            for sid in sample_ids
        ]
        failures = [
            {
                "sample_id": sid,
                "text_sha256": self.obs.samples[sid].text_sha256,
                "detector_id": "test",
                "error_type": "Timeout",
            }
            for sid in sample_ids
        ]
        snapshot = self.obs.snapshot_from_observations(observations, failures=failures)
        self.assertEqual(snapshot["failure_count"], len(sample_ids))

    def test_snapshot_observation_validation_unknown_sample(self):
        with self.assertRaises(ValueError):
            self.obs.snapshot_from_observations(
                [
                    {
                        "sample_id": "unknown-999",
                        "score": 0.5,
                        "verdict": "ai_like",
                        "detector_id": "test",
                        "detector_version": "1.0",
                        "detector_family": "test",
                        "execution": "local",
                    }
                ]
            )

    def test_snapshot_observation_validation_bad_verdict(self):
        sample_id = list(self.obs.samples.keys())[0]
        with self.assertRaises(ValueError):
            self.obs.snapshot_from_observations(
                [
                    {
                        "sample_id": sample_id,
                        "score": 0.5,
                        "verdict": "bad_verdict",
                        "detector_id": "test",
                        "detector_version": "1.0",
                        "detector_family": "test",
                        "execution": "local",
                    }
                ]
            )

    def test_snapshot_observation_validation_bad_execution(self):
        sample_id = list(self.obs.samples.keys())[0]
        with self.assertRaises(ValueError):
            self.obs.snapshot_from_observations(
                [
                    {
                        "sample_id": sample_id,
                        "score": 0.5,
                        "verdict": "ai_like",
                        "detector_id": "test",
                        "detector_version": "1.0",
                        "detector_family": "test",
                        "execution": "bad",
                    }
                ]
            )

    def test_save_and_load_snapshots(self):
        self.obs.take_snapshot(detectors=[self.detector], snapshot_id="s1")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "store.json")
            self.obs.save_snapshots(path)
            obs2 = DriftObservatory(corpus=self.corpus)
            loaded = obs2.load_snapshots(path)
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0]["snapshot_id"], "s1")

    def test_load_snapshots_corpus_hash_mismatch(self):
        self.obs.take_snapshot(detectors=[self.detector], snapshot_id="s1")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "store.json")
            self.obs.save_snapshots(path)
            obs2 = DriftObservatory(corpus={"samples": [{"id": "different", "text_sha256": "a" * 64, "metadata": {}}]})
            with self.assertRaises(ValueError):
                obs2.load_snapshots(path, expected_corpus_sha256=obs2.corpus_sha256)

    def test_add_snapshot(self):
        snapshot = _baseline_snapshot(
            [list(self.obs.samples.keys())[0]],
            detector_id="external",
            snapshot_id="external-1",
        )
        # Patch corpus hash so add_snapshot validates
        snapshot["corpus_sha256"] = self.obs.corpus_sha256
        self.obs.add_snapshot(snapshot)
        self.assertIn("external-1", self.obs.snapshots[0]["snapshot_id"])

    def test_read_snapshot_file_single(self):
        self.obs.take_snapshot(detectors=[self.detector], snapshot_id="file-test")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "snap.json")
            snap_data = self.obs.snapshots[0]
            Path(path).write_text(json.dumps(snap_data), encoding="utf-8")
            read = DriftObservatory.read_snapshot_file(path)
            self.assertEqual(read["snapshot_id"], "file-test")


# ─── snapshot comparison ────────────────────────────────────────


class SnapshotComparisonTests(unittest.TestCase):
    def setUp(self):
        self.corpus = {
            "samples": [
                {"id": f"sample-{i:02d}", "text": f"This is sample text number {i} that is long enough to trigger analysis. It has more than enough words to meet minimum length requirements for drift tracking and comparison purposes.", "metadata": {"label": "human" if i % 2 == 0 else "ai", "domain": "general"}}
                for i in range(1, 7)
            ]
        }
        self.sample_ids = list(self.corpus["samples"][0]["id"] if isinstance(self.corpus["samples"][0], dict) else self.corpus["samples"][0] for _ in range(1))

    def _make_obs(self, corpus=None):
        return DriftObservatory(
            corpus=corpus or self.corpus,
            min_samples_for_drift_claim=2,
        )

    def _make_snap(self, obs: DriftObservatory, **kwargs):
        return _make_snapshot(list(obs.samples.keys()), **kwargs)

    def test_compare_identical_stable(self):
        obs = self._make_obs()
        sample_ids = list(obs.samples.keys())
        baseline = _make_snapshot(
            sample_ids,
            score=0.5,
            verdict="ai_like",
        )
        baseline["corpus_sha256"] = obs.corpus_sha256
        current = _make_snapshot(
            sample_ids,
            score=0.5,
            verdict="ai_like",
        )
        current["corpus_sha256"] = obs.corpus_sha256

        report = obs.compare_snapshots(baseline, current)
        self.assertEqual(report["schema"], "textforensics.drift-report/v1")
        self.assertEqual(report["overall"]["status"], "stable")
        self.assertFalse(report["overall"]["detectors_with_drift"])

    def test_compare_score_shift_detected(self):
        obs = self._make_obs()
        sample_ids = list(obs.samples.keys())
        baseline = _make_snapshot(sample_ids, score=0.3, verdict="human_like")
        baseline["corpus_sha256"] = obs.corpus_sha256
        current = _make_snapshot(sample_ids, score=0.8, verdict="ai_like")
        current["corpus_sha256"] = obs.corpus_sha256

        report = obs.compare_snapshots(baseline, current)
        # Large score shift + verdict flip should trigger drift
        overall = report["overall"]
        self.assertEqual(overall["status"], "drift_detected")
        self.assertEqual(overall["detectors_with_drift"], 1)

    def test_compare_verdict_flip(self):
        obs = self._make_obs()
        sample_ids = list(obs.samples.keys())
        baseline = _make_snapshot(sample_ids, score=0.5, verdict="human_like")
        baseline["corpus_sha256"] = obs.corpus_sha256
        current = _make_snapshot(sample_ids, score=0.5, verdict="ai_like")
        current["corpus_sha256"] = obs.corpus_sha256

        report = obs.compare_snapshots(baseline, current)
        overall = report["overall"]
        self.assertEqual(overall["status"], "drift_detected")

    def test_compare_detector_missing_in_baseline(self):
        obs = self._make_obs()
        sample_ids = list(obs.samples.keys())
        baseline = _make_snapshot(sample_ids, detector_id="baseline-det")
        baseline["corpus_sha256"] = obs.corpus_sha256
        current = _make_snapshot(sample_ids, detector_id="current-det")
        current["corpus_sha256"] = obs.corpus_sha256

        report = obs.compare_snapshots(baseline, current)
        overall = report["overall"]
        self.assertTrue(overall["detectors_missing"] >= 2)

    def test_compare_calibrated_probability_drift(self):
        obs = self._make_obs()
        sample_ids = list(obs.samples.keys())
        baseline = _make_snapshot(
            sample_ids,
            calibrated_ai_probability=0.3,
            calibration_id="cal-v1",
        )
        baseline["corpus_sha256"] = obs.corpus_sha256
        current = _make_snapshot(
            sample_ids,
            calibrated_ai_probability=0.9,
            calibration_id="cal-v2",
        )
        current["corpus_sha256"] = obs.corpus_sha256

        report = obs.compare_snapshots(baseline, current)
        detector_report = report["detectors"][0]
        self.assertTrue(detector_report["calibration_drift"]["calibration_id_changed"])
        self.assertEqual(
            detector_report["calibration_drift"]["calibration_id_change_count"],
            len(sample_ids),
        )

    def test_compare_provider_version_missing(self):
        obs = self._make_obs()
        sample_ids = list(obs.samples.keys())
        baseline = _make_snapshot(sample_ids, execution="remote", provider_version="api-2025-01-01")
        baseline["corpus_sha256"] = obs.corpus_sha256
        current = _make_snapshot(sample_ids, execution="remote", provider_version=None)
        current["corpus_sha256"] = obs.corpus_sha256

        report = obs.compare_snapshots(baseline, current)
        provider = report["detectors"][0]["provider_metadata"]
        self.assertTrue(provider["missing_provider_version"])
        self.assertTrue(provider["changed_provider_version"])

    def test_compare_supported_language_change(self):
        obs = self._make_obs()
        sample_ids = list(obs.samples.keys())
        baseline = _make_snapshot(sample_ids, supported_languages=["en"])
        baseline["corpus_sha256"] = obs.corpus_sha256
        current = _make_snapshot(sample_ids, supported_languages=["en", "fr"])
        current["corpus_sha256"] = obs.corpus_sha256

        report = obs.compare_snapshots(baseline, current)
        regime = report["detectors"][0]["supported_regime"]
        self.assertTrue(regime["language_changed"])
        self.assertIn("fr", regime["added_languages"])

    def test_compare_threshold_change(self):
        obs = self._make_obs()
        sample_ids = list(obs.samples.keys())
        baseline = _make_snapshot(sample_ids, threshold=0.5)
        baseline["corpus_sha256"] = obs.corpus_sha256
        current = _make_snapshot(sample_ids, threshold=0.7)
        current["corpus_sha256"] = obs.corpus_sha256

        report = obs.compare_snapshots(baseline, current)
        thresholds = report["detectors"][0]["threshold_changes"]
        self.assertTrue(thresholds["threshold_changed"])

    def test_compare_corpus_mismatch(self):
        obs = self._make_obs()
        sample_ids = list(obs.samples.keys())
        baseline = _make_snapshot(sample_ids)
        baseline["corpus_sha256"] = obs.corpus_sha256
        current = _make_snapshot(sample_ids)
        current["corpus_sha256"] = "different" * 21 + "a"

        report = obs.compare_snapshots(baseline, current)
        self.assertEqual(report["overall"]["status"], "corpus_mismatch")

    def test_compare_schema(self):
        obs = self._make_obs()
        sample_ids = list(obs.samples.keys())
        baseline = _make_snapshot(sample_ids)
        baseline["corpus_sha256"] = obs.corpus_sha256
        current = _make_snapshot(sample_ids)
        current["corpus_sha256"] = obs.corpus_sha256

        report = obs.compare_snapshots(baseline, current)
        self.assertIn("schema", report)
        self.assertIn("generated_at", report)
        self.assertIn("detectors", report)
        self.assertIn("overall", report)
        self.assertIn("settings", report)
        self.assertIn("limitations", report)

    def test_compare_minimal_drift_not_claimed_with_single_sample(self):
        """With min_samples_for_drift_claim=2, a single comparable sample should not trigger drift claims."""
        obs = DriftObservatory(
            corpus={
                "samples": [
                    {
                        "id": "s1",
                        "text": "This is a single sample that is long enough for analysis and comparison.",
                        "metadata": {"label": "human", "domain": "general"},
                    }
                ]
            },
            min_samples_for_drift_claim=2,
        )
        baseline = _make_snapshot(["s1"], score=0.3, verdict="human_like")
        baseline["corpus_sha256"] = obs.corpus_sha256
        current = _make_snapshot(["s1"], score=0.9, verdict="ai_like")
        current["corpus_sha256"] = obs.corpus_sha256

        report = obs.compare_snapshots(baseline, current)
        overall = report["overall"]
        # With only 1 sample and min_samples_for_drift_claim=2, drift should not be claimed
        self.assertEqual(overall["status"], "insufficient_evidence")
        self.assertEqual(overall["detectors_with_drift"], 0)

    def test_compare_human_fpr_increase(self):
        obs = self._make_obs()
        sample_ids = list(obs.samples.keys())
        # All samples are labelled alternately human/ai in corpus
        baseline = _make_snapshot(sample_ids, score=0.5, verdict="human_like")
        baseline["corpus_sha256"] = obs.corpus_sha256
        # Current misclassifies all as ai_like
        current = _make_snapshot(sample_ids, score=0.5, verdict="ai_like")
        current["corpus_sha256"] = obs.corpus_sha256

        report = obs.compare_snapshots(baseline, current)
        detector_report = report["detectors"][0]
        human_fpr = detector_report["human_slice_fpr"]
        self.assertGreater(human_fpr["human_sample_count"], 0)
        self.assertEqual(human_fpr["baseline_fpr"], 0.0)
        self.assertEqual(human_fpr["current_fpr"], 1.0)


# ─── settings validation ────────────────────────────────────────


class SettingsValidationTests(unittest.TestCase):
    def test_min_samples_too_low(self):
        with self.assertRaises(ValueError):
            DriftObservatory(
                corpus={"samples": []},
                min_samples_for_drift_claim=0,
            )

    def test_min_slice_samples_too_low(self):
        with self.assertRaises(ValueError):
            DriftObservatory(
                corpus={"samples": []},
                min_slice_samples=0,
            )

    def test_both_corpus_sources_raises(self):
        with self.assertRaises(ValueError):
            DriftObservatory(
                corpus_path=CORPUS_PATH,
                corpus={"samples": []},
            )


# ─── observation validation ─────────────────────────────────────


class ObservationValidationTests(unittest.TestCase):
    def setUp(self):
        self.obs = DriftObservatory(corpus={
            "samples": [
                {
                    "id": "s1",
                    "text": "This is a long enough text to meet the minimum word count requirements for drift testing and validation purposes.",
                    "metadata": {},
                },
            ]
        })

    def test_observation_missing_required_field(self):
        with self.assertRaises(ValueError):
            self.obs.snapshot_from_observations([{
                "sample_id": "s1",
                "score": 0.5,
                "verdict": "ai_like",
                # missing detector_id
            }])

    def test_observation_text_sha256_mismatch(self):
        with self.assertRaises(ValueError):
            self.obs.snapshot_from_observations([{
                "sample_id": "s1",
                "text_sha256": "wrong" * 21 + "a",
                "score": 0.5,
                "verdict": "ai_like",
                "detector_id": "test",
                "detector_version": "1.0",
                "detector_family": "test",
                "execution": "local",
            }])

    def test_observation_calibration_without_id_raises(self):
        with self.assertRaises(ValueError):
            self.obs.snapshot_from_observations([{
                "sample_id": "s1",
                "score": 0.5,
                "verdict": "ai_like",
                "detector_id": "test",
                "detector_version": "1.0",
                "detector_family": "test",
                "execution": "local",
                "calibration_id": "orphan",
            }])

    def test_observation_probability_requires_calibration_id(self):
        with self.assertRaises(ValueError):
            self.obs.snapshot_from_observations([{
                "sample_id": "s1",
                "score": 0.5,
                "verdict": "ai_like",
                "detector_id": "test",
                "detector_version": "1.0",
                "detector_family": "test",
                "execution": "local",
                "calibrated_ai_probability": 0.8,
            }])


# ─── end-to-end with real builtin detector ─────────────────────


class E2EBuiltinSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.corpus = {
            "samples": [
                {
                    "id": f"snap-s{i:02d}",
                    "text": f"This is sample text number {i} that is deliberately written to be long enough for analysis. It contains more than enough words to satisfy the built-in detector minimum length requirements for drift tracking.",
                    "metadata": {
                        "label": "human" if i % 2 == 0 else "ai",
                        "domain": "general",
                    },
                }
                for i in range(1, 5)
            ]
        }
        self.obs = DriftObservatory(corpus=self.corpus)

    def test_e2e_snapshot_then_compare(self):
        detector = BuiltinHeuristicDetector()
        snap1 = self.obs.take_snapshot(
            detectors=[detector],
            taken_at="2025-01-01T00:00:00+00:00",
            snapshot_id="t1",
        )
        snap2 = self.obs.take_snapshot(
            detectors=[detector],
            taken_at="2025-06-01T00:00:00+00:00",
            snapshot_id="t2",
        )
        report = self.obs.compare_snapshots(snap1, snap2)
        self.assertEqual(report["schema"], "textforensics.drift-report/v1")
        self.assertIn("detectors", report)
        self.assertIn("overall", report)

    def test_e2e_save_load_and_compare(self):
        detector = BuiltinHeuristicDetector()
        self.obs.take_snapshot(
            detectors=[detector],
            snapshot_id="t1",
        )
        with tempfile.TemporaryDirectory() as tmp:
            store_path = os.path.join(tmp, "snapshots.json")
            self.obs.save_snapshots(store_path)
            obs2 = DriftObservatory(corpus=self.corpus)
            loaded = obs2.load_snapshots(store_path)
            snap1_loaded = loaded[0]

            snap2 = obs2.take_snapshot(
                detectors=[detector],
                snapshot_id="t2",
            )
            report = obs2.compare_snapshots(snap1_loaded, snap2)
            self.assertIn("detectors", report)


if __name__ == "__main__":
    unittest.main()
