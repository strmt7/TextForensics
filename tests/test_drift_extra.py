"""Additional tests for drift module to improve coverage."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from textforensics.detectors import BuiltinHeuristicDetector, Detector
from textforensics.drift import (
    DriftObservatory,
    _coerce_float,
    _coerce_int_or_none,
    _compare_calibration,
    _compare_human_fpr,
    _compare_provider_metadata,
    _compare_score_distribution,
    _compare_supported_regime,
    _compare_thresholds,
    _compare_verdict_flips,
    _index_by_sample,
    _is_human_sample,
    _overall_summary,
    _records_by_detector,
    _round,
    _sort_key,
)


def _make_snapshot(
    sample_ids: list[str],
    detector_id: str = "test-detector",
    **kwargs: Any,
) -> dict[str, Any]:
    """Helper to create a snapshot."""
    records = []
    for sid in sample_ids:
        record: dict[str, Any] = {
            "sample_id": sid,
            "score": kwargs.get("score", 0.5),
            "score_semantics": "higher_means_more_machine_like",
            "verdict": kwargs.get("verdict", "ai_like"),
            "detector_id": detector_id,
            "detector_version": kwargs.get("detector_version", "1.0.0"),
            "detector_family": kwargs.get("detector_family", "stylometric-heuristic"),
            "execution": kwargs.get("execution", "local"),
            "threshold": kwargs.get("threshold", 0.5),
            "supported_languages": kwargs.get("supported_languages", ["en"]),
            "min_words": kwargs.get("min_words"),
            "observed_at": "2025-01-01T00:00:00+00:00",
        }
        if kwargs.get("calibrated_ai_probability") is not None:
            record["calibrated_ai_probability"] = kwargs["calibrated_ai_probability"]
        if kwargs.get("calibration_id") is not None:
            record["calibration_id"] = kwargs["calibration_id"]
        if kwargs.get("provider_version") is not None:
            record["provider_version"] = kwargs["provider_version"]
        records.append(record)
    return {
        "schema": "textforensics.drift-snapshot/v1",
        "snapshot_id": kwargs.get("snapshot_id", "baseline"),
        "taken_at": "2025-01-01T00:00:00+00:00",
        "corpus_sha256": None,
        "label": kwargs.get("label"),
        "detector_ids": [detector_id],
        "record_count": len(records),
        "failure_count": 0,
        "records": records,
        "failures": [],
    }


class CoerceFloatTests(unittest.TestCase):
    def test_coerce_float_null_allow_none(self):
        self.assertIsNone(_coerce_float(None, "test", allow_none=True))

    def test_coerce_float_null_disallow(self):
        with self.assertRaises(ValueError):
            _coerce_float(None, "test", allow_none=False)

    def test_coerce_float_bool(self):
        with self.assertRaises(ValueError):
            _coerce_float(True, "test")

    def test_coerce_float_string(self):
        with self.assertRaises(ValueError):
            _coerce_float("not a number", "test")

    def test_coerce_float_nan(self):
        with self.assertRaises(ValueError):
            _coerce_float(float("nan"), "test")

    def test_coerce_float_inf(self):
        with self.assertRaises(ValueError):
            _coerce_float(float("inf"), "test")

    def test_coerce_float_below_minimum(self):
        with self.assertRaises(ValueError):
            _coerce_float(-0.1, "test", minimum=0.0)

    def test_coerce_float_above_maximum(self):
        with self.assertRaises(ValueError):
            _coerce_float(1.5, "test", maximum=1.0)

    def test_coerce_float_valid_int(self):
        self.assertEqual(_coerce_float(5, "test"), 5.0)


class CoerceIntOrNoneTests(unittest.TestCase):
    def test_coerce_int_none(self):
        self.assertIsNone(_coerce_int_or_none(None, "test"))

    def test_coerce_int_bool(self):
        with self.assertRaises(ValueError):
            _coerce_int_or_none(True, "test")

    def test_coerce_int_float(self):
        with self.assertRaises(ValueError):
            _coerce_int_or_none(1.5, "test")

    def test_coerce_int_negative(self):
        with self.assertRaises(ValueError):
            _coerce_int_or_none(-1, "test")

    def test_coerce_int_valid(self):
        self.assertEqual(_coerce_int_or_none(42, "test"), 42)


class RoundEdgeCaseTests(unittest.TestCase):
    def test_round_bool_returns_none(self):
        self.assertIsNone(_round(True))

    def test_round_string_returns_none(self):
        self.assertIsNone(_round("abc"))


class DistributionSummaryEdgeCases(unittest.TestCase):
    def test_distribution_summary_ignores_none(self):
        from textforensics.drift import _distribution_summary
        summary = _distribution_summary([0.5, None, 0.9])
        self.assertEqual(summary["n"], 2)

    def test_distribution_summary_ignores_bool(self):
        from textforensics.drift import _distribution_summary
        summary = _distribution_summary([0.5, True, 0.9])
        self.assertEqual(summary["n"], 2)

    def test_distribution_summary_ignores_string(self):
        from textforensics.drift import _distribution_summary
        summary = _distribution_summary([0.5, "abc", 0.9])
        self.assertEqual(summary["n"], 2)

    def test_distribution_summary_statistics_error(self):
        from textforensics.drift import _distribution_summary
        import statistics
        # This is hard to trigger, but let's make sure the code path exists
        # We can't easily trigger StatisticsError with pstdev for count > 1
        # The test just ensures the function runs
        summary = _distribution_summary([0.5, 1.0])
        self.assertEqual(summary["n"], 2)


class UniqueScalarsEdgeCases(unittest.TestCase):
    def test_unique_scalars_with_bool(self):
        from textforensics.drift import _unique_scalars
        result = _unique_scalars([True, 1, 2])
        self.assertIn(True, result)

    def test_unique_scalars_with_string(self):
        from textforensics.drift import _unique_scalars
        result = _unique_scalars(["a", "b", 1])
        self.assertIn("a", result)

    def test_sort_key_none(self):
        self.assertEqual(_sort_key(None), (0, 0.0, ""))

    def test_sort_key_bool(self):
        self.assertEqual(_sort_key(True), (3, 0.0, "True"))


class HumanSampleAliasTests(unittest.TestCase):
    def test_expected_label_alias(self):
        self.assertTrue(_is_human_sample({"expected_label": "human"}))

    def test_ground_truth_alias(self):
        self.assertTrue(_is_human_sample({"ground_truth": "human"}))

    def test_true_human(self):
        self.assertTrue(_is_human_sample({"label": "true_human"}))

    def test_person(self):
        self.assertTrue(_is_human_sample({"label": "person"}))


class CompareScoreDistributionTests(unittest.TestCase):
    def test_no_paired_scores(self):
        result = _compare_score_distribution(
            [({"score": None}, {"score": 0.5}, "s1")],
            claim_allowed=True,
            shift_threshold=0.05,
            min_samples=2,
        )
        self.assertEqual(result["n_paired"], 0)
        self.assertEqual(result["status"], "no_paired_scores")

    def test_score_shift_significant(self):
        pairs = [
            ({"score": 0.2}, {"score": 0.8}, "s1"),
            ({"score": 0.2}, {"score": 0.8}, "s2"),
        ]
        result = _compare_score_distribution(
            pairs,
            claim_allowed=True,
            shift_threshold=0.05,
            min_samples=2,
        )
        self.assertTrue(result["significant"])
        self.assertEqual(result["status"], "score_distribution_shift")

    def test_score_shift_not_significant(self):
        pairs = [
            ({"score": 0.5}, {"score": 0.51}, "s1"),
            ({"score": 0.5}, {"score": 0.51}, "s2"),
        ]
        result = _compare_score_distribution(
            pairs,
            claim_allowed=True,
            shift_threshold=0.5,
            min_samples=2,
        )
        self.assertFalse(result["significant"])
        self.assertEqual(result["status"], "stable")

    def test_score_distribution_claims_not_allowed(self):
        pairs = [
            ({"score": 0.2}, {"score": 0.8}, "s1"),
            ({"score": 0.2}, {"score": 0.8}, "s2"),
        ]
        result = _compare_score_distribution(
            pairs,
            claim_allowed=False,
            shift_threshold=0.05,
            min_samples=2,
        )
        self.assertFalse(result["significant"])
        self.assertEqual(result["status"], "stable")


class CompareVerdictFlipsTests(unittest.TestCase):
    def test_no_flips(self):
        pairs = [
            ({"verdict": "ai_like"}, {"verdict": "ai_like"}, "s1"),
            ({"verdict": "ai_like"}, {"verdict": "ai_like"}, "s2"),
        ]
        result = _compare_verdict_flips(
            pairs,
            claim_allowed=True,
            flip_rate_threshold=0.10,
            min_samples=2,
        )
        self.assertEqual(result["flip_count"], 0)
        self.assertEqual(result["status"], "stable")

    def test_severe_flip(self):
        pairs = [
            ({"verdict": "ai_like"}, {"verdict": "human_like"}, "s1"),
            ({"verdict": "human_like"}, {"verdict": "ai_like"}, "s2"),
        ]
        result = _compare_verdict_flips(
            pairs,
            claim_allowed=True,
            flip_rate_threshold=0.10,
            min_samples=2,
        )
        self.assertEqual(result["severe_flip_count"], 2)
        self.assertEqual(result["status"], "verdict_flip_change")

    def test_verdict_flips_same_verdict_skipped(self):
        pairs = [
            ({"verdict": "ai_like"}, {"verdict": "ai_like"}, "s1"),
            ({"verdict": "abstain"}, {"verdict": "abstain"}, "s2"),
        ]
        result = _compare_verdict_flips(
            pairs,
            claim_allowed=True,
            flip_rate_threshold=0.10,
            min_samples=2,
        )
        self.assertEqual(result["flip_count"], 0)
        self.assertEqual(result["flip_rate"], 0.0)


class CompareCalibrationTests(unittest.TestCase):
    def test_no_calibrated_probabilities(self):
        result = _compare_calibration(
            [({"score": 0.5}, {"score": 0.6}, "s1")],
            claim_allowed=True,
            shift_threshold=0.05,
            min_samples=2,
        )
        self.assertEqual(result["n_paired_probabilities"], 0)
        self.assertEqual(result["status"], "no_calibrated_probabilities")

    def test_calibration_id_changed(self):
        pairs = [
            (
                {"calibration_id": "cal-v1", "calibrated_ai_probability": 0.3},
                {"calibration_id": "cal-v2", "calibrated_ai_probability": 0.9},
                "s1",
            ),
            (
                {"calibration_id": "cal-v1", "calibrated_ai_probability": 0.3},
                {"calibration_id": "cal-v2", "calibrated_ai_probability": 0.9},
                "s2",
            ),
        ]
        result = _compare_calibration(
            pairs,
            claim_allowed=True,
            shift_threshold=0.05,
            min_samples=2,
        )
        self.assertTrue(result["calibration_id_changed"])
        self.assertEqual(result["calibration_id_change_count"], 2)
        self.assertTrue(result["significant"])

    def test_calibration_status_calibrated_drift(self):
        pairs = [
            (
                {"calibration_id": "cal-v1", "calibrated_ai_probability": 0.1},
                {"calibration_id": "cal-v2", "calibrated_ai_probability": 0.9},
                "s1",
            ),
            (
                {"calibration_id": "cal-v1", "calibrated_ai_probability": 0.1},
                {"calibration_id": "cal-v2", "calibrated_ai_probability": 0.9},
                "s2",
            ),
        ]
        result = _compare_calibration(
            pairs,
            claim_allowed=True,
            shift_threshold=0.05,
            min_samples=2,
        )
        self.assertEqual(result["status"], "calibration_drift")


class CompareThresholdTests(unittest.TestCase):
    def test_threshold_unchanged(self):
        pairs = [
            ({"threshold": 0.5}, {"threshold": 0.5}, "s1"),
            ({"threshold": 0.5}, {"threshold": 0.5}, "s2"),
        ]
        result = _compare_thresholds(pairs, [
            {"threshold": 0.5},
            {"threshold": 0.5},
        ], [
            {"threshold": 0.5},
            {"threshold": 0.5},
        ])
        self.assertFalse(result["threshold_changed"])


class CompareProviderMetadataTests(unittest.TestCase):
    def test_provider_metadata_unchanged(self):
        result = _compare_provider_metadata(
            [{"provider_version": "v1", "detector_version": "1.0", "execution": "local"}],
            [{"provider_version": "v1", "detector_version": "1.0", "execution": "local"}],
        )
        self.assertFalse(result["provider_metadata_changed"])

    def test_detector_version_changed(self):
        result = _compare_provider_metadata(
            [{"provider_version": "v1", "detector_version": "1.0", "execution": "local"}],
            [{"provider_version": "v1", "detector_version": "2.0", "execution": "local"}],
        )
        self.assertTrue(result["changed_detector_version"])

    def test_execution_changed(self):
        result = _compare_provider_metadata(
            [{"provider_version": "v1", "detector_version": "1.0", "execution": "local"}],
            [{"provider_version": "v1", "detector_version": "1.0", "execution": "remote"}],
        )
        self.assertTrue(result["execution_changed"])


class CompareSupportedRegimeTests(unittest.TestCase):
    def test_regime_unchanged(self):
        result = _compare_supported_regime(
            [{"supported_languages": ["en"], "min_words": 50}],
            [{"supported_languages": ["en"], "min_words": 50}],
        )
        self.assertFalse(result["supported_regime_changed"])

    def test_min_words_changed(self):
        result = _compare_supported_regime(
            [{"supported_languages": ["en"], "min_words": 50}],
            [{"supported_languages": ["en"], "min_words": 100}],
        )
        self.assertTrue(result["min_words_changed"])


class OverallSummaryTests(unittest.TestCase):
    def test_no_detectors_compared(self):
        result = _overall_summary([])
        self.assertEqual(result["status"], "no_detectors_compared")

    def test_all_stable(self):
        reports = [{"status": "stable"}, {"status": "stable"}]
        result = _overall_summary(reports)
        self.assertEqual(result["status"], "stable")

    def test_drift_detected(self):
        reports = [{"status": "stable"}, {"status": "drift_detected"}]
        result = _overall_summary(reports)
        self.assertEqual(result["status"], "drift_detected")

    def test_insufficient_evidence(self):
        reports = [{"status": "insufficient_evidence"}, {"status": "insufficient_evidence"}]
        result = _overall_summary(reports)
        self.assertEqual(result["status"], "insufficient_evidence")

    def test_no_comparable_detectors(self):
        reports = [{"status": "missing_in_baseline"}, {"status": "missing_in_current"}]
        result = _overall_summary(reports)
        self.assertEqual(result["status"], "no_comparable_detectors")

    def test_stable_with_coverage_gaps(self):
        reports = [{"status": "stable"}, {"status": "missing_in_baseline"}]
        result = _overall_summary(reports)
        self.assertEqual(result["status"], "stable_with_coverage_gaps")

    def test_overall_status_mixed(self):
        reports = [{"status": "unknown_status"}]
        result = _overall_summary(reports)
        self.assertEqual(result["status"], "mixed")


class CorpusLoadingEdgeCases(unittest.TestCase):
    def test_unsupported_schema_raises(self):
        corpus = {"schema": "textforensics.drift-corpus/v2", "samples": []}
        with self.assertRaises(ValueError):
            DriftObservatory(corpus=corpus)

    def test_missing_samples_raises(self):
        corpus = {"schema": "textforensics.drift-corpus/v1"}
        with self.assertRaises(ValueError):
            DriftObservatory(corpus=corpus)

    def test_samples_not_a_list_raises(self):
        corpus = {"schema": "textforensics.drift-corpus/v1", "samples": "not a list"}
        with self.assertRaises(ValueError):
            DriftObservatory(corpus=corpus)

    def test_corpus_not_mapping_or_list_raises(self):
        with self.assertRaises(ValueError):
            DriftObservatory(corpus="not a valid corpus")

    def test_sample_not_mapping_raises(self):
        corpus = {"samples": ["not a mapping"]}
        with self.assertRaises(ValueError):
            DriftObservatory(corpus=corpus)

    def test_text_not_string_raises(self):
        corpus = {"samples": [{"id": "s1", "text": 123, "metadata": {}}]}
        with self.assertRaises(ValueError):
            DriftObservatory(corpus=corpus)

    def test_text_empty_raises(self):
        corpus = {"samples": [{"id": "s1", "text": "   ", "metadata": {}}]}
        with self.assertRaises(ValueError):
            DriftObservatory(corpus=corpus)

    def test_no_text_no_sha_raises(self):
        corpus = {"samples": [{"id": "s1", "metadata": {}}]}
        with self.assertRaises(ValueError):
            DriftObservatory(corpus=corpus)

    def test_invalid_text_sha256_raises(self):
        corpus = {"samples": [{"id": "s1", "text_sha256": "not-a-valid-hash", "metadata": {}}]}
        with self.assertRaises(ValueError):
            DriftObservatory(corpus=corpus)

    def test_metadata_not_mapping_raises(self):
        corpus = {"samples": [{"id": "s1", "text_sha256": "a" * 64, "metadata": "not a mapping"}]}
        with self.assertRaises(ValueError):
            DriftObservatory(corpus=corpus)


class RecordsByDetectorEdgeCases(unittest.TestCase):
    def test_records_by_detector_empty_detector_id(self):
        snapshot = {"records": [{"detector_id": "", "sample_id": "s1"}]}
        with self.assertRaises(ValueError):
            _records_by_detector(snapshot)

    def test_records_by_detector_missing_detector_id(self):
        snapshot = {"records": [{"sample_id": "s1"}]}
        with self.assertRaises(ValueError):
            _records_by_detector(snapshot)

    def test_index_by_sample_missing_sample_id(self):
        records = [{"score": 0.5}]
        with self.assertRaises(ValueError):
            _index_by_sample(records)

    def test_index_by_sample_empty_sample_id(self):
        records = [{"sample_id": "", "score": 0.5}]
        with self.assertRaises(ValueError):
            _index_by_sample(records)


class TakeSnapshotEdgeCases(unittest.TestCase):
    def test_take_snapshot_sample_no_text_raises(self):
        obs = DriftObservatory(corpus={
            "samples": [{"id": "s1", "text_sha256": "a" * 64, "metadata": {}}]
        })
        detector = BuiltinHeuristicDetector()
        with self.assertRaises(ValueError):
            obs.take_snapshot(detectors=[detector])


class ValidateSnapshotSchemaTests(unittest.TestCase):
    def test_validate_not_mapping(self):
        obs = DriftObservatory(corpus={"samples": []})
        with self.assertRaises(ValueError):
            obs._validate_snapshot_schema("not a mapping")

    def test_validate_wrong_schema(self):
        obs = DriftObservatory(corpus={"samples": []})
        with self.assertRaises(ValueError):
            obs._validate_snapshot_schema({"schema": "wrong"})

    def test_validate_records_not_list(self):
        obs = DriftObservatory(corpus={"samples": []})
        with self.assertRaises(ValueError):
            obs._validate_snapshot_schema({
                "schema": "textforensics.drift-snapshot/v1",
                "records": "not a list",
                "failures": [],
            })

    def test_validate_failures_not_list(self):
        obs = DriftObservatory(corpus={"samples": []})
        with self.assertRaises(ValueError):
            obs._validate_snapshot_schema({
                "schema": "textforensics.drift-snapshot/v1",
                "records": [],
                "failures": "not a list",
            })


class SnapshotLoadingEdgeCases(unittest.TestCase):
    def test_load_snapshots_unrecognized_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "store.json")
            Path(path).write_text(
                json.dumps({"schema": "unknown", "snapshots": []}),
                encoding="utf-8",
            )
            obs = DriftObservatory(corpus={"samples": []})
            with self.assertRaises(ValueError):
                obs.load_snapshots(path)

    def test_load_snapshots_not_a_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "store.json")
            Path(path).write_text(
                json.dumps({
                    "schema": "textforensics.drift-snapshot-store/v1",
                    "snapshots": "not a list"
                }),
                encoding="utf-8",
            )
            obs = DriftObservatory(corpus={"samples": []})
            with self.assertRaises(ValueError):
                obs.load_snapshots(path)

    def test_load_snapshots_replace_false(self):
        """Test load_snapshots with replace=False (append mode)."""
        obs = DriftObservatory(corpus={
            "samples": [
                {"id": "s1", "text": "This is a long enough text to meet the minimum word count requirements for drift testing and validation purposes.", "metadata": {}},
            ]
        })
        # Manually add a snapshot
        snap1 = _make_snapshot(["s1"], snapshot_id="snap1")
        snap1["corpus_sha256"] = obs.corpus_sha256
        obs.add_snapshot(snap1)
        
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "store.json")
            obs.save_snapshots(path)
            
            obs2 = DriftObservatory(corpus={
                "samples": [
                    {"id": "s1", "text": "This is a long enough text to meet the minimum word count requirements for drift testing and validation purposes.", "metadata": {}},
                ]
            })
            snap2 = _make_snapshot(["s1"], snapshot_id="snap2")
            snap2["corpus_sha256"] = obs2.corpus_sha256
            obs2.add_snapshot(snap2)
            
            # Load with replace=False (append)
            loaded = obs2.load_snapshots(path, replace=False)
            self.assertEqual(len(loaded), 2)  # snap2 (existing) + snap1 (loaded)

    def test_load_snapshots_single_snapshot_schema(self):
        """Test loading a file with single snapshot schema."""
        obs = DriftObservatory(corpus={
            "samples": [
                {"id": "s1", "text": "This is a long enough text to meet the minimum word count requirements for drift testing and validation purposes.", "metadata": {}},
            ]
        })
        snap = _make_snapshot(["s1"], snapshot_id="single")
        snap["corpus_sha256"] = obs.corpus_sha256
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "snap.json")
            Path(path).write_text(json.dumps(snap), encoding="utf-8")
            loaded = obs.load_snapshots(path)
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0]["snapshot_id"], "single")


class ReadSnapshotFileTests(unittest.TestCase):
    def test_read_snapshot_file_store_multiple_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "store.json")
            Path(path).write_text(
                json.dumps({
                    "schema": "textforensics.drift-snapshot-store/v1",
                    "snapshots": [
                        {"schema": "textforensics.drift-snapshot/v1", "records": [], "failures": []},
                        {"schema": "textforensics.drift-snapshot/v1", "records": [], "failures": []},
                    ],
                }),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                DriftObservatory.read_snapshot_file(path)

    def test_read_snapshot_file_unrecognized_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "snap.json")
            Path(path).write_text(json.dumps({"schema": "unknown"}), encoding="utf-8")
            with self.assertRaises(ValueError):
                DriftObservatory.read_snapshot_file(path)


class CorpusPathLoadingTests(unittest.TestCase):
    def test_load_from_corpus_path(self):
        """Test loading corpus from a file path."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "corpus.json")
            corpus_data = {
                "schema": "textforensics.drift-corpus/v1",
                "samples": [
                    {"id": "s1", "text": "This is a long enough text to meet the minimum word count requirements for drift testing and validation purposes.", "metadata": {}},
                ]
            }
            Path(path).write_text(json.dumps(corpus_data), encoding="utf-8")
            obs = DriftObservatory(corpus_path=path)
            self.assertEqual(len(obs.samples), 1)


class ObservationValidationEdgeCases(unittest.TestCase):
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

    def test_observation_text_sha256_mismatch(self):
        sample_id = list(self.obs.samples.keys())[0]
        with self.assertRaises(ValueError):
            self.obs.snapshot_from_observations([{
                "sample_id": sample_id,
                "text_sha256": "wrong" * 21 + "a",
                "score": 0.5,
                "verdict": "ai_like",
                "detector_id": "test",
                "detector_version": "1.0",
                "detector_family": "test",
                "execution": "local",
            }])

    def test_observation_calibration_id_required(self):
        sample_id = list(self.obs.samples.keys())[0]
        with self.assertRaises(ValueError):
            self.obs.snapshot_from_observations([{
                "sample_id": sample_id,
                "score": 0.5,
                "verdict": "ai_like",
                "detector_id": "test",
                "detector_version": "1.0",
                "detector_family": "test",
                "execution": "local",
                "calibrated_ai_probability": 0.8,
                # Missing calibration_id
            }])

    def test_observation_supported_languages_not_list(self):
        sample_id = list(self.obs.samples.keys())[0]
        with self.assertRaises(ValueError):
            self.obs.snapshot_from_observations([{
                "sample_id": sample_id,
                "score": 0.5,
                "verdict": "ai_like",
                "detector_id": "test",
                "detector_version": "1.0",
                "detector_family": "test",
                "execution": "local",
                "supported_languages": "en",
            }])

    def test_observation_provider_version_empty(self):
        sample_id = list(self.obs.samples.keys())[0]
        with self.assertRaises(ValueError):
            self.obs.snapshot_from_observations([{
                "sample_id": sample_id,
                "score": 0.5,
                "verdict": "ai_like",
                "detector_id": "test",
                "detector_version": "1.0",
                "detector_family": "test",
                "execution": "local",
                "provider_version": "",
            }])

    def test_observation_score_semantics_empty(self):
        sample_id = list(self.obs.samples.keys())[0]
        # score_semantics defaults to "unspecified" when empty, so no error
        snapshot = self.obs.snapshot_from_observations([{
            "sample_id": sample_id,
            "score": 0.5,
            "verdict": "ai_like",
            "detector_id": "test",
            "detector_version": "1.0",
            "detector_family": "test",
            "execution": "local",
            "score_semantics": "",
        }])
        self.assertEqual(snapshot["record_count"], 1)
        self.assertEqual(snapshot["records"][0]["score_semantics"], "unspecified")


class FailureNormalizationTests(unittest.TestCase):
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

    def test_failure_unknown_sample_raises(self):
        with self.assertRaises(ValueError):
            self.obs.snapshot_from_observations([], failures=[{
                "sample_id": "unknown-999",
                "detector_id": "test",
                "error_type": "Timeout",
            }])

    def test_failure_text_sha256_mismatch_raises(self):
        sample_id = list(self.obs.samples.keys())[0]
        with self.assertRaises(ValueError):
            self.obs.snapshot_from_observations([], failures=[{
                "sample_id": sample_id,
                "text_sha256": "wrong" * 21 + "a",
                "detector_id": "test",
                "error_type": "Timeout",
            }])

    def test_failure_text_sha256_not_hex_raises(self):
        with self.assertRaises(ValueError):
            self.obs.snapshot_from_observations([], failures=[{
                "text_sha256": "not-hex",
                "detector_id": "test",
                "error_type": "Timeout",
            }])

    def test_failure_auto_derives_text_sha256(self):
        sample_id = list(self.obs.samples.keys())[0]
        snapshot = self.obs.snapshot_from_observations([], failures=[{
            "sample_id": sample_id,
            "detector_id": "test",
            "error_type": "Timeout",
        }])
        self.assertEqual(snapshot["failure_count"], 1)

    def test_failure_without_sample_id_or_text_sha(self):
        """Test failure with no sample_id and no text_sha256."""
        snapshot = self.obs.snapshot_from_observations([], failures=[{
            "detector_id": "test",
            "error_type": "Timeout",
        }])
        self.assertEqual(snapshot["failure_count"], 1)
        self.assertIsNone(snapshot["failures"][0]["sample_id"])


class TakeSnapshotEdgeCases(unittest.TestCase):
    def test_take_snapshot_sample_no_text_raises(self):
        obs = DriftObservatory(corpus={
            "samples": [{"id": "s1", "text_sha256": "a" * 64, "metadata": {}}]
        })
        detector = BuiltinHeuristicDetector()
        with self.assertRaises(ValueError):
            obs.take_snapshot(detectors=[detector])

    def test_take_snapshot_detector_ids_filter(self):
        corpus = {
            "samples": [
                {"id": "s1", "text": "This is a long enough text to meet the minimum word count requirements for drift testing and validation purposes.", "metadata": {}},
            ]
        }
        obs = DriftObservatory(corpus=corpus)
        detector = BuiltinHeuristicDetector()
        snapshot = obs.take_snapshot(
            detectors=[detector],
            detector_ids=[detector.detector_id],
        )
        self.assertIn("skipped_detectors", snapshot)

    def test_take_snapshot_remote_detector_skipped(self):
        corpus = {
            "samples": [
                {"id": "s1", "text": "This is a long enough text to meet the minimum word count requirements for drift testing and validation purposes.", "metadata": {}},
            ]
        }
        obs = DriftObservatory(corpus=corpus)
        
        # Create a remote detector - _is_remote_detector checks for execution or remote attribute
        from dataclasses import dataclass
        
        @dataclass(slots=True)
        class FakeRemoteDetector:
            detector_id: str = "remote-detector"
            detector_version: str = "1.0"
            detector_family: str = "remote"
            remote: bool = True  # This makes _is_remote_detector return True
            
            @property
            def provider_version(self):
                return "api-1.0"
            
            def detect(self, text: str):
                from textforensics.detectors import DetectorPrediction
                return DetectorPrediction(
                    schema="textforensics.detector-result/v1",
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    detector_family=self.detector_family,
                    execution="remote",
                    score=0.5,
                    score_semantics="test",
                    verdict="ai_like",
                    threshold=0.5,
                )

        remote_det = FakeRemoteDetector()
        snapshot = obs.take_snapshot(
            detectors=[remote_det],
            allow_remote=False,
        )
        self.assertTrue(len(snapshot.get("skipped_detectors", [])) > 0)


class CompareDetectorFindingsTests(unittest.TestCase):
    def _make_obs(self):
        return DriftObservatory(
            corpus={
                "samples": [
                    {"id": f"sample-{i:02d}", "text": f"This is sample text number {i} that is long enough to trigger analysis. It has more than enough words to meet minimum length requirements for drift tracking and comparison purposes.", "metadata": {"label": "human" if i % 2 == 0 else "ai", "domain": "general"}}
                    for i in range(1, 7)
                ]
            },
            min_samples_for_drift_claim=2,
        )

    def test_findings_detector_version_changed(self):
        obs = self._make_obs()
        sample_ids = list(obs.samples.keys())
        baseline = _make_snapshot(sample_ids, detector_version="1.0.0", execution="remote", provider_version="api-2025-01")
        baseline["corpus_sha256"] = obs.corpus_sha256
        current = _make_snapshot(sample_ids, detector_version="2.0.0", execution="remote", provider_version="api-2025-01")
        current["corpus_sha256"] = obs.corpus_sha256

        report = obs.compare_snapshots(baseline, current)
        detector_report = report["detectors"][0]
        findings = detector_report.get("findings", [])
        codes = [f.get("code") for f in findings]
        self.assertIn("changed_detector_version", codes)

    def test_findings_execution_mode_changed(self):
        obs = self._make_obs()
        sample_ids = list(obs.samples.keys())
        baseline = _make_snapshot(sample_ids, execution="local")
        baseline["corpus_sha256"] = obs.corpus_sha256
        current = _make_snapshot(sample_ids, execution="remote", provider_version="api-1.0")
        current["corpus_sha256"] = obs.corpus_sha256

        report = obs.compare_snapshots(baseline, current)
        detector_report = report["detectors"][0]
        findings = detector_report.get("findings", [])
        codes = [f.get("code") for f in findings]
        self.assertIn("execution_mode_changed", codes)

    def test_findings_min_words_changed(self):
        obs = self._make_obs()
        sample_ids = list(obs.samples.keys())
        baseline = _make_snapshot(sample_ids, min_words=50)
        baseline["corpus_sha256"] = obs.corpus_sha256
        current = _make_snapshot(sample_ids, min_words=100)
        current["corpus_sha256"] = obs.corpus_sha256

        report = obs.compare_snapshots(baseline, current)
        detector_report = report["detectors"][0]
        findings = detector_report.get("findings", [])
        codes = [f.get("code") for f in findings]
        self.assertIn("min_words_change", codes)


if __name__ == "__main__":
    unittest.main()
