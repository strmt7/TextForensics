"""Tests for replayable detector decision ledger."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from textforensics.detectors import DetectorPrediction
from textforensics.ledger import (
    DecisionLedger,
    DecisionLedgerError,
    DecisionRecord,
    ReplayResult,
    detect_drift,
    load_ledger,
    save_ledger,
    text_sha256,
)


def make_prediction(
    detector_id: str = "test/detector",
    detector_version: str = "1.0.0",
    score: float | None = 0.75,
    verdict: str = "ai_like",
    runtime_ms: float | None = 10.5,
) -> DetectorPrediction:
    """Create a DetectorPrediction for testing."""
    return DetectorPrediction(
        schema="textforensics.detector-result/v1",
        detector_id=detector_id,
        detector_version=detector_version,
        detector_family="test-family",
        execution="local",
        score=score,
        score_semantics="test score",
        verdict=verdict,
        threshold=0.5,
        calibrated_ai_probability=None,
        calibration_id=None,
        reliability=None,
        supported_languages=["en"],
        min_words=50,
        evidence=[],
        warnings=[],
        runtime_ms=runtime_ms,
    )


class TestDecisionRecord:
    def test_record_fields_populated(self):
        """DecisionRecord should have all required fields populated."""
        record = DecisionRecord(
            record_id="abc123",
            timestamp="2024-01-01T00:00:00+00:00",
            text_sha256="a" * 64,
            detector_id="test/detector",
            detector_version="1.0.0",
            raw_score=0.75,
            verdict="ai_like",
            runtime_ms=10.5,
        )

        assert record.record_id == "abc123"
        assert record.timestamp == "2024-01-01T00:00:00+00:00"
        assert record.text_sha256 == "a" * 64
        assert record.detector_id == "test/detector"
        assert record.detector_version == "1.0.0"
        assert record.raw_score == 0.75
        assert record.verdict == "ai_like"
        assert record.runtime_ms == 10.5
        assert record.ledger_schema == "textforensics.decision-record/v1"

    def test_record_to_dict_excludes_raw_text(self):
        """to_dict() must never contain raw text."""
        record = DecisionRecord(
            record_id="abc123",
            timestamp="2024-01-01T00:00:00+00:00",
            text_sha256="a" * 64,
            detector_id="test/detector",
            detector_version="1.0.0",
            raw_score=0.75,
            verdict="ai_like",
            runtime_ms=10.5,
        )

        d = record.to_dict()
        assert "text" not in d
        # Ensure raw text value is not accidentally in the JSON
        json_str = json.dumps(d)
        assert "this is secret text" not in json_str

    def test_record_roundtrip(self):
        """Serialization/deserialization should preserve data."""
        record = DecisionRecord(
            record_id="abc123",
            timestamp="2024-01-01T00:00:00+00:00",
            text_sha256="a" * 64,
            detector_id="test/detector",
            detector_version="1.0.0",
            raw_score=0.75,
            verdict="ai_like",
            runtime_ms=10.5,
        )

        d = record.to_dict()
        record2 = DecisionRecord.from_dict(d)

        assert record2.record_id == record.record_id
        assert record2.timestamp == record.timestamp
        assert record2.text_sha256 == record.text_sha256
        assert record2.detector_id == record.detector_id
        assert record2.detector_version == record.detector_version
        assert record2.raw_score == record.raw_score
        assert record2.verdict == record.verdict
        assert record2.runtime_ms == record.runtime_ms
        assert record2.ledger_schema == record.ledger_schema

    def test_record_with_none_score(self):
        """Record should handle None score."""
        record = DecisionRecord(
            record_id="abc123",
            timestamp="2024-01-01T00:00:00+00:00",
            text_sha256="a" * 64,
            detector_id="test/detector",
            detector_version="1.0.0",
            raw_score=None,
            verdict="abstain",
            runtime_ms=None,
        )

        assert record.raw_score is None
        assert record.runtime_ms is None
        d = record.to_dict()
        assert d["raw_score"] is None
        assert d["runtime_ms"] is None


class TestReplayResult:
    def test_replay_result_fields(self):
        """ReplayResult should have all fields."""
        result = ReplayResult(
            record_id="rec123",
            matched=True,
            expected_score=0.75,
            actual_score=0.7500000001,
            expected_verdict="ai_like",
            actual_verdict="ai_like",
            score_delta=1e-10,
            detail="matched",
        )

        assert result.record_id == "rec123"
        assert result.matched is True
        assert result.expected_score == 0.75
        assert result.actual_score == 0.7500000001
        assert result.expected_verdict == "ai_like"
        assert result.actual_verdict == "ai_like"
        assert result.score_delta == 1e-10
        assert result.detail == "matched"

    def test_replay_result_to_dict(self):
        """ReplayResult should serialize correctly."""
        result = ReplayResult(
            record_id="rec123",
            matched=False,
            expected_score=0.75,
            actual_score=0.85,
            expected_verdict="ai_like",
            actual_verdict="human_like",
            score_delta=0.1,
            detail="score mismatch",
        )

        d = result.to_dict()
        assert d["matched"] is False
        assert d["score_delta"] == 0.1


class TestDecisionLedger:
    def test_record_single_decision(self):
        """Recording a single decision should populate all fields correctly."""
        ledger = DecisionLedger()
        text = "This is a test document for detection."
        prediction = make_prediction()

        record = ledger.record(text, prediction)

        assert len(ledger) == 1
        assert record.text_sha256 == text_sha256(text)
        assert record.detector_id == "test/detector"
        assert record.detector_version == "1.0.0"
        assert record.raw_score == 0.75
        assert record.verdict == "ai_like"
        assert record.runtime_ms == 10.5
        assert record.ledger_schema == "textforensics.decision-record/v1"
        # Verify raw text is never stored
        d = record.to_dict()
        assert "text" not in d
        json_str = json.dumps(d)
        assert text not in json_str

    def test_record_all_multiple_predictions(self):
        """record_all should record multiple predictions for the same text."""
        ledger = DecisionLedger()
        text = "Test text for multiple detectors."
        predictions = [
            make_prediction(detector_id="detector/a", score=0.8, verdict="ai_like"),
            make_prediction(detector_id="detector/b", score=0.3, verdict="human_like"),
            make_prediction(detector_id="detector/c", score=None, verdict="abstain"),
        ]

        records = ledger.record_all(text, predictions)

        assert len(records) == 3
        assert len(ledger) == 3
        assert records[0].detector_id == "detector/a"
        assert records[1].detector_id == "detector/b"
        assert records[2].detector_id == "detector/c"
        assert records[2].raw_score is None
        assert records[2].verdict == "abstain"

    def test_persistence_write_and_load(self):
        """Records should persist to JSONL and load correctly."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.jsonl"

            # Create ledger and record
            ledger1 = DecisionLedger(path)
            text = "Persistent test text."
            ledger1.record(text, make_prediction(detector_id="detector/x", score=0.9))
            ledger1.record(text, make_prediction(detector_id="detector/y", score=0.2))

            # Create new ledger on same path
            ledger2 = DecisionLedger(path)

            assert len(ledger2) == 2
            assert ledger2._records[0].detector_id == "detector/x"
            assert ledger2._records[1].detector_id == "detector/y"
            assert ledger2._records[0].raw_score == 0.9
            assert ledger2._records[1].raw_score == 0.2

    def test_corrupt_jsonl_raises_error_with_line_number(self):
        """Corrupt JSONL should raise DecisionLedgerError mentioning line number."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.jsonl"
            # Write a valid record first, then a corrupt line
            valid_record = {
                "record_id": "rec1",
                "timestamp": "2024-01-01T00:00:00+00:00",
                "text_sha256": "a" * 64,
                "detector_id": "detector/x",
                "detector_version": "1.0",
                "raw_score": 0.5,
                "verdict": "ai_like",
                "runtime_ms": 10.0,
                "ledger_schema": "textforensics.decision-record/v1",
            }
            path.write_text(json.dumps(valid_record) + "\nnot valid json\n")

            with pytest.raises(DecisionLedgerError) as exc_info:
                DecisionLedger(path)

            assert "line 2" in str(exc_info.value).lower()

    def test_verify_matching_decision(self):
        """Verifying a matching decision should return matched=True."""
        ledger = DecisionLedger()
        text = "Text to verify."
        prediction = make_prediction(score=0.75, verdict="ai_like")

        record = ledger.record(text, prediction)
        result = ledger.verify(text, prediction)

        assert result.matched is True
        assert result.record_id == record.record_id
        assert result.expected_score == 0.75
        assert result.actual_score == 0.75
        assert result.score_delta is not None
        assert result.score_delta <= 1e-9
        assert result.detail == "matched"

    def test_verify_score_beyond_tolerance(self):
        """Score difference beyond tolerance should return matched=False."""
        ledger = DecisionLedger()
        text = "Text for score tolerance test."
        pred1 = make_prediction(score=0.75, verdict="ai_like")
        pred2 = make_prediction(score=0.85, verdict="ai_like")  # 0.1 difference > 1e-9

        ledger.record(text, pred1)
        result = ledger.verify(text, pred2, tolerance=1e-9)

        assert result.matched is False
        assert abs(result.score_delta - 0.1) < 1e-10
        assert result.detail == "score mismatch"

    def test_verify_different_verdict(self):
        """Different verdict should return matched=False."""
        ledger = DecisionLedger()
        text = "Text for verdict test."
        pred1 = make_prediction(score=0.75, verdict="ai_like")
        pred2 = make_prediction(score=0.75, verdict="human_like")

        ledger.record(text, pred1)
        result = ledger.verify(text, pred2)

        assert result.matched is False
        assert result.expected_verdict == "ai_like"
        assert result.actual_verdict == "human_like"
        assert result.detail == "verdict mismatch"

    def test_verify_no_matching_record(self):
        """Verify with no matching record should return matched=False."""
        ledger = DecisionLedger()
        text = "Text with no prior record."
        prediction = make_prediction()

        result = ledger.verify(text, prediction)

        assert result.matched is False
        assert result.detail == "no matching record"
        assert result.record_id == ""
        assert result.expected_score is None
        assert result.expected_verdict == ""

    def test_verify_text_multiple_predictions(self):
        """verify_text should verify all predictions."""
        ledger = DecisionLedger()
        text = "Multi-prediction verify text."
        predictions = [
            make_prediction(detector_id="detector/a", score=0.8),
            make_prediction(detector_id="detector/b", score=0.3),
        ]

        ledger.record_all(text, predictions)
        results = ledger.verify_text(text, predictions)

        assert len(results) == 2
        assert all(r.matched for r in results)

    def test_verify_determinism_same_predictions(self):
        """verify_determinism with same predictions should all match."""
        ledger = DecisionLedger()
        text = "Determinism test text."
        predictions = [
            make_prediction(detector_id="detector/a", score=0.8),
            make_prediction(detector_id="detector/b", score=0.3),
        ]

        ledger.record_all(text, predictions)

        # Lambda returns the same predictions
        def run_fn(t: str) -> list[DetectorPrediction]:
            return predictions

        results = ledger.verify_determinism(text, run_fn)

        assert len(results) == 2
        assert all(r.matched for r in results)

    def test_verify_determinism_perturbed_scores(self):
        """verify_determinism with perturbed scores should not match."""
        ledger = DecisionLedger()
        text = "Determinism perturbed test."
        predictions = [
            make_prediction(detector_id="detector/a", score=0.8),
            make_prediction(detector_id="detector/b", score=0.3),
        ]

        ledger.record_all(text, predictions)

        # Lambda returns perturbed predictions
        def run_fn(t: str) -> list[DetectorPrediction]:
            return [
                make_prediction(detector_id="detector/a", score=0.81),  # 0.01 diff > 1e-9
                make_prediction(detector_id="detector/b", score=0.3),
            ]

        results = ledger.verify_determinism(text, run_fn, tolerance=1e-9)

        assert len(results) == 2
        assert results[0].matched is False  # score perturbed
        assert results[1].matched is True  # same score

    def test_records_for_text_filtering(self):
        """records_for_text should return only records for that text."""
        ledger = DecisionLedger()
        text1 = "First text."
        text2 = "Second text."
        ledger.record(text1, make_prediction(detector_id="detector/a"))
        ledger.record(text2, make_prediction(detector_id="detector/b"))
        ledger.record(text1, make_prediction(detector_id="detector/c"))

        records = ledger.records_for_text(text1)

        assert len(records) == 2
        assert all(r.text_sha256 == text_sha256(text1) for r in records)
        assert {r.detector_id for r in records} == {"detector/a", "detector/c"}

    def test_records_for_detector_filtering(self):
        """records_for_detector should return only records for that detector."""
        ledger = DecisionLedger()
        text1 = "Text one."
        text2 = "Text two."
        ledger.record(text1, make_prediction(detector_id="detector/x"))
        ledger.record(text2, make_prediction(detector_id="detector/x"))
        ledger.record(text1, make_prediction(detector_id="detector/y"))

        records = ledger.records_for_detector("detector/x")

        assert len(records) == 2
        assert all(r.detector_id == "detector/x" for r in records)

    def test_len_and_iteration(self):
        """__len__ and __iter__ should work correctly."""
        ledger = DecisionLedger()
        assert len(ledger) == 0

        ledger.record("text1", make_prediction(detector_id="a"))
        ledger.record("text2", make_prediction(detector_id="b"))

        assert len(ledger) == 2
        count = sum(1 for _ in ledger)
        assert count == 2

    def test_to_list_structure(self):
        """to_list should return list of dicts with correct structure."""
        ledger = DecisionLedger()
        ledger.record("text", make_prediction(detector_id="detector/test"))

        lst = ledger.to_list()

        assert isinstance(lst, list)
        assert len(lst) == 1
        assert isinstance(lst[0], dict)
        assert lst[0]["detector_id"] == "detector/test"
        assert "text" not in lst[0]

    def test_empty_text_raises_error(self):
        """Recording with empty text should raise DecisionLedgerError."""
        ledger = DecisionLedger()
        prediction = make_prediction()

        with pytest.raises(DecisionLedgerError) as exc_info:
            ledger.record("", prediction)

        assert "non-empty" in str(exc_info.value).lower()

    def test_whitespace_only_text_raises_error(self):
        """Recording with whitespace-only text should raise DecisionLedgerError."""
        ledger = DecisionLedger()
        prediction = make_prediction()

        with pytest.raises(DecisionLedgerError):
            ledger.record("   ", prediction)

        with pytest.raises(DecisionLedgerError):
            ledger.record("\n\t", prediction)


class TestSaveLoadLedger:
    def test_save_ledger_roundtrip(self):
        """save_ledger and load_ledger should preserve records."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.jsonl"

            records = [
                DecisionRecord(
                    record_id="rec1",
                    timestamp="2024-01-01T00:00:00+00:00",
                    text_sha256="a" * 64,
                    detector_id="detector/a",
                    detector_version="1.0",
                    raw_score=0.8,
                    verdict="ai_like",
                    runtime_ms=10.0,
                ),
                DecisionRecord(
                    record_id="rec2",
                    timestamp="2024-01-01T00:00:01+00:00",
                    text_sha256="b" * 64,
                    detector_id="detector/b",
                    detector_version="2.0",
                    raw_score=0.3,
                    verdict="human_like",
                    runtime_ms=5.0,
                ),
            ]

            save_ledger(records, path)
            loaded = load_ledger(path)

            assert len(loaded) == 2
            assert loaded[0].record_id == "rec1"
            assert loaded[0].detector_id == "detector/a"
            assert loaded[1].record_id == "rec2"
            assert loaded[1].detector_id == "detector/b"

    def test_load_ledger_missing_file(self):
        """load_ledger on missing file should return empty list."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nonexistent.jsonl"
            loaded = load_ledger(path)
            assert loaded == []

    def test_load_ledger_corrupt_raises_error(self):
        """load_ledger on corrupt file should raise DecisionLedgerError with line number."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.jsonl"
            # Write a valid record first, then a corrupt line
            valid_record = {
                "record_id": "rec1",
                "timestamp": "2024-01-01T00:00:00+00:00",
                "text_sha256": "a" * 64,
                "detector_id": "detector/x",
                "detector_version": "1.0",
                "raw_score": 0.5,
                "verdict": "ai_like",
                "runtime_ms": 10.0,
                "ledger_schema": "textforensics.decision-record/v1",
            }
            path.write_text(json.dumps(valid_record) + "\ncorrupt line\n")

            with pytest.raises(DecisionLedgerError) as exc_info:
                load_ledger(path)

            assert "line 2" in str(exc_info.value).lower()


class TestDetectDrift:
    def test_detect_drift_no_drift_identical_records(self):
        """detect_drift should return no drift for identical records."""
        records = [
            DecisionRecord(
                record_id="r1",
                timestamp="2024-01-01T00:00:00+00:00",
                text_sha256="a" * 64,
                detector_id="detector/x",
                detector_version="1.0",
                raw_score=0.75,
                verdict="ai_like",
                runtime_ms=10.0,
            ),
            DecisionRecord(
                record_id="r2",
                timestamp="2024-01-01T00:00:01+00:00",
                text_sha256="b" * 64,
                detector_id="detector/x",
                detector_version="1.0",
                raw_score=0.25,
                verdict="human_like",
                runtime_ms=10.0,
            ),
        ]

        results = detect_drift(records, records)

        assert len(results) == 1
        assert results[0]["detector_id"] == "detector/x"
        assert results[0]["paired_count"] == 2
        assert results[0]["mean_score_delta"] == 0.0
        assert results[0]["verdict_flips"] == 0
        assert results[0]["drift_detected"] is False

    def test_detect_drift_score_drift(self):
        """detect_drift should detect score drift > 0.05."""
        baseline = [
            DecisionRecord(
                record_id="r1",
                timestamp="2024-01-01T00:00:00+00:00",
                text_sha256="a" * 64,
                detector_id="detector/x",
                detector_version="1.0",
                raw_score=0.50,
                verdict="ai_like",
                runtime_ms=10.0,
            ),
            DecisionRecord(
                record_id="r2",
                timestamp="2024-01-01T00:00:01+00:00",
                text_sha256="b" * 64,
                detector_id="detector/x",
                detector_version="1.0",
                raw_score=0.50,
                verdict="ai_like",
                runtime_ms=10.0,
            ),
        ]

        current = [
            DecisionRecord(
                record_id="r3",
                timestamp="2024-01-02T00:00:00+00:00",
                text_sha256="a" * 64,
                detector_id="detector/x",
                detector_version="1.0",
                raw_score=0.60,  # delta = 0.10 > 0.05
                verdict="ai_like",
                runtime_ms=10.0,
            ),
            DecisionRecord(
                record_id="r4",
                timestamp="2024-01-02T00:00:01+00:00",
                text_sha256="b" * 64,
                detector_id="detector/x",
                detector_version="1.0",
                raw_score=0.60,  # delta = 0.10 > 0.05
                verdict="ai_like",
                runtime_ms=10.0,
            ),
        ]

        results = detect_drift(current, baseline)

        assert len(results) == 1
        assert results[0]["detector_id"] == "detector/x"
        assert results[0]["paired_count"] == 2
        assert results[0]["mean_score_delta"] == 0.10
        assert results[0]["verdict_flips"] == 0
        assert results[0]["drift_detected"] is True

    def test_detect_drift_verdict_flip(self):
        """detect_drift should detect verdict flips."""
        baseline = [
            DecisionRecord(
                record_id="r1",
                timestamp="2024-01-01T00:00:00+00:00",
                text_sha256="a" * 64,
                detector_id="detector/x",
                detector_version="1.0",
                raw_score=0.75,
                verdict="ai_like",
                runtime_ms=10.0,
            ),
        ]

        current = [
            DecisionRecord(
                record_id="r2",
                timestamp="2024-01-02T00:00:00+00:00",
                text_sha256="a" * 64,
                detector_id="detector/x",
                detector_version="1.0",
                raw_score=0.75,
                verdict="human_like",  # verdict flipped
                runtime_ms=10.0,
            ),
        ]

        results = detect_drift(current, baseline)

        assert len(results) == 1
        assert results[0]["detector_id"] == "detector/x"
        assert results[0]["paired_count"] == 1
        assert results[0]["verdict_flips"] == 1
        assert results[0]["drift_detected"] is True

    def test_detect_drift_empty_and_unknown_detector(self):
        """detect_drift should handle empty sets and detectors not in both."""
        baseline = [
            DecisionRecord(
                record_id="r1",
                timestamp="2024-01-01T00:00:00+00:00",
                text_sha256="a" * 64,
                detector_id="detector/a",
                detector_version="1.0",
                raw_score=0.5,
                verdict="ai_like",
                runtime_ms=10.0,
            ),
        ]

        current = [
            DecisionRecord(
                record_id="r2",
                timestamp="2024-01-02T00:00:00+00:00",
                text_sha256="b" * 64,
                detector_id="detector/b",  # different detector
                detector_version="1.0",
                raw_score=0.5,
                verdict="ai_like",
                runtime_ms=10.0,
            ),
        ]

        # No common detectors -> empty result
        results = detect_drift(current, baseline)
        assert results == []

        # Empty current
        results = detect_drift([], baseline)
        assert results == []

        # Empty baseline
        results = detect_drift(current, [])
        assert results == []

    def test_detect_drift_none_scores_skipped(self):
        """detect_drift should skip None scores in mean calculation."""
        baseline = [
            DecisionRecord(
                record_id="r1",
                timestamp="2024-01-01T00:00:00+00:00",
                text_sha256="a" * 64,
                detector_id="detector/x",
                detector_version="1.0",
                raw_score=0.50,
                verdict="ai_like",
                runtime_ms=10.0,
            ),
            DecisionRecord(
                record_id="r2",
                timestamp="2024-01-01T00:00:01+00:00",
                text_sha256="b" * 64,
                detector_id="detector/x",
                detector_version="1.0",
                raw_score=None,
                verdict="abstain",
                runtime_ms=10.0,
            ),
        ]

        current = [
            DecisionRecord(
                record_id="r3",
                timestamp="2024-01-02T00:00:00+00:00",
                text_sha256="a" * 64,
                detector_id="detector/x",
                detector_version="1.0",
                raw_score=0.60,
                verdict="ai_like",
                runtime_ms=10.0,
            ),
            DecisionRecord(
                record_id="r4",
                timestamp="2024-01-02T00:00:01+00:00",
                text_sha256="b" * 64,
                detector_id="detector/x",
                detector_version="1.0",
                raw_score=None,
                verdict="abstain",
                runtime_ms=10.0,
            ),
        ]

        results = detect_drift(current, baseline)

        assert len(results) == 1
        assert results[0]["paired_count"] == 2
        assert results[0]["mean_score_delta"] == 0.10  # Only one pair had scores
        assert results[0]["drift_detected"] is True


class TestEdgeCases:
    def test_different_detector_versions_same_id(self):
        """Records with same detector_id but different versions should be separate."""
        ledger = DecisionLedger()
        text = "Version test."
        pred_v1 = make_prediction(detector_id="detector/x", detector_version="1.0", score=0.8)
        pred_v2 = make_prediction(detector_id="detector/x", detector_version="2.0", score=0.7)

        ledger.record(text, pred_v1)
        ledger.record(text, pred_v2)

        # Should find the most recent (v2)
        result = ledger.verify(text, pred_v2)
        assert result.matched is True

        # Should find v1 when verifying with v1
        result = ledger.verify(text, pred_v1)
        assert result.matched is True

    def test_verify_with_none_score_matching(self):
        """Verification should match when both scores are None."""
        ledger = DecisionLedger()
        text = "None score test."
        pred = make_prediction(score=None, verdict="abstain")

        ledger.record(text, pred)
        result = ledger.verify(text, pred)

        assert result.matched is True
        assert result.expected_score is None
        assert result.actual_score is None
        assert result.score_delta is None

    def test_verify_with_one_none_score(self):
        """Verification should fail when one score is None and other is not."""
        ledger = DecisionLedger()
        text = "Mixed None score test."
        pred1 = make_prediction(score=0.5, verdict="ai_like")
        pred2 = make_prediction(score=None, verdict="ai_like")

        ledger.record(text, pred1)
        result = ledger.verify(text, pred2)

        assert result.matched is False
        assert result.detail == "score mismatch"

    def test_jsonl_format_one_record_per_line(self):
        """JSONL file should have one record per line."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.jsonl"
            ledger = DecisionLedger(path)

            ledger.record("text1", make_prediction(detector_id="a"))
            ledger.record("text2", make_prediction(detector_id="b"))

            content = path.read_text()
            lines = content.strip().split("\n")
            assert len(lines) == 2
            # Each line should be valid JSON
            for line in lines:
                json.loads(line)

    def test_verify_tolerance_parameter(self):
        """verify should respect custom tolerance parameter."""
        ledger = DecisionLedger()
        text = "Tolerance test."
        pred1 = make_prediction(score=0.75, verdict="ai_like")
        pred2 = make_prediction(score=0.751, verdict="ai_like")  # delta = 0.001

        ledger.record(text, pred1)

        # With default tolerance (1e-9) - should fail
        result = ledger.verify(text, pred2, tolerance=1e-9)
        assert result.matched is False

        # With larger tolerance - should pass
        result = ledger.verify(text, pred2, tolerance=0.01)
        assert result.matched is True

    def test_ledger_without_store_path(self):
        """Ledger without store_path should work in-memory only."""
        ledger = DecisionLedger()  # No path
        ledger.record("text", make_prediction())

        assert len(ledger) == 1
        assert ledger.store_path is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
