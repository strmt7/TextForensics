"""W5 Worker F kill tests for report (audit-w5-f).

Kill evidence for the 15 killable runtime survivors in
textforensics.report (5 more are equivalents; see
hidden_files/audit-w5-f-equiv-reasons-report.json):

* ``_predictions_from_observations`` OrWithAnd (line 382): a
  non-string detector_id must raise "requires a detector_id" (the
  mutant falls through to the "unknown detector" error instead).
* The skipped-detector ``failed is True`` guard (line 385): a
  ``failed=True`` row for a skipped detector is dropped silently,
  while a truthy-but-not-True value (``failed=1``) still raises.
  ``failed=True`` kills AddNot, Is_Gt, Is_IsNot, Is_Lt, Is_NotEq and
  ReplaceTrueWithFalse (all take the raise branch instead of
  continuing); ``failed=1`` kills Is_Eq, Is_GtE and Is_LtE (all treat
  ``1`` as True and continue silently, because ``1 == True``).
* ReplaceContinueWithBreak (line 386): a dropped row must not stop
  the rows after it from being processed.
* Is_Eq on the failure branch (line 394): ``failed=1`` is a
  prediction, not a failure.
* ExceptionReplacer (line 405): an incomplete observation row
  (TypeError building the prediction) must raise ValueError.
* ``build_forensic_bundle`` Mul_Div (line 412): the ``*`` -> ``/``
  mutant makes ``text`` positional-only, so the kill is passing
  ``text`` by keyword (same lesson as ollama/atomic_io).
* OrWithAnd on the deterministic timestamp (line 536): a given
  fixed_timestamp must be used, not the 1970 default.
"""

import pytest

from textforensics.detectors import DetectorPrediction
from textforensics.report import _predictions_from_observations, build_forensic_bundle

TEXT = (
    "I tested the device twice yesterday and wrote down what changed. "
    "The second run was warmer, so I plan to repeat it before drawing conclusions."
)


class _FakeDetector:
    detector_id = "fake/d"
    detector_version = "1"
    detector_family = "fake-family"

    def detect(self, text):
        return _prediction_for(self.detector_id)


def _prediction_for(detector_id):
    return DetectorPrediction(
        schema="textforensics.detector-result/v1",
        detector_id=detector_id,
        detector_version="1",
        detector_family="fake-family",
        execution="local",
        score=0.5,
        score_semantics="test",
        verdict="ai_like",
        threshold=0.5,
        calibrated_ai_probability=None,
        calibration_id=None,
    )


class _FakeDetectorE(_FakeDetector):
    detector_id = "fake/e"


def _prediction_row(detector_id="fake/d", **overrides):
    row = _prediction_for(detector_id).to_dict()
    row.update(overrides)
    return row


def _failure_row(**overrides):
    row = {
        "detector_id": "fake/d",
        "detector_version": "1",
        "detector_family": "fake-family",
        "error_type": "RuntimeError",
        "message": "boom",
        "runtime_ms": 1.0,
        "failed": True,
    }
    row.update(overrides)
    return row


def _rebuild(rows, *, skipped=(), allowed=None):
    return _predictions_from_observations(
        rows, allowed if allowed is not None else [_FakeDetector()], list(skipped)
    )


def test_non_string_detector_id_rejected():
    """A non-string detector_id raises 'requires a detector_id'."""
    with pytest.raises(ValueError, match="requires a detector_id"):
        _rebuild([_prediction_row(detector_id=123)])


def test_skipped_failed_row_is_dropped():
    """A failed=True row for a skipped detector is dropped silently."""
    predictions, failures, successful = _rebuild(
        [_failure_row()], skipped=[{"detector_id": "fake/d"}]
    )
    assert predictions == [] and failures == [] and successful == []


def test_skipped_truthy_non_true_failed_row_raises():
    """A failed=1 row for a skipped detector still raises (1 is not True)."""
    with pytest.raises(ValueError, match="cannot be a prediction"):
        _rebuild([_failure_row(failed=1)], skipped=[{"detector_id": "fake/d"}])


def test_dropped_row_does_not_stop_later_rows():
    """A dropped skipped row does not stop the rows after it."""
    predictions, failures, successful = _rebuild(
        [_failure_row(), _prediction_row(detector_id="fake/e")],
        skipped=[{"detector_id": "fake/d"}],
        allowed=[_FakeDetector(), _FakeDetectorE()],
    )
    assert len(predictions) == 1
    assert len(successful) == 1


def test_failed_one_is_a_prediction_not_a_failure():
    """A failed=1 observation row is a prediction, not a failure."""
    predictions, failures, successful = _rebuild([_prediction_row(failed=1)])
    assert len(predictions) == 1
    assert failures == []


def test_incomplete_observation_row_raises_value_error():
    """An observation row missing prediction fields raises ValueError."""
    with pytest.raises(ValueError, match="is incomplete"):
        _rebuild([{"detector_id": "fake/d", "score": 0.5}])


def test_build_text_is_keyword_only():
    """build_forensic_bundle accepts text as a keyword argument."""
    bundle = build_forensic_bundle(
        text=TEXT,
        detectors=[_FakeDetector()],
        deterministic=True,
        fixed_timestamp="2026-01-02T00:00:00+00:00",
    )
    assert bundle.generated_at_utc == "2026-01-02T00:00:00+00:00"


def test_deterministic_fixed_timestamp_is_used():
    """A deterministic build uses the given fixed timestamp."""
    data = build_forensic_bundle(
        TEXT,
        detectors=[_FakeDetector()],
        deterministic=True,
        fixed_timestamp="2026-01-02T00:00:00+00:00",
    ).to_dict()
    assert data["generated_at_utc"] == "2026-01-02T00:00:00+00:00"
