"""W5 Worker F kill tests for bundle_consistency (audit-w5-f).

Kill evidence for the 26 killable runtime survivors in
textforensics.bundle_consistency (6 more are domain-equivalent /
unobservable-value; see hidden_files/audit-w5-f-equiv-reasons-bundle_consistency.json):

* OrWithAnd on the calibrated-probability type check (line 177) and
  the calibration-id check (line 197): a bool probability and a
  non-string id must each be flagged.
* ReplaceContinueWithBreak in the detector-results loop (line 245)
  and the trust-dimensions loop (line 309): issues after the first
  bad entry must still be reported.
* The low-reliability guard (line 264): reliability 0.05 with a score
  flags; 0.1 and 0.2 do not. Each comparison/number mutant flips one
  of those three cases.
* AddNot / ZeroIterationForLoop on the trust dimensions (lines 298-299)
  and AddNot / IsNot_Is on the dimension state (line 311): a bogus
  dimension state must be flagged.
* The word/sentence mismatch guard (lines 345-346): word_count=1 with
  sentence_count=0 flags; word_count=0, word_count=-5 and
  sentence_count=-1 with the matching partner do not. Negative counts
  are accepted by the input (only word_count<0 gets its own error),
  so the ``> 0`` / ``!= 0`` and ``== 0`` / ``<= 0`` mutants are
  distinguishable and killable, not equivalent.
* NotEq_Lt on content_sha256 length (line 369): a 65-char hash flags.
* Eq_GtE on critical_errors==0 (line 397): any error makes the bundle
  inconsistent.
* The critical-severity aggregation (lines 394-395): a synthetic
  critical issue (injected by stubbing _check_bundle_consistency,
  since no producer emits "critical" yet) must make the bundle
  inconsistent -- this kills sum(1->0) and ``severity < "critical"``.
"""

import textforensics.bundle_consistency as bc
from textforensics.bundle_consistency import (
    ConsistencyIssue,
    _check_bundle_consistency,
    check_bundle_consistency,
)


def _base_bundle() -> dict:
    return {
        "schema": "textforensics.bundle/v1",
        "consensus": {},
        "detector_results": [],
        "trust_map": {},
        "input": {},
    }


def _fields(issues):
    return [(i.field, i.issue_type) for i in issues]


def test_bool_calibrated_probability_is_flagged():
    """A bool calibrated_ai_probability is a type error."""
    bundle = _base_bundle()
    bundle["consensus"] = {
        "calibrated_ai_probability": True,
        "ensemble_calibration_id": "cal-1",
    }
    issues = _check_bundle_consistency(bundle)
    assert ("consensus.calibrated_ai_probability", "type_error") in _fields(issues)


def test_non_string_calibration_id_is_flagged():
    """A non-string ensemble_calibration_id is invalid."""
    bundle = _base_bundle()
    bundle["consensus"] = {
        "calibrated_ai_probability": 0.5,
        "ensemble_calibration_id": 123,
    }
    issues = _check_bundle_consistency(bundle)
    assert ("consensus.calibrated_ai_probability", "invalid") in _fields(issues)


def test_empty_calibration_id_is_flagged():
    """An empty ensemble_calibration_id is invalid."""
    bundle = _base_bundle()
    bundle["consensus"] = {
        "calibrated_ai_probability": 0.5,
        "ensemble_calibration_id": "",
    }
    issues = _check_bundle_consistency(bundle)
    assert ("consensus.calibrated_ai_probability", "invalid") in _fields(issues)


def test_non_dict_detector_result_does_not_stop_loop():
    """Issues after a non-dict detector result are still reported."""
    bundle = _base_bundle()
    bundle["detector_results"] = [
        "not-a-dict",
        {"detector_id": "d", "score": 0.5, "reliability": 0.05},
        {"detector_id": "d", "score": 0.5, "reliability": 0.05},
    ]
    issues = _check_bundle_consistency(bundle)
    fields = _fields(issues)
    assert ("detector_results[0]", "type_error") in fields
    assert ("detector_results[1].reliability", "warning") in fields
    assert ("detector_results[2].reliability", "warning") in fields
    assert ("detector_results[2].detector_id", "mismatch") in fields


def _low_reliability_issues(reliability):
    bundle = _base_bundle()
    bundle["detector_results"] = [{"detector_id": "d", "score": 0.5, "reliability": reliability}]
    return _check_bundle_consistency(bundle)


def test_low_reliability_flags_at_0_05():
    """reliability 0.05 with a score flags a low-reliability warning."""
    issues = _low_reliability_issues(0.05)
    assert ("detector_results[0].reliability", "warning") in _fields(issues)


def test_reliability_at_boundary_0_1_does_not_flag():
    """reliability exactly 0.1 does not flag."""
    assert _low_reliability_issues(0.1) == []


def test_reliability_0_2_does_not_flag():
    """reliability 0.2 does not flag."""
    assert _low_reliability_issues(0.2) == []


def test_bogus_dimension_state_is_flagged():
    """A trust dimension with an invalid state is flagged."""
    bundle = _base_bundle()
    bundle["trust_map"] = {"dimensions": [{"state": "bogus"}]}
    issues = _check_bundle_consistency(bundle)
    assert ("trust_map.dimensions[0].state", "invalid") in _fields(issues)


def test_non_dict_dimension_does_not_stop_loop():
    """Issues after a non-dict trust dimension are still reported."""
    bundle = _base_bundle()
    bundle["trust_map"] = {"dimensions": ["not-a-dict", {"state": "bogus"}]}
    issues = _check_bundle_consistency(bundle)
    fields = _fields(issues)
    assert ("trust_map.dimensions[0]", "type_error") in fields
    assert ("trust_map.dimensions[1].state", "invalid") in fields


def _sentence_issues(word_count, sentence_count):
    bundle = _base_bundle()
    bundle["input"] = {"word_count": word_count, "sentence_count": sentence_count}
    return _check_bundle_consistency(bundle)


def test_words_without_sentences_flags():
    """word_count=1 with sentence_count=0 is a mismatch."""
    issues = _sentence_issues(1, 0)
    assert ("input.sentence_count", "mismatch") in _fields(issues)


def test_zero_words_zero_sentences_does_not_flag_sentence():
    """word_count=0 with sentence_count=0 is not a sentence mismatch."""
    issues = _sentence_issues(0, 0)
    assert ("input.sentence_count", "mismatch") not in _fields(issues)


def test_negative_word_count_does_not_flag_sentence():
    """word_count=-5 with sentence_count=0 flags only the negative count."""
    issues = _sentence_issues(-5, 0)
    fields = _fields(issues)
    assert ("input.word_count", "invalid") in fields
    assert ("input.sentence_count", "mismatch") not in fields


def test_negative_sentence_count_does_not_flag_sentence():
    """sentence_count=-1 with words present is not a sentence mismatch."""
    issues = _sentence_issues(5, -1)
    assert ("input.sentence_count", "mismatch") not in _fields(issues)


def test_long_content_sha256_is_flagged():
    """A 65-char content_sha256 is invalid."""
    bundle = _base_bundle()
    bundle["content_sha256"] = "a" * 65
    issues = _check_bundle_consistency(bundle)
    assert ("content_sha256", "invalid") in _fields(issues)


def test_short_content_sha256_is_flagged():
    """A 63-char content_sha256 is invalid."""
    bundle = _base_bundle()
    bundle["content_sha256"] = "a" * 63
    issues = _check_bundle_consistency(bundle)
    assert ("content_sha256", "invalid") in _fields(issues)


def test_any_error_makes_bundle_inconsistent():
    """A bundle with an error issue is not consistent."""
    bundle = _base_bundle()
    del bundle["schema"]  # missing-schema error
    report = check_bundle_consistency(bundle)
    assert report.is_consistent is False


def test_clean_bundle_is_consistent():
    """A bundle with no issues is consistent."""
    assert check_bundle_consistency(_base_bundle()).is_consistent is True


def test_critical_issue_makes_bundle_inconsistent(monkeypatch):
    """A critical-severity issue makes the bundle inconsistent.

    No producer emits "critical" yet, so the issue list is injected by
    stubbing _check_bundle_consistency; the aggregation in
    check_bundle_consistency is what is under test.
    """
    critical = [
        ConsistencyIssue(field="x", issue_type="mismatch", message="m", severity="critical")
    ]
    monkeypatch.setattr(bc, "_check_bundle_consistency", lambda bundle: critical)
    assert check_bundle_consistency(_base_bundle()).is_consistent is False
