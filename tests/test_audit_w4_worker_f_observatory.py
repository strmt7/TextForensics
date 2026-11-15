"""Kill tests for W4 audit observatory runtime survivors (Worker F2).

Covers textforensics.observatory runtime survivors: snapshot
validation/normalisation, snapshot loading, compare_snapshots,
health alerts/reports/checks, built-in checks, and the health
monitor. Each test names the (line, operator, occurrence) mutants it
kills in its docstring.
"""

from __future__ import annotations

import contextlib
import copy
import json
import os
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

import pytest

from textforensics.observatory import (
    DRIFT_SNAPSHOT_SCHEMA,
    DRIFT_SNAPSHOT_STORE_SCHEMA,
    AlertSeverity,
    DetectorHealthMonitor,
    DetectorHealthReport,
    DriftObservatory,
    HealthAlert,
    HealthCheck,
    HealthMetric,
    HealthState,
    _create_latency_check,
    _create_score_distribution_check,
    _create_throughput_check,
    _require_iso_timestamp,
    _validate_snapshot_records_structural,
)

CORPUS_PATH = Path(__file__).resolve().parent.parent / "testdata" / "drift_corpus.json"

ZERO_HASH = "0" * 64
FULL_HASH = "f" * 64


def _obs() -> DriftObservatory:
    return DriftObservatory(corpus_path=CORPUS_PATH)


def _sample_id(obs: DriftObservatory, index: int = 0) -> str:
    return list(obs.samples.keys())[index]


def _observation(obs: DriftObservatory, **overrides) -> dict:
    """One minimal valid observation for the first corpus sample."""
    sample_id = _sample_id(obs)
    data = {
        "sample_id": sample_id,
        "score": 0.5,
        "verdict": "ai_like",
        "detector_id": "det-a",
        "detector_version": "1.0",
        "detector_family": "fam",
        "execution": "local",
    }
    data.update(overrides)
    return data


def _snapshot(obs: DriftObservatory, **overrides) -> dict:
    """One valid snapshot (1 record) via the construction path."""
    snap = obs.snapshot_from_observations([_observation(obs)])
    snap.update(overrides)
    return snap


def _structural_snapshot(**overrides) -> dict:
    """A snapshot dict for the structural validator (no observatory)."""
    snap: dict = {"taken_at": "2026-01-01T00:00:00+00:00", "records": []}
    snap.update(overrides)
    return snap


def _record(**overrides) -> dict:
    """One structurally valid record (no corpus linkage checked)."""
    record: dict = {"score": 0.5, "threshold": 0.5}
    record.update(overrides)
    return record


def _write_json(tmp_path: Path, name: str, payload: dict) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _distinct(text: str) -> str:
    """An equal-valued but distinct string object (never interned)."""
    return "".join([c for c in text])


@contextlib.contextmanager
def _non_utc_timezone():
    """Run a block with a non-UTC system timezone (restored after).

    Needed to distinguish `naive.replace(tzinfo=UTC).astimezone(UTC)`
    from `naive.astimezone(UTC)`: the latter treats a naive datetime
    as local time, which coincides with UTC only when the system
    timezone is UTC (as in the proof/CI environment)."""
    old_tz = os.environ.get("TZ")
    os.environ["TZ"] = "America/New_York"
    time.tzset()
    try:
        yield
    finally:
        if old_tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = old_tz
        time.tzset()


# ---------------------------------------------------------------------------
# _require_iso_timestamp
# ---------------------------------------------------------------------------


def test_require_iso_timestamp_rejects_empty():
    """(120,34) ReplaceOrWithAnd#1: an empty string is not an ISO-8601
    timestamp, so it must be rejected."""
    with pytest.raises(ValueError, match="must be an ISO-8601 timestamp string"):
        _require_iso_timestamp("", "taken_at")


def test_require_iso_timestamp_accepts_valid():
    """(120,34) ReplaceOrWithAnd#1 (twin direction): a valid ISO-8601
    timestamp passes."""
    assert (
        _require_iso_timestamp("2026-01-01T00:00:00+00:00", "taken_at")
        == "2026-01-01T00:00:00+00:00"
    )


# ---------------------------------------------------------------------------
# _validate_snapshot_records_structural
# ---------------------------------------------------------------------------


def test_structural_taken_at_none_is_valid():
    """(702,7) AddNot#51 + (702,16) IsNot_Is#5: a snapshot without
    taken_at is valid; the mutants call the timestamp validator on
    None and raise."""
    _validate_snapshot_records_structural(_structural_snapshot(taken_at=None))


def test_structural_taken_at_bad_raises():
    """(702,7) AddNot#51 + (702,16) IsNot_Is#5 (twin direction): a
    malformed taken_at must be rejected."""
    with pytest.raises(ValueError, match="must be an ISO-8601 timestamp"):
        _validate_snapshot_records_structural(_structural_snapshot(taken_at="not-a-date"))


def test_structural_bad_score_range_raises():
    """(709,11) AddNot#54: a record carrying a malformed score_range
    must be rejected (the mutant skips the range check)."""
    snap = _structural_snapshot(records=[_record(score_range="not-a-range")])
    with pytest.raises(ValueError, match="score_range"):
        _validate_snapshot_records_structural(snap)


def test_structural_no_score_range_is_valid():
    """(709,11) AddNot#54 (twin direction): a record without a
    score_range is valid; the mutant validates None and raises."""
    _validate_snapshot_records_structural(_structural_snapshot(records=[_record()]))


def test_structural_bad_score_raises():
    """(711,29) ZeroIterationForLoop#7 + (712,15) AddNot#55 +
    (712,41) IsNot_Is#6: a non-numeric score must be rejected."""
    snap = _structural_snapshot(records=[_record(score="bad")])
    with pytest.raises(ValueError, match="score must be a finite number"):
        _validate_snapshot_records_structural(snap)


def test_structural_none_score_is_valid():
    """(712,15) AddNot#55 + (712,41) IsNot_Is#6 (twin direction): a
    null score is valid; the mutants coerce None and raise."""
    snap = _structural_snapshot(records=[_record(score=None, threshold=None)])
    _validate_snapshot_records_structural(snap)


def test_structural_bad_calibrated_probability_raises():
    """(714,11) AddNot#56 + (714,51) IsNot_Is#7: a non-numeric
    calibrated_ai_probability must be rejected."""
    snap = _structural_snapshot(records=[_record(calibrated_ai_probability="bad")])
    with pytest.raises(ValueError, match="calibrated_ai_probability"):
        _validate_snapshot_records_structural(snap)


def test_structural_calibrated_probability_bounds():
    """(718,24) NumberReplacer#118/#119 + (719,24) NumberReplacer
    #120/#121: calibrated_ai_probability must stay in [0, 1]. -0.5
    kills the -1.0 minimum; 0.5 kills the 1.0 minimum; 1.5 kills the
    2.0 maximum; 0.5 kills the 0.0 maximum."""
    with pytest.raises(ValueError, match="must be >="):
        _validate_snapshot_records_structural(
            _structural_snapshot(records=[_record(calibrated_ai_probability=-0.5)])
        )
    with pytest.raises(ValueError, match="must be <="):
        _validate_snapshot_records_structural(
            _structural_snapshot(records=[_record(calibrated_ai_probability=1.5)])
        )
    _validate_snapshot_records_structural(
        _structural_snapshot(records=[_record(calibrated_ai_probability=0.5)])
    )


def test_structural_bad_observed_at_raises():
    """(721,11) AddNot#57 + (721,37) IsNot_Is#8: a malformed
    observed_at must be rejected."""
    snap = _structural_snapshot(records=[_record(observed_at="not-a-date")])
    with pytest.raises(ValueError, match="must be an ISO-8601 timestamp"):
        _validate_snapshot_records_structural(snap)


def test_structural_observed_at_none_is_valid():
    """(721,11) AddNot#57 + (721,37) IsNot_Is#8 (twin direction): a
    null observed_at is valid; the mutants validate None and raise."""
    _validate_snapshot_records_structural(_structural_snapshot(records=[_record(observed_at=None)]))


# ---------------------------------------------------------------------------
# _normalize_observation (via snapshot_from_observations)
# ---------------------------------------------------------------------------


def test_normalize_text_sha_mismatch_high_raises():
    """(849,20) NotEq_Lt#14: a text_sha256 above the corpus hash must
    still be a mismatch. The real hash is below "f"*64 (premise), so
    the `<` mutant does not raise."""
    obs = _obs()
    real = obs.samples[_sample_id(obs)].text_sha256
    assert real != FULL_HASH
    with pytest.raises(ValueError, match="does not match the probe corpus"):
        obs.snapshot_from_observations([_observation(obs, text_sha256=FULL_HASH)])


def test_normalize_text_sha_mismatch_low_raises():
    """(849,20) NotEq_Lt#14 (twin direction): a text_sha256 below the
    corpus hash is a mismatch under both the original and the mutant."""
    obs = _obs()
    with pytest.raises(ValueError, match="does not match the probe corpus"):
        obs.snapshot_from_observations([_observation(obs, text_sha256=ZERO_HASH)])


def test_normalize_score_below_minimum_raises():
    """(869,20) NumberReplacer#139: a calibrated_ai_probability
    below 0.0 must be rejected (the mutant moves the minimum to
    -1.0)."""
    obs = _obs()
    with pytest.raises(ValueError, match="must be >="):
        obs.snapshot_from_observations(
            [
                _observation(
                    obs,
                    calibrated_ai_probability=-0.5,
                    calibration_id="cal-1",
                )
            ]
        )


def test_normalize_score_above_maximum_raises():
    """(870,20) NumberReplacer#140: a calibrated_ai_probability
    above 1.0 must be rejected (the mutant moves the maximum to
    2.0)."""
    obs = _obs()
    with pytest.raises(ValueError, match="must be <="):
        obs.snapshot_from_observations(
            [
                _observation(
                    obs,
                    calibrated_ai_probability=1.5,
                    calibration_id="cal-1",
                )
            ]
        )


def test_normalize_reliability_bounds():
    """(878,60) NumberReplacer#143 + (878,73) NumberReplacer#144:
    reliability must stay in [0, 1]."""
    obs = _obs()
    with pytest.raises(ValueError, match="must be >="):
        obs.snapshot_from_observations([_observation(obs, reliability=-0.5)])
    with pytest.raises(ValueError, match="must be <="):
        obs.snapshot_from_observations([_observation(obs, reliability=1.5)])


def test_normalize_score_range_boundaries():
    """(912,36) LtE_Lt#0 + LtE_NotEq#0 + (912,45) LtE_Lt#1: a score
    exactly on either declared range boundary is in range. The
    lower-boundary case kills the `<` and `!=` mutants on the first
    comparison; the upper-boundary case kills the `<` mutant on the
    second."""
    obs = _obs()
    snap = obs.snapshot_from_observations([_observation(obs, score=0.0, score_range=[0.0, 1.0])])
    assert snap["records"][0]["score"] == 0.0
    snap = obs.snapshot_from_observations([_observation(obs, score=1.0, score_range=[0.0, 1.0])])
    assert snap["records"][0]["score"] == 1.0


def test_normalize_score_below_range_raises():
    """(912,36) LtE_IsNot#0: a score below its declared range must be
    rejected. The `is not` mutant is always True (the coerced score
    is a fresh float object, never identical to the range bound), so
    it accepts the out-of-range score."""
    obs = _obs()
    with pytest.raises(ValueError, match="outside its declared score_range"):
        obs.snapshot_from_observations([_observation(obs, score=-0.5, score_range=[0.0, 1.0])])


def test_normalize_score_above_range_raises():
    """(912,45) LtE_Lt#1 (twin direction): a score above its declared
    range must be rejected."""
    obs = _obs()
    with pytest.raises(ValueError, match="outside its declared score_range"):
        obs.snapshot_from_observations([_observation(obs, score=1.5, score_range=[0.0, 1.0])])


# ---------------------------------------------------------------------------
# _normalize_failure (via snapshot_from_observations failures)
# ---------------------------------------------------------------------------


def _failure(obs: DriftObservatory, **overrides) -> dict:
    sample_id = _sample_id(obs)
    data = {
        "sample_id": sample_id,
        "text_sha256": obs.samples[sample_id].text_sha256,
        "detector_id": "det-a",
        "error_type": "Timeout",
    }
    data.update(overrides)
    return data


def test_normalize_failure_text_sha_mismatch_high_raises():
    """(959,24) NotEq_Lt#15: a failure text_sha256 above the corpus
    hash must still be a mismatch."""
    obs = _obs()
    real = obs.samples[_sample_id(obs)].text_sha256
    assert real != FULL_HASH
    with pytest.raises(ValueError, match="does not match corpus"):
        obs.snapshot_from_observations([], failures=[_failure(obs, text_sha256=FULL_HASH)])


def test_normalize_failure_text_sha_mismatch_low_raises():
    """(959,24) NotEq_Gt#15: a failure text_sha256 below the corpus
    hash must still be a mismatch."""
    obs = _obs()
    with pytest.raises(ValueError, match="does not match corpus"):
        obs.snapshot_from_observations([], failures=[_failure(obs, text_sha256=ZERO_HASH)])


def test_normalize_failure_matching_hash_accepted():
    """(959,24) NotEq_IsNot#13: a failure whose text_sha256 matches
    the corpus hash as a value must be accepted, even when it is a
    distinct string object (the `is not` mutant rejects it)."""
    obs = _obs()
    sample_id = _sample_id(obs)
    real = obs.samples[sample_id].text_sha256
    snap = obs.snapshot_from_observations([], failures=[_failure(obs, text_sha256=_distinct(real))])
    assert snap["failure_count"] == 1


# ---------------------------------------------------------------------------
# DriftObservatory.load_snapshots
# ---------------------------------------------------------------------------


def _store_file(tmp_path: Path, snapshots: list[dict]) -> Path:
    return _write_json(
        tmp_path,
        "store.json",
        {"schema": DRIFT_SNAPSHOT_STORE_SCHEMA, "snapshots": snapshots},
    )


def test_load_snapshots_path_keyword_only(tmp_path):
    """(1185,8) Mul_Div#13: `path` is keyword-capable (the `*`
    marker); the mutant makes it positional-only, so a keyword call
    raises TypeError."""
    obs = _obs()
    snap = _snapshot(obs)
    path = _write_json(tmp_path, "snap.json", snap)
    loaded = obs.load_snapshots(path=str(path))
    assert len(loaded) == 1


def test_load_snapshots_replace_default_replaces(tmp_path):
    """(1186,24) ReplaceTrueWithFalse#5: the default `replace=True`
    replaces previously loaded snapshots instead of appending."""
    obs = _obs()
    snap = _snapshot(obs)
    path = _write_json(tmp_path, "snap.json", snap)
    obs.load_snapshots(path)
    obs.load_snapshots(path)
    assert len(obs.snapshots) == 1


def test_load_snapshots_unknown_schema_below_raises(tmp_path):
    """(1190,30) Eq_LtE#15: a store-schema string sorting below the
    store schema must be rejected as unrecognized (the mutant treats
    it as a store and returns an empty list)."""
    obs = _obs()
    path = _write_json(tmp_path, "bad.json", {"schema": "a", "snapshots": []})
    with pytest.raises(ValueError, match="Unrecognized drift snapshot store schema"):
        obs.load_snapshots(path)


def test_load_snapshots_single_schema_neighbours_raise(tmp_path):
    """(1192,32) Eq_GtE#16 + Eq_IsNot#12 + Eq_LtE#16: a schema that is
    neither the store nor the single snapshot schema must raise the
    *store* error. The mutants route it through the single-snapshot
    branch, which raises the *snapshot* error instead (message
    mismatch kills them)."""
    obs = _obs()
    for schema in ("a", "zzz"):
        path = _write_json(tmp_path, f"bad-{schema}.json", {"schema": schema})
        with pytest.raises(ValueError, match="Unrecognized drift snapshot store schema"):
            obs.load_snapshots(path)


def test_load_snapshots_expected_corpus_match(tmp_path):
    """(1204,50) NotEq_Eq#16 + NotEq_IsNot#14: a snapshot whose corpus
    hash matches the expected hash (as a value, via a distinct string
    object) must load. The `==` mutant raises on a match; the `is
    not` mutant raises on distinct-but-equal strings."""
    obs = _obs()
    snap = _snapshot(obs)
    path = _write_json(tmp_path, "snap.json", snap)
    loaded = obs.load_snapshots(path, expected_corpus_sha256=_distinct(obs.corpus_sha256))
    assert len(loaded) == 1


def test_load_snapshots_expected_corpus_mismatch_low(tmp_path):
    """(1204,50) NotEq_Gt#16 + NotEq_GtE#16 + NotEq_Eq#16 +
    NotEq_Is#14: an expected hash below the snapshot corpus must
    raise. The `>`/`>=` mutants do not raise (the real hash is above
    "0"*64); the `==`/`is` mutants do not raise either."""
    obs = _obs()
    snap = _snapshot(obs)
    path = _write_json(tmp_path, "snap.json", snap)
    assert obs.corpus_sha256 > ZERO_HASH
    with pytest.raises(ValueError, match="corpus hash does not match"):
        obs.load_snapshots(path, expected_corpus_sha256=ZERO_HASH)


def test_load_snapshots_expected_corpus_mismatch_high(tmp_path):
    """(1204,50) NotEq_Lt#16 + NotEq_LtE#16 + NotEq_Eq#16 +
    NotEq_Is#14: an expected hash above the snapshot corpus must
    raise. The `<`/`<=` mutants do not raise (the real hash is below
    "f"*64)."""
    obs = _obs()
    snap = _snapshot(obs)
    path = _write_json(tmp_path, "snap.json", snap)
    assert obs.corpus_sha256 < FULL_HASH
    with pytest.raises(ValueError, match="corpus hash does not match"):
        obs.load_snapshots(path, expected_corpus_sha256=FULL_HASH)


# ---------------------------------------------------------------------------
# DriftObservatory.read_snapshot_file
# ---------------------------------------------------------------------------


def test_read_snapshot_file_class_call():
    """(1219,4) RemoveDecorator#1: read_snapshot_file is a static
    method, so it must be callable on an instance AND on the class.
    The mutant makes it an instance method: the instance call then
    passes the observatory as `path` and the real path as a second
    argument, raising TypeError. (A class-only call would NOT kill
    it — an unbound plain function called on the class takes its
    single argument as `path`.)"""
    obs = _obs()
    snap = _snapshot(obs)
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "snap.json"
        p.write_text(json.dumps(snap), encoding="utf-8")
        loaded = obs.read_snapshot_file(p)
        assert loaded["schema"] == DRIFT_SNAPSHOT_SCHEMA
        loaded2 = DriftObservatory.read_snapshot_file(p)
        assert loaded2["schema"] == DRIFT_SNAPSHOT_SCHEMA


def test_read_snapshot_file_store_schema_is_identity(tmp_path):
    """(1224,30) Eq_Is#13: a valid store file must load. The `is`
    mutant never matches the freshly parsed schema string, so it
    falls through to the unrecognized-schema error."""
    obs = _obs()
    snap = _snapshot(obs)
    path = _store_file(tmp_path, [snap])
    loaded = DriftObservatory.read_snapshot_file(path)
    assert loaded["schema"] == DRIFT_SNAPSHOT_SCHEMA


def test_read_snapshot_file_store_schema_below_raises(tmp_path):
    """(1224,30) Eq_Lt#17 + Eq_LtE#17: a schema sorting below the
    store schema must raise the unrecognized-schema error (the
    mutants treat it as a store and raise the exactly-one-snapshot
    error instead)."""
    path = _write_json(tmp_path, "bad.json", {"schema": "a", "snapshots": []})
    with pytest.raises(ValueError, match="Unrecognized drift snapshot schema"):
        DriftObservatory.read_snapshot_file(path)


def test_read_snapshot_file_store_zero_snapshots_raises(tmp_path):
    """(1226,32) NotEq_Gt#17 + NotEq_GtE#17: a store with zero
    snapshots must raise the exactly-one error. The mutants skip the
    check and crash on snapshots[0] (IndexError, not ValueError)."""
    path = _store_file(tmp_path, [])
    with pytest.raises(ValueError, match="exactly one snapshot"):
        DriftObservatory.read_snapshot_file(path)


def test_read_snapshot_file_store_one_snapshot_loads(tmp_path):
    """(1226,33) NumberReplacer#153: a store with exactly one snapshot
    must load (the `!= 0` mutant raises)."""
    obs = _obs()
    snap = _snapshot(obs)
    path = _store_file(tmp_path, [snap])
    loaded = DriftObservatory.read_snapshot_file(path)
    assert loaded["snapshot_id"] == snap["snapshot_id"]


def test_read_snapshot_file_single_index_zero(tmp_path):
    """(1230,33) NumberReplacer#154: a store with one snapshot must
    return that snapshot (the `[1]` mutant raises IndexError)."""
    obs = _obs()
    snap = _snapshot(obs)
    path = _store_file(tmp_path, [snap])
    loaded = DriftObservatory.read_snapshot_file(path)
    assert loaded["snapshot_id"] == snap["snapshot_id"]


def test_read_snapshot_file_single_schema_neighbours_raise(tmp_path):
    """Guard for (1231,32) Eq_GtE#18 + Eq_IsNot#14 + Eq_LtE#18: a
    schema that is neither schema must raise the unrecognized error.
    Those three mutants are EQUIVALENT, not killable: the elif
    mutants route an unknown schema into the single-snapshot branch,
    but the follow-up guard at line 1235 (`snapshot.get("schema")
    != DRIFT_SNAPSHOT_SCHEMA`) raises the identical ValueError with
    the identical message. This test pins the message."""
    for schema in ("a", "zzz"):
        path = _write_json(tmp_path, f"bad-{schema}.json", {"schema": schema})
        with pytest.raises(ValueError, match="Unrecognized drift snapshot schema"):
            DriftObservatory.read_snapshot_file(path)


def test_read_snapshot_file_wrong_schema_dict_raises(tmp_path):
    """(1235,42) ReplaceOrWithAnd#34: a dict snapshot whose schema is
    wrong must be rejected. The `and` mutant skips the check (the
    dict passes isinstance) and returns it."""
    obs = _obs()
    snap = _snapshot(obs)
    snap["schema"] = "textforensics.drift-snapshot/v999"
    path = _store_file(tmp_path, [snap])
    with pytest.raises(ValueError, match="Unrecognized drift snapshot schema"):
        DriftObservatory.read_snapshot_file(path)


def test_read_snapshot_file_wrong_schema_neighbours_raise(tmp_path):
    """(1235,68) NotEq_Gt#18 + NotEq_Is#15 + NotEq_Lt#18: a snapshot
    schema sorting either side of the snapshot schema must be
    rejected. "a" kills Gt and Is; "zzz" kills Lt."""
    obs = _obs()
    for schema in ("a", "zzz"):
        snap = _snapshot(obs)
        snap["schema"] = schema
        path = _store_file(tmp_path, [snap])
        with pytest.raises(ValueError, match="Unrecognized drift snapshot schema"):
            DriftObservatory.read_snapshot_file(path)


# ---------------------------------------------------------------------------
# DriftObservatory._validate_imported_snapshot
# ---------------------------------------------------------------------------


def test_validate_imported_corpus_mismatch_low(tmp_path):
    """(1285,22) NotEq_Gt#20: an imported corpus hash below the
    observatory corpus must be rejected (the `>` mutant does not
    raise)."""
    obs = _obs()
    snap = _snapshot(obs)
    snap["corpus_sha256"] = ZERO_HASH
    assert obs.corpus_sha256 > ZERO_HASH
    with pytest.raises(ValueError, match="does not match the loaded probe corpus"):
        obs._validate_imported_snapshot(snap)


def test_validate_imported_corpus_mismatch_high(tmp_path):
    """(1285,22) NotEq_Lt#20: an imported corpus hash above the
    observatory corpus must be rejected (the `<` mutant does not
    raise)."""
    obs = _obs()
    snap = _snapshot(obs)
    snap["corpus_sha256"] = FULL_HASH
    assert obs.corpus_sha256 < FULL_HASH
    with pytest.raises(ValueError, match="does not match the loaded probe corpus"):
        obs._validate_imported_snapshot(snap)


def test_validate_imported_taken_at_none_is_valid():
    """(1289,11) AddNot#114 + (1289,20) IsNot_Is#29: an imported
    snapshot without taken_at is valid; the mutants validate None
    and raise."""
    obs = _obs()
    snap = _snapshot(obs)
    snap["taken_at"] = None
    assert obs._validate_imported_snapshot(snap)["schema"] == DRIFT_SNAPSHOT_SCHEMA


def test_validate_imported_taken_at_bad_raises():
    """(1289,11) AddNot#114 + (1289,20) IsNot_Is#29 (twin
    direction): a malformed taken_at must be rejected."""
    obs = _obs()
    snap = _snapshot(obs)
    snap["taken_at"] = "not-a-date"
    with pytest.raises(ValueError, match="must be an ISO-8601 timestamp"):
        obs._validate_imported_snapshot(snap)


def test_validate_imported_bool_count_raises():
    """(1297,46) ReplaceOrWithAnd#36: a boolean record_count must be
    rejected as non-integer. The `and` mutant accepts True (True ==
    1 matches the single record)."""
    obs = _obs()
    snap = _snapshot(obs)
    snap["record_count"] = True
    with pytest.raises(ValueError, match="must be an integer"):
        obs._validate_imported_snapshot(snap)


def test_validate_imported_count_mismatch_low_raises():
    """(1299,28) NotEq_Gt#21: a record_count below the actual record
    count must be rejected (the `>` mutant does not raise)."""
    obs = _obs()
    snap = _snapshot(obs)
    snap["record_count"] = 0
    with pytest.raises(ValueError, match="record_count"):
        obs._validate_imported_snapshot(snap)


def _many_record_snapshot(obs: DriftObservatory, count: int) -> dict:
    """A valid snapshot with `count` distinct (detector, sample)
    records, built from the construction path's normalization."""
    ids = list(obs.samples.keys())
    observations = []
    for i in range(count):
        sample_id = ids[i % len(ids)]
        observations.append(
            _observation(
                obs,
                sample_id=sample_id,
                detector_id=f"det-{i // len(ids)}",
            )
        )
    return obs.snapshot_from_observations(observations)


def test_validate_imported_count_300_matches():
    """(1299,28) NotEq_IsNot#18: a record_count of 300 with 300
    records must validate. The `is not` mutant raises: the JSON-parsed
    300 and len(items) are distinct int objects (300 is outside the
    small-int cache)."""
    obs = _obs()
    snap = _many_record_snapshot(obs, 300)
    assert snap["record_count"] == 300
    assert len(snap["records"]) == 300
    assert obs._validate_imported_snapshot(snap)["record_count"] == 300


def test_validate_imported_duplicate_records_raise():
    """(1309,22) ZeroIterationForLoop#15: duplicate (detector,
    sample) records must be rejected (the mutant skips the loop)."""
    obs = _obs()
    snap = _snapshot(obs)
    snap["records"] = [snap["records"][0], copy.deepcopy(snap["records"][0])]
    snap["record_count"] = 2
    with pytest.raises(ValueError, match="Duplicate drift record"):
        obs._validate_imported_snapshot(snap)


def test_validate_imported_duplicate_message_names_detector_and_sample():
    """(1312,76) NumberReplacer#156/#157 + (1312,92) NumberReplacer
    #159: the duplicate error names the detector (key[0]) and the
    sample (key[1]) exactly. The mutants swap one for the other."""
    obs = _obs()
    snap = _snapshot(obs)
    snap["records"] = [snap["records"][0], copy.deepcopy(snap["records"][0])]
    snap["record_count"] = 2
    with pytest.raises(ValueError) as excinfo:
        obs._validate_imported_snapshot(snap)
    message = str(excinfo.value)
    assert f"detector det-a sample {_sample_id(obs)}" in message


# ---------------------------------------------------------------------------
# DriftObservatory.compare_snapshots
# ---------------------------------------------------------------------------


def test_compare_corpus_mismatch_counts_are_zero():
    """(1346,42) NumberReplacer#160/#161 + (1347,44) #162/#163 +
    (1348,46) #164/#165 + (1349,41) #166/#167 + (1350,40) #168/#169:
    a corpus-mismatch report carries exactly 0 for every detector
    count."""
    obs = _obs()
    base = _snapshot(obs)
    current = _snapshot(obs)
    current["corpus_sha256"] = ZERO_HASH
    report = obs.compare_snapshots(base, current)
    assert report["overall"]["status"] == "corpus_mismatch"
    assert report["overall"]["detectors_compared"] == 0
    assert report["overall"]["detectors_with_drift"] == 0
    assert report["overall"]["detectors_insufficient"] == 0
    assert report["overall"]["detectors_missing"] == 0
    assert report["overall"]["detectors_stable"] == 0


def test_compare_matching_corpora_distinct_objects():
    """(1331,27) NotEq_IsNot#19: snapshots whose corpus hashes match
    as values (distinct string objects) must compare normally, not
    report a corpus mismatch. The `is not` mutant reports a
    mismatch."""
    obs = _obs()
    base = _snapshot(obs)
    current = _snapshot(obs)
    current["corpus_sha256"] = _distinct(obs.corpus_sha256)
    base["corpus_sha256"] = _distinct(obs.corpus_sha256)
    report = obs.compare_snapshots(base, current)
    assert report["overall"]["status"] != "corpus_mismatch"


def test_compare_baseline_above_observatory_mismatch():
    """(1331,64) NotEq_Lt#23: a baseline corpus above the
    observatory corpus must report a mismatch (the `<` mutant does
    not)."""
    obs = _obs()
    base = _snapshot(obs)
    current = _snapshot(obs)
    base["corpus_sha256"] = FULL_HASH
    current["corpus_sha256"] = FULL_HASH
    assert obs.corpus_sha256 < FULL_HASH
    report = obs.compare_snapshots(base, current)
    assert report["overall"]["status"] == "corpus_mismatch"


def test_compare_baseline_below_observatory_mismatch():
    """(1331,64) NotEq_Gt#23: a baseline corpus below the observatory
    corpus must report a mismatch (the `>` mutant does not)."""
    obs = _obs()
    base = _snapshot(obs)
    current = _snapshot(obs)
    base["corpus_sha256"] = ZERO_HASH
    current["corpus_sha256"] = ZERO_HASH
    assert obs.corpus_sha256 > ZERO_HASH
    report = obs.compare_snapshots(base, current)
    assert report["overall"]["status"] == "corpus_mismatch"


def test_compare_baseline_below_current_mismatch():
    """(1331,27) NotEq_Lt#22: a baseline corpus below the current
    corpus must report a mismatch (the `<` mutant does not)."""
    obs = _obs()
    base = _snapshot(obs)
    current = _snapshot(obs)
    base["corpus_sha256"] = ZERO_HASH
    report = obs.compare_snapshots(base, current)
    assert report["overall"]["status"] == "corpus_mismatch"


def test_compare_baseline_above_current_mismatch():
    """(1331,64) NotEq_IsNot#20: a baseline corpus above the current
    corpus (as a distinct object) must report a mismatch. The `is
    not` mutant reports a mismatch even for matching corpora (see
    test_compare_matching_corpora_distinct_objects)."""
    obs = _obs()
    base = _snapshot(obs)
    current = _snapshot(obs)
    base["corpus_sha256"] = FULL_HASH
    report = obs.compare_snapshots(base, current)
    assert report["overall"]["status"] == "corpus_mismatch"


def test_compare_failure_detector_only_in_failures():
    """(1378,48) ReplaceAndWithOr#30: a failure entry whose
    detector_id is a non-string (123) must not add a detector to the
    comparison. The `or` mutant adds it (123 is truthy)."""
    obs = _obs()
    base = _snapshot(obs)
    current = _snapshot(obs)
    current["failures"] = [
        {
            "sample_id": _sample_id(obs),
            "text_sha256": obs.samples[_sample_id(obs)].text_sha256,
            "detector_id": 123,
            "error_type": "Timeout",
        }
    ]
    current["failure_count"] = 1
    report = obs.compare_snapshots(base, current)
    assert not any(d["detector_id"] == 123 for d in report["detectors"])


def test_compare_failure_detector_in_both_union_and_failures():
    """(1381,65) BitOr_BitXor#31: a detector present in the current
    records AND in the failures (but not in the baseline records)
    must stay in the comparison. The mutant replaces the second `|`
    with `^`, giving `baseline | (current ^ failures)`: det-a is in
    both current and failures, so the XOR drops it and the baseline
    (which has no det-a) does not re-add it. (Putting det-a in the
    baseline records too does NOT kill it — the outer `|` re-adds
    it; that is why the first two versions of this test survived.)"""
    obs = _obs()
    base = obs.snapshot_from_observations([_observation(obs, detector_id="det-b")])
    current = _snapshot(obs)
    failure = {
        "sample_id": _sample_id(obs),
        "text_sha256": obs.samples[_sample_id(obs)].text_sha256,
        "detector_id": "det-a",
        "error_type": "Timeout",
    }
    current["failures"] = [failure]
    current["failure_count"] = 1
    report = obs.compare_snapshots(base, current)
    assert any(d["detector_id"] == "det-a" for d in report["detectors"])


# ---------------------------------------------------------------------------
# HealthAlert
# ---------------------------------------------------------------------------


def _alert(**overrides) -> HealthAlert:
    data = {
        "alert_id": "alert-01234567",
        "detector_id": "det-a",
        "severity": AlertSeverity.WARNING,
        "message": "m",
        "metric_name": "latency_ms",
        "metric_value": 1.0,
        "threshold": 2.0,
        "timestamp": "2026-01-01T00:00:00+00:00",
    }
    data.update(overrides)
    return HealthAlert(**data)


def test_alert_nonfinite_metric_value_raises():
    """(1924,50) ReplaceOrWithAnd#46: a HealthAlert with a non-finite
    metric_value must be rejected. The `and` mutant skips the check
    when the threshold is finite (True and False is False)."""
    with pytest.raises(ValueError, match="finite"):
        _alert(metric_value=float("inf"), threshold=1.0)


def test_alert_nonfinite_threshold_raises():
    """(1924,50) ReplaceOrWithAnd#46 (twin direction): a HealthAlert
    with a non-finite threshold must be rejected."""
    with pytest.raises(ValueError, match="finite"):
        _alert(metric_value=1.0, threshold=float("inf"))


# ---------------------------------------------------------------------------
# DetectorHealthReport.load
# ---------------------------------------------------------------------------


def _report_dict(**overrides) -> dict:
    data = {
        "detector_id": "det-a",
        "health_score": 0.5,
        "overall_state": "healthy",
        "metrics": {},
        "alerts": [],
        "last_updated": "2026-01-01T00:00:00+00:00",
        "metadata": {},
    }
    data.update(overrides)
    return data


def _write_report(tmp_path: Path, payload: dict) -> Path:
    return _write_json(tmp_path, "report.json", payload)


def test_report_load_bool_health_score_rejected():
    """(1955,15) ReplaceOrWithAnd#47 + (1955,29) #48: a boolean
    health_score must be rejected (load returns None). For True, C
    implies D (the 0.0<=s<=1.0 chain passes), so the `and` mutant
    only skips when B (isinstance bool) is True and A/C/D are False
    — both mutants load the report instead of returning None."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        report = DetectorHealthReport.load(_write_report(Path(td), _report_dict(health_score=True)))
        assert report is None


def test_report_load_health_score_above_max_rejected():
    """(1955,35) ReplaceOrWithAnd#49: a health_score above 1.0 must
    be rejected (load returns None). The `and` mutant loads it."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        report = DetectorHealthReport.load(_write_report(Path(td), _report_dict(health_score=1.5)))
        assert report is None


def test_report_load_health_score_below_min_rejected():
    """(1979,16) NumberReplacer#195: a health_score below 0.0 must
    be rejected (load returns None). The mutant moves the minimum to
    -1.0 and loads it."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        report = DetectorHealthReport.load(_write_report(Path(td), _report_dict(health_score=-0.5)))
        assert report is None


def test_report_load_health_score_boundaries_accepted():
    """(1969,30) LtE_Lt#2 + LtE_NotEq#2 + (1970,30) LtE_Lt#3 +
    LtE_NotEq#3: health_score 0.0 and 1.0 are both valid and load.
    The `0.0 < s` mutants reject 0.0; the `s < 1.0` mutants reject
    1.0 (both return None instead of a report)."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        for score in (0.0, 1.0):
            report = DetectorHealthReport.load(
                _write_report(Path(td), _report_dict(health_score=score))
            )
            assert report is not None
            assert report.health_score == score


def test_report_load_health_score_above_maximum_2():
    """(1980,16) NumberReplacer#196: a health_score above the
    maximum must be rejected (load returns None). The mutant moves
    the maximum to 2.0 and loads 1.5."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        report = DetectorHealthReport.load(_write_report(Path(td), _report_dict(health_score=1.5)))
        assert report is None


def test_report_load_nonfinite_metric_rejected():
    """(1990,26) ZeroIterationForLoop#20 + (1991,30) #21: a report
    with a non-finite metric value must be rejected (load returns
    None). The mutants skip the metric loop entirely and load it."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        payload = _report_dict(
            metrics={
                "latency_ms": [
                    {
                        "name": "latency_ms",
                        "value": float("inf"),
                        "unit": "ms",
                        "timestamp": "2026-01-01T00:00:00+00:00",
                        "detector_id": "det-a",
                        "metadata": {},
                    }
                ]
            }
        )
        report = DetectorHealthReport.load(_write_report(Path(td), payload))
        assert report is None


# ---------------------------------------------------------------------------
# HealthCheck
# ---------------------------------------------------------------------------


def _check(**overrides) -> HealthCheck:
    data = {
        "name": "latency",
        "metric_name": "latency_ms",
        "check_fn": lambda values: (True, 1.0),
        "warning_threshold": 10.0,
        "critical_threshold": 20.0,
    }
    data.update(overrides)
    return HealthCheck(**data)


def test_check_bool_min_samples_raises():
    """(2041,32) ReplaceOrWithAnd#51: a boolean min_samples must be
    rejected. The `and` mutant accepts True (True is an int and not
    a bool is False, so `and` gives False)."""
    with pytest.raises(ValueError, match="min_samples must be an integer"):
        _check(min_samples=True)


def test_check_min_samples_zero_raises():
    """(2046,28) NumberReplacer#201: min_samples 0 must be rejected
    (the mutant moves the bound to < 0)."""
    with pytest.raises(ValueError, match="at least 1"):
        _check(min_samples=0)


def test_check_evaluate_normal_warning():
    """Boundary guard for the normal branch: a value exactly on the
    warning threshold is WARNING, and exactly on the critical
    threshold is CRITICAL. The `>=` branch mutants here were killed
    in phase 1 by the existing suite; the only surviving branch
    mutant is GtE_IsNot#10 at (2067,23), killed by
    test_check_evaluate_normal_passes."""
    check = _check(check_fn=lambda values: (False, values[0]))
    warning = check.evaluate([10.0])
    assert warning is not None
    assert warning.severity == AlertSeverity.WARNING
    assert warning.metric_value == 10.0
    critical = check.evaluate([20.0])
    assert critical is not None
    assert critical.severity == AlertSeverity.CRITICAL
    assert critical.metric_value == 20.0


def test_check_evaluate_normal_passes():
    """(2067,23) GtE_IsNot#10: a value below the warning threshold
    passes (no alert). The `is not` mutant always takes the WARNING
    branch (a computed float is never identical to the threshold
    constant), so it alerts on 5.0."""
    assert _check().evaluate([5.0]) is None


def test_check_evaluate_inverted_warning():
    """(2058,23) LtE_Lt#5 + LtE_NotEq#5: in the inverted branch a
    value exactly on the warning threshold is WARNING, and exactly
    on the critical threshold is CRITICAL. Inverted checks need
    warning > critical (lower is worse). The `<` mutant returns None
    for 20.0; the `!=` mutant returns None for 20.0 too."""
    check = _check(
        inverted=True,
        warning_threshold=20.0,
        critical_threshold=10.0,
        check_fn=lambda values: (False, values[0]),
    )
    warning = check.evaluate([20.0])
    assert warning is not None
    assert warning.severity == AlertSeverity.WARNING
    critical = check.evaluate([10.0])
    assert critical is not None
    assert critical.severity == AlertSeverity.CRITICAL


def test_check_evaluate_inverted_passes():
    """(2058,23) LtE_IsNot#4: in the inverted branch a value above
    the warning threshold passes. The `is not` mutant always takes
    the WARNING branch, so it alerts on 25.0."""
    check = _check(
        inverted=True,
        warning_threshold=20.0,
        critical_threshold=10.0,
        check_fn=lambda values: (False, values[0]),
    )
    assert check.evaluate([25.0]) is None


def test_check_evaluate_check_fn_pass_returns_none():
    """Guard: a check whose check_fn reports (True, value) produces
    no alert. (The `if passed` AddNot here was killed in phase 1 by
    the existing suite; this test pins the behaviour.)"""
    check = _check(check_fn=lambda values: (True, 1.0))
    assert check.evaluate([10.0]) is None
    failing = _check(check_fn=lambda values: (False, 15.0))
    assert failing.evaluate([15.0]) is not None


def test_check_evaluate_alert_id_format():
    """(2074,96) NumberReplacer#202 + #203: the alert id is
    "alert-" plus the first 8 hex chars of a hash. The mutants slice
    9 / 7 chars, breaking the 8-char format."""
    check = _check(check_fn=lambda values: (False, 15.0))
    alert = check.evaluate([15.0])
    assert alert is not None
    assert re.fullmatch(r"alert-[0-9a-f]{8}", alert.alert_id)


def test_check_evaluate_message_names_warning_threshold():
    """(2077,91) Eq_Gt#26 + Eq_GtE#26 + Eq_IsNot#22 + Eq_NotEq#26: a
    WARNING alert message names the warning threshold (10.0), not
    the critical one. "warning" > "critical" lexicographically, so
    the `>`/`>=`/`!=`/`is not` mutants name the critical threshold
    (20.0) instead."""
    check = _check(check_fn=lambda values: (False, values[0]))
    alert = check.evaluate([15.0])
    assert alert is not None
    assert alert.severity == AlertSeverity.WARNING
    assert "10.0" in alert.message
    assert "20.0" not in alert.message
    assert "15.0" in alert.message


def test_check_evaluate_message_names_critical_threshold():
    """(2077,91) Eq_Gt#26 + Eq_Lt#26 + Eq_IsNot#22 + Eq_NotEq#26: a
    CRITICAL alert message names the critical threshold (20.0).
    "critical" is not greater/less than itself, so the `>`/`<`/`!=`
    mutants name the warning threshold (10.0) instead, and the `is
    not` mutant does too."""
    check = _check(check_fn=lambda values: (False, values[0]))
    alert = check.evaluate([25.0])
    assert alert is not None
    assert alert.severity == AlertSeverity.CRITICAL
    assert "20.0" in alert.message
    assert "10.0" not in alert.message
    assert "25.0" in alert.message


def test_check_evaluate_threshold_kwarg_uses_critical():
    """(2081,24) Eq_GtE#27 + Eq_IsNot#23 + Eq_NotEq#27: a CRITICAL
    alert's threshold kwarg is the critical threshold. A WARNING
    alert (value on the warning threshold) kills GtE/IsNot/NotEq."""
    check = _check(check_fn=lambda values: (False, values[0]))
    alert = check.evaluate([15.0])
    assert alert is not None
    assert alert.threshold == 10.0
    critical = _check(check_fn=lambda values: (False, values[0])).evaluate([25.0])
    assert critical is not None
    assert critical.threshold == 20.0


# ---------------------------------------------------------------------------
# Built-in checks: _create_latency_check
# ---------------------------------------------------------------------------


def test_latency_check_p95_20_values():
    """(2091,28) GtE_Eq#11 + GtE_Gt#11 + (2094,37) NumberReplacer
    #204 + (2095,31) #207 + (2096,31) #208: with 20 latency values
    the p95 is the 19th quantile cut point, 19.95 for 1..20 — not the
    maximum (20), not the 21-quantile value (19.0), not the 17th cut
    point (18.9)."""
    check = _create_latency_check()
    values = [float(i) for i in range(1, 21)]
    ok, p95 = check.check_fn(values)
    assert ok is True
    assert p95 == pytest.approx(19.95, abs=1e-9)
    assert p95 != max(values)


def test_latency_check_p95_21_values():
    """(2091,28) GtE_Eq#11 (twin direction): with 21 values the p95
    is 20.9 for 1..21, distinct from the 20-value result."""
    check = _create_latency_check()
    values = [float(i) for i in range(1, 22)]
    ok, p95 = check.check_fn(values)
    assert ok is True
    assert p95 == pytest.approx(20.9, abs=1e-9)


def test_latency_check_p95_19_values_is_max():
    """Guard for (2099,71) NumberReplacer#209 (`len >= 20` -> `>=
    19`): with 19 values the p95 is the maximum. For 19 values
    statistics.quantiles(values, n=20)[18] is mathematically the
    maximum, so the mutant returns the same 19.0 — this test pins
    the behaviour and the mutant survives it (see the equivalence
    reason, which documents the 1-ULP measurement)."""
    check = _create_latency_check()
    values = [float(i) for i in range(1, 20)]
    ok, p95 = check.check_fn(values)
    assert ok is True
    assert p95 == 19.0
    assert p95 == max(values)


def test_latency_check_below_3000_passes():
    """(2105,23) NumberReplacer#211: 20 values of 2999.5 give a p95
    below 3000 and pass (the mutant lowers the pass bound to 2999)."""
    check = _create_latency_check()
    ok, p95 = check.check_fn([2999.5] * 20)
    assert ok is True
    assert p95 == 2999.5


def test_latency_check_thresholds_declared():
    """(2106,24) NumberReplacer#213: the latency check declares
    warning 3000.0 and critical 10000.0."""
    check = _create_latency_check()
    assert check.warning_threshold == 3000.0
    assert check.critical_threshold == 10000.0


# ---------------------------------------------------------------------------
# Built-in checks: _create_score_distribution_check
# ---------------------------------------------------------------------------


def test_score_distribution_9_values_returns_true():
    """(2134,23) Lt_Eq#9 + (2134,29) NumberReplacer#227 +
    (2135,12) ReplaceTrueWithFalse#13 + (2138,28) #228/#229: with
    only 9 values the check returns (True, 1.0) — the "insufficient
    data" branch. The Eq mutant proceeds and returns (False, 0.0);
    the `< 9` mutant proceeds too; the True->False mutant returns
    (False, 1.0); the 1.0->2.0/0.0 mutants return a different ratio."""
    check = _create_score_distribution_check()
    ok, ratio = check.check_fn([0.05] * 9)
    assert ok is True
    assert ratio == 1.0


def test_score_distribution_10_spread_ratio():
    """(2134,25) Lt_LtE#9 + (2134,33) NumberReplacer#226 +
    (2139,28) #256/#257 + (2144,39) #259: 10 spread values give a
    ratio of ~1.0 (above 0.5, so the check passes). The `<= 10`
    mutant treats 10 as insufficient; the `< 11` mutant does too;
    the `*11`/`*9` binning mutants change the ratio to 0.985; the
    cap-8 mutant changes the binning."""
    check = _create_score_distribution_check()
    values = [0.05, 0.15, 0.25, 0.35, 0.45, 0.55, 0.65, 0.75, 0.85, 0.95]
    ok, ratio = check.check_fn(values)
    assert ok is True
    assert ratio == pytest.approx(1.0000000000000002, abs=1e-9)


def test_score_distribution_value_one_caps_at_bin_9():
    """(2144,39) NumberReplacer#258: 11 values including 1.0 must
    not crash — the value 1.0 is capped into bin 9. The cap-10
    mutant raises IndexError."""
    check = _create_score_distribution_check()
    values = [0.05, 0.15, 0.25, 0.35, 0.45, 0.55, 0.65, 0.75, 0.85, 0.95, 1.0]
    ok, ratio = check.check_fn(values)
    assert ok is True
    assert ratio == pytest.approx(0.9866599586738649, abs=1e-9)


def test_score_distribution_two_bins_ratio_one():
    """(2153,47) NumberReplacer#270: two equally populated bins give
    a ratio of exactly 1.0 (the `> 1` mutant returns 0.0 instead)."""
    check = _create_score_distribution_check()
    values = [0.05] * 5 + [0.55] * 5
    ok, ratio = check.check_fn(values)
    assert ok is True
    assert ratio == 1.0


def test_score_distribution_one_bin_ratio_zero():
    """(2154,47) NumberReplacer#273: a single populated bin gives a
    ratio of 0.0 (the else-branch -1.0 mutant returns -1.0)."""
    check = _create_score_distribution_check()
    values = [0.05] * 10
    ok, ratio = check.check_fn(values)
    assert ok is False
    assert ratio == 0.0


def test_score_distribution_two_bins_passes_half():
    """(2155,57) NumberReplacer#274: a ratio of exactly 1.0 passes
    the > 0.5 test (the `> 1.5` mutant fails it)."""
    check = _create_score_distribution_check()
    values = [0.05] * 5 + [0.55] * 5
    ok, ratio = check.check_fn(values)
    assert ok is True
    assert ratio == 1.0


def test_score_distribution_factory_thresholds():
    """(2157,36) NumberReplacer#276 + (2158,37) #279 + (2160,29)
    #280/#281: the score-distribution check declares warning 0.5,
    critical 0.3, min_samples 10."""
    check = _create_score_distribution_check()
    assert check.warning_threshold == 0.5
    assert check.critical_threshold == 0.3
    assert check.min_samples == 10


# ---------------------------------------------------------------------------
# Built-in checks: _create_throughput_check
# ---------------------------------------------------------------------------

_T_FIXED = 1_700_000_000.0


def _throughput(values: list[float]) -> tuple[bool, float]:
    check = _create_throughput_check()
    with mock.patch("time.time", return_value=_T_FIXED):
        return check.check_fn(values)


def test_throughput_subtraction_window():
    """(2186,31) Sub_Div#8 + Sub_FloorDiv#8 + Sub_Mod#8: the recent
    window is `now - t < 60`. Values [T-1000, T/2] give throughput
    0.0. The Div mutant computes now/(T-1000) ~= 1 < 60 (recent);
    FloorDiv gives 1 (recent); Mod gives now % (T/2) == 0 (recent)
    — all three return a nonzero throughput instead. The check is
    inverted (low throughput is bad), so ok is False at 0.0."""
    ok, throughput = _throughput([_T_FIXED - 1000.0, _T_FIXED / 2.0])
    assert ok is False
    assert throughput == 0.0


def test_throughput_sixty_second_boundary():
    """(2188,28) Lt_LtE#10 + Lt_NotEq#10 + (2189,29) NumberReplacer
    #282: a value exactly 60s old is not recent; one 61s old is
    not recent either. The `<= 60` mutant counts the 60s value; the
    `!= 60` mutant counts the 61s value; the `< 61` mutant counts
    the 60s value — all return a nonzero throughput."""
    ok, throughput = _throughput([_T_FIXED - 60.0, _T_FIXED - 61.0])
    assert ok is False
    assert throughput == 0.0


def test_throughput_fifty_nine_seconds_is_recent():
    """(2189,32) NumberReplacer#283: a value 59s old is recent
    (throughput 1/60). The `< 59` mutant excludes it and returns
    0.0. Throughput 1/60 is below the 0.5 warning threshold, so ok
    is False."""
    ok, throughput = _throughput([_T_FIXED - 59.0])
    assert ok is False
    assert throughput == pytest.approx(1.0 / 60.0, abs=1e-12)


def test_throughput_sixty_recent_is_one():
    """(2197,31) GtE_Eq#12: 60 recent values give throughput 1.0 and
    pass. The `== 0.5` mutant fails it (1.0 != 0.5)."""
    ok, throughput = _throughput([_T_FIXED - 1.0] * 60)
    assert ok is True
    assert throughput == 1.0


def test_throughput_factory_threshold():
    """(2199,28) NumberReplacer#288: the throughput check declares
    warning threshold 0.5."""
    assert _create_throughput_check().warning_threshold == 0.5


# ---------------------------------------------------------------------------
# DetectorHealthMonitor.__init__
# ---------------------------------------------------------------------------


def test_monitor_max_history_default():
    """(2223,27) NumberReplacer#296/#297: the default max_history is
    10000."""
    assert DetectorHealthMonitor().max_history == 10000


def test_monitor_bool_max_history_raises():
    """(2228,44) ReplaceOrWithAnd#52: a boolean max_history must be
    rejected. The `and` mutant accepts True."""
    with pytest.raises(ValueError, match="max_history must be an integer"):
        DetectorHealthMonitor(max_history=True)


def test_monitor_max_history_zero_raises():
    """(2230,23) Lt_Eq#11 + (2230,25) NumberReplacer#299: a
    max_history of 0 must be rejected. The `== 1` mutant does not
    raise for 0; the `< 0` mutant does not raise either."""
    with pytest.raises(ValueError, match="at least 1"):
        DetectorHealthMonitor(max_history=0)


def test_monitor_max_history_one_is_valid():
    """(2230,23) Lt_LtE#11 + (2230,25) NumberReplacer#298: a
    max_history of 1 is valid. The `<= 1` mutant rejects it; the
    `< 2` mutant rejects it too."""
    assert DetectorHealthMonitor(max_history=1).max_history == 1


# ---------------------------------------------------------------------------
# DetectorHealthMonitor._parse_metric_timestamp
# ---------------------------------------------------------------------------


def test_parse_metric_timestamp_bad_string_returns_none():
    """(2267,16) ExceptionReplacer#6: an unparseable string returns
    None (the mutant lets the ValueError propagate)."""
    assert DetectorHealthMonitor._parse_metric_timestamp("not-a-date") is None


def test_parse_metric_timestamp_bytes_returns_none():
    """(2267,28) ExceptionReplacer#7: a bytes timestamp returns None
    (the mutant lets the TypeError from bytes.replace propagate)."""
    assert DetectorHealthMonitor._parse_metric_timestamp(b"2026-01-01") is None


def test_parse_metric_timestamp_int_returns_none():
    """(2267,39) ExceptionReplacer#8: an int timestamp returns None
    (the mutant lets the AttributeError from int.replace propagate)."""
    assert DetectorHealthMonitor._parse_metric_timestamp(123) is None


def test_parse_metric_timestamp_naive_gets_utc():
    """(2269,11) AddNot#172 + (2269,25) Is_IsNot#23: a naive
    timestamp is treated as UTC. The mutants skip the tzinfo
    assignment, so .astimezone(UTC) treats the naive value as local
    time. With the system timezone set to America/New_York (UTC-5
    in January), the mutant returns 05:00 UTC instead of 00:00 UTC.
    (With the system timezone at UTC the two coincide, which is why
    the plain assertion could not kill them.)"""
    with _non_utc_timezone():
        parsed = DetectorHealthMonitor._parse_metric_timestamp("2026-01-01T00:00:00")
    assert parsed == datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# DetectorHealthMonitor._fresh_values
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _fresh_monitor() -> DetectorHealthMonitor:
    return DetectorHealthMonitor()


def _record_at(monitor: DetectorHealthMonitor, value: float, when: datetime) -> None:
    monitor.record_metric("det-a", "latency_ms", value, timestamp=_iso(when))


def test_fresh_values_keyword_only_params():
    """(2274,52) Mul_Div#19: detector_id and source_metric are
    keyword-capable (the `*` marker); the mutant makes them
    positional-only, so a keyword call raises TypeError."""
    monitor = _fresh_monitor()
    values = monitor._fresh_values(detector_id="det-a", source_metric="latency_ms")
    assert values == []


def test_fresh_values_nonfinite_first_skipped():
    """(2287,16) ReplaceContinueWithBreak#7: a non-finite metric
    followed by a good one must return only the good value (the
    `break` mutant returns nothing)."""
    monitor = _fresh_monitor()
    monitor._metrics["det-a"]["latency_ms"].append(
        HealthMetric(
            name="latency_ms",
            value=float("inf"),
            unit="ms",
            timestamp=_iso(_NOW),
            detector_id="det-a",
        )
    )
    _record_at(monitor, 5.0, _NOW)
    assert monitor._fresh_values("det-a", "latency_ms", now=_NOW) == [5.0]


def test_fresh_values_bad_timestamp_first_skipped():
    """(2290,16) ReplaceContinueWithBreak#8: a metric with an
    unparseable timestamp followed by a good one must return only
    the good value."""
    monitor = _fresh_monitor()
    monitor._metrics["det-a"]["latency_ms"].append(
        HealthMetric(
            name="latency_ms",
            value=1.0,
            unit="ms",
            timestamp="not-a-date",
            detector_id="det-a",
        )
    )
    _record_at(monitor, 5.0, _NOW)
    assert monitor._fresh_values("det-a", "latency_ms", now=_NOW) == [5.0]


def test_fresh_values_stale_first_skipped():
    """(2293,16) ReplaceContinueWithBreak#9: a stale metric followed
    by a fresh one must return only the fresh value."""
    monitor = _fresh_monitor()
    _record_at(monitor, 1.0, datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC))
    _record_at(monitor, 5.0, _NOW)
    assert monitor._fresh_values("det-a", "latency_ms", now=_NOW) == [5.0]


def test_fresh_values_future_first_skipped():
    """(2295,16) ReplaceContinueWithBreak#10: a far-future metric
    followed by a fresh one must return only the fresh value."""
    monitor = _fresh_monitor()
    _record_at(monitor, 1.0, datetime(2026, 1, 1, 12, 5, 0, tzinfo=UTC))
    _record_at(monitor, 5.0, _NOW)
    assert monitor._fresh_values("det-a", "latency_ms", now=_NOW) == [5.0]


def test_fresh_values_exactly_max_age_is_fresh():
    """(2292,19) Gt_GtE#9 + (2292,19) NumberReplacer#293: a metric
    exactly 3600s old is fresh. The `>=` mutant treats it as stale;
    the 3599s-max mutant treats it as stale too."""
    monitor = _fresh_monitor()
    _record_at(monitor, 5.0, datetime(2026, 1, 1, 11, 0, 0, tzinfo=UTC))
    assert monitor._fresh_values("det-a", "latency_ms", now=_NOW) == [5.0]


def test_fresh_values_just_over_max_age_is_stale():
    """(2292,19) NumberReplacer#292: a metric 3601s old is stale.
    The 3601s-max mutant treats it as fresh."""
    monitor = _fresh_monitor()
    _record_at(monitor, 5.0, datetime(2026, 1, 1, 10, 59, 59, tzinfo=UTC))
    assert monitor._fresh_values("det-a", "latency_ms", now=_NOW) == []


def test_fresh_values_exactly_tolerance_is_fresh():
    """(2294,19) Lt_Eq#12 + Lt_LtE#12 + (2294,19) NumberReplacer
    #295: a metric exactly 60s in the future is fresh. The `== -60`
    mutant skips it; the `<= -60` mutant skips it; the 59s-tolerance
    mutant skips it too."""
    monitor = _fresh_monitor()
    _record_at(monitor, 5.0, datetime(2026, 1, 1, 12, 1, 0, tzinfo=UTC))
    assert monitor._fresh_values("det-a", "latency_ms", now=_NOW) == [5.0]


def test_fresh_values_sixty_one_seconds_future_is_stale():
    """(2294,19) Lt_Is#3 + (2294,19) NumberReplacer#294: a metric
    61s in the future is stale. The `is` mutant keeps it (a computed
    float is never identical to the tolerance constant); the
    61s-tolerance mutant keeps it too."""
    monitor = _fresh_monitor()
    _record_at(monitor, 5.0, datetime(2026, 1, 1, 12, 1, 1, tzinfo=UTC))
    assert monitor._fresh_values("det-a", "latency_ms", now=_NOW) == []


# ---------------------------------------------------------------------------
# DetectorHealthMonitor._checks_without_fresh_data
# ---------------------------------------------------------------------------


def _monitor_with_check(min_samples: int = 10) -> DetectorHealthMonitor:
    monitor = DetectorHealthMonitor()
    check = HealthCheck(
        name="latency",
        metric_name="latency_ms",
        check_fn=lambda values: (True, 1.0),
        warning_threshold=10.0,
        critical_threshold=20.0,
        min_samples=min_samples,
    )
    monitor._health_checks["det-a"] = [check]
    return monitor


def test_checks_without_fresh_data_none_present():
    """(2302,21) ZeroIterationForLoop#24: a check with no fresh data
    is named (the mutant skips the loop and names nothing)."""
    monitor = _monitor_with_check()
    assert monitor._checks_without_fresh_data("det-a") == ["latency"]


def test_checks_without_fresh_data_exact_minimum_is_sufficient():
    """(2303,15) AddNot#177 + (2303,73) Lt_Eq#13 + Lt_GtE#13 +
    Lt_Is#4 + Lt_LtE#13: exactly min_samples fresh values are
    sufficient. The AddNot mutant names the check anyway; the `==`
    mutant names it (10 == 10); the `>=` mutant names it; the `is`
    mutant names it (both sides are the cached small int 10); the
    `<=` mutant names it. The values must be recorded near the real
    current time: _checks_without_fresh_data reads freshness
    against now, not against a passed-in time."""
    monitor = _monitor_with_check()
    now = datetime.now(UTC)
    for _ in range(10):
        _record_at(monitor, 5.0, now)
    assert monitor._checks_without_fresh_data("det-a") == []


def test_checks_without_fresh_data_above_minimum_is_sufficient():
    """(2303,73) Lt_Gt#13 + Lt_IsNot#4 + Lt_NotEq#13: more than
    min_samples fresh values are sufficient. The `>` mutant names
    the check (11 > 10); the `is not` mutant names it (11 is not the
    cached 10); the `!=` mutant names it."""
    monitor = _monitor_with_check()
    now = datetime.now(UTC)
    for _ in range(11):
        _record_at(monitor, 5.0, now)
    assert monitor._checks_without_fresh_data("det-a") == []


# ---------------------------------------------------------------------------
# DetectorHealthMonitor.record_metric
# ---------------------------------------------------------------------------


def test_record_metric_bool_value_raises():
    """(2324,47) ReplaceOrWithAnd#54: a boolean metric value must be
    rejected. The `and` mutant accepts True."""
    monitor = DetectorHealthMonitor()
    with pytest.raises(ValueError, match="must be a number"):
        monitor.record_metric("det-a", "latency_ms", True)


def test_record_metric_neighbour_names_accept_negative():
    """(2328,23) Eq_GtE#29 + Eq_LtE#29: the negative-latency check
    applies only to "latency_ms" exactly. "latency_mt" (above) kills
    the `>=` mutant; "latency_mr" (below) kills the `<=` mutant —
    both must accept -1 without raising."""
    monitor = DetectorHealthMonitor()
    monitor.record_metric("det-a", "latency_mt", -1.0, timestamp=_iso(_NOW))
    monitor.record_metric("det-a", "latency_mr", -1.0, timestamp=_iso(_NOW))


def test_record_metric_latency_zero_is_valid():
    """(2328,49) Lt_LtE#14 + (2328,51) NumberReplacer#300: a
    latency_ms of 0 is valid (the `<=` mutant rejects it; the `< 1`
    mutant rejects it too)."""
    monitor = DetectorHealthMonitor()
    monitor.record_metric("det-a", "latency_ms", 0.0, timestamp=_iso(_NOW))
    monitor.record_metric("det-a", "latency_ms", 0.5, timestamp=_iso(_NOW))


def test_record_metric_negative_latency_raises():
    """(2328,49) Lt_LtE#14 (twin direction): a negative latency_ms
    must be rejected."""
    monitor = DetectorHealthMonitor()
    with pytest.raises(ValueError, match="non-negative"):
        monitor.record_metric("det-a", "latency_ms", -1.0, timestamp=_iso(_NOW))


def test_record_metric_naive_timestamp_gets_utc():
    """(2334,15) AddNot#182 + (2334,34) Is_IsNot#26: a naive datetime
    timestamp is stored as UTC. Same timezone argument as the parse
    test: with America/New_York local time, the mutant stores
    17:00 UTC instead of 12:00 UTC."""
    monitor = DetectorHealthMonitor()
    with _non_utc_timezone():
        monitor.record_metric("det-a", "latency_ms", 5.0, timestamp=datetime(2026, 1, 1, 12, 0, 0))
    stored = monitor._metrics["det-a"]["latency_ms"][0]
    assert stored.timestamp == "2026-01-01T12:00:00+00:00"


# ---------------------------------------------------------------------------
# DetectorHealthMonitor._append_alert
# ---------------------------------------------------------------------------


def test_append_alert_trims_to_max_history():
    """(2398,49) Sub_Add#10 + Sub_BitAnd#10 + Sub_BitOr#10 +
    Sub_BitXor#10 + Sub_FloorDiv#10 + Sub_LShift#10 + Sub_Mod#10 +
    Sub_Mul#10 + Sub_Pow#10: appending 5 alerts with max_history 2
    keeps exactly the last 2. Every replacement of the `len -
    max_history` slice changes which alerts survive."""
    monitor = DetectorHealthMonitor(max_history=2)
    alerts = [_alert(alert_id=f"alert-0000000{i}") for i in range(5)]
    for alert in alerts:
        monitor._append_alert(alert)
    assert [a.alert_id for a in monitor._alerts] == [
        "alert-00000003",
        "alert-00000004",
    ]


def test_append_alert_trim_from_large_history():
    """(2398,49) Sub_*#10 (all nine): trimming from a large history
    keeps exactly the last max_history alerts. With 7 pre-loaded
    alerts and max_history 2, appending one more gives len 8 and the
    original deletes alerts[:6], keeping the last 2. Every
    replacement of the `len - max_history` slice changes the result:
    + deletes all, & deletes none (8&2=0), | deletes all, ^ deletes
    all (8^2=10), // keeps 4, << deletes all, % deletes none
    (8%2=0), * deletes all, ** deletes all. (Appending one alert at
    a time from empty does NOT kill them — the incremental flow
    never lets len exceed max_history + 1, where several mutants
    coincide with the original.)"""
    monitor = DetectorHealthMonitor(max_history=2)
    monitor._alerts = [_alert(alert_id=f"alert-0000000{i}") for i in range(7)]
    monitor._append_alert(_alert(alert_id="alert-00000007"))
    assert [a.alert_id for a in monitor._alerts] == [
        "alert-00000006",
        "alert-00000007",
    ]


def test_append_alert_at_max_history_keeps_all():
    """(2397,29) Gt_IsNot#3 + Gt_NotEq#11: with len < max_history
    (2 alerts, max 3) both alerts are kept. The `is not` mutant
    trims (2 is not 3); the `!=` mutant trims too — both run
    `del alerts[:-1]`, dropping the first alert. (A 1-alert test
    does NOT kill them: `del alerts[:-1]` on a 1-element list is a
    no-op.)"""
    monitor = DetectorHealthMonitor(max_history=3)
    monitor._append_alert(_alert(alert_id="alert-00000001"))
    monitor._append_alert(_alert(alert_id="alert-00000002"))
    assert len(monitor._alerts) == 2


# ---------------------------------------------------------------------------
# DetectorHealthMonitor._evaluate_health_checks
# ---------------------------------------------------------------------------


def _eval_monitor(check_name: str, firing: bool, min_samples: int = 1) -> DetectorHealthMonitor:
    monitor = DetectorHealthMonitor()
    check = HealthCheck(
        name=check_name,
        metric_name="latency_ms",
        check_fn=(lambda values: (False, 15.0)) if firing else (lambda values: (True, 1.0)),
        warning_threshold=10.0,
        critical_threshold=20.0,
        min_samples=min_samples,
    )
    monitor._health_checks["det-a"] = [check]
    return monitor


def test_evaluate_insufficient_data_removes_equal_key():
    """(2409,74) Eq_Gt#30 + Eq_Lt#30 + Eq_NotEq#30 + Eq_IsNot#26
    (same family at the insufficient-data site): with no fresh data
    the check's active key is cleared. The `>` mutant keeps it
    (equal is not greater); the `<` mutant keeps it; the `!=`
    mutant keeps it; the `is not` mutant keeps it (same object)."""
    monitor = _eval_monitor("aaa-check", firing=False, min_samples=2)
    monitor._active_alert_keys["det-a"] = {("aaa-check", AlertSeverity.WARNING)}
    monitor._evaluate_health_checks("det-a")
    assert monitor._active_alert_keys["det-a"] == set()


def test_evaluate_insufficient_data_keeps_greater_key():
    """(2409,74) Eq_GtE#30 + Eq_NotEq#30 + Eq_IsNot#26: an unrelated
    active key sorting above the check name is preserved when data
    is insufficient. The `>=` mutant removes it; the `!=` mutant
    removes it; the `is not` mutant removes it."""
    monitor = _eval_monitor("aaa-check", firing=False, min_samples=2)
    monitor._active_alert_keys["det-a"] = {("zzz-check", AlertSeverity.WARNING)}
    monitor._evaluate_health_checks("det-a")
    assert monitor._active_alert_keys["det-a"] == {("zzz-check", AlertSeverity.WARNING)}


def test_evaluate_insufficient_data_keeps_lesser_key():
    """(2409,74) Eq_Lt#30 + Eq_LtE#30 + Eq_NotEq#30 + Eq_IsNot#26:
    an unrelated active key sorting below the check name is
    preserved when data is insufficient. The `<` and `<=` mutants
    remove it; the `!=` and `is not` mutants remove it too."""
    monitor = _eval_monitor("zzz-check", firing=False, min_samples=2)
    monitor._active_alert_keys["det-a"] = {("aaa-check", AlertSeverity.WARNING)}
    monitor._evaluate_health_checks("det-a")
    assert monitor._active_alert_keys["det-a"] == {("aaa-check", AlertSeverity.WARNING)}


def test_evaluate_firing_replaces_equal_key():
    """(2422,72) Eq_Gt#31 + Eq_Lt#31 + Eq_NotEq#31 + Eq_IsNot#26
    (firing site): when a check fires at a new severity, its old
    severity key is replaced. The `>`/`<`/`!=`/`is not` mutants keep
    the stale CRITICAL key alongside the new WARNING key."""
    monitor = _eval_monitor("aaa-check", firing=True)
    monitor._active_alert_keys["det-a"] = {("aaa-check", AlertSeverity.CRITICAL)}
    _record_at(monitor, 5.0, datetime.now(UTC))
    assert monitor._active_alert_keys["det-a"] == {("aaa-check", AlertSeverity.WARNING)}
    assert len(monitor._alerts) == 1


def test_evaluate_firing_keeps_greater_key():
    """(2422,72) Eq_GtE#31 + Eq_NotEq#31 + Eq_IsNot#26: an unrelated
    key sorting above the firing check's name is preserved."""
    monitor = _eval_monitor("aaa-check", firing=True)
    monitor._active_alert_keys["det-a"] = {("zzz-check", AlertSeverity.WARNING)}
    _record_at(monitor, 5.0, datetime.now(UTC))
    assert ("zzz-check", AlertSeverity.WARNING) in monitor._active_alert_keys["det-a"]


def test_evaluate_firing_keeps_lesser_key():
    """(2422,72) Eq_Lt#31 + Eq_LtE#31 + Eq_NotEq#31 + Eq_IsNot#26:
    an unrelated key sorting below the firing check's name is
    preserved."""
    monitor = _eval_monitor("zzz-check", firing=True)
    monitor._active_alert_keys["det-a"] = {("aaa-check", AlertSeverity.WARNING)}
    _record_at(monitor, 5.0, datetime.now(UTC))
    assert ("aaa-check", AlertSeverity.WARNING) in monitor._active_alert_keys["det-a"]


def test_evaluate_passing_removes_equal_key():
    """(2428,74) Eq_GtE#32 + Eq_LtE#32 (passing site): when a check
    passes, its active key is cleared. The `>=` mutant keeps an
    equal key? No — `>=` is True for equal, so it removes it like
    the original. The equal-key case kills nothing here; the
    greater/lesser cases below kill GtE/LtE. This test pins the
    equal case as a guard."""
    monitor = _eval_monitor("aaa-check", firing=False)
    monitor._active_alert_keys["det-a"] = {("aaa-check", AlertSeverity.WARNING)}
    _record_at(monitor, 5.0, datetime.now(UTC))
    assert monitor._active_alert_keys["det-a"] == set()


def test_evaluate_passing_keeps_greater_key():
    """(2428,74) Eq_GtE#32 + Eq_NotEq#32 (passing site): an unrelated
    key sorting above the passing check's name is preserved. The
    `>=` mutant removes it; the `!=` mutant removes it."""
    monitor = _eval_monitor("aaa-check", firing=False)
    monitor._active_alert_keys["det-a"] = {("zzz-check", AlertSeverity.WARNING)}
    _record_at(monitor, 5.0, datetime.now(UTC))
    assert monitor._active_alert_keys["det-a"] == {("zzz-check", AlertSeverity.WARNING)}


def test_evaluate_passing_keeps_lesser_key():
    """(2428,74) Eq_LtE#32 + Eq_NotEq#32 (passing site): an unrelated
    key sorting below the passing check's name is preserved. The
    `<=` mutant removes it; the `!=` mutant removes it."""
    monitor = _eval_monitor("zzz-check", firing=False)
    monitor._active_alert_keys["det-a"] = {("aaa-check", AlertSeverity.WARNING)}
    _record_at(monitor, 5.0, datetime.now(UTC))
    assert monitor._active_alert_keys["det-a"] == {("aaa-check", AlertSeverity.WARNING)}


# ---------------------------------------------------------------------------
# DetectorHealthMonitor.get_report
# ---------------------------------------------------------------------------


def test_get_report_alerts_filtered_by_detector():
    """(2448,66) Eq_GtE#33 + Eq_LtE#33: a report for "mmm" contains
    no alerts from "aaa" or "zzz". The `>=` mutant includes "zzz";
    the `<=` mutant includes "aaa"."""
    monitor = DetectorHealthMonitor()
    monitor._alerts = [
        _alert(detector_id="aaa", alert_id="alert-00000001"),
        _alert(detector_id="zzz", alert_id="alert-00000002"),
    ]
    report = monitor.get_report("mmm")
    assert report.alerts == []


def test_get_report_alert_matching_distinct_object():
    """(2448,66) Eq_Is#28: an alert whose detector_id equals the
    requested id as a value (distinct string object) is included.
    The `is` mutant excludes it."""
    monitor = DetectorHealthMonitor()
    monitor._alerts = [_alert(detector_id=_distinct("det-a"))]
    report = monitor.get_report("det-a")
    assert len(report.alerts) == 1


def test_get_report_unparseable_timestamp_does_not_crash():
    """(2454,62) ReplaceOrWithAnd#56: a report over metrics whose
    timestamps include an unparseable one must still be generated.
    The `and` mutant sorts with a None key and raises TypeError."""
    monitor = DetectorHealthMonitor()
    monitor._metrics["det-a"]["latency_ms"].append(
        HealthMetric(
            name="latency_ms",
            value=1.0,
            unit="ms",
            timestamp="not-a-date",
            detector_id="det-a",
        )
    )
    monitor._metrics["det-a"]["latency_ms"].append(
        HealthMetric(
            name="latency_ms",
            value=2.0,
            unit="ms",
            timestamp=_iso(_NOW),
            detector_id="det-a",
        )
    )
    report = monitor.get_report("det-a")
    assert report.last_updated == _iso(_NOW)


def test_get_report_unknown_detector_score_zero():
    """Guard for (2443,29) NumberReplacer#312/#313: an unknown
    detector's report has health_score 0.0. The `0.0` -> `1.0` /
    `-1.0` mutants are EQUIVALENT, not killable: the constructor
    default is overwritten by _compute_overall_health on every
    get_report call (which returns (UNKNOWN, 0.0) for a detector
    with no checks) before the report is returned, so the initial
    value is never observable. This test pins the final score."""
    monitor = DetectorHealthMonitor()
    report = monitor.get_report("never-seen")
    assert report.health_score == 0.0
    assert report.overall_state == HealthState.UNKNOWN


# ---------------------------------------------------------------------------
# DetectorHealthMonitor._compute_overall_health
# ---------------------------------------------------------------------------


def _health_monitor(*checks: HealthCheck) -> DetectorHealthMonitor:
    monitor = DetectorHealthMonitor()
    monitor._health_checks["det-a"] = list(checks)
    return monitor


def _firing_check(name: str, value: float) -> HealthCheck:
    return HealthCheck(
        name=name,
        metric_name="latency_ms",
        check_fn=lambda values: (False, value),
        warning_threshold=10.0,
        critical_threshold=20.0,
        min_samples=1,
    )


def _passing_check(name: str) -> HealthCheck:
    return HealthCheck(
        name=name,
        metric_name="latency_ms",
        check_fn=lambda values: (True, 1.0),
        warning_threshold=10.0,
        critical_threshold=20.0,
        min_samples=1,
    )


def _compute(monitor: DetectorHealthMonitor) -> tuple[HealthState, float]:
    _record_at(monitor, 5.0, datetime.now(UTC))
    return monitor._compute_overall_health("det-a")


def test_overall_health_one_critical_of_one():
    """(2488,28) NumberReplacer#322 + (2492,38) #324 + (2500,45)
    #334 + (2500,50) #337: one critical check of one gives
    (CRITICAL, 0.2). #322 (total_checks += 2) gives 0.6; #324
    (critical_count += 2) gives 0.0; #334 (max(1.0, ...)) gives 1.0;
    #337 (1.0 -> 0.0) gives 0.0."""
    monitor = _health_monitor(_firing_check("c1", 25.0))
    state, score = _compute(monitor)
    assert state == HealthState.CRITICAL
    assert score == pytest.approx(0.2, abs=1e-9)


def test_overall_health_one_critical_of_two():
    """(2500,54) Sub_*#11 + (2500,72) Div_*#13 + (2500,88) Mul_*#20
    + (2500,90) NumberReplacer#338: one critical of two gives
    (CRITICAL, 0.6). Every replacement in `1.0 - (1/2) * 0.8`
    changes the score."""
    monitor = _health_monitor(_firing_check("c1", 25.0), _passing_check("c2"))
    state, score = _compute(monitor)
    assert state == HealthState.CRITICAL
    assert score == pytest.approx(0.6, abs=1e-9)


def test_overall_health_one_warning_of_two():
    """(2494,37) NumberReplacer#326 + (2502,45) #342 + (2502,50)
    #344/#345 + (2502,54) Sub_*#12 + (2502,71) Div_*#14 + (2502,87)
    Mul_*#21 + (2502,89) #346/#347: one warning of two gives
    (DEGRADED, 0.75). Every replacement in `1.0 - (1/2) * 0.5`
    changes the score; #326 (warning_count += 2) gives 0.5; #342
    (max(1.5, ...)) gives 1.5."""
    monitor = _health_monitor(_firing_check("c1", 15.0), _passing_check("c2"))
    state, score = _compute(monitor)
    assert state == HealthState.DEGRADED
    assert score == pytest.approx(0.75, abs=1e-9)


def test_overall_health_exact_minimum_counts():
    """(2486,27) Lt_LtE#16: a check with exactly min_samples fresh
    values counts toward the total. The `<=` mutant skips it, so a
    healthy check with min_samples 10 and 10 fresh values would
    report UNKNOWN instead of HEALTHY."""
    monitor = DetectorHealthMonitor()
    check = HealthCheck(
        name="c1",
        metric_name="latency_ms",
        check_fn=lambda values: (True, 1.0),
        warning_threshold=10.0,
        critical_threshold=20.0,
        min_samples=10,
    )
    monitor._health_checks["det-a"] = [check]
    for _ in range(10):
        _record_at(monitor, 5.0, datetime.now(UTC))
    state, score = monitor._compute_overall_health("det-a")
    assert state == HealthState.HEALTHY
    assert score == 1.0


# ---------------------------------------------------------------------------
# DetectorHealthMonitor.clear_alerts
# ---------------------------------------------------------------------------


def test_clear_alerts_keeps_unrelated_detectors():
    """(2515,69) NotEq_Gt#24: clearing "mmm" keeps alerts for "aaa"
    and "zzz". The `>` mutant drops "aaa" (it keeps only ids >
    "mmm")."""
    monitor = DetectorHealthMonitor()
    monitor._alerts = [
        _alert(detector_id="aaa", alert_id="alert-00000001"),
        _alert(detector_id="zzz", alert_id="alert-00000002"),
    ]
    removed = monitor.clear_alerts("mmm")
    assert removed == 0
    assert len(monitor._alerts) == 2


def test_clear_alerts_matching_distinct_object():
    """(2515,69) NotEq_IsNot#21: clearing "aaa" removes an alert
    whose detector_id equals "aaa" as a value (distinct string
    object). The `is not` mutant keeps it."""
    monitor = DetectorHealthMonitor()
    monitor._alerts = [_alert(detector_id=_distinct("aaa"))]
    removed = monitor.clear_alerts("aaa")
    assert removed == 1
    assert monitor._alerts == []


def test_clear_alerts_returns_removed_count():
    """(2517,26) Sub_RShift#13: clearing 2 of 3 alerts returns 2.
    The `>>` mutant returns 3 >> 1 == 1."""
    monitor = DetectorHealthMonitor()
    monitor._alerts = [
        _alert(detector_id="aaa", alert_id="alert-00000001"),
        _alert(detector_id="aaa", alert_id="alert-00000002"),
        _alert(detector_id="zzz", alert_id="alert-00000003"),
    ]
    removed = monitor.clear_alerts("aaa")
    assert removed == 2
    assert len(monitor._alerts) == 1
