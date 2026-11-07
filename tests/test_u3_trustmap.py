"""Tests for U3 longitudinal evidence in Trust Map derivation.

``derive_trust_map(longitudinal=...)`` lifts the single-snapshot cap on
``temporal_version_stability`` only when U3 probe runs supply enough
consecutive clean full-corpus runs at the same detector version.
Fixtures are synthetic (the U1 test module's helpers); no dataset data
and no measured numbers appear here.
"""

from __future__ import annotations

import pytest

from tests.test_validation_trustmap import (
    DETECTOR_ID,
    VERSION,
    derive,
    make_conditions,
    make_record_dict,
    registry_of,
)
from textforensics.probe_runs import summarize_longitudinal
from textforensics.schema import validate_trust_map
from textforensics.validation import (
    MIN_CLEAN_FULL_RUNS_FOR_TEMPORAL_SUPPORT,
    ValidationError,
)

HEX64 = "a" * 64


def _longitudinal(*, clean_runs: int = 2, watch=None, **overrides):
    evidence = {
        "detector_id": DETECTOR_ID,
        "detector_version": VERSION,
        "corpus_fingerprint": HEX64,
        "consecutive_clean_full_runs": clean_runs,
        "clean_full_run_ids": [f"run-{i}" for i in range(clean_runs)],
        "watch": watch,
    }
    evidence.update(overrides)
    return evidence


def _temporal_dimension(trust_map):
    return next(d for d in trust_map.dimensions if d.dimension == "temporal_version_stability")


def test_no_longitudinal_temporal_stays_partial():
    registry = registry_of(make_record_dict())
    result = derive(make_conditions(), registry)
    dimension = _temporal_dimension(result)
    assert dimension.state == "partial"
    assert "single snapshot" in dimension.reason
    assert result.overall == "mixed"


def test_longitudinal_zero_clean_runs_stays_partial_and_records_count():
    registry = registry_of(make_record_dict())
    result = derive(make_conditions(), registry, longitudinal=_longitudinal(clean_runs=0))
    dimension = _temporal_dimension(result)
    assert dimension.state == "partial"
    assert dimension.observed["u3_clean_full_runs"] == 0
    assert dimension.observed["u3_clean_full_run_ids"] == []
    assert dimension.observed["u3_corpus_fingerprint"] == HEX64


def test_longitudinal_one_clean_run_stays_partial():
    registry = registry_of(make_record_dict())
    result = derive(make_conditions(), registry, longitudinal=_longitudinal(clean_runs=1))
    dimension = _temporal_dimension(result)
    assert dimension.state == "partial"
    assert "single snapshot" in dimension.reason
    assert dimension.observed["u3_clean_full_runs"] == 1


def test_longitudinal_two_clean_runs_supports_temporal():
    registry = registry_of(make_record_dict())
    result = derive(make_conditions(), registry, longitudinal=_longitudinal(clean_runs=2))
    dimension = _temporal_dimension(result)
    assert dimension.state == "supported"
    assert dimension.observed["u3_clean_full_runs"] == 2
    assert dimension.observed["u3_clean_full_run_ids"] == ["run-0", "run-1"]
    assert dimension.observed["u3_corpus_fingerprint"] == HEX64
    assert "run-0" in dimension.reason and "run-1" in dimension.reason
    # The 8th evidence dimension is now supported; the 2 live dimensions
    # are still unknown, so overall stays mixed (strong needs all 10).
    assert result.overall == "mixed"
    validate_trust_map(result.to_dict())


def test_longitudinal_watch_does_not_change_state_but_is_surfaced():
    watch = {
        "run_id": "run-9",
        "run_at_utc": "2026-11-07T00:00:00+00:00",
        "alerts": [{"tier": 2, "rule": "drift_statistic"}],
    }
    registry = registry_of(make_record_dict())
    result = derive(
        make_conditions(),
        registry,
        longitudinal=_longitudinal(clean_runs=2, watch=watch),
    )
    dimension = _temporal_dimension(result)
    assert dimension.state == "supported"
    assert dimension.observed["u3_watch"]["run_id"] == "run-9"
    assert any("watch" in item.lower() for item in result.limitations)


def test_longitudinal_for_other_detector_is_refused():
    registry = registry_of(make_record_dict())
    with pytest.raises(ValidationError, match="longitudinal evidence is for detector"):
        derive(
            make_conditions(),
            registry,
            longitudinal=_longitudinal(detector_id="textforensics/other"),
        )


def test_longitudinal_for_other_version_is_refused():
    registry = registry_of(make_record_dict())
    with pytest.raises(ValidationError, match="longitudinal evidence is for detector"):
        derive(
            make_conditions(),
            registry,
            longitudinal=_longitudinal(detector_version="9.9.9"),
        )


def test_longitudinal_bad_fingerprint_is_refused():
    registry = registry_of(make_record_dict())
    with pytest.raises(ValidationError, match="corpus_fingerprint"):
        derive(
            make_conditions(),
            registry,
            longitudinal=_longitudinal(corpus_fingerprint="not-a-hash"),
        )


def test_longitudinal_run_id_count_must_match():
    registry = registry_of(make_record_dict())
    with pytest.raises(ValidationError, match="clean_full_run_ids"):
        derive(
            make_conditions(),
            registry,
            longitudinal=_longitudinal(clean_runs=2, clean_full_run_ids=["only-one"]),
        )


def test_longitudinal_does_not_rescue_a_demoted_record():
    registry = registry_of(
        make_record_dict(demoted_by="U3 probe run run-1: Tier-1 alert(s) flip_rate")
    )
    result = derive(make_conditions(), registry, longitudinal=_longitudinal(clean_runs=2))
    dimension = _temporal_dimension(result)
    assert dimension.state == "stale"


def test_longitudinal_threshold_constant_is_two():
    assert MIN_CLEAN_FULL_RUNS_FOR_TEMPORAL_SUPPORT == 2


def test_summarize_longitudinal_feeds_derive_trust_map():
    """End-to-end seam: run history -> summary -> Trust Map."""
    history = [
        {
            "schema": "textforensics.probe-run/v1",
            "run_id": "r1",
            "run_at_utc": "2026-11-01T00:00:00+00:00",
            "scope": "full",
            "corpus_fingerprint": HEX64,
            "detector_id": DETECTOR_ID,
            "detector_version": VERSION,
            "alerts": [],
        },
        {
            "schema": "textforensics.probe-run/v1",
            "run_id": "r2",
            "run_at_utc": "2026-11-02T00:00:00+00:00",
            "scope": "full",
            "corpus_fingerprint": HEX64,
            "detector_id": DETECTOR_ID,
            "detector_version": VERSION,
            "alerts": [],
        },
    ]
    summary = summarize_longitudinal(
        history,
        detector_id=DETECTOR_ID,
        detector_version=VERSION,
        corpus_fingerprint=HEX64,
    )
    assert summary["temporal_support"] is True
    registry = registry_of(make_record_dict())
    result = derive(make_conditions(), registry, longitudinal=summary)
    assert _temporal_dimension(result).state == "supported"
