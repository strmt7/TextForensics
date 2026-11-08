"""Tests for scripts/measure_human_fpr.py pure functions.

No network, no dataset cache: only the Wilson-rate helper, the
pooled-rate helper, the FPR-bar assessment and the registry-patch
recommendation builder are tested here. The live re-run itself is
covered by the script's own run, whose artifact is the evidence.
"""

import importlib.util
import math
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"


def _load_measure_module():
    spec = importlib.util.spec_from_file_location(
        "measure_human_fpr", SCRIPTS_DIR / "measure_human_fpr.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["measure_human_fpr"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def measure():
    return _load_measure_module()


def _reference_wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Independent Wilson implementation, written from the formula."""
    p = k / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def test_rate_with_ci_matches_reference_wilson(measure):
    for k, n in [(0, 56), (0, 92), (0, 100), (0, 200), (2, 283), (55, 2908), (5, 100)]:
        got = measure.rate_with_ci(k, n)
        lower, upper = _reference_wilson(k, n)
        assert got["k"] == k
        assert got["n"] == n
        assert got["rate"] == pytest.approx(k / n)
        assert got["ci_lower"] == pytest.approx(lower, abs=1e-12)
        assert got["ci_upper"] == pytest.approx(upper, abs=1e-12)
        assert "Wilson" in got["method"]


def test_rate_with_ci_zero_events_closed_form(measure):
    # k=0: Wilson upper is exactly z^2 / (n + z^2), lower is 0.
    for n in (56, 92, 100, 200, 400, 4785):
        got = measure.rate_with_ci(0, n)
        assert got["ci_lower"] == 0.0
        assert got["ci_upper"] == pytest.approx(1.96**2 / (n + 1.96**2), abs=1e-12)


def test_rate_with_ci_rejects_bad_counts(measure):
    with pytest.raises(ValueError):
        measure.rate_with_ci(0, 0)
    with pytest.raises(ValueError):
        measure.rate_with_ci(3, 2)
    with pytest.raises(ValueError):
        measure.rate_with_ci(-1, 10)


def test_rate_with_ci_opai_56_upper_exceeds_ceiling(measure):
    # The headline finding: 0/56 humans gives a Wilson upper above 0.05.
    got = measure.rate_with_ci(0, 56)
    assert got["ci_upper"] == pytest.approx(0.0642, abs=0.0001)
    assert got["ci_upper"] > 0.05


def test_assess_slice_passes_for_adequate_slice(measure):
    result = measure.assess_slice(record_id="evr-x", n_human=200, n_ai=700, fpr_ci_upper=0.0188)
    assert result["can_support_fpr_claim"] is True
    assert result["blockers"] == []


def test_assess_slice_fails_small_human_sample(measure):
    # RAID: n=92 passes the Wilson ceiling but fails the 100 minimum.
    result = measure.assess_slice(record_id="evr-raid", n_human=92, n_ai=2908, fpr_ci_upper=0.0401)
    assert result["can_support_fpr_claim"] is False
    assert any("92" in b and "100" in b for b in result["blockers"])


def test_assess_slice_fails_wide_interval(measure):
    # OpAI-Bench 20261106: n=56 fails on sample size AND on the ceiling.
    result = measure.assess_slice(record_id="evr-opai", n_human=56, n_ai=55, fpr_ci_upper=0.0642)
    assert result["can_support_fpr_claim"] is False
    assert len(result["blockers"]) == 3  # n_human, n_ai, ci_upper
    assert any("0.0642" in b for b in result["blockers"])


def test_assess_slice_fails_without_ci(measure):
    result = measure.assess_slice(
        record_id="evr-x",
        n_human=200,
        n_ai=700,
        fpr_ci_upper=None,
        fpr_ci_present=False,
    )
    assert result["can_support_fpr_claim"] is False
    assert any("confidence interval" in b for b in result["blockers"])


def test_assess_slice_segment_never_supports_document_claim(measure):
    result = measure.assess_slice(
        record_id="evr-seg",
        n_human=4785,
        n_ai=5268,
        fpr_ci_upper=0.0008,
        segment_level=True,
    )
    assert result["can_support_fpr_claim"] is False
    assert any("segment-level" in b for b in result["blockers"])


def test_pooled_rate_sums_counts(measure):
    pooled = measure.pooled_rate([(0, 200), (0, 400)])
    assert pooled["k"] == 0
    assert pooled["n"] == 600
    assert pooled["rate"] == 0.0
    assert pooled["ci_upper"] == pytest.approx(1.96**2 / (600 + 1.96**2), abs=1e-12)


def test_pooled_rate_rejects_empty(measure):
    with pytest.raises(ValueError):
        measure.pooled_rate([])


def _fake_slice(record_id, kind, can_support, blockers):
    return {
        "record_id": record_id,
        "dataset": record_id,
        "slice_kind": kind,
        "fpr_native_wilson": {
            "k": 0,
            "n": 200,
            "value": 0.0,
            "ci_lower": 0.0,
            "ci_upper": 0.018845,
            "method": "Wilson score interval, 95% (z=1.96)",
        },
        "assessment": {
            "can_support_fpr_claim": can_support,
            "blockers": blockers,
        },
    }


def test_build_patch_assessment_recommends_no_status_change(measure):
    patch = measure.build_patch_assessment(
        [
            _fake_slice("evr-ok", "document", True, []),
            _fake_slice("evr-thin", "document", False, ["n_human=56 below"]),
        ]
    )
    assert patch["evidence_record_id"] == "EV-20261108-human-fpr-registry-patch"
    assert len(patch["records"]) == 2
    ok, thin = patch["records"]
    assert ok["fpr_bar_met"] is True
    assert "keep status partial" in ok["recommendation"]
    assert thin["fpr_bar_met"] is False
    assert "must not be cited as human-FPR evidence" in thin["recommendation"]
    assert "keep status partial" in thin["recommendation"]
