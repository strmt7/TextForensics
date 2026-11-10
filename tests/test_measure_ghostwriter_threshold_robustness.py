"""Tests for scripts/measure_ghostwriter_threshold_robustness.py.

Pure functions only: no network, no dataset cache, no detector run. The
live re-run itself is covered by the script's own run, whose numbers are
recorded in docs/evidence/EV-20261110-ghostwriter-threshold-robustness.md.
"""

import importlib.util
import json
import math
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"


def _load_robustness_module():
    spec = importlib.util.spec_from_file_location(
        "measure_ghostwriter_threshold_robustness",
        SCRIPTS_DIR / "measure_ghostwriter_threshold_robustness.py",
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["measure_ghostwriter_threshold_robustness"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def robustness():
    return _load_robustness_module()


def _reference_wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Independent Wilson implementation, written from the formula."""
    p = k / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def test_quantile_linear_interpolation(robustness):
    values = [0.1, 0.2, 0.3, 0.4]
    assert robustness.quantile(values, 0.0) == pytest.approx(0.1)
    assert robustness.quantile(values, 1.0) == pytest.approx(0.4)
    assert robustness.quantile(values, 0.5) == pytest.approx(0.25)
    assert robustness.quantile(values, 0.25) == pytest.approx(0.175)
    assert robustness.quantile([0.674], 0.99) == pytest.approx(0.674)


def test_quantile_rejects_empty_and_bad_p(robustness):
    with pytest.raises(ValueError):
        robustness.quantile([], 0.5)
    with pytest.raises(ValueError):
        robustness.quantile([0.1, 0.2], -0.1)
    with pytest.raises(ValueError):
        robustness.quantile([0.1, 0.2], 1.1)


def test_count_within_below_threshold(robustness):
    # Mirrors the measured GhostWriter shape: 0.6740 is the only row
    # within 0.01 below 0.68, 0.66 joins within 0.02, 0.65 within 0.05;
    # a row exactly at the threshold never counts (strictly below).
    scores = [0.674, 0.66, 0.65, 0.60, 0.68]
    assert robustness.count_within_below(scores, 0.68, 0.01) == 1
    assert robustness.count_within_below(scores, 0.68, 0.02) == 2
    assert robustness.count_within_below(scores, 0.68, 0.05) == 3
    assert robustness.count_within_below(scores, 0.68, 0.0) == 0
    with pytest.raises(ValueError):
        robustness.count_within_below(scores, 0.68, -0.01)


def test_fpr_at_threshold_counts_verdict_equivalent_flips(robustness):
    scores = [0.674, 0.66, 0.65]
    reliabilities = [0.77, 0.82, 0.50]
    at_066 = robustness.fpr_at_threshold(scores, reliabilities, 0.66)
    assert (at_066["k"], at_066["n"]) == (2, 3)
    assert at_066["rate"] == pytest.approx(2 / 3)
    at_068 = robustness.fpr_at_threshold(scores, reliabilities, 0.68)
    assert (at_068["k"], at_068["n"]) == (0, 3)
    assert at_068["rate"] == 0.0
    at_070 = robustness.fpr_at_threshold(scores, reliabilities, 0.70)
    assert at_070["k"] == 0


def test_fpr_at_threshold_applies_reliability_floor(robustness):
    # A row above the score threshold with reliability below the 0.28
    # floor is not a verdict-equivalent false positive: the native
    # verdict would abstain, not call it ai_like.
    result = robustness.fpr_at_threshold([0.69], [0.20], 0.68)
    assert result["k"] == 0
    result = robustness.fpr_at_threshold([0.69], [0.28], 0.68)
    assert result["k"] == 1


def test_fpr_at_threshold_wilson_matches_reference(robustness):
    for k, n in [(0, 137), (1, 137), (2, 137), (0, 56)]:
        scores = [0.99] * k + [0.10] * (n - k)
        reliabilities = [0.90] * n
        got = robustness.fpr_at_threshold(scores, reliabilities, 0.68)
        lower, upper = _reference_wilson(k, n)
        assert got["k"] == k and got["n"] == n
        assert got["ci_lower"] == pytest.approx(lower, abs=1e-12)
        assert got["ci_upper"] == pytest.approx(upper, abs=1e-12)
    # The measured GhostWriter sensitivity: 1/137 at 0.66, 0/137 at 0.68.
    assert robustness.fpr_at_threshold([0.674] + [0.10] * 136, [0.9] * 137, 0.66)[
        "ci_upper"
    ] == pytest.approx(0.0402, abs=0.0001)
    assert robustness.fpr_at_threshold([0.674] + [0.10] * 136, [0.9] * 137, 0.68)[
        "ci_upper"
    ] == pytest.approx(0.0273, abs=0.0001)


def test_fpr_at_threshold_rejects_mismatched_lengths(robustness):
    with pytest.raises(ValueError):
        robustness.fpr_at_threshold([0.5, 0.6], [0.9], 0.68)


def _fixture_rows():
    return [
        {
            "analyzers": {
                "structural_uniformity": 0.86,
                "formulaic_language": 0.25,
                "lexical_profile": 0.98,
            },
            "features": {
                "sentence_length_cv": 0.33,
                "paragraph_length_cv": 0.0,
                "repeated_sentence_start_ratio": 0.5,
                "transition_density": 0.0,
                "cliche_density": 0.0,
                "repeated_trigram_ratio": 0.15,
                "type_token_ratio": 0.30,
                "hapax_ratio": 0.43,
                "punctuation_variety": 1.0,
            },
        },
        {
            "analyzers": {
                "structural_uniformity": 0.72,
                "formulaic_language": 0.35,
                "lexical_profile": 0.96,
            },
            "features": {
                "sentence_length_cv": 0.31,
                "paragraph_length_cv": 0.0,
                "repeated_sentence_start_ratio": 0.12,
                "transition_density": 0.80,
                "cliche_density": 0.0,
                "repeated_trigram_ratio": 0.10,
                "type_token_ratio": 0.30,
                "hapax_ratio": 0.46,
                "punctuation_variety": 2.0,
            },
        },
    ]


def test_analyzer_mean_scores(robustness):
    means = robustness.analyzer_mean_scores(_fixture_rows())
    assert means["structural_uniformity"] == pytest.approx(0.79)
    assert means["formulaic_language"] == pytest.approx(0.30)
    assert means["lexical_profile"] == pytest.approx(0.97)
    with pytest.raises(ValueError):
        robustness.analyzer_mean_scores([])


def test_feature_means(robustness):
    means = robustness.feature_means(_fixture_rows())
    assert means["type_token_ratio"] == pytest.approx(0.30)
    assert means["hapax_ratio"] == pytest.approx(0.445)
    assert means["punctuation_variety"] == pytest.approx(1.5)
    assert means["paragraph_length_cv"] == pytest.approx(0.0)
    with pytest.raises(ValueError):
        robustness.feature_means([])


def test_module_constants_match_registry(robustness):
    # The script must measure the record and cache the registry actually
    # describes — pin the constants to the registry instead of trusting
    # them. No detector run: this only reads the registry file.
    assert robustness.NATIVE_THRESHOLD == 0.68
    assert robustness.RELIABILITY_FLOOR == 0.28
    registry = json.loads(
        (REPO_ROOT / "docs" / "validation" / "registry.json").read_text(encoding="utf-8")
    )
    record = next(r for r in registry["records"] if r["record_id"] == robustness.RECORD_ID)
    assert record["data"]["file_sha256"] == robustness.EXPECTED_CACHE_SHA256
    assert record["metrics"][0]["n_human"] == 137
    assert record["metrics"][0]["n_ai"] == 210


def test_evidence_note_states_headline_numbers_and_non_conclusion():
    note = (
        REPO_ROOT / "docs" / "evidence" / "EV-20261110-ghostwriter-threshold-robustness.md"
    ).read_text(encoding="utf-8")
    # Headline numbers from the 2026-11-10 re-run.
    assert "0.6740" in note
    assert "1/137" in note
    assert "0/137" in note
    # The non-conclusion: threshold unchanged, fragile downward by one row.
    assert "UNCHANGED" in note
    assert "does NOT survive a" in note
    assert "AGENTS.md rule 17" in note
