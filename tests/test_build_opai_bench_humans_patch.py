"""Tests for scripts/build_opai_bench_humans_patch.py (Phase 5 OpAI-Bench humans-100).

Only the text-composition helper is tested here (pure function over
measured numbers): the full patch build needs the real 2000-row cache
and run artifact and is exercised by the run itself, not by unit tests.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from textforensics.evidence import MetricEstimate

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"


def _load_patch_module():
    spec = importlib.util.spec_from_file_location(
        "build_opai_bench_humans_patch", SCRIPTS_DIR / "build_opai_bench_humans_patch.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["build_opai_bench_humans_patch"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def patch():
    return _load_patch_module()


def _measurements(
    *,
    n_human=224,
    n_ai=222,
    auroc=0.3961,
    fpr=0.0,
    fpr_upper=0.0,
    tpr_01=0.0,
    tpr_05=0.0,
):
    return {
        "n_human": n_human,
        "n_ai": n_ai,
        "auroc": MetricEstimate(
            value=auroc,
            n=n_human + n_ai,
            ci_lower=max(0.0, auroc - 0.05),
            ci_upper=min(1.0, auroc + 0.05),
            method="bootstrap, 1000 resamples, seed 20261110",
        ),
        "fpr_native": MetricEstimate(
            value=fpr,
            n=n_human,
            ci_lower=0.0,
            ci_upper=max(fpr, fpr_upper),
            method="bootstrap, 1000 resamples, seed 20261110",
        ),
        "tpr_at_fpr_0_01": MetricEstimate(
            value=tpr_01,
            n=n_human + n_ai,
            ci_lower=0.0,
            ci_upper=max(tpr_01, 0.01),
            method="bootstrap, 1000 resamples, seed 20261110",
        ),
        "tpr_at_fpr_0_05": MetricEstimate(
            value=tpr_05,
            n=n_human + n_ai,
            ci_lower=0.0,
            ci_upper=max(tpr_05, 0.01),
            method="bootstrap, 1000 resamples, seed 20261110",
        ),
    }


class TestComposeOpaiTexts:
    def test_zero_fpr_goes_to_limitations_with_wilson_not_failure_modes(self, patch):
        texts = patch.compose_opai_texts(
            _measurements(), ["abstracts", "news"], n_partial=1554, wilson_lo=0.0, wilson_hi=0.0169
        )
        joined_modes = " ".join(texts["known_failure_modes"])
        assert "AUROC 0.3961" in joined_modes
        assert "inverts the baseline" in joined_modes
        assert "only 224 human rows" not in joined_modes
        assert "native false-positive rate is 0.0109" not in joined_modes
        assert "both TPR@1% and TPR@5% FPR are 0.0 on this slice" in joined_modes
        joined_limits = " ".join(texts["limitations_extra"])
        assert "1554 partial (mixed-origin) rows" in joined_limits
        assert "evr-20261106-opai-bench-builtin-heuristic" in joined_limits
        assert (
            "native false-positive rate is 0.0 on this sample (0 of 224 human rows" in joined_limits
        )
        assert "Wilson 95% CI [0.0000, 0.0169]" in joined_limits
        assert "reviewed assessment" in texts["appeal_note"]

    def test_nonzero_fpr_is_a_failure_mode_with_its_count_and_wilson(self, patch):
        texts = patch.compose_opai_texts(
            _measurements(fpr=0.0089, fpr_upper=0.0267),
            ["news"],
            n_partial=1554,
            wilson_lo=0.0016,
            wilson_hi=0.0319,
        )
        joined_modes = " ".join(texts["known_failure_modes"])
        assert "native false-positive rate is 0.0089 (2 of 224 human rows" in joined_modes
        assert "Wilson 95% CI [0.0016, 0.0319]" in joined_modes
        joined_limits = " ".join(texts["limitations_extra"])
        assert "native false-positive rate is 0.0" not in joined_limits

    def test_thin_human_slice_keeps_the_old_failure_mode(self, patch):
        texts = patch.compose_opai_texts(
            _measurements(n_human=56, n_ai=55),
            ["news"],
            n_partial=389,
            wilson_lo=0.0,
            wilson_hi=0.0642,
        )
        joined_modes = " ".join(texts["known_failure_modes"])
        assert "only 56 human rows" in joined_modes

    def test_auroc_above_chance_drops_the_inversion_claim(self, patch):
        texts = patch.compose_opai_texts(
            _measurements(auroc=0.55),
            ["news"],
            n_partial=1554,
            wilson_lo=0.0,
            wilson_hi=0.0169,
        )
        joined_modes = " ".join(texts["known_failure_modes"])
        assert "inverts the baseline" not in joined_modes
        assert "AUROC 0.5500" in joined_modes

    def test_nonzero_tpr_drops_the_zero_tpr_claim(self, patch):
        texts = patch.compose_opai_texts(
            _measurements(tpr_01=0.02, tpr_05=0.05),
            ["news"],
            n_partial=1554,
            wilson_lo=0.0,
            wilson_hi=0.0169,
        )
        joined_modes = " ".join(texts["known_failure_modes"])
        assert "both TPR@1% and TPR@5% FPR are 0.0" not in joined_modes

    def test_excluded_u1_duplicates_are_stated_in_limitations(self, patch):
        texts = patch.compose_opai_texts(
            _measurements(n_human=218, n_ai=223),
            ["abstracts", "news"],
            n_partial=1555,
            wilson_lo=0.0,
            wilson_hi=0.0169,
            n_excluded=4,
        )
        joined_limits = " ".join(texts["limitations_extra"])
        assert (
            "n=2000 rows fetched, 4 excluded as U1 duplicates by content hash, n=1996 kept"
            in joined_limits
        )

    def test_no_exclusion_keeps_the_plain_sampling_note(self, patch):
        texts = patch.compose_opai_texts(
            _measurements(),
            ["news"],
            n_partial=1554,
            wilson_lo=0.0,
            wilson_hi=0.0169,
        )
        joined_limits = " ".join(texts["limitations_extra"])
        assert "n=2000 rows fetched, +49 rows" in joined_limits
        assert "excluded as U1 duplicates" not in joined_limits
