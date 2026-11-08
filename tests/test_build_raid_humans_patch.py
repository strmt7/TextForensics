"""Tests for scripts/build_raid_humans_patch.py (Phase 5 RAID humans-100).

Only the text-composition helper is tested here (pure function over
measured numbers): the full patch build needs the real 6000-row cache
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
        "build_raid_humans_patch", SCRIPTS_DIR / "build_raid_humans_patch.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["build_raid_humans_patch"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def patch():
    return _load_patch_module()


def _measurements(*, n_human=184, n_ai=5816, auroc=0.5937, fpr=0.0, fpr_upper=0.0):
    return {
        "n_human": n_human,
        "n_ai": n_ai,
        "auroc": MetricEstimate(
            value=auroc,
            n=n_human + n_ai,
            ci_lower=0.5468,
            ci_upper=0.6442,
            method="bootstrap, 1000 resamples, seed 20261108",
        ),
        "fpr_native": MetricEstimate(
            value=fpr,
            n=n_human,
            ci_lower=0.0,
            ci_upper=fpr_upper,
            method="bootstrap, 1000 resamples, seed 20261108",
        ),
    }


class TestComposeRaidTexts:
    def test_zero_fpr_goes_to_limitations_not_failure_modes(self, patch):
        texts = patch.compose_raid_texts(_measurements(), ["abstracts", "books"])
        joined_modes = " ".join(texts["known_failure_modes"])
        assert "AUROC 0.5937" in joined_modes
        assert "only 184 human rows" not in joined_modes
        assert "native false-positive rate is 0.0" not in joined_modes
        joined_limits = " ".join(texts["limitations_extra"])
        assert "abstracts, books" in joined_limits
        assert "evr-20261106-raid-builtin-heuristic" in joined_limits
        assert (
            "native false-positive rate is 0.0 on this sample (0 of 184 human rows" in joined_limits
        )
        assert "reviewed assessment" in texts["appeal_note"]
        assert "100 humans" not in texts["appeal_note"]

    def test_nonzero_fpr_is_a_failure_mode_with_its_count(self, patch):
        texts = patch.compose_raid_texts(_measurements(fpr=0.0109, fpr_upper=0.0326), ["news"])
        joined_modes = " ".join(texts["known_failure_modes"])
        assert "native false-positive rate is 0.0109 (2 of 184 human rows" in joined_modes
        assert "95% CI [0.0000, 0.0326]" in joined_modes
        joined_limits = " ".join(texts["limitations_extra"])
        assert "native false-positive rate is 0.0" not in joined_limits

    def test_thin_human_slice_keeps_the_old_failure_mode(self, patch):
        texts = patch.compose_raid_texts(_measurements(n_human=92, n_ai=2908), ["news"])
        joined_modes = " ".join(texts["known_failure_modes"])
        assert "only 92 human rows" in joined_modes
