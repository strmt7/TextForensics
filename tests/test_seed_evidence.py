"""Tests for scripts/seed_evidence.py helpers (U7 evidence seeding)."""

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"


def _load_seed_module():
    spec = importlib.util.spec_from_file_location("seed_evidence", SCRIPTS_DIR / "seed_evidence.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["seed_evidence"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def seed():
    return _load_seed_module()


def test_parse_pytest_summary_all_pass(seed):
    out = "some output\n2336 passed in 5.00s\n"
    result = seed._parse_pytest_summary(out)
    assert result["tests_passed"] == 2336
    assert result["tests_failed"] == 0
    assert result["tests_skipped"] == 0
    assert result["duration_s"] == 5.00


def test_parse_pytest_summary_failures_first(seed):
    # Pytest lists failures before passes.
    out = "2 failed, 2335 passed in 128.18s\n"
    result = seed._parse_pytest_summary(out)
    assert result["tests_passed"] == 2335
    assert result["tests_failed"] == 2


def test_parse_pytest_summary_long_run_suffix(seed):
    # Runs over 60s get a "(H:MM:SS)" suffix after the duration.
    out = (
        "FAILED tests/test_diagnostics.py::TestDiagnosticsEngine::test_memory_check\n"
        "1 failed, 2336 passed in 128.46s (0:02:08)\n"
    )
    result = seed._parse_pytest_summary(out)
    assert result["tests_passed"] == 2336
    assert result["tests_failed"] == 1
    assert result["duration_s"] == 128.46
    assert result["failed_tests"] == [
        "tests/test_diagnostics.py::TestDiagnosticsEngine::test_memory_check"
    ]


def test_parse_pytest_summary_with_skips(seed):
    out = "2224 passed, 1 failed, 112 skipped in 103.02s (0:01:43)\n"
    result = seed._parse_pytest_summary(out)
    assert result["tests_passed"] == 2224
    assert result["tests_failed"] == 1
    assert result["tests_skipped"] == 112
