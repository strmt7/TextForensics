"""RED regression tests for ENG-07(3): fuzz child exit status must not be silent.

A child atheris process that exits nonzero (e.g. exit 2: startup /
instrumentation failure) without producing a crash artifact must be
recorded as an error and must make the run fail — never "zero
crashes/hangs, no error" with exit 0.
"""

import importlib.util
import sys
from pathlib import Path
from unittest import mock

import pytest

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"


def _load_run_fuzz():
    spec = importlib.util.spec_from_file_location("run_fuzz", SCRIPTS_DIR / "run_fuzz.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["run_fuzz"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def run_fuzz():
    return _load_run_fuzz()


class _FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@pytest.fixture()
def isolated_run_fuzz(run_fuzz, tmp_path, monkeypatch):
    """Point artifact/corpus dirs at tmp so no repo state is touched."""
    monkeypatch.setattr(run_fuzz, "ARTIFACTS_DIR", tmp_path / "artifacts")
    monkeypatch.setattr(run_fuzz, "CORPUS_DIR", tmp_path / "corpus")
    return run_fuzz


def test_child_exit_2_without_crash_artifact_is_recorded_as_error(isolated_run_fuzz, tmp_path):
    """ENG-07(3): controlled child-exit-2 probe — error must be recorded."""
    target = isolated_run_fuzz.FUZZ_TARGETS["text_parsing"]
    fake = _FakeProc(returncode=2, stdout="fake atheris startup failure\n")
    with mock.patch.object(isolated_run_fuzz.subprocess, "run", return_value=fake):
        result = isolated_run_fuzz.run_atheris_target(target, 1, False)
    assert result["crashes"] == 0
    assert result["error"] is not None, "exit 2 with no crash artifact left error=None"
    assert "2" in str(result["error"])


def test_child_exit_2_without_crash_artifact_fails_the_run(isolated_run_fuzz, tmp_path):
    """ENG-07(3): the run's exit code must be nonzero when a child errors."""
    target = isolated_run_fuzz.FUZZ_TARGETS["text_parsing"]
    error_result = {
        "target": target.name,
        "crashes": 0,
        "hangs": 0,
        "timed_out": False,
        "error": "atheris child exited with status 2 without a crash artifact",
        "elapsed": 0.1,
    }
    with (
        mock.patch.object(isolated_run_fuzz, "generate_corpus", return_value=None),
        mock.patch.object(isolated_run_fuzz, "run_atheris_target", return_value=error_result),
        mock.patch.object(
            sys,
            "argv",
            ["run_fuzz.py", "--method", "direct", "--target", "text_parsing", "--duration", "0"],
        ),
    ):
        assert isolated_run_fuzz.main() != 0


def test_child_exit_0_without_crash_is_clean(isolated_run_fuzz, tmp_path):
    """Clean control: exit 0 and no crash artifact is not an error."""
    target = isolated_run_fuzz.FUZZ_TARGETS["text_parsing"]
    fake = _FakeProc(returncode=0, stdout="fake atheris ok\n")
    with mock.patch.object(isolated_run_fuzz.subprocess, "run", return_value=fake):
        result = isolated_run_fuzz.run_atheris_target(target, 1, False)
    assert result["error"] is None
    assert result["crashes"] == 0


def test_child_exit_1_with_crash_artifact_records_error(isolated_run_fuzz, tmp_path):
    """A crashing child (nonzero + crash artifact) is an error, not info."""
    target = isolated_run_fuzz.FUZZ_TARGETS["text_parsing"]
    crashes_dir = tmp_path / "artifacts" / target.name / "crashes"

    def _run_with_crash(*args, **kwargs):
        # Simulate the child writing a crash artifact before exiting 1.
        crashes_dir.mkdir(parents=True, exist_ok=True)
        (crashes_dir / "crash-abc123").write_bytes(b"fake crash input")
        return _FakeProc(returncode=1, stdout="fake atheris crash\n")

    with mock.patch.object(isolated_run_fuzz.subprocess, "run", side_effect=_run_with_crash):
        result = isolated_run_fuzz.run_atheris_target(target, 1, False)
    assert result["crashes"] == 1
    assert result["error"] is not None, "nonzero child exit must be recorded as an error"
    assert "1" in str(result["error"])


def test_child_timeout_is_recorded_as_error(isolated_run_fuzz, tmp_path):
    """A child that never exits (timeout) is a failed execution, not clean."""
    import subprocess

    target = isolated_run_fuzz.FUZZ_TARGETS["text_parsing"]
    with mock.patch.object(
        isolated_run_fuzz.subprocess,
        "run",
        side_effect=subprocess.TimeoutExpired(cmd=["fake"], timeout=61),
    ):
        result = isolated_run_fuzz.run_atheris_target(target, 1, False)
    assert result["timed_out"] is True
    assert result["error"] is not None, "timed-out child left error=None"
