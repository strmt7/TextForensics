"""W9 Worker D: absent-optional-dependency failure contracts.

In a core-only install (no api/mcp/fuzzing/diagnostics/ollama extras),
every optional surface must fail with a CLEAR, actionable install hint —
never a bare ``ModuleNotFoundError`` traceback. The canonical venv HAS all
extras, so each test blocks the optional import with a ``None`` entry in
``sys.modules`` (the established pattern from
tests/test_audit_w5_worker_f_mcp_server.py).

Isolation rule (W9-D full-suite finding): tests that need a module
imported WITHOUT its optional dependency run in a FRESH SUBPROCESS.
An earlier version reloaded the module in-process with
``importlib.reload``; reload redefines every class in the module, so
``isinstance`` checks in other test modules holding the pre-reload
class objects failed — 39 poisoned tests in the full suite
(``test_w1_ollama_transport``, ``test_diagnostics``, …). The subprocess
also reproduces the real core-only venv most faithfully.

Reproduced 2026-11-16 in a fresh core-only venv
(``textforensics==0.2.0``, no extras, ``pip list`` = pip +
textforensics only):

- ``textforensics serve`` / ``web`` — PASS (clean ``error: Install ...``).
- ``textforensics-api`` — RuntimeError traceback (hint present, not clean).
- ``textforensics-web`` — bare ``ModuleNotFoundError: No module named
  'fastapi'`` (no hint).
- ``textforensics.diagnostics`` — bare ``ModuleNotFoundError: No module
  named 'psutil'`` at import.
- ``textforensics.ollama`` — bare ``ModuleNotFoundError: No module named
  'aiohttp'`` at import.
- ``scripts/run_fuzz.py --method direct`` — exits 1 but reports only
  "atheris child exited with status 1 without a crash artifact" (no
  install hint; the child's ModuleNotFoundError is swallowed).
"""

from __future__ import annotations

import importlib
import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).parent.parent
SRC_DIR = REPO_ROOT / "src"
SCRIPTS_DIR = REPO_ROOT / "scripts"


def _run_with_blocked_import(blocked: str, code: str) -> subprocess.CompletedProcess:
    """Run ``code`` in a fresh interpreter with ``blocked`` unimportable.

    PYTHONPATH puts this worktree's ``src`` first so the subprocess
    tests this branch, not any installed copy. The test code must print
    ``TF-FILE:`` via the ``import textforensics`` preamble, which the
    helper asserts.
    """
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    script = (
        "import sys\n"
        "import textforensics\n"
        "print('TF-FILE:', textforensics.__file__)\n"
        f"sys.modules[{blocked!r}] = None\n" + code
    )
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    assert f"TF-FILE: {SRC_DIR}" in proc.stdout, (
        "subprocess imported textforensics from elsewhere, not this worktree:\n"
        f"stdout={proc.stdout!r}\nstderr={proc.stderr!r}"
    )
    return proc


def _load_run_fuzz():
    spec = importlib.util.spec_from_file_location("run_fuzz_w9d", SCRIPTS_DIR / "run_fuzz.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["run_fuzz_w9d"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def run_fuzz():
    return _load_run_fuzz()


@pytest.fixture()
def isolated_run_fuzz(run_fuzz, tmp_path, monkeypatch):
    """Point artifact/corpus dirs at tmp so no repo state is touched."""
    monkeypatch.setattr(run_fuzz, "ARTIFACTS_DIR", tmp_path / "artifacts")
    monkeypatch.setattr(run_fuzz, "CORPUS_DIR", tmp_path / "corpus")
    return run_fuzz


class _FakeProc:
    def __init__(self, returncode=1, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# ---------------------------------------------------------------------------
# API server entry point (textforensics-api)
# ---------------------------------------------------------------------------


def test_api_main_converts_install_hint_to_system_exit_without_uvicorn(monkeypatch, capsys):
    """textforensics-api must exit with the install hint, not a traceback.

    A-fix contract (supersedes the W9-D print + exit 1): api.main()
    converts the install-hint RuntimeError to SystemExit carrying the
    hint text; any other RuntimeError still propagates.
    """
    from textforensics import api

    monkeypatch.setitem(sys.modules, "uvicorn", None)
    with pytest.raises(SystemExit) as excinfo:
        api.main()
    assert str(excinfo.value.code) == "Install API support with: pip install 'textforensics[api]'"
    assert capsys.readouterr().err == ""


def test_cli_serve_prints_install_hint_without_uvicorn(monkeypatch, capsys):
    """`textforensics serve` stays clean (CLI catches the RuntimeError)."""
    from textforensics.cli import main

    monkeypatch.setitem(sys.modules, "uvicorn", None)
    monkeypatch.setattr(sys, "argv", ["textforensics", "serve"])
    assert main() == 3
    assert (
        "error: Install API support with: pip install 'textforensics[api]'"
        in capsys.readouterr().err
    )


# ---------------------------------------------------------------------------
# Web UI (textforensics-web / `textforensics web`)
# ---------------------------------------------------------------------------


def test_web_ui_import_succeeds_without_fastapi_and_create_web_app_raises_hint():
    """web_ui.main stays importable without fastapi; create_web_app refuses.

    A-fix contract (supersedes the W9-D import-time RuntimeError): the
    import guard leaves the fastapi names as None sentinels so the module
    stays importable; create_web_app() raises the install hint instead.
    """
    proc = _run_with_blocked_import(
        "fastapi",
        "import textforensics.web_ui.main as m\n"
        "print('sentinels:', m.FastAPI is None, m.BaseModel is None)\n"
        "try:\n"
        "    m.create_web_app()\n"
        "except RuntimeError as exc:\n"
        "    print('RUNTIMEERROR:', exc)\n"
        "else:\n"
        "    print('NO-ERROR')\n",
    )
    assert proc.returncode == 0, proc.stderr
    assert "sentinels: True True" in proc.stdout
    assert (
        "RUNTIMEERROR: Install web UI support with: pip install 'textforensics[api]'"
        in proc.stdout
    )


def test_web_ui_main_converts_install_hint_to_system_exit_without_uvicorn(monkeypatch, capsys):
    """textforensics-web must exit with the install hint, not a traceback.

    A-fix contract (supersedes the W9-D print + exit 1): web main()
    converts the install-hint RuntimeError to SystemExit carrying the
    hint text; any other RuntimeError still propagates.
    """
    import textforensics.web_ui.main as web_main

    monkeypatch.setitem(sys.modules, "uvicorn", None)
    with pytest.raises(SystemExit) as excinfo:
        web_main.main()
    assert str(excinfo.value.code) == "Install web UI support with: pip install 'textforensics[api]'"
    assert capsys.readouterr().err == ""


# ---------------------------------------------------------------------------
# Diagnostics ([diagnostics] extra: psutil)
# ---------------------------------------------------------------------------


def test_diagnostics_import_succeeds_without_psutil():
    """diagnostics must stay importable without psutil (lazy guard)."""
    proc = _run_with_blocked_import(
        "psutil",
        "import textforensics.diagnostics as d\nprint('psutil-is-none:', d.psutil is None)\n",
    )
    assert proc.returncode == 0, proc.stderr
    assert "psutil-is-none: True" in proc.stdout


def test_diagnostics_engine_fails_with_install_hint_without_psutil():
    """Creating the diagnostics engine without psutil names the extra."""
    proc = _run_with_blocked_import(
        "psutil",
        "from textforensics.diagnostics import create_diagnostics_engine\n"
        "try:\n"
        "    create_diagnostics_engine()\n"
        "except RuntimeError as exc:\n"
        "    print('RUNTIMEERROR:', exc)\n"
        "else:\n"
        "    print('NO-ERROR')\n",
    )
    assert proc.returncode == 0, proc.stderr
    assert (
        "RUNTIMEERROR: psutil is required for diagnostics. "
        "Install with: pip install 'textforensics[diagnostics]'" in proc.stdout
    )


# ---------------------------------------------------------------------------
# Ollama adapter ([ollama] extra: aiohttp)
# ---------------------------------------------------------------------------


def test_ollama_import_succeeds_without_aiohttp():
    """ollama must stay importable without aiohttp (lazy guard)."""
    proc = _run_with_blocked_import(
        "aiohttp",
        "import textforensics.ollama as m\nprint('aiohttp-is-none:', m.aiohttp is None)\n",
    )
    assert proc.returncode == 0, proc.stderr
    assert "aiohttp-is-none: True" in proc.stdout


def test_ollama_session_fails_with_install_hint_without_aiohttp():
    """First Ollama use without aiohttp must name the [ollama] extra."""
    proc = _run_with_blocked_import(
        "aiohttp",
        "import asyncio\n"
        "from textforensics.ollama import OllamaClient, OllamaConfig\n"
        "try:\n"
        "    asyncio.run(OllamaClient(OllamaConfig()).__aenter__())\n"
        "except RuntimeError as exc:\n"
        "    print('RUNTIMEERROR:', exc)\n"
        "else:\n"
        "    print('NO-ERROR')\n",
    )
    assert proc.returncode == 0, proc.stderr
    assert (
        "RUNTIMEERROR: aiohttp is required for the Ollama adapter. "
        "Install with: pip install 'textforensics[ollama]'" in proc.stdout
    )


# ---------------------------------------------------------------------------
# Fuzz runner (scripts/run_fuzz.py, [fuzzing] extra: atheris)
# ---------------------------------------------------------------------------


def test_run_fuzz_direct_target_names_fuzzing_extra_without_atheris(isolated_run_fuzz, monkeypatch):
    """Direct fuzzing without atheris must name the [fuzzing] extra."""
    monkeypatch.setitem(sys.modules, "atheris", None)
    target = isolated_run_fuzz.FUZZ_TARGETS["text_parsing"]
    fake = _FakeProc(
        returncode=1,
        stdout="",
        stderr="ModuleNotFoundError: No module named 'atheris'\n",
    )
    with mock.patch.object(isolated_run_fuzz.subprocess, "run", return_value=fake) as run_mock:
        result = isolated_run_fuzz.run_atheris_target(target, 60, False)
    run_mock.assert_not_called()
    assert result["error"] is not None
    assert "textforensics[fuzzing]" in result["error"]


def test_run_fuzz_main_direct_fails_fast_with_hint_without_atheris(
    isolated_run_fuzz, monkeypatch, capsys
):
    """run_fuzz.py --method direct without atheris fails fast with a hint."""
    monkeypatch.setitem(sys.modules, "atheris", None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_fuzz.py",
            "--method",
            "direct",
            "--target",
            "text_parsing",
            "--duration",
            "1",
            "--artifacts-dir",
            str(isolated_run_fuzz.ARTIFACTS_DIR),
        ],
    )
    assert isolated_run_fuzz.main() == 1
    assert "textforensics[fuzzing]" in capsys.readouterr().out
