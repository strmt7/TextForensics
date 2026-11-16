"""W9 Worker D: absent-optional-dependency failure contracts.

In a core-only install (no api/mcp/fuzzing/diagnostics/ollama extras),
every optional surface must fail with a CLEAR, actionable install hint —
never a bare ``ModuleNotFoundError`` traceback. The canonical venv HAS all
extras, so each test blocks the optional import with a ``None`` entry in
``sys.modules`` (the established pattern from
tests/test_audit_w5_worker_f_mcp_server.py) and reloads the module under
test.

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

import asyncio
import importlib
import sys
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

import pytest

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"


@contextmanager
def _blocked_import(module_name: str, reload_name: str):
    """Block ``module_name`` and reload ``reload_name`` without it.

    Restores the real import and reloads the module back afterwards, so
    other tests keep seeing the installed dependency.
    """
    target = sys.modules.get(reload_name)
    old_blocked = sys.modules.get(module_name, ...)
    sys.modules[module_name] = None
    try:
        importlib.reload(target)
        yield target
    finally:
        if old_blocked is ...:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = old_blocked
        importlib.reload(target)


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


def test_api_main_prints_install_hint_without_uvicorn(monkeypatch, capsys):
    """textforensics-api must print the install hint, not a traceback."""
    from textforensics import api

    monkeypatch.setitem(sys.modules, "uvicorn", None)
    with pytest.raises(SystemExit) as excinfo:
        api.main()
    assert excinfo.value.code == 1
    assert "error: Install API support with: pip install 'textforensics[api]'" in capsys.readouterr().err


def test_cli_serve_prints_install_hint_without_uvicorn(monkeypatch, capsys):
    """`textforensics serve` stays clean (CLI catches the RuntimeError)."""
    from textforensics.cli import main

    monkeypatch.setitem(sys.modules, "uvicorn", None)
    monkeypatch.setattr(sys, "argv", ["textforensics", "serve"])
    assert main() == 3
    assert "error: Install API support with: pip install 'textforensics[api]'" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Web UI (textforensics-web / `textforensics web`)
# ---------------------------------------------------------------------------


def test_web_ui_import_raises_actionable_error_without_fastapi():
    """Importing web_ui.main without fastapi must name the [api] extra."""
    import textforensics.web_ui.main as web_main

    # Block + reload must raise RuntimeError with the hint (not a bare
    # ModuleNotFoundError); reload back afterwards.
    sys.modules["fastapi"] = None
    try:
        with pytest.raises(RuntimeError, match=r"Install web UI support with: pip install 'textforensics\[api\]'"):
            importlib.reload(web_main)
    finally:
        sys.modules.pop("fastapi", None)
        importlib.reload(web_main)


def test_web_ui_main_prints_install_hint_without_uvicorn(monkeypatch, capsys):
    """textforensics-web must print the install hint, not a traceback."""
    import textforensics.web_ui.main as web_main

    monkeypatch.setitem(sys.modules, "uvicorn", None)
    with pytest.raises(SystemExit) as excinfo:
        web_main.main()
    assert excinfo.value.code == 1
    assert "error: Install web UI support with: pip install 'textforensics[api]'" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Diagnostics ([diagnostics] extra: psutil)
# ---------------------------------------------------------------------------


def test_diagnostics_import_succeeds_without_psutil():
    """diagnostics must stay importable without psutil (lazy guard)."""
    import textforensics.diagnostics as diag

    with _blocked_import("psutil", "textforensics.diagnostics"):
        assert diag.psutil is None


def test_diagnostics_engine_fails_with_install_hint_without_psutil():
    """Creating the diagnostics engine without psutil names the extra."""
    import textforensics.diagnostics as diag

    with _blocked_import("psutil", "textforensics.diagnostics"):
        with pytest.raises(
            RuntimeError, match=r"pip install 'textforensics\[diagnostics\]'"
        ):
            diag.create_diagnostics_engine()


# ---------------------------------------------------------------------------
# Ollama adapter ([ollama] extra: aiohttp)
# ---------------------------------------------------------------------------


def test_ollama_import_succeeds_without_aiohttp():
    """ollama must stay importable without aiohttp (lazy guard)."""
    import textforensics.ollama as ollama_mod

    with _blocked_import("aiohttp", "textforensics.ollama"):
        assert ollama_mod.aiohttp is None


def test_ollama_session_fails_with_install_hint_without_aiohttp():
    """First Ollama use without aiohttp must name the [ollama] extra."""
    import textforensics.ollama as ollama_mod

    with _blocked_import("aiohttp", "textforensics.ollama"):
        client = ollama_mod.OllamaClient(ollama_mod.OllamaConfig())
        with pytest.raises(
            RuntimeError, match=r"pip install 'textforensics\[ollama\]'"
        ):
            asyncio.run(client.__aenter__())


# ---------------------------------------------------------------------------
# Fuzz runner (scripts/run_fuzz.py, [fuzzing] extra: atheris)
# ---------------------------------------------------------------------------


def test_run_fuzz_direct_target_names_fuzzing_extra_without_atheris(
    isolated_run_fuzz, monkeypatch
):
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
