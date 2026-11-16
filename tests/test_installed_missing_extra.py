"""Missing-extra contract for console scripts (W9 F1) and web env bind (W9 F2).

Red-first history: on the W8 head (``audit-w7`` @ ``4374990``) the bare-core
install failed the missing-extra contract for two of the three console
scripts, as proven by W9 Worker A in fresh wheel + sdist venvs:

* ``textforensics-web`` died at import time with a raw
  ``ModuleNotFoundError: No module named 'fastapi'`` traceback and no
  install hint, because ``web_ui/main.py`` imported FastAPI at module top
  level (F1a).
* ``textforensics-api`` printed the clear install hint as its final line
  but preceded by a full chained traceback (F1b).
* ``textforensics-mcp`` already satisfied the contract: exit 1 with a
  single clean line on stderr (the control case below).
* ``textforensics-web`` also ignored ``TEXTFORENSICS_HOST`` /
  ``TEXTFORENSICS_PORT``: ``serve_web()`` built ``Settings.from_env()``
  and then discarded host/port for hard defaults (F2).

The contract these tests pin: with the optional extra absent, a console
script exits 1 with exactly one clean error line on stderr naming the
missing extra and how to install it -- no traceback, nothing on stdout.
With the extra installed, ``textforensics-web`` binds the host/port from
the environment.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).parent.parent

WEB_INSTALL_HINT = "Install web UI support with: pip install 'textforensics[api]'"
API_INSTALL_HINT = "Install API support with: pip install 'textforensics[api]'"
MCP_INSTALL_HINT = "Install MCP support with: pip install 'textforensics[mcp]'"

BUILD_TIMEOUT_SECONDS = 300
INSTALL_TIMEOUT_SECONDS = 600
SERVER_START_TIMEOUT_SECONDS = 90


def _clean_env() -> dict[str, str]:
    """Environment for the fresh venv that cannot see the checkout.

    The test process itself runs with the repo ``src`` on ``sys.path``
    (the repo's pytest convention). A subprocess would inherit
    ``PYTHONPATH`` and import ``textforensics`` from the checkout instead
    of the installed wheel, which would make these tests vacuous. Strip
    it (and any other checkout pointer) so the only ``textforensics``
    importable is the one installed in the fresh venv.
    """
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.pop("VIRTUAL_ENV", None)
    return env


def _run(
    cmd: list[str], *, env: dict[str, str] | None = None, **kwargs
) -> subprocess.CompletedProcess[str]:
    """Run a command, failing the test with its output on error."""
    result = subprocess.run(cmd, capture_output=True, text=True, env=env, **kwargs)
    if result.returncode != 0:
        raise AssertionError(
            f"command failed ({result.returncode}): {' '.join(cmd)}\n"
            f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
        )
    return result


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _http_get(base_url: str, path: str) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(base_url + path, timeout=30) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


@pytest.fixture(scope="module")
def wheel_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build the wheel from the current tree into a scratch directory."""
    outdir = tmp_path_factory.mktemp("missing-extra-wheel")
    # pip wheel (the same mechanism the Dockerfile uses), not
    # `python -m build`: the canonical venv carries an importable
    # `wheel` package without its dist-info metadata, and `build`
    # refuses to run when importlib.metadata cannot find it.
    _run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            ".",
            "--no-deps",
            "--no-build-isolation",
            "--disable-pip-version-check",
            "--quiet",
            "-w",
            str(outdir),
        ],
        cwd=str(REPO_ROOT),
        timeout=BUILD_TIMEOUT_SECONDS,
    )
    wheels = sorted(outdir.glob("textforensics-*.whl"))
    assert wheels, f"no wheel built in {outdir}"
    assert len(wheels) == 1, f"expected one wheel, got {wheels}"
    return wheels[0]


def _make_venv(
    workdir: Path, wheel_path: Path, *, extra: str | None
) -> tuple[Path, dict[str, str]]:
    """Create a fresh venv and install the wheel (bare, or with one extra)."""
    clean_env = _clean_env()
    venv_dir = workdir / "venv"
    _run(
        [sys.executable, "-m", "venv", str(venv_dir)],
        env=clean_env,
        timeout=BUILD_TIMEOUT_SECONDS,
    )
    venv_python = venv_dir / "bin" / "python"
    spec = str(wheel_path) if extra is None else f"{wheel_path}[{extra}]"
    _run(
        [
            str(venv_python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--quiet",
            spec,
        ],
        env=clean_env,
        timeout=INSTALL_TIMEOUT_SECONDS,
    )
    # Isolation proof: the only importable textforensics must be the
    # wheel installed in this venv, never the checkout.
    probe = _run(
        [
            str(venv_python),
            "-c",
            "import textforensics; print(textforensics.__file__)",
        ],
        env=clean_env,
        cwd=str(workdir),
        timeout=60,
    )
    imported_from = probe.stdout.strip()
    assert imported_from.startswith(str(venv_dir)), (
        f"fresh venv imports textforensics from outside the venv: {imported_from}"
    )
    return venv_dir, clean_env


@pytest.fixture(scope="module")
def bare_venv(
    wheel_path: Path, tmp_path_factory: pytest.TempPathFactory
) -> tuple[Path, dict[str, str]]:
    """Fresh venv with the bare core wheel: no optional extras."""
    workdir = tmp_path_factory.mktemp("missing-extra-bare-venv")
    venv_dir, clean_env = _make_venv(workdir, wheel_path, extra=None)
    # Contract precondition: fastapi must really be absent here.
    probe = subprocess.run(
        [str(venv_dir / "bin" / "python"), "-c", "import fastapi"],
        capture_output=True,
        text=True,
        env=clean_env,
        timeout=60,
    )
    assert probe.returncode != 0, "bare venv unexpectedly has fastapi installed"
    return venv_dir, clean_env


@pytest.fixture(scope="module")
def api_venv(
    wheel_path: Path, tmp_path_factory: pytest.TempPathFactory
) -> tuple[Path, dict[str, str]]:
    """Fresh venv with the wheel plus the ``[api]`` extra."""
    workdir = tmp_path_factory.mktemp("missing-extra-api-venv")
    return _make_venv(workdir, wheel_path, extra="api")


def _assert_clean_missing_extra_failure(
    result: subprocess.CompletedProcess[str], *, expected_line: str
) -> None:
    """The missing-extra contract: exit 1, one clean line, no traceback."""
    assert result.returncode == 1, (
        f"expected exit 1, got {result.returncode}\n"
        f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
    )
    assert result.stdout == "", f"expected empty stdout, got:\n{result.stdout}"
    assert "Traceback" not in result.stderr, (
        f"missing-extra failure must not print a traceback:\n{result.stderr}"
    )
    assert "ModuleNotFoundError" not in result.stderr, (
        f"missing-extra failure must not leak a raw ModuleNotFoundError:\n{result.stderr}"
    )
    lines = result.stderr.strip().splitlines()
    assert lines == [expected_line], (
        f"expected exactly one clean error line {expected_line!r}, got:\n{result.stderr}"
    )


class TestBareConsoleScripts:
    """W9 F1: bare-core console scripts fail with one clean line (no traceback)."""

    @pytest.mark.parametrize(
        ("script", "expected_line"),
        [
            ("textforensics-web", WEB_INSTALL_HINT),
            ("textforensics-api", API_INSTALL_HINT),
            ("textforensics-mcp", MCP_INSTALL_HINT),
        ],
    )
    def test_bare_console_script_exits_clean(
        self,
        bare_venv: tuple[Path, dict[str, str]],
        script: str,
        expected_line: str,
    ) -> None:
        venv_dir, clean_env = bare_venv
        result = subprocess.run(
            [str(venv_dir / "bin" / script)],
            capture_output=True,
            text=True,
            env=clean_env,
            cwd=str(venv_dir),
            timeout=120,
        )
        _assert_clean_missing_extra_failure(result, expected_line=expected_line)


class TestWebHonoursEnvBind:
    """W9 F2: the installed ``textforensics-web`` binds TEXTFORENSICS_PORT."""

    def test_web_binds_env_port(self, api_venv: tuple[Path, dict[str, str]]) -> None:
        venv_dir, clean_env = api_venv
        port = _free_port()
        env = dict(clean_env)
        env["TEXTFORENSICS_PORT"] = str(port)
        server = subprocess.Popen(
            [str(venv_dir / "bin" / "textforensics-web")],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
            cwd=str(venv_dir),
        )
        base_url = f"http://127.0.0.1:{port}"
        try:
            deadline = time.monotonic() + SERVER_START_TIMEOUT_SECONDS
            ready = False
            while time.monotonic() < deadline:
                if server.poll() is not None:
                    output = server.stdout.read() if server.stdout else ""
                    raise AssertionError(
                        "textforensics-web exited during startup "
                        f"(exit {server.returncode}):\n{output}"
                    )
                try:
                    status, _ = _http_get(base_url, "/healthz")
                except OSError:
                    time.sleep(0.5)
                    continue
                if status == 200:
                    ready = True
                    break
                time.sleep(0.5)
            assert ready, (
                "textforensics-web did not serve /healthz on the "
                f"TEXTFORENSICS_PORT={port} within {SERVER_START_TIMEOUT_SECONDS}s; "
                "it must honour the env port instead of the hard default 8765"
            )
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=10)


class TestServeWebEnvBind:
    """W9 F2 (unit level): ``serve_web()`` honours env host/port by default."""

    def test_serve_web_defaults_to_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from textforensics.web_ui.main import serve_web

        port = _free_port()
        monkeypatch.setenv("TEXTFORENSICS_HOST", "127.0.0.1")
        monkeypatch.setenv("TEXTFORENSICS_PORT", str(port))
        with patch("uvicorn.run") as mock_run:
            serve_web()
        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["host"] == "127.0.0.1"
        assert call_kwargs["port"] == port

    def test_serve_web_explicit_args_override_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from textforensics.web_ui.main import serve_web

        monkeypatch.setenv("TEXTFORENSICS_HOST", "127.0.0.1")
        monkeypatch.setenv("TEXTFORENSICS_PORT", "18765")
        with patch("uvicorn.run") as mock_run:
            serve_web(host="127.0.0.1", port=9997)
        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["host"] == "127.0.0.1"
        assert call_kwargs["port"] == 9997

    def test_serve_web_defaults_without_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from textforensics.web_ui.main import serve_web

        monkeypatch.delenv("TEXTFORENSICS_HOST", raising=False)
        monkeypatch.delenv("TEXTFORENSICS_PORT", raising=False)
        with patch("uvicorn.run") as mock_run:
            serve_web()
        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["host"] == "127.0.0.1"
        assert call_kwargs["port"] == 8765


class TestEntryPointMainCleanExit:
    """W9 F1 (unit level): ``main()`` converts the install hint to SystemExit."""

    def test_web_main_converts_install_hint_to_system_exit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from textforensics.web_ui import main as web_main

        def _raise(exc: RuntimeError) -> None:
            raise exc

        monkeypatch.setattr(
            web_main, "serve_web", lambda *a, **k: _raise(RuntimeError(WEB_INSTALL_HINT))
        )
        with pytest.raises(SystemExit) as excinfo:
            web_main.main()
        assert str(excinfo.value.code) == WEB_INSTALL_HINT

    def test_web_main_reraises_other_runtime_errors(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from textforensics.web_ui import main as web_main

        monkeypatch.setattr(
            web_main, "serve_web", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        )
        with pytest.raises(RuntimeError, match="boom"):
            web_main.main()

    def test_api_main_converts_install_hint_to_system_exit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import textforensics.api as api

        monkeypatch.setattr(
            api, "serve_api", lambda *a, **k: (_ for _ in ()).throw(RuntimeError(API_INSTALL_HINT))
        )
        with pytest.raises(SystemExit) as excinfo:
            api.main()
        assert str(excinfo.value.code) == API_INSTALL_HINT

    def test_api_main_reraises_other_runtime_errors(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import textforensics.api as api

        monkeypatch.setattr(
            api, "serve_api", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        )
        with pytest.raises(RuntimeError, match="boom"):
            api.main()
