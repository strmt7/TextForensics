"""Installed-wheel web resources (ENG-01) and vendored notices (ENG-15).

Builds the wheel from the current tree, installs it into a fresh venv
outside the checkout, starts the real server from the installed files,
and requests real web resources over HTTP.

Red-first history: before the W6 fix the wheel contained neither the
``web_ui/static`` nor the ``web_ui/templates`` package data, so
``create_web_app()`` raised at ``StaticFiles`` mount time (the static
directory did not exist in the install) and the index template was
unresolvable; there was also no standalone third-party notice file for
the vendored Chart.js bundle. These tests failed on the pre-fix wheel
and pass once the resources ship as package data.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent

# Resources the installed wheel must contain (ENG-01: web entry point;
# ENG-15: third-party notices shipped alongside the vendored files).
EXPECTED_WHEEL_RESOURCES = (
    "textforensics/web_ui/static/app.js",
    "textforensics/web_ui/static/chart.umd.min.js",
    "textforensics/web_ui/static/style.css",
    "textforensics/web_ui/templates/index.html",
)
EXPECTED_NOTICE_FILE = "textforensics/web_ui/static/THIRD-PARTY-NOTICES.txt"

# Markers that prove the served bytes are the real resources, not an
# error page or a placeholder.
APP_JS_MARKER = "renderGaugeChart"
INDEX_MARKER = "TextForensics - AI Text Detection Dashboard"
CHART_JS_MARKER = "Chart.js v4.4.1"
NOTICE_MARKERS = (
    "Copyright (c) 2014-2022 Chart.js Contributors",
    "Copyright (c) 2018-2021 Jukka Kurkela",
    "The MIT License (MIT)",
)

BUILD_TIMEOUT_SECONDS = 300
INSTALL_TIMEOUT_SECONDS = 600
SERVER_START_TIMEOUT_SECONDS = 90


def _clean_env() -> dict[str, str]:
    """Environment for the fresh venv that cannot see the checkout.

    The test process itself runs with ``PYTHONPATH=<repo>/src`` (the
    repo's pytest convention). A subprocess would inherit that and
    import ``textforensics`` from the checkout instead of the installed
    wheel, which would make these tests vacuous. Strip it (and any
    other checkout pointer) so the only ``textforensics`` importable
    is the one installed in the fresh venv.
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


def _wheel_names(wheel_path: Path) -> list[str]:
    with zipfile.ZipFile(wheel_path) as archive:
        return archive.namelist()


def _wheel_text(wheel_path: Path, member: str) -> str:
    with zipfile.ZipFile(wheel_path) as archive:
        return archive.read(member).decode("utf-8")


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
    outdir = tmp_path_factory.mktemp("installed-web-wheel")
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


@pytest.fixture(scope="module")
def installed_server_url(wheel_path: Path, tmp_path_factory: pytest.TempPathFactory) -> str:
    """Install the wheel into a fresh venv and serve it on a free port.

    The venv is created outside the checkout and the wheel is installed
    with its ``[api]`` extra, exactly as the container runtime does
    (``pip install "textforensics[api]==0.2.0"`` from the built wheels).
    Yields the base URL; the server is terminated on teardown.
    """
    workdir = tmp_path_factory.mktemp("installed-web-venv")
    venv_dir = workdir / "venv"
    clean_env = _clean_env()
    _run(
        [sys.executable, "-m", "venv", str(venv_dir)],
        env=clean_env,
        timeout=BUILD_TIMEOUT_SECONDS,
    )
    venv_python = venv_dir / "bin" / "python"
    _run(
        [
            str(venv_python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--quiet",
            f"{wheel_path}[api]",
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
    port = _free_port()
    server = subprocess.Popen(
        [
            str(venv_python),
            "-c",
            "from textforensics.web_ui.main import serve_web; "
            f"serve_web(port={port}, access_log=False, log_level='warning')",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=clean_env,
        cwd=str(workdir),
    )
    base_url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + SERVER_START_TIMEOUT_SECONDS
    ready = False
    while time.monotonic() < deadline:
        if server.poll() is not None:
            output = server.stdout.read() if server.stdout else ""
            raise AssertionError(
                f"installed web server exited during startup (exit {server.returncode}):\n{output}"
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
    if not ready:
        server.terminate()
        output = ""
        try:
            output = server.communicate(timeout=10)[0] or ""
        except subprocess.TimeoutExpired:
            server.kill()
            output = server.communicate()[0] or ""
        raise AssertionError(
            "installed web server did not become ready within "
            f"{SERVER_START_TIMEOUT_SECONDS}s:\n{output}"
        )
    yield base_url
    server.terminate()
    try:
        server.wait(timeout=10)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=10)


class TestWheelContents:
    """ENG-01/ENG-15 at the wheel level (fast; no venv needed)."""

    def test_wheel_contains_web_resources(self, wheel_path: Path) -> None:
        """The wheel ships the static files and templates (ENG-01)."""
        names = _wheel_names(wheel_path)
        for resource in EXPECTED_WHEEL_RESOURCES:
            assert resource in names, (
                f"installed wheel is missing {resource}; "
                "pyproject package-data must include web_ui/static/* "
                "and web_ui/templates/* (ENG-01)"
            )

    def test_wheel_contains_third_party_notices(self, wheel_path: Path) -> None:
        """The wheel ships the vendored-asset licence notices (ENG-15)."""
        names = _wheel_names(wheel_path)
        assert EXPECTED_NOTICE_FILE in names, (
            "installed wheel is missing the third-party licence notices "
            "for the vendored Chart.js bundle (ENG-15)"
        )
        text = _wheel_text(wheel_path, EXPECTED_NOTICE_FILE)
        for marker in NOTICE_MARKERS:
            assert marker in text, (
                f"third-party notices are missing {marker!r}; the shipped "
                "notices must carry the exact full MIT texts (ENG-15)"
            )
        assert "chart.umd.min.js" in text
        assert "@kurkle/color" in text


class TestInstalledServer:
    """ENG-01/ENG-15 end to end: the installed app serves real resources."""

    def test_index_template_renders(self, installed_server_url: str) -> None:
        """GET / renders the shipped index template (ENG-01)."""
        status, body = _http_get(installed_server_url, "/")
        assert status == 200, f"GET / returned {status}: {body[:500]}"
        assert INDEX_MARKER in body
        assert "/static/chart.umd.min.js" in body

    def test_static_app_js_served(self, installed_server_url: str) -> None:
        """GET /static/app.js serves the shipped script (ENG-01)."""
        status, body = _http_get(installed_server_url, "/static/app.js")
        assert status == 200, f"GET /static/app.js returned {status}"
        assert APP_JS_MARKER in body
        assert len(body) > 1000

    def test_static_style_css_served(self, installed_server_url: str) -> None:
        """GET /static/style.css serves the shipped stylesheet (ENG-01)."""
        status, body = _http_get(installed_server_url, "/static/style.css")
        assert status == 200, f"GET /static/style.css returned {status}"
        assert "--bg:" in body

    def test_static_chart_js_served(self, installed_server_url: str) -> None:
        """GET /static/chart.umd.min.js serves the vendored bundle (ENG-01)."""
        status, body = _http_get(installed_server_url, "/static/chart.umd.min.js")
        assert status == 200, f"GET /static/chart.umd.min.js returned {status}"
        assert CHART_JS_MARKER in body
        assert "@kurkle/color v0.3.2" in body

    def test_static_notices_served(self, installed_server_url: str) -> None:
        """GET /static/THIRD-PARTY-NOTICES.txt serves the notices (ENG-15)."""
        status, body = _http_get(installed_server_url, "/static/THIRD-PARTY-NOTICES.txt")
        assert status == 200, f"GET /static/THIRD-PARTY-NOTICES.txt returned {status}: {body[:200]}"
        for marker in NOTICE_MARKERS:
            assert marker in body


def test_sbom_records_vendored_assets() -> None:
    """The checked-in SBOM lists the vendored assets with licences (ENG-15).

    Reads the committed SBOM (regenerated by scripts/generate_sbom.py):
    Chart.js v4.4.1 and @kurkle/color v0.3.2 must appear as components
    with MIT licences, npm purls, and the SHA-256 of the shipped file.
    """
    import hashlib

    sbom_path = REPO_ROOT / "sbom" / "textforensics.cdx.json"
    bom = json.loads(sbom_path.read_text(encoding="utf-8"))
    by_name = {c["name"]: c for c in bom["components"]}
    vendored_file = REPO_ROOT / "src" / "textforensics" / "web_ui" / "static" / "chart.umd.min.js"
    file_sha256 = hashlib.sha256(vendored_file.read_bytes()).hexdigest()
    expected = {
        "chart.js": {
            "version": "4.4.1",
            "purl": "pkg:npm/chart.js@4.4.1",
        },
        "@kurkle/color": {
            "version": "0.3.2",
            "purl": "pkg:npm/%40kurkle/color@0.3.2",
        },
    }
    for name, fields in expected.items():
        assert name in by_name, (
            f"SBOM is missing vendored asset {name}; "
            "generate_sbom.py must record vendored assets (ENG-15)"
        )
        component = by_name[name]
        assert component["version"] == fields["version"]
        assert component["purl"] == fields["purl"]
        assert component["licenses"] == [{"license": {"id": "MIT"}}]
        hashes = {h["alg"]: h["content"] for h in component.get("hashes", [])}
        assert hashes.get("SHA-256") == file_sha256, (
            f"SBOM hash for {name} does not match the shipped file"
        )
