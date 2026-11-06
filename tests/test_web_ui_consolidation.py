"""Wave (c) consolidation tests: one web UI.

Covers the behaviour ported from the deleted stdlib ``webapp.py`` into
``web_ui/main.py``: the ``POST /api/report`` raw-bundle alias, the
``GET /index.html`` alias, the CSP / Permissions-Policy headers, the
vendored Chart.js (no CDN fetch), ``serve_web`` URL print + browser
auto-open, and the ``textforensics web`` CLI dispatch.
"""

from __future__ import annotations

import sys
import time
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

src_path = Path(__file__).parent.parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

try:
    from fastapi.testclient import TestClient

    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

try:
    from textforensics.config import Settings
    from textforensics.web_ui.main import create_web_app as _create_web_app

    HAS_WEB_UI = True
except ImportError:
    HAS_WEB_UI = False

TEXT = (
    "I tried the new setup on Tuesday and hit two problems. The first was mundane: "
    "the cable was too short. The second took longer to understand. After three runs, "
    "I noticed the sensor drifted only when the enclosure was warm. I don't yet know "
    "why, but tomorrow I'll repeat the test with the fan locked at one speed."
)


def _strip_volatile(value):
    """Drop run metadata (timestamps, runtimes) so two analyses compare."""
    if isinstance(value, dict):
        return {
            key: _strip_volatile(item)
            for key, item in value.items()
            if key not in {"generated_at_utc", "runtime_ms", "runtime_ms_total"}
        }
    if isinstance(value, list):
        return [_strip_volatile(item) for item in value]
    return value


@pytest.fixture
def test_app():
    if not HAS_FASTAPI:
        pytest.skip("fastapi not installed")
    if _create_web_app is None:
        pytest.skip("create_web_app not available")
    return _create_web_app(Settings.from_env())


@pytest.fixture
def client(test_app):
    if not HAS_FASTAPI:
        pytest.skip("fastapi not installed")
    return TestClient(test_app)


@pytest.mark.skipif(not HAS_WEB_UI, reason="web_ui module not available")
class TestApiReportAlias:
    def test_report_returns_raw_bundle(self, client):
        resp = client.post("/api/report", json={"text": TEXT})
        assert resp.status_code == 200
        data = resp.json()
        # Raw bundle, not the {success, data} wrapper of /api/analyze.
        assert "success" not in data
        assert data["schema"] == "textforensics.forensic-bundle/v2"
        assert data["trust_map"]["overall"] in {
            "strong",
            "mixed",
            "insufficient",
        }

    def test_report_matches_analyze_data(self, client):
        report = client.post("/api/report", json={"text": TEXT}).json()
        analyzed = client.post("/api/analyze", json={"text": TEXT}).json()
        assert analyzed["success"] is True
        # Two separate analyses of the same text agree on every field
        # except the volatile run metadata (timestamps, runtimes).
        assert _strip_volatile(report) == _strip_volatile(analyzed["data"])

    def test_report_rejects_invalid_input(self, client):
        assert client.post("/api/report", json={}).status_code == 400
        assert client.post("/api/report", json={"text": ""}).status_code == 400
        assert client.post("/api/report", json={"text": 42}).status_code == 400
        assert client.post("/api/report", json=[1, 2]).status_code == 400
        assert (
            client.post(
                "/api/report",
                content="{not json",
                headers={"Content-Type": "application/json"},
            ).status_code
            == 400
        )

    def test_report_does_not_store_history(self, client):
        assert client.post("/api/report", json={"text": TEXT}).status_code == 200
        history = client.get("/api/history").json()
        assert history["total"] == 0

    def test_report_emergency_stop_blocks(self, client):
        with patch(
            "textforensics.emergency_stop.check_emergency_stop",
            return_value=True,
        ):
            assert client.post("/api/report", json={"text": TEXT}).status_code == 503


@pytest.mark.skipif(not HAS_WEB_UI, reason="web_ui module not available")
class TestIndexAliasAndHeaders:
    def test_index_html_alias(self, client):
        root = client.get("/")
        alias = client.get("/index.html")
        assert alias.status_code == 200
        assert alias.text == root.text

    def test_security_headers_present(self, client):
        resp = client.get("/")
        csp = resp.headers["Content-Security-Policy"]
        assert "script-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "object-src 'none'" in csp
        assert resp.headers["Permissions-Policy"] == ("camera=(), microphone=(), geolocation=()")
        # The headers apply to API responses too.
        api_csp = client.post("/api/report", json={"text": TEXT}).headers["Content-Security-Policy"]
        assert "script-src 'self'" in api_csp

    def test_chart_js_vendored_no_cdn(self, client):
        page = client.get("/")
        assert page.status_code == 200
        assert "/static/chart.umd.min.js" in page.text
        assert "cdn.jsdelivr.net" not in page.text
        assert "https://" not in page.text
        chart = client.get("/static/chart.umd.min.js")
        assert chart.status_code == 200
        assert "Chart.js v4.4.1" in chart.text


@pytest.mark.skipif(not HAS_WEB_UI, reason="web_ui module not available")
class TestServeWeb:
    @patch("uvicorn.run")
    @patch("textforensics.web_ui.main.webbrowser.open")
    def test_prints_url_and_opens_browser(self, mock_open, mock_run, capsys):
        from textforensics.web_ui.main import serve_web

        serve_web(host="127.0.0.1", port=9998, open_browser=True)
        mock_run.assert_called_once()
        time.sleep(0.5)  # serve_web opens the browser on a 0.25 s timer
        mock_open.assert_called_once_with("http://127.0.0.1:9998/")
        assert "TextForensics UI: http://127.0.0.1:9998/" in capsys.readouterr().out

    @patch("uvicorn.run")
    @patch("textforensics.web_ui.main.webbrowser.open")
    def test_no_browser_flag_skips_open(self, mock_open, mock_run):
        from textforensics.web_ui.main import serve_web

        serve_web(host="127.0.0.1", port=9998, open_browser=False)
        mock_run.assert_called_once()
        time.sleep(0.5)
        mock_open.assert_not_called()


@pytest.mark.skipif(not HAS_WEB_UI, reason="web_ui module not available")
class TestWebCliDispatch:
    def _run_main(self, argv):
        from textforensics.cli import main

        old_argv, old_stdout, old_stderr = sys.argv, sys.stdout, sys.stderr
        try:
            sys.argv = ["textforensics", *argv]
            sys.stdout, sys.stderr = StringIO(), StringIO()
            return main()
        except SystemExit as exc:
            return exc.code
        finally:
            sys.argv, sys.stdout, sys.stderr = old_argv, old_stdout, old_stderr

    @patch("textforensics.web_ui.main.serve_web")
    def test_web_command_calls_serve_web(self, mock_serve):
        from textforensics.constants import EXIT_OK

        assert self._run_main(["web", "--no-browser"]) == EXIT_OK
        mock_serve.assert_called_once()
        _, kwargs = mock_serve.call_args
        assert kwargs["open_browser"] is False
        assert kwargs["allow_remote"] is False

    @patch("textforensics.web_ui.main.serve_web")
    def test_web_command_opens_browser_by_default(self, mock_serve):
        from textforensics.constants import EXIT_OK

        assert self._run_main(["web"]) == EXIT_OK
        _, kwargs = mock_serve.call_args
        assert kwargs["open_browser"] is True
