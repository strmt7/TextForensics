"""W1 Worker C regression tests: IF-05 (web trust boundary), IF-03 WebSocket
wiring, IF-07 web wiring.

Written from the stated expected results (plan rule 3) before the source
fix. Every test uses reserved example domains (attacker.example), ephemeral
keys and disposable directories; no real user text, accounts or keys.

Audit vectors reproduced here:
- IF-05 ``cross_origin_websocket``: Origin https://attacker.example must
  not drive an analysis.
- IF-05 ``websocket_forged_history``: a caller-created verdict containing
  ``<strong id="injected">FORGED</strong>`` + 65,536 padding bytes (vs
  max_input_bytes=1024) must not be read back from server history.
- IF-05 ``unescaped_history``: the shipped history renderer must render
  imported verdicts as inert text, never verbatim markup. The test asserts
  escaped output; it does NOT assert script execution, which the shipped
  CSP (script-src 'self') already constrains and no browser run proves.
- IF-03 ``stopped_websocket``: stop before connect and after connect but
  before analyze must refuse work with zero detector calls and no
  ``started`` frame; history/share mutations are refused while stopped.
- IF-07 ``web_error_echo`` / ``web_invalid_input``: oversize text is 413,
  invalid type is 422, unexpected errors are 500, with no canary text,
  traceback or path disclosure in public errors.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from textforensics.detectors import BuiltinHeuristicDetector  # noqa: E402

try:
    from fastapi.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    HAS_FASTAPI = True
except ImportError:  # pragma: no cover - fastapi is an extra
    HAS_FASTAPI = False

# Shared recording-detector helpers from Worker A's W1 tests (same
# dispatch/consent fixtures; no network I/O is performed by them).
from test_w1_consent_stop import (  # noqa: E402
    TEXT,
    RecordingRemoteDetector,
    _DiscoveryPatch,
    _prediction,
    _registry,
)

CANARY = "CANARY-W1C-9f27d1"
FORGED_MARKUP = '<strong id="injected">FORGED</strong>'
REPO_ROOT = Path(__file__).parent.parent
APP_JS = REPO_ROOT / "src" / "textforensics" / "web_ui" / "static" / "app.js"
HARNESS_JS = Path(__file__).parent / "w1c_history_sink_harness.js"


def _make_client(max_input_bytes: int = 1024, base_url: str = "http://testserver"):
    from textforensics.config import Settings
    from textforensics.web_ui.main import create_web_app

    app = create_web_app(
        Settings(
            host="127.0.0.1",
            port=8765,
            max_input_bytes=max_input_bytes,
            allow_remote=False,
            access_log=False,
            log_level="INFO",
        )
    )
    return TestClient(app, raise_server_exceptions=False, base_url=base_url)


def _drain(ws, limit: int = 20):
    """Collect message types until error/complete or the limit."""
    types = []
    for _ in range(limit):
        data = ws.receive_json()
        types.append(data.get("type"))
        if data.get("type") in {"error", "complete"}:
            break
    return types


def _forged_bundle(padding: int = 65536) -> dict:
    return {
        "consensus": {"verdict": FORGED_MARKUP + "x" * padding, "ai_probability": 0.5},
        "detector_results": [],
        "trust_map": {},
    }


class _StopAfterFirst:
    """First detector activates the stop sentinel when called."""

    detector_id = "audit.example/first"
    detector_version = "1"
    detector_family = "local-recording"
    execution = "local"

    def __init__(self, sentinel: Path):
        self.calls: list[str] = []
        self._sentinel = sentinel

    def detect(self, text):
        self.calls.append(text)
        self._sentinel.write_text("stop\n", encoding="utf-8")
        return _prediction(
            self.detector_id,
            execution="local",
            verdict="human_like",
            family="local-recording",
        )


class _StopAfterFirstSecond:
    detector_id = "audit.example/second"
    detector_version = "1"
    detector_family = "local-recording"
    execution = "local"

    def __init__(self):
        self.calls: list[str] = []

    def detect(self, text):
        self.calls.append(text)
        return _prediction(
            self.detector_id,
            execution="local",
            verdict="human_like",
            family="local-recording",
        )


@pytest.mark.skipif(not HAS_FASTAPI, reason="fastapi not installed")
class TestIF05CrossOriginWebSocket:
    def test_cross_origin_origin_rejected_at_handshake(self):
        client = _make_client()
        with (
            pytest.raises(WebSocketDisconnect),
            client.websocket_connect("/ws/analyze", headers={"Origin": "https://attacker.example"}),
        ):
            pass

    def test_cross_origin_origin_with_port_rejected(self):
        client = _make_client()
        with (
            pytest.raises(WebSocketDisconnect),
            client.websocket_connect(
                "/ws/analyze", headers={"Origin": "http://attacker.example:8765"}
            ),
        ):
            pass

    def test_origin_without_port_rejected_exact_match(self):
        # Exact Origin matching: the served origin always carries its port.
        client = _make_client()
        with (
            pytest.raises(WebSocketDisconnect),
            client.websocket_connect("/ws/analyze", headers={"Origin": "http://127.0.0.1"}),
        ):
            pass

    def test_untrusted_host_rejected_at_handshake(self):
        # NOTE: TestClient's websocket_connect always sends Host:
        # testserver unless overridden, so the untrusted Host must be
        # passed explicitly via headers (base_url alone is ignored).
        client = _make_client()
        with (
            pytest.raises(WebSocketDisconnect),
            client.websocket_connect("/ws/analyze", headers={"Host": "attacker.example"}),
        ):
            pass

    def test_same_origin_flow_still_works(self):
        client = _make_client()
        with client.websocket_connect(
            "/ws/analyze", headers={"Origin": "http://127.0.0.1:8765"}
        ) as ws:
            ws.send_json({"type": "analyze", "text": TEXT})
            types = _drain(ws)
        assert "complete" in types
        assert "error" not in types

    def test_no_origin_flow_still_works(self):
        # Non-browser clients send no Origin; they are not the CSWSH vector.
        client = _make_client()
        with client.websocket_connect("/ws/analyze") as ws:
            ws.send_json({"type": "analyze", "text": TEXT})
            types = _drain(ws)
        assert "complete" in types


@pytest.mark.skipif(not HAS_FASTAPI, reason="fastapi not installed")
class TestIF05ForgedHistory:
    def _joined_client(self):
        client = _make_client()
        session_id = client.post("/api/session").json()["session_id"]
        return client, session_id

    def test_forged_markup_verdict_rejected_not_retained(self):
        client, session_id = self._joined_client()
        with client.websocket_connect("/ws/analyze") as ws:
            ws.send_json(
                {"type": "join_session", "session_id": session_id, "display_name": "Probe"}
            )
            assert ws.receive_json()["type"] == "session_joined"
            ws.send_json(
                {"type": "analysis_shared", "data": _forged_bundle(), "shared_by": "attacker"}
            )
            reply = ws.receive_json()
            assert reply["type"] == "error"
        history = client.get("/api/history?limit=10").json()
        assert history["total"] == 0
        assert "FORGED" not in json.dumps(history)

    def test_forged_verdict_never_read_back(self):
        # Even if a forged bundle were stored, read-back must not serve it;
        # the primary assertion is rejection, this pins the read path too.
        client, session_id = self._joined_client()
        with client.websocket_connect("/ws/analyze") as ws:
            ws.send_json(
                {"type": "join_session", "session_id": session_id, "display_name": "Probe"}
            )
            ws.receive_json()
            ws.send_json({"type": "analysis_shared", "data": _forged_bundle()})
            ws.receive_json()
        assert "FORGED" not in client.get("/api/history?limit=10").text

    def test_oversized_frame_closed_before_json_parse(self):
        client = _make_client()
        oversized = json.dumps({"type": "analyze", "text": "x" * 70000})
        assert len(oversized.encode("utf-8")) > 1024 + 65536
        with client.websocket_connect("/ws/analyze") as ws:
            ws.send_text(oversized)
            with pytest.raises(WebSocketDisconnect):
                ws.receive_json()

    def test_malformed_shared_bundles_rejected(self):
        client, session_id = self._joined_client()
        bad_bundles = [
            ["not", "a", "mapping"],
            {"consensus": {"verdict": "evil_verdict"}},
            {"consensus": {"verdict": "ai_like", "ai_probability": 5}},
            {
                "consensus": {"verdict": "ai_like"},
                "detector_results": [{"detector_id": "d", "verdict": FORGED_MARKUP}],
            },
            {"consensus": {"verdict": "ai_like"}, "detector_results": "not-a-list"},
            {"consensus": "not-a-mapping"},
            {"detector_results": []},  # no consensus at all
        ]
        with client.websocket_connect("/ws/analyze") as ws:
            ws.send_json(
                {"type": "join_session", "session_id": session_id, "display_name": "Probe"}
            )
            ws.receive_json()
            for bad in bad_bundles:
                ws.send_json({"type": "analysis_shared", "data": bad})
                reply = ws.receive_json()
                assert reply["type"] == "error", bad
        assert client.get("/api/history?limit=10").json()["total"] == 0

    def test_unknown_message_type_and_bad_shapes_rejected(self):
        client = _make_client()
        with client.websocket_connect("/ws/analyze") as ws:
            ws.send_json({"type": "explode_the_server"})
            assert ws.receive_json()["type"] == "error"
            ws.send_text("{not json")
            assert ws.receive_json()["type"] == "error"
            ws.send_json({"type": "analyze", "text": 42})
            assert ws.receive_json()["type"] == "error"
            # The connection survives content errors: a valid analysis works.
            ws.send_json({"type": "analyze", "text": TEXT})
            assert "complete" in _drain(ws)

    def test_valid_server_id_share_acknowledges_stored_bundle(self):
        client, session_id = self._joined_client()
        # Produce a real server-side analysis and learn its server ID.
        with client.websocket_connect("/ws/analyze") as ws:
            ws.send_json({"type": "analyze", "text": TEXT})
            assert "complete" in _drain(ws)
        entries = client.get("/api/history?limit=1").json()["entries"]
        assert len(entries) == 1
        analysis_id = entries[0]["id"]
        stored = client.get(f"/api/history/{analysis_id}").json()["data"]
        # Share by server-side ID: the sender gets an ack naming the
        # server ID, and the retained entry is not duplicated. Peer
        # broadcast routing is IF-10's (W5): the join path currently
        # corrupts the ws->session map, so no peer assertion is made
        # here; the stored object is verified through the REST read-back.
        with client.websocket_connect("/ws/analyze") as ws:
            ws.send_json({"type": "join_session", "session_id": session_id, "display_name": "Peer"})
            assert ws.receive_json()["type"] == "session_joined"
            ws.send_json({"type": "analysis_shared", "analysis_id": analysis_id})
            ack = ws.receive_json()
            assert ack["type"] == "analysis_shared"
            assert ack["analysis_id"] == analysis_id
        assert client.get("/api/history?limit=10").json()["total"] == 1
        assert client.get(f"/api/history/{analysis_id}").json()["data"] == stored

    def test_share_unknown_server_id_rejected(self):
        client, session_id = self._joined_client()
        with client.websocket_connect("/ws/analyze") as ws:
            ws.send_json({"type": "join_session", "session_id": session_id, "display_name": "Peer"})
            assert ws.receive_json()["type"] == "session_joined"
            ws.send_json({"type": "analysis_shared", "analysis_id": "no-such-id"})
            assert ws.receive_json()["type"] == "error"
        assert client.get("/api/history?limit=10").json()["total"] == 0

    def test_history_entry_byte_quota(self):
        client, session_id = self._joined_client()
        # A schema-valid bundle whose retained size exceeds the per-entry
        # quota (65,536 bytes) while the frame stays under the frame cap.
        frame_cap = 1024 + 65536
        entry_cap = 65536
        notes = ""
        while True:
            candidate = {
                "consensus": {"verdict": "ai_like"},
                "detector_results": [],
                "trust_map": {},
                "notes": notes,
            }
            entry_size = len(json.dumps(candidate).encode("utf-8"))
            frame_size = len(
                json.dumps({"type": "analysis_shared", "data": candidate}).encode("utf-8")
            )
            if entry_size > entry_cap and frame_size < frame_cap:
                break
            notes += "x" * 1024
        with client.websocket_connect("/ws/analyze") as ws:
            ws.send_json(
                {"type": "join_session", "session_id": session_id, "display_name": "Probe"}
            )
            ws.receive_json()
            ws.send_json({"type": "analysis_shared", "data": candidate})
            assert ws.receive_json()["type"] == "error"
        assert client.get("/api/history?limit=10").json()["total"] == 0

    def test_history_count_quota(self):
        client, session_id = self._joined_client()
        small = {"consensus": {"verdict": "abstain"}, "detector_results": [], "trust_map": {}}
        with client.websocket_connect("/ws/analyze") as ws:
            ws.send_json(
                {"type": "join_session", "session_id": session_id, "display_name": "Probe"}
            )
            ws.receive_json()
            for _ in range(105):
                ws.send_json({"type": "analysis_shared", "data": small})
                assert ws.receive_json()["type"] == "analysis_shared"
        assert client.get("/api/history?limit=200").json()["total"] == 100


@pytest.mark.skipif(not HAS_FASTAPI, reason="fastapi not installed")
class TestIF03WebSocketWiring:
    def _client(self):
        return _make_client(max_input_bytes=100_000)

    def test_stop_before_connect_refuses_handshake_zero_calls(self, tmp_path, monkeypatch):
        remote = RecordingRemoteDetector()
        registry = _registry(BuiltinHeuristicDetector(), remote)
        sentinel = tmp_path / "stop"
        sentinel.write_text("stop\n", encoding="utf-8")
        monkeypatch.setenv("TEXTFORENSICS_EMERGENCY_STOP", str(sentinel))
        # Refusal happens at the handshake: no socket, no "started",
        # and the detector registry is never consulted.
        with (
            _DiscoveryPatch(registry),
            pytest.raises(WebSocketDisconnect),
            self._client().websocket_connect("/ws/analyze"),
        ):
            pass
        assert remote.calls == []

    def test_stop_after_connect_before_analyze_refuses_without_started(self, tmp_path, monkeypatch):
        remote = RecordingRemoteDetector()
        registry = _registry(BuiltinHeuristicDetector(), remote)
        sentinel = tmp_path / "stop"
        monkeypatch.setenv("TEXTFORENSICS_EMERGENCY_STOP", str(sentinel))
        with (
            _DiscoveryPatch(registry),
            self._client().websocket_connect("/ws/analyze") as ws,
        ):
            sentinel.write_text("stop\n", encoding="utf-8")
            ws.send_json({"type": "analyze", "text": TEXT})
            first = ws.receive_json()
            assert first["type"] == "error"
            assert first.get("error_code") == "emergency_stop_active"
        assert remote.calls == []

    def test_stop_between_detector_steps_starts_no_further_plugin(self, tmp_path, monkeypatch):
        sentinel = tmp_path / "stop"
        monkeypatch.setenv("TEXTFORENSICS_EMERGENCY_STOP", str(sentinel))
        first = _StopAfterFirst(sentinel)
        second = _StopAfterFirstSecond()
        registry = _registry(first, second)
        with (
            _DiscoveryPatch(registry),
            self._client().websocket_connect("/ws/analyze") as ws,
        ):
            ws.send_json({"type": "analyze", "text": TEXT})
            types = _drain(ws)
        assert "error" in types
        assert "complete" not in types
        assert "detector_result" not in types
        assert len(first.calls) == 1
        assert second.calls == []

    def test_history_share_mutations_refused_while_stopped(self, tmp_path, monkeypatch):
        client = self._client()
        session_id = client.post("/api/session").json()["session_id"]
        sentinel = tmp_path / "stop"
        monkeypatch.setenv("TEXTFORENSICS_EMERGENCY_STOP", str(sentinel))
        with client.websocket_connect("/ws/analyze") as ws:
            ws.send_json(
                {"type": "join_session", "session_id": session_id, "display_name": "Probe"}
            )
            assert ws.receive_json()["type"] == "session_joined"
            sentinel.write_text("stop\n", encoding="utf-8")
            # Share mutation refused while stopped; nothing retained.
            ws.send_json(
                {
                    "type": "analysis_shared",
                    "data": {
                        "consensus": {"verdict": "ai_like"},
                        "detector_results": [],
                        "trust_map": {},
                    },
                }
            )
            reply = ws.receive_json()
            assert reply["type"] == "error"
            assert reply.get("error_code") == "emergency_stop_active"
            # Join mutation refused while stopped.
            ws.send_json({"type": "join_session", "session_id": session_id, "display_name": "Late"})
            reply = ws.receive_json()
            assert reply["type"] == "error"
            assert reply.get("error_code") == "emergency_stop_active"
            # Leaving (cleanup) still works while stopped.
            ws.send_json({"type": "leave_session"})
            assert ws.receive_json()["type"] == "session_left"
        # The HTTP middleware also gates on the stop; clear the sentinel
        # before reading history back over HTTP.
        sentinel.unlink()
        assert client.get("/api/history?limit=10").json()["total"] == 0


@pytest.mark.skipif(not HAS_FASTAPI, reason="fastapi not installed")
class TestIF07WebWiring:
    def test_oversize_text_is_413(self):
        client = _make_client()
        resp = client.post("/api/analyze", json={"text": "x" * 2000})
        assert resp.status_code == 413
        assert resp.json()["detail"] == "Invalid text input."
        assert "xxxxx" not in resp.text

    def test_invalid_type_is_422_sanitized(self):
        client = _make_client()
        resp = client.post("/api/analyze", json={"text": [CANARY]})
        assert resp.status_code == 422
        assert CANARY not in resp.text
        for entry in resp.json()["detail"]:
            assert "input" not in entry
            assert "ctx" not in entry

    def test_nested_validation_failure_does_not_echo(self):
        client = _make_client()
        resp = client.post("/api/analyze", json={"text": {"nested": CANARY}})
        assert resp.status_code == 422
        assert CANARY not in resp.text

    def test_unexpected_error_is_500_without_echo_or_paths(self):
        client = _make_client()
        with patch(
            "textforensics.web_ui.main.build_forensic_bundle",
            side_effect=RuntimeError(f"plugin blew up on {CANARY}"),
        ):
            resp = client.post("/api/analyze", json={"text": TEXT})
        assert resp.status_code == 500
        assert resp.json()["detail"] == "Internal error."
        assert CANARY not in resp.text
        assert "Traceback" not in resp.text
        assert "/home/" not in resp.text
        # Correlation travels in the header for HTTPException details,
        # per the shared redacting-handler contract (Worker A).
        assert resp.headers.get("x-request-id")

    def test_session_404_does_not_echo_caller_id(self):
        client = _make_client()
        resp = client.get(f"/api/session/PROBE-ID-{CANARY}")
        assert resp.status_code == 404
        assert CANARY not in resp.text
        assert "PROBE-ID" not in resp.text

    def test_export_format_error_does_not_echo_format(self):
        client = _make_client()
        resp = client.post("/api/export", json={"data": {}, "format": f"xml-{CANARY}"})
        assert resp.status_code == 400
        # The old message lower-cased the format before echoing it, so
        # the check must be case-insensitive to be meaningful.
        assert CANARY.lower() not in resp.text.lower()

    def test_websocket_plugin_exception_does_not_echo(self):
        client = _make_client()
        with (
            patch(
                "textforensics.detectors.run_all_detectors",
                side_effect=RuntimeError(f"detector blew up on {CANARY}"),
            ),
            client.websocket_connect("/ws/analyze") as ws,
        ):
            ws.send_json({"type": "analyze", "text": TEXT})
            # "started" is legitimately sent before dispatch; the
            # failure surfaces as a generic error after it, and the
            # run never completes.
            seen = []
            for _ in range(10):
                reply = ws.receive_json()
                seen.append(reply)
                if reply.get("type") == "error":
                    break
            assert seen[-1]["type"] == "error"
            assert "complete" not in [m.get("type") for m in seen]
            assert CANARY not in json.dumps(seen)
            assert "Traceback" not in json.dumps(seen)

    def test_websocket_oversize_text_is_invalid_input_error(self):
        client = _make_client()
        with client.websocket_connect("/ws/analyze") as ws:
            ws.send_json({"type": "analyze", "text": "x" * 2000})
            reply = ws.receive_json()
            assert reply["type"] == "error"
            assert reply.get("error_code") == "invalid_text_input"
            assert "413" not in reply.get("message", "")
            # The connection survives a content error.
            ws.send_json({"type": "analyze", "text": TEXT})
            assert "complete" in _drain(ws)


@pytest.mark.skipif(not HAS_FASTAPI, reason="fastapi not installed")
class TestIF05HistorySinkRendersLiteralText:
    """Execute the shipped app.js history renderer against forged items.

    The harness stubs a minimal DOM (no browser is opened). The test
    asserts the verdict is rendered as escaped inert text and that no
    raw markup or attribute breakout survives -- it does NOT assert
    script execution, which the shipped CSP already constrains and no
    headless-DOM run could prove.
    """

    @staticmethod
    def _render(item: dict) -> str:
        if shutil.which("node") is None:
            pytest.skip("node is not available for the JS sink test")
        proc = subprocess.run(
            ["node", str(HARNESS_JS), str(APP_JS), json.dumps(item)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        return json.loads(proc.stdout)["innerHTML"]

    def test_forged_verdict_rendered_as_inert_text(self):
        html = self._render(
            {
                "id": "abc123",
                "content_sha256": "deadbeef",
                "word_count": 42,
                "stored_at": "2026-11-10T00:00:00Z",
                "verdict": FORGED_MARKUP,
                "ai_probability": 0.5,
            }
        )
        assert "&lt;strong" in html
        assert '<strong id="injected">' not in html
        # The verdict text is inert: "<" and ">" are escaped, so no
        # element is created. Quotes inside a *text* node need no
        # escaping (a browser does not escape them there either), so
        # `id="injected"` may still appear as literal text inside the
        # escaped `&lt;strong ...&gt;` -- what must not appear is the
        # raw tag. Attribute breakout is covered separately below.
        assert "FORGED" in html  # visible as literal text, not markup

    def test_forged_id_cannot_break_out_of_attribute(self):
        html = self._render(
            {
                "id": 'x" onmouseover="alert(1)',
                "content_sha256": "deadbeef",
                "word_count": 42,
                "stored_at": "2026-11-10T00:00:00Z",
                "verdict": "ai_like",
                "ai_probability": 0.5,
            }
        )
        assert 'onmouseover="alert(1)' not in html
        assert "&quot;" in html

    def test_forged_verdict_class_is_allowlisted(self):
        html = self._render(
            {
                "id": "abc123",
                "content_sha256": "deadbeef",
                "word_count": 42,
                "stored_at": "2026-11-10T00:00:00Z",
                "verdict": FORGED_MARKUP,
                "ai_probability": None,
            }
        )
        assert "verdict-badge unknown" in html
        assert "verdict-badge <strong" not in html
