"""W5 Worker A regression tests: IF-04 (server side), IF-05 (verify),
IF-06 (UI/server contract), IF-10 (session bookkeeping), IF-14 (exports).

Written from the stated expected results before the source fix (red
tests first). Every test drives the REAL shipped code: real server
bundles from ``build_forensic_bundle`` / the real WebSocket endpoint
through the REAL ``app.js`` in Node, real ``/api/export`` responses,
and the real ``SessionManager``. No real user text, accounts or keys.

Audit vectors reproduced here:
- IF-04: the server bundle must expose the canonical
  ``consensus.calibrated_ai_probability`` with its ensemble-calibration
  provenance and must NOT emit a legacy ``ai_probability`` field any
  consumer could mistake for a calibrated probability.
- IF-05: the W1 IF-05 regression tests still pass on the W5 head; the
  token-vs-authenticated-session decision stays a documented HUMAN
  decision, not an invented auth deployment.
- IF-06: a real bundle through the complete and streaming paths with no
  JS errors, correct family labels, visible abstention/limitations,
  populated raw data/history; every declared DOM ID resolves; wss under
  HTTPS; exactly-once base-observation reuse.
- IF-10: join/leave, normal/abnormal disconnect, duplicate join and
  reconnect each release the exact user/socket references; last-user
  departure removes the session; cleanup reclaims stale entries;
  multi-client broadcasts reach live users exactly once and never
  closed connections.
- IF-14: each actual export action yields its own format (parsed
  independently), with MIME/extension/content agreement, abstention /
  limitations / provenance preserved, and content agreeing with the API
  export for the same real bundle; unsafe metadata is escaped and CSV
  cells are formula-safe.
"""

from __future__ import annotations

import csv
import io
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from textforensics.report import build_forensic_bundle  # noqa: E402

try:
    from fastapi.testclient import TestClient
    from starlette.websockets import WebSocketState

    HAS_FASTAPI = True
except ImportError:  # pragma: no cover - fastapi is an extra
    HAS_FASTAPI = False

from test_w1_consent_stop import (  # noqa: E402
    TEXT,
    RecordingLocalDetector,
    _DiscoveryPatch,
    _registry,
)

REPO_ROOT = Path(__file__).parent.parent
APP_JS = REPO_ROOT / "src" / "textforensics" / "web_ui" / "static" / "app.js"
TEMPLATE = REPO_ROOT / "src" / "textforensics" / "web_ui" / "templates" / "index.html"
HARNESS_JS = Path(__file__).parent / "w5a_if06_if14_harness.js"
W1_TESTS = Path(__file__).parent / "test_w1_web_console.py"
CALIBRATION_ID = "ens-cal-2026-11-01"

# Text whose benign variants all differ from the original (double
# spaces, curly quotes / em-dash, markdown list markers), so the
# exactly-once test can tell a base observation apart from a
# robustness-variant probe by the exact text passed to detect().
VARIANT_TEXT = (
    "First  item has double spaces. \u201cCurly quotes\u201d and an em\u2014dash appear here.\n"
    "- a markdown list item\n- another list item\n"
    "The text continues with enough ordinary sentences to keep the analysis "
    "meaningful and long enough for the detector to run."
)


def _make_client(max_input_bytes: int = 100_000, base_url: str = "http://testserver"):
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


def _drain(ws, limit: int = 30):
    """Collect message types until error/complete or the limit."""
    types = []
    for _ in range(limit):
        data = ws.receive_json()
        types.append(data.get("type"))
        if data.get("type") in {"error", "complete"}:
            break
    return types


def _recv_or_none(ws, timeout: float = 10.0):
    """Receive one message, or return None after `timeout` seconds.

    A missing broadcast must fail the test, not hang it forever.
    """
    box: queue.Queue = queue.Queue()

    def _recv() -> None:
        try:
            box.put(ws.receive_json())
        except Exception as exc:  # noqa: BLE001 - report as missing
            box.put(exc)

    thread = threading.Thread(target=_recv, daemon=True)
    thread.start()
    try:
        item = box.get(timeout=timeout)
    except queue.Empty:
        return None
    return None if isinstance(item, Exception) else item


def _run_harness(case: dict) -> dict:
    if shutil.which("node") is None:
        pytest.skip("node is not available for the JS UI test")
    proc = subprocess.run(
        ["node", str(HARNESS_JS), str(APP_JS), json.dumps(case)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def _collect_keys(obj, keys: set | None = None) -> set:
    keys = set() if keys is None else keys
    if isinstance(obj, dict):
        for key, value in obj.items():
            keys.add(key)
            _collect_keys(value, keys)
    elif isinstance(obj, list):
        for item in obj:
            _collect_keys(item, keys)
    return keys


def _real_bundle() -> dict:
    """A real server bundle: builtin detector, no ensemble calibration."""
    return build_forensic_bundle(TEXT, deterministic=True).to_dict()


def _calibrated_bundle(prob: float = 0.62) -> dict:
    bundle = _real_bundle()
    bundle["consensus"]["calibrated_ai_probability"] = prob
    bundle["consensus"]["ensemble_calibration_id"] = CALIBRATION_ID
    return bundle


class _FailingLocalDetector:
    detector_id = "audit.example/failing-local"
    detector_version = "1"
    detector_family = "local-recording"
    execution = "local"

    def __init__(self):
        self.calls: list[str] = []

    def detect(self, text):
        self.calls.append(text)
        raise RuntimeError("disposable probe failure")


# ── IF-04 server side ───────────────────────────────────────────────


@pytest.mark.skipif(not HAS_FASTAPI, reason="fastapi not installed")
class TestIF04ServerSide:
    def test_real_server_bundle_has_no_legacy_ai_probability_key(self):
        bundle = _real_bundle()
        keys = _collect_keys(bundle)
        assert "ai_probability" not in keys
        consensus = bundle["consensus"]
        assert "calibrated_ai_probability" in consensus
        assert "ensemble_calibration_id" in consensus
        # The builtin bundle is uncalibrated: both are None, never a number.
        assert consensus["calibrated_ai_probability"] is None
        assert consensus["ensemble_calibration_id"] is None

    def test_real_bundle_through_ui_shows_na_never_a_number(self):
        out = _run_harness({"fn": "complete", "bundle": _real_bundle()})
        assert out["error"] is None, out["error"]
        assert out["fillTexts"][0] == "N/A"
        assert "not calibrated" in out["fillTexts"][1].lower()
        for text in out["fillTexts"]:
            assert not re.search(r"\d+(\.\d+)?%", text), text

    def test_calibrated_bundle_through_ui_shows_exact_value_and_identity(self):
        out = _run_harness({"fn": "complete", "bundle": _calibrated_bundle(0.62)})
        assert out["error"] is None, out["error"]
        assert out["fillTexts"][0] == "62.0%"
        assert CALIBRATION_ID in out["fillTexts"][1]
        assert "62.0%" in out["texts"]["consensusConfidence"]
        assert CALIBRATION_ID in out["texts"]["consensusConfidence"]

    def test_bundle_consistency_flags_legacy_field(self):
        from textforensics.bundle_consistency import check_bundle_consistency

        legacy = {
            "schema": "textforensics.forensic-bundle/v1",
            "consensus": {"verdict": "ai_like", "ai_probability": 0.75},
        }
        report = check_bundle_consistency(legacy)
        assert any(i.field == "consensus.ai_probability" for i in report.issues), (
            "legacy ai_probability must be flagged as non-canonical"
        )

    def test_bundle_consistency_checks_canonical_calibrated_pair(self):
        from textforensics.bundle_consistency import check_bundle_consistency

        base = {"schema": "textforensics.forensic-bundle/v1"}
        # Calibrated value without its calibration identity is invalid.
        orphan = dict(base, consensus={"verdict": "ai_like", "calibrated_ai_probability": 0.62})
        assert any(
            i.field == "consensus.calibrated_ai_probability"
            for i in check_bundle_consistency(orphan).issues
        )
        # Calibrated value outside [0, 1] is invalid.
        bad_range = dict(
            base,
            consensus={
                "verdict": "ai_like",
                "calibrated_ai_probability": 1.5,
                "ensemble_calibration_id": CALIBRATION_ID,
            },
        )
        assert any(
            "calibrated_ai_probability" in i.field
            for i in check_bundle_consistency(bad_range).issues
        )
        # Canonical pair is clean.
        good = dict(
            base,
            consensus={
                "verdict": "ai_like",
                "calibrated_ai_probability": 0.62,
                "ensemble_calibration_id": CALIBRATION_ID,
            },
        )
        report = check_bundle_consistency(good)
        assert not any("probability" in i.field for i in report.issues)

    def test_shared_bundle_with_legacy_field_is_rejected(self):
        client = _make_client()
        session_id = client.post("/api/session").json()["session_id"]
        with client.websocket_connect("/ws/analyze") as ws:
            ws.send_json({"type": "join_session", "session_id": session_id, "display_name": "P"})
            assert ws.receive_json()["type"] == "session_joined"
            ws.send_json(
                {
                    "type": "analysis_shared",
                    "data": {"consensus": {"verdict": "ai_like", "ai_probability": 0.5}},
                }
            )
            assert ws.receive_json()["type"] == "error"
        assert client.get("/api/history?limit=10").json()["total"] == 0

    def test_shared_bundle_with_canonical_calibration_is_accepted(self):
        client = _make_client()
        session_id = client.post("/api/session").json()["session_id"]
        with client.websocket_connect("/ws/analyze") as ws:
            ws.send_json({"type": "join_session", "session_id": session_id, "display_name": "P"})
            assert ws.receive_json()["type"] == "session_joined"
            ws.send_json(
                {
                    "type": "analysis_shared",
                    "data": {
                        "consensus": {
                            "verdict": "ai_like",
                            "calibrated_ai_probability": 0.5,
                            "ensemble_calibration_id": CALIBRATION_ID,
                        },
                        "detector_results": [],
                        "trust_map": {},
                    },
                }
            )
            assert ws.receive_json()["type"] == "analysis_shared"
        assert client.get("/api/history?limit=10").json()["total"] == 1

    def test_history_entries_expose_canonical_calibration_fields(self):
        client = _make_client()
        resp = client.post("/api/analyze", json={"text": TEXT})
        assert resp.status_code == 200
        entries = client.get("/api/history?limit=10").json()["entries"]
        assert len(entries) == 1
        entry = entries[0]
        assert "ai_probability" not in entry
        assert "calibrated_ai_probability" in entry
        assert "ensemble_calibration_id" in entry
        assert entry["calibrated_ai_probability"] is None

    def test_compare_uses_canonical_calibrated_fields(self):
        client = _make_client()
        data = client.post("/api/analyze", json={"text": TEXT}).json()["data"]
        result = client.post("/api/compare", json={"a": data, "b": data}).json()
        assert "ai_probability_a" not in result["summary"]
        assert "ai_probability_b" not in result["summary"]
        assert "calibrated_ai_probability_a" in result["summary"]
        assert "calibrated_ai_probability_b" in result["summary"]


# ── IF-05 verification only ─────────────────────────────────────────


class TestIF05Verified:
    def test_w1_if05_regression_tests_still_pass(self):
        """Run the W1 IF-05/IF-03/IF-07 file on this branch head."""
        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONPATH"] = str(REPO_ROOT / "src")
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", str(W1_TESTS), "-q", "-p", "no:cacheprovider"],
            capture_output=True,
            text=True,
            timeout=600,
            cwd=str(REPO_ROOT),
            env=env,
        )
        assert proc.returncode == 0, proc.stdout[-4000:] + proc.stderr[-4000:]

    def test_token_vs_session_decision_stays_a_documented_human_decision(self):
        """No auth deployment is invented here: the open decision is pinned
        in code and docs, not silently resolved by a new token scheme."""
        main_py = (REPO_ROOT / "src" / "textforensics" / "web_ui" / "main.py").read_text()
        assert "human-only decision" in main_py
        assert "token" in main_py.lower()
        policy = (REPO_ROOT / "docs" / "verification" / "deployment-policy.md").read_text()
        assert "no token" in policy.lower()
        assert "no authentication" in policy.lower()
        # No token/auth mechanism was added to the web app.
        assert "Authorization" not in main_py
        assert "Bearer" not in main_py


# ── IF-06 real bundle through the real UI ───────────────────────────


@pytest.mark.skipif(not HAS_FASTAPI, reason="fastapi not installed")
class TestIF06RealBundleThroughUI:
    def test_complete_path_no_errors_correct_labels_visible_limitations(self):
        bundle = _real_bundle()
        out = _run_harness({"fn": "complete", "bundle": bundle})
        assert out["error"] is None, out["error"]
        # Family chart: labels are the canonical family names.
        detector_chart = [c for c in out["charts"] if c["type"] == "bar"][0]
        expected_labels = [
            v["family"].replace("-", " ") for v in bundle["consensus"]["family_votes"]
        ]
        assert detector_chart["labels"] == expected_labels
        # Gauge chart exists; uncalibrated bundle draws no probability.
        assert any(c["type"] == "doughnut" for c in out["charts"])
        # Abstention/limitations visible: at least one limitation renders.
        warnings_html = out["html"]["warningsList"]
        assert any(lim[:40] in warnings_html for lim in bundle["limitations"])
        # Raw data + history populated.
        assert "consensus" in out["texts"]["rawData"]
        assert bundle["consensus"]["verdict"] in out["html"]["historyList"]

    def test_streaming_path_no_errors(self):
        bundle = _real_bundle()
        out = _run_harness({"fn": "streaming", "bundle": bundle})
        assert out["error"] is None, out["error"]
        # Streaming updates the detector list and the detector chart.
        assert bundle["detector_results"][0]["detector_id"] in out["html"]["detectorList"]
        assert any(c["type"] == "bar" for c in out["charts"])

    def test_ws_url_is_wss_under_https_and_ws_under_http(self):
        out = _run_harness(
            {
                "fn": "ws_url",
                "extra": {"location": {"protocol": "https:", "host": "audit.localhost:8765"}},
            }
        )
        assert out["error"] is None, out["error"]
        assert out["wsUrl"] == "wss://audit.localhost:8765/ws/analyze"
        out = _run_harness(
            {
                "fn": "ws_url",
                "extra": {"location": {"protocol": "http:", "host": "audit.localhost:8765"}},
            }
        )
        assert out["error"] is None, out["error"]
        assert out["wsUrl"] == "ws://audit.localhost:8765/ws/analyze"

    def test_every_declared_dom_id_resolves_in_template(self):
        template = TEMPLATE.read_text(encoding="utf-8")
        template_ids = set(re.findall(r'id="([^"]+)"', template))
        js = APP_JS.read_text(encoding="utf-8")
        declared_ids = set(re.findall(r"getElementById\('([^']+)'\)", js))
        assert declared_ids, "no getElementById calls found in app.js"
        missing = sorted(declared_ids - template_ids)
        assert missing == [], f"DOM ids declared in app.js but missing from index.html: {missing}"
        for cls in ("btn-text", "btn-loader"):
            assert f'class="{cls}' in template or f'class="{cls} ' in template

    def test_websocket_analysis_reuses_streamed_observations_exactly_once(self):
        local = RecordingLocalDetector()
        registry = _registry(local)
        run_all_calls: list = []
        build_kwargs: list = []
        import textforensics.detectors as detectors_mod
        import textforensics.web_ui.main as web_main

        real_run_all = detectors_mod.run_all_detectors
        real_build = web_main.build_forensic_bundle

        def counting_run_all(*args, **kwargs):
            run_all_calls.append((args, kwargs))
            return real_run_all(*args, **kwargs)

        def recording_build(*args, **kwargs):
            build_kwargs.append(kwargs)
            return real_build(*args, **kwargs)

        client = _make_client()
        with (
            _DiscoveryPatch(registry),
            patch.object(detectors_mod, "run_all_detectors", counting_run_all),
            patch.object(web_main, "build_forensic_bundle", recording_build),
            client.websocket_connect("/ws/analyze") as ws,
        ):
            ws.send_json({"type": "analyze", "text": VARIANT_TEXT})
            messages = []
            for _ in range(30):
                msg = ws.receive_json()
                messages.append(msg)
                if msg.get("type") == "complete":
                    break
        assert any(m.get("type") == "complete" for m in messages)
        streamed = [m["data"] for m in messages if m.get("type") == "detector_result"]
        assert streamed, "no detector_result frames were streamed"
        # Base observations are produced exactly once ...
        assert len(run_all_calls) == 1
        # ... and the final bundle reuses them instead of re-running.
        assert len(build_kwargs) == 1
        assert "observations" in build_kwargs[0]
        assert build_kwargs[0]["observations"] == streamed
        # The streamed rows ARE the bundle's detector results.
        bundle_data = next(m["data"] for m in messages if m.get("type") == "complete")
        assert bundle_data["detector_results"] == streamed
        # Base detector ran once on the original text; the other calls
        # are the three benign-variant robustness probes (the
        # "original" variant reuses the base prediction and does not
        # re-call detect).
        from textforensics.features import benign_variants

        variants = benign_variants(VARIANT_TEXT)
        expected_calls = sorted(
            [VARIANT_TEXT] + [v for k, v in variants.items() if k != "original"]
        )
        assert sorted(local.calls) == expected_calls
        assert local.calls.count(VARIANT_TEXT) == 1

    def test_build_with_observations_matches_build_without(self):
        local = RecordingLocalDetector()
        registry = _registry(local)
        with _DiscoveryPatch(registry):
            from textforensics.detectors import run_all_detectors

            observations = run_all_detectors(TEXT)
            plain = build_forensic_bundle(
                TEXT, deterministic=True, fixed_timestamp="2026-11-15T00:00:00+00:00"
            ).to_dict()
            reused = build_forensic_bundle(
                TEXT,
                deterministic=True,
                fixed_timestamp="2026-11-15T00:00:00+00:00",
                observations=observations,
            ).to_dict()
        assert reused == plain

    def test_build_with_observations_reproduces_failures(self):
        good = RecordingLocalDetector()
        failing = _FailingLocalDetector()
        registry = _registry(good, failing)
        with _DiscoveryPatch(registry):
            from textforensics.detectors import run_all_detectors

            observations = run_all_detectors(TEXT)
            assert any(row.get("failed") for row in observations)
            plain = build_forensic_bundle(
                TEXT, deterministic=True, fixed_timestamp="2026-11-15T00:00:00+00:00"
            ).to_dict()
            reused = build_forensic_bundle(
                TEXT,
                deterministic=True,
                fixed_timestamp="2026-11-15T00:00:00+00:00",
                observations=observations,
            ).to_dict()
        assert reused == plain
        assert reused["detector_failures"] == plain["detector_failures"]
        assert len(reused["detector_failures"]) == 1

    def test_build_with_observations_rejects_unknown_detector(self):
        local = RecordingLocalDetector()
        registry = _registry(local)
        with _DiscoveryPatch(registry):
            bogus = [
                {
                    "detector_id": "audit.example/not-installed",
                    "detector_version": "1",
                    "detector_family": "local-recording",
                    "score": 0.5,
                    "verdict": "ai_like",
                }
            ]
            with pytest.raises(ValueError):
                build_forensic_bundle(TEXT, observations=bogus)


# ── IF-10 session bookkeeping ───────────────────────────────────────


@pytest.mark.skipif(not HAS_FASTAPI, reason="fastapi not installed")
class TestIF10Sessions:
    def _join(self, ws, session_id, name):
        ws.send_json({"type": "join_session", "session_id": session_id, "display_name": name})
        reply = ws.receive_json()
        assert reply["type"] == "session_joined", reply
        return reply

    def test_leave_session_releases_user_and_removes_empty_session(self):
        client = _make_client()
        session_id = client.post("/api/session").json()["session_id"]
        with client.websocket_connect("/ws/analyze") as ws:
            self._join(ws, session_id, "Alice")
            ws.send_json({"type": "leave_session"})
            reply = ws.receive_json()
            assert reply["type"] == "session_left"
            assert reply["session_id"] == session_id
        assert client.get(f"/api/session/{session_id}").status_code == 404
        assert client.get(f"/api/session/{session_id}/users").json() == []

    def test_normal_disconnect_releases_user(self):
        client = _make_client()
        session_id = client.post("/api/session").json()["session_id"]
        with client.websocket_connect("/ws/analyze") as ws:
            self._join(ws, session_id, "Alice")
            ws.send_json({"type": "leave_session"})
            assert ws.receive_json()["type"] == "session_left"
        # Socket closed after an explicit leave: nothing remains.
        assert client.get(f"/api/session/{session_id}").status_code == 404

    def test_abnormal_disconnect_releases_user(self):
        client = _make_client()
        session_id = client.post("/api/session").json()["session_id"]
        with client.websocket_connect("/ws/analyze") as ws:
            self._join(ws, session_id, "Alice")
            # Close without any leave message: the finally path must clean up.
        assert client.get(f"/api/session/{session_id}").status_code == 404
        assert client.get(f"/api/session/{session_id}/users").json() == []

    def test_duplicate_join_keeps_one_user(self):
        client = _make_client()
        session_id = client.post("/api/session").json()["session_id"]
        with client.websocket_connect("/ws/analyze") as ws:
            self._join(ws, session_id, "Alice")
            self._join(ws, session_id, "Alice")
            info = client.get(f"/api/session/{session_id}").json()
            assert info["user_count"] == 1
        assert client.get(f"/api/session/{session_id}").status_code == 404

    def test_reconnect_replaces_old_socket_reference(self):
        client = _make_client()
        session_id = client.post("/api/session").json()["session_id"]
        with client.websocket_connect("/ws/analyze") as ws_bob:
            self._join(ws_bob, session_id, "Bob")
            with client.websocket_connect("/ws/analyze") as ws:
                self._join(ws, session_id, "Alice")
                assert ws_bob.receive_json()["type"] == "user_joined"
            # Alice's socket is gone; Bob keeps the session alive and
            # no ghost Alice entry remains.
            info = client.get(f"/api/session/{session_id}").json()
            assert info["user_count"] == 1
            assert [u["display_name"] for u in info["users"].values()] == ["Bob"]
            with client.websocket_connect("/ws/analyze") as ws:
                self._join(ws, session_id, "Alice-again")
                assert ws_bob.receive_json()["type"] == "user_joined"
                info = client.get(f"/api/session/{session_id}").json()
                assert info["user_count"] == 2
                names = sorted(u["display_name"] for u in info["users"].values())
                assert names == ["Alice-again", "Bob"]
        assert client.get(f"/api/session/{session_id}").status_code == 404

    def test_last_user_departure_removes_session_others_keep_it(self):
        client = _make_client()
        session_id = client.post("/api/session").json()["session_id"]
        with client.websocket_connect("/ws/analyze") as ws_a:
            self._join(ws_a, session_id, "Alice")
            with client.websocket_connect("/ws/analyze") as ws_b:
                self._join(ws_b, session_id, "Bob")
                assert client.get(f"/api/session/{session_id}").json()["user_count"] == 2
                ws_b.send_json({"type": "leave_session"})
                assert ws_b.receive_json()["type"] == "session_left"
            # Bob left and disconnected; Alice remains, session lives.
            info = client.get(f"/api/session/{session_id}").json()
            assert info["user_count"] == 1
        assert client.get(f"/api/session/{session_id}").status_code == 404

    def test_broadcast_reaches_live_users_exactly_once_never_sender_twice(self):
        client = _make_client()
        session_id = client.post("/api/session").json()["session_id"]
        with client.websocket_connect("/ws/analyze") as ws_a:
            self._join(ws_a, session_id, "Alice")
            with client.websocket_connect("/ws/analyze") as ws_b:
                self._join(ws_b, session_id, "Bob")
                # Alice reads Bob's join broadcast before sharing.
                assert ws_a.receive_json()["type"] == "user_joined"
                # Produce a real stored analysis on Alice's socket.
                ws_a.send_json({"type": "analyze", "text": TEXT})
                assert "complete" in _drain(ws_a)
                # The analyze itself is broadcast to Bob first; consume it.
                first = _recv_or_none(ws_b)
                assert first is not None and first["type"] == "analysis_result_shared", first
                analysis_id = client.get("/api/history?limit=1").json()["entries"][0]["id"]
                ws_a.send_json({"type": "analysis_shared", "analysis_id": analysis_id})
                ack = ws_a.receive_json()
                assert ack["type"] == "analysis_shared"
                assert ack["analysis_id"] == analysis_id
                assert "data" not in ack  # ack only; the broadcast is separate
                shared = _recv_or_none(ws_b)
                assert shared is not None, "Bob never received the shared analysis"
                assert shared["type"] == "analysis_shared"
                assert shared["analysis_id"] == analysis_id
                assert shared["data"]["consensus"]["verdict"] in {
                    "ai_like",
                    "human_like",
                    "abstain",
                    "insufficient_evidence",
                    "mixed",
                }
                # No second copy for Bob.
                assert _recv_or_none(ws_b, timeout=2.0) is None

    def test_analyze_broadcast_reaches_peer_in_joined_session(self):
        client = _make_client()
        session_id = client.post("/api/session").json()["session_id"]
        with client.websocket_connect("/ws/analyze") as ws_a:
            self._join(ws_a, session_id, "Alice")
            with client.websocket_connect("/ws/analyze") as ws_b:
                self._join(ws_b, session_id, "Bob")
                assert ws_a.receive_json()["type"] == "user_joined"
                ws_a.send_json({"type": "analyze", "text": TEXT})
                assert "complete" in _drain(ws_a)
                shared = _recv_or_none(ws_b)
                assert shared is not None, "Bob never received the analysis broadcast"
                assert shared["type"] == "analysis_result_shared"
                assert "data" in shared
                assert _recv_or_none(ws_b, timeout=2.0) is None

    def test_cleanup_reclaims_stale_sessions_and_keeps_live_ones(self):
        from textforensics.web_ui.main import SessionManager

        live = SessionManager(session_timeout_seconds=3600)
        live_sid = live.create_session()
        live.join_user(live_sid, "ws-live", object(), "Live")
        assert live.cleanup() == 0
        assert live.has_session(live_sid)

        stale = SessionManager(session_timeout_seconds=0)
        stale_sid = stale.create_session()
        stale.join_user(stale_sid, "ws-stale", object(), "Stale")
        assert stale.cleanup() == 1
        assert not stale.has_session(stale_sid)

        empty = SessionManager()
        empty_sid = empty.create_session()
        assert empty.cleanup() == 1
        assert not empty.has_session(empty_sid)

    def test_broadcast_never_sends_to_closed_connections(self):
        import asyncio

        from textforensics.web_ui.main import SessionManager

        async def _run():
            manager = SessionManager()
            sid = manager.create_session()

            class FakeSocket:
                def __init__(self, state):
                    self.client_state = state
                    self.sent: list = []

                async def send_json(self, payload):
                    self.sent.append(payload)

            live = FakeSocket(WebSocketState.CONNECTED)
            dead = FakeSocket(WebSocketState.DISCONNECTED)
            manager.join_user(sid, "ws-live", live, "Live")
            manager.join_user(sid, "ws-dead", dead, "Dead")
            sent = await manager.broadcast(sid, {"type": "ping"})
            assert sent == 1
            assert len(live.sent) == 1
            assert dead.sent == []
            # The dead reference is pruned, not retained.
            assert manager.session_id_for("ws-dead") is None
            assert [u["display_name"] for u in manager.list_users(sid)] == ["Live"]

        asyncio.run(_run())

    def test_session_managers_are_application_scoped(self):
        client_a = _make_client()
        client_b = _make_client()
        session_id = client_a.post("/api/session").json()["session_id"]
        assert client_a.get(f"/api/session/{session_id}").status_code == 200
        assert client_b.get(f"/api/session/{session_id}").status_code == 404


# ── IF-14 exports ───────────────────────────────────────────────────


@pytest.mark.skipif(not HAS_FASTAPI, reason="fastapi not installed")
class TestIF14Exports:
    def _real_data(self, client):
        resp = client.post("/api/analyze", json={"text": TEXT})
        assert resp.status_code == 200
        return resp.json()["data"]

    def test_json_export_is_the_report_not_the_request_envelope(self):
        client = _make_client()
        data = self._real_data(client)
        resp = client.post("/api/export", json={"data": data, "format": "json"})
        assert resp.status_code == 200
        assert "application/json" in resp.headers["content-type"]
        assert resp.headers["content-disposition"].endswith('.json"')
        parsed = json.loads(resp.content.decode("utf-8"))
        assert parsed == data
        assert "format" not in parsed
        assert "data" not in parsed

    def test_csv_export_parses_and_agrees_with_api_export(self):
        client = _make_client()
        data = self._real_data(client)
        resp = client.post("/api/export", json={"data": data, "format": "csv"})
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]
        assert resp.headers["content-disposition"].endswith('.csv"')
        content = resp.content.decode("utf-8")
        assert not content.lstrip().startswith("{")
        rows = list(csv.reader(io.StringIO(content)))
        assert rows[0] == ["Section", "Field", "Value"]
        by_field = {(r[0], r[1]): r[2] for r in rows if len(r) == 3}
        assert by_field[("Consensus", "Verdict")] == data["consensus"]["verdict"]
        assert by_field[("Consensus", "Calibrated AI Probability")] == "Not calibrated"
        assert by_field[("Consensus", "Ensemble Calibration ID")] == "Not calibrated"
        # Abstention/limitations + provenance preserved.
        assert any(row and row[0] == "Limitations" for row in rows)
        limitations = [row[2] for row in rows if row and row[0] == "Limitations"]
        assert len(limitations) == len(data["limitations"])
        assert any("not proof of authorship" in lim for lim in limitations)
        assert any(data["content_sha256"] in row for row in rows)

    def test_html_export_parses_and_agrees_with_api_export(self):
        client = _make_client()
        data = self._real_data(client)
        resp = client.post("/api/export", json={"data": data, "format": "html"})
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert resp.headers["content-disposition"].endswith('.html"')
        content = resp.content.decode("utf-8")
        assert not content.lstrip().startswith("{")

        class _Parser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.tags: list[str] = []

            def handle_starttag(self, tag, attrs):
                self.tags.append(tag)

        parser = _Parser()
        parser.feed(content)  # raises on malformed input
        assert "html" in parser.tags
        assert data["consensus"]["verdict"] in content or "Abstain" in content
        assert "Not calibrated" in content
        assert data["content_sha256"][:16] in content
        assert any(lim[:40] in content for lim in data["limitations"])

    def test_csv_and_html_agree_with_json_on_verdict_and_provenance(self):
        client = _make_client()
        data = self._real_data(client)
        verdict = data["consensus"]["verdict"]
        sha = data["content_sha256"]
        for fmt in ("csv", "html"):
            resp = client.post("/api/export", json={"data": data, "format": fmt})
            assert resp.status_code == 200
            content = resp.content.decode("utf-8")
            assert verdict in content or "Abstain" in content
            assert sha in content or sha[:16] in content

    def test_export_serializer_is_formula_safe_and_escapes_metadata(self):
        from textforensics.web_ui.main import _build_html_report, _write_csv_report

        hostile = {
            "schema": "textforensics.forensic-bundle/v1",
            "consensus": {
                "verdict": "ai_like",
                "calibrated_ai_probability": 0.5,
                "ensemble_calibration_id": "<script>cal</script>",
                "independent_families": 1,
            },
            "detector_results": [
                {
                    "detector_id": "=2+5",
                    "detector_version": "+cmd",
                    "detector_family": "@evil",
                    "score": 0.5,
                    "verdict": "ai_like",
                    "calibrated_ai_probability": 0.5,
                },
                {
                    "detector_id": '\t=HYPERLINK("http://example.invalid")',
                    "detector_version": "-x",
                    "detector_family": "plain",
                    "score": 0.5,
                    "verdict": "ai_like",
                    "calibrated_ai_probability": None,
                },
            ],
            "trust_map": {"overall": "partial", "dimensions": []},
            "input": {"word_count": 10, "sentence_count": 1, "paragraph_count": 1},
            "content_sha256": "ab" * 32,
            "generated_at_utc": "2026-11-15T00:00:00+00:00",
            "limitations": ["<script>alert(1)</script>"],
        }
        buf = io.StringIO()
        _write_csv_report(csv.writer(buf), hostile)
        rows = list(csv.reader(io.StringIO(buf.getvalue())))
        for row in rows:
            for cell in row:
                assert not re.match(r"^[=+\-@\t\r]", cell), f"formula-unsafe cell: {cell!r}"
        assert any(cell.startswith("'=") for row in rows for cell in row)
        html = _build_html_report(hostile)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html
        assert "50.0%" in html
        assert "&lt;script&gt;cal&lt;/script&gt;" in html

    def test_js_export_routes_through_api_export_for_each_format(self):
        bundle = _real_bundle()
        for fmt, content_type in (
            ("json", "application/json"),
            ("csv", "text/csv"),
            ("html", "text/html"),
        ):
            body = {"verdict": bundle["consensus"]["verdict"]}
            out = _run_harness(
                {
                    "fn": "export",
                    "bundle": bundle,
                    "extra": {
                        "format": fmt,
                        "response": {
                            "contentType": content_type,
                            "disposition": (
                                f'attachment; filename="textforensics-report-20261115T120000.{fmt}"'
                            ),
                            "body": json.dumps(body)
                            if fmt == "json"
                            else "Section,Field,Value\n"
                            if fmt == "csv"
                            else "<!DOCTYPE html>",
                        },
                    },
                }
            )
            assert out["error"] is None, out["error"]
            assert len(out["fetchCalls"]) == 1
            call = out["fetchCalls"][0]
            assert call["url"] == "/api/export"
            assert call["method"] == "POST"
            request = json.loads(call["body"])
            assert request["format"] == fmt
            assert request["data"] == bundle
            # The download honors the server's content type and filename;
            # no client-side JSON blob is constructed for any format.
            assert out["responseBlobType"] == content_type
            assert out["createdBlobs"] == []
            assert len(out["anchorClicks"]) == 1
            assert out["anchorClicks"][0]["download"].endswith(f".{fmt}")
