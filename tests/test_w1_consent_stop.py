"""W1 Worker A integration tests: IF-01, IF-03, IF-07, S08, CORE-07.

Written from the stated expected results (plan rule 3). A recording
remote adapter stands in for a discovered remote plugin: it performs
no network I/O, so call counts demonstrate dispatch/consent failure,
not an actual external transmission (as in the audit probes).
"""

from __future__ import annotations

import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from textforensics.detectors import (  # noqa: E402
    DETECTOR_SCHEMA_V2,
    BuiltinHeuristicDetector,
    DetectorPrediction,
    DetectorRegistry,
)
from textforensics.emergency_stop import EmergencyStopError  # noqa: E402
from textforensics.execution_policy import ExecutionPolicy  # noqa: E402
from textforensics.report import _robustness_for_detector, build_forensic_bundle  # noqa: E402

TEXT = (
    "I ran this test yesterday. The first result looked odd, so I changed "
    "one cable, repeated it, and wrote down the second result. The morning "
    "run was quiet, the afternoon run was louder, and the notes stayed on "
    "the bench the whole time for later review by the team."
)
REMOTE_ID = "audit.example/recording-remote"
REMOTE_ID_B = "audit.example/recording-remote-b"

try:
    import fastapi  # noqa: F401
    from fastapi.testclient import TestClient  # noqa: F401

    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False


def _prediction(detector_id, *, execution="remote", verdict="ai_like", family="remote-recording"):
    return DetectorPrediction(
        schema=DETECTOR_SCHEMA_V2,
        detector_id=detector_id,
        detector_version="1",
        detector_family=family,
        execution=execution,
        score=0.7,
        score_semantics="test native score",
        verdict=verdict,
        threshold=0.5,
        runtime={"mode": execution},
    )


class RecordingRemoteDetector:
    detector_id = REMOTE_ID
    detector_version = "1"
    detector_family = "remote-recording"
    execution = "remote"

    def __init__(self):
        self.calls: list[str] = []

    def detect(self, text):
        self.calls.append(text)
        return _prediction(self.detector_id)


class RecordingRemoteDetectorB(RecordingRemoteDetector):
    detector_id = REMOTE_ID_B


class RecordingLocalDetector:
    detector_id = "audit.example/recording-local"
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


def _registry(*detectors):
    return DetectorRegistry(
        detectors={d.detector_id: d for d in detectors},
        plugin_health=[],
    )


def _patch_discovery(registry):
    """Patch discovery at its single canonical location.

    All consumers resolve ``discover_detector_registry`` from the
    detectors module at call time, so patching that one attribute
    covers report construction, API, MCP, CLI, WebSocket dispatch and
    the observatory alike.
    """
    return (
        patch(
            "textforensics.detectors.discover_detector_registry",
            return_value=registry,
        ),
    )


class _DiscoveryPatch:
    """Context manager applying both discovery patches."""

    def __init__(self, registry):
        self._patches = _patch_discovery(registry)

    def __enter__(self):
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in reversed(self._patches):
            p.stop()
        return False


# ---------------------------------------------------------------------------
# IF-01 — default report must make zero remote calls
# ---------------------------------------------------------------------------


class TestIf01ReportBoundary(unittest.TestCase):
    def test_default_bundle_makes_zero_remote_calls(self):
        remote = RecordingRemoteDetector()
        bundle = build_forensic_bundle(
            TEXT, detectors=[BuiltinHeuristicDetector(), remote]
        ).to_dict()
        assert remote.calls == []
        assert all(row["detector_id"] != REMOTE_ID for row in bundle["detector_results"])
        assert bundle["provenance"]["execution_policy"]["remote_detector_ids"] == []
        assert bundle["provenance"]["execution_policy"]["remote_consent"] is False

    def test_explicit_consent_authorizes_only_selected_id(self):
        remote_a = RecordingRemoteDetector()
        remote_b = RecordingRemoteDetectorB()
        policy = ExecutionPolicy.with_remote_consent([REMOTE_ID])
        bundle = build_forensic_bundle(
            TEXT,
            detectors=[BuiltinHeuristicDetector(), remote_a, remote_b],
            execution_policy=policy,
        ).to_dict()
        assert len(remote_a.calls) == 4  # main run + 3 benign variants
        assert remote_b.calls == []
        assert any(row["detector_id"] == REMOTE_ID for row in bundle["detector_results"])
        assert all(row["detector_id"] != REMOTE_ID_B for row in bundle["detector_results"])
        assert bundle["provenance"]["execution_policy"]["remote_detector_ids"] == [REMOTE_ID]

    def test_consent_to_unknown_id_is_rejected(self):
        remote = RecordingRemoteDetector()
        policy = ExecutionPolicy.with_remote_consent(["audit.example/no-such-detector"])
        with pytest.raises(ValueError):
            build_forensic_bundle(
                TEXT,
                detectors=[BuiltinHeuristicDetector(), remote],
                execution_policy=policy,
            )
        assert remote.calls == []

    def test_remote_prediction_without_consent_is_discarded(self):
        """An adapter that only reveals remoteness in its prediction
        (no `execution` attribute) must never contribute a result.

        Its remoteness is unknowable before the first call (the builtin
        detector likewise declares no `execution` attribute), so the
        call happens once to learn it — but the remote prediction is
        refused and recorded as a consent failure, never as evidence.
        """

        class SneakyRemote:
            detector_id = "audit.example/sneaky-remote"
            detector_version = "1"
            detector_family = "remote-recording"

            def __init__(self):
                self.calls: list[str] = []

            def detect(self, text):
                self.calls.append(text)
                return _prediction(self.detector_id)

        sneaky = SneakyRemote()
        bundle = build_forensic_bundle(
            TEXT, detectors=[BuiltinHeuristicDetector(), sneaky]
        ).to_dict()
        assert len(sneaky.calls) == 1
        assert all(row["detector_id"] != sneaky.detector_id for row in bundle["detector_results"])
        assert any(
            row["detector_id"] == sneaky.detector_id and row["error_type"] == "RemoteNotConsented"
            for row in bundle["detector_failures"]
        )

    def test_benign_variants_cannot_widen_authorized_set(self):
        remote = RecordingRemoteDetector()
        build_forensic_bundle(TEXT, detectors=[BuiltinHeuristicDetector(), remote])
        assert remote.calls == []


@pytest.mark.skipif(not HAS_FASTAPI, reason="fastapi not installed")
class TestIf01Api:
    def _client(self):
        from fastapi.testclient import TestClient

        from textforensics.api import create_app
        from textforensics.config import Settings

        app = create_app(
            Settings(
                host="127.0.0.1",
                port=8765,
                max_input_bytes=100_000,
                allow_remote=False,
                access_log=False,
                log_level="INFO",
            )
        )
        return TestClient(app, raise_server_exceptions=False)

    def test_api_default_report_makes_zero_remote_calls(self):
        remote = RecordingRemoteDetector()
        registry = _registry(BuiltinHeuristicDetector(), remote)
        with _DiscoveryPatch(registry):
            response = self._client().post("/v1/report", json={"text": TEXT})
        assert response.status_code == 200
        assert remote.calls == []

    def test_api_explicit_consent_calls_only_selected_id(self):
        remote_a = RecordingRemoteDetector()
        remote_b = RecordingRemoteDetectorB()
        registry = _registry(BuiltinHeuristicDetector(), remote_a, remote_b)
        with _DiscoveryPatch(registry):
            response = self._client().post(
                "/v1/report",
                json={
                    "text": TEXT,
                    "remote_detector_ids": [REMOTE_ID],
                    "remote_consent": True,
                },
            )
        assert response.status_code == 200
        assert len(remote_a.calls) == 4
        assert remote_b.calls == []

    def test_api_ids_without_consent_are_rejected(self):
        remote = RecordingRemoteDetector()
        registry = _registry(BuiltinHeuristicDetector(), remote)
        with _DiscoveryPatch(registry):
            response = self._client().post(
                "/v1/report",
                json={"text": TEXT, "remote_detector_ids": [REMOTE_ID]},
            )
        assert response.status_code == 422
        assert remote.calls == []

    def test_api_consent_without_ids_is_rejected(self):
        remote = RecordingRemoteDetector()
        registry = _registry(BuiltinHeuristicDetector(), remote)
        with _DiscoveryPatch(registry):
            response = self._client().post(
                "/v1/report",
                json={"text": TEXT, "remote_consent": True},
            )
        assert response.status_code == 422
        assert remote.calls == []

    def test_api_unknown_remote_id_is_rejected(self):
        remote = RecordingRemoteDetector()
        registry = _registry(BuiltinHeuristicDetector(), remote)
        with _DiscoveryPatch(registry):
            response = self._client().post(
                "/v1/report",
                json={
                    "text": TEXT,
                    "remote_detector_ids": ["audit.example/no-such-detector"],
                    "remote_consent": True,
                },
            )
        assert response.status_code == 422
        assert remote.calls == []


class TestIf01Mcp:
    def _call(self, name, **kwargs):
        from textforensics.mcp_server import _server

        server = _server()

        async def _run():
            return await server.call_tool(name, kwargs)

        return asyncio.run(_run())

    @staticmethod
    def _text(result):
        content = getattr(result, "content", None) or result
        if isinstance(content, list) and content:
            first = content[0]
            return getattr(first, "text", None) or str(first)
        return str(content)

    def test_mcp_default_report_makes_zero_remote_calls(self):
        pytest.importorskip("mcp")
        remote = RecordingRemoteDetector()
        registry = _registry(BuiltinHeuristicDetector(), remote)
        with _DiscoveryPatch(registry):
            result = self._call("build_forensic_report", text=TEXT)
        payload = json.loads(self._text(result))
        assert remote.calls == []
        assert all(row["detector_id"] != REMOTE_ID for row in payload["detector_results"])

    def test_mcp_explicit_consent_calls_only_selected_id(self):
        pytest.importorskip("mcp")
        remote = RecordingRemoteDetector()
        registry = _registry(BuiltinHeuristicDetector(), remote)
        with _DiscoveryPatch(registry):
            result = self._call(
                "build_forensic_report",
                text=TEXT,
                remote_detector_ids=[REMOTE_ID],
                remote_consent=True,
            )
        payload = json.loads(self._text(result))
        assert len(remote.calls) == 4
        assert any(row["detector_id"] == REMOTE_ID for row in payload["detector_results"])


class TestIf01Cli(unittest.TestCase):
    def _run_main(self, argv):
        import sys
        from io import StringIO

        from textforensics.cli import main

        old_argv, old_stdout, old_stderr = sys.argv, sys.stdout, sys.stderr
        try:
            sys.argv = ["textforensics", *argv]
            sys.stdout, sys.stderr = StringIO(), StringIO()
            code = main()
            return code, sys.stdout.getvalue(), sys.stderr.getvalue()
        finally:
            sys.argv, sys.stdout, sys.stderr = old_argv, old_stdout, old_stderr

    def test_cli_default_report_makes_zero_remote_calls(self):
        remote = RecordingRemoteDetector()
        registry = _registry(BuiltinHeuristicDetector(), remote)
        with _DiscoveryPatch(registry):
            code, out, _err = self._run_main(["report", "--text", TEXT])
        assert code == 0
        payload = json.loads(out)
        assert remote.calls == []
        assert all(row["detector_id"] != REMOTE_ID for row in payload["detector_results"])

    def test_cli_explicit_remote_detector_is_consented(self):
        remote = RecordingRemoteDetector()
        registry = _registry(BuiltinHeuristicDetector(), remote)
        with _DiscoveryPatch(registry):
            code, out, _err = self._run_main(
                ["report", "--text", TEXT, "--remote-detector", REMOTE_ID]
            )
        assert code == 0
        payload = json.loads(out)
        assert len(remote.calls) == 4
        assert any(row["detector_id"] == REMOTE_ID for row in payload["detector_results"])

    def test_cli_unknown_remote_detector_is_rejected(self):
        remote = RecordingRemoteDetector()
        registry = _registry(BuiltinHeuristicDetector(), remote)
        with _DiscoveryPatch(registry):
            code, _out, err = self._run_main(
                ["report", "--text", TEXT, "--remote-detector", "audit.example/nope"]
            )
        assert code != 0
        assert remote.calls == []


# ---------------------------------------------------------------------------
# IF-03 — emergency stop gates every dispatch path, including WebSocket
# ---------------------------------------------------------------------------


class TestIf03StopBetweenDetectors(unittest.TestCase):
    def test_stop_activated_by_first_detector_blocks_second(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            sentinel = Path(tmp) / "stop"
            import os

            os.environ["TEXTFORENSICS_EMERGENCY_STOP"] = str(sentinel)
            try:
                first_calls: list[str] = []
                second_calls: list[str] = []

                class First(RecordingLocalDetector):
                    detector_id = "audit.example/first"

                    def detect(self, text):
                        first_calls.append(text)
                        sentinel.write_text("stop\n", encoding="utf-8")
                        return _prediction(
                            self.detector_id,
                            execution="local",
                            verdict="human_like",
                            family="local-recording",
                        )

                class Second(RecordingLocalDetector):
                    detector_id = "audit.example/second"

                    def detect(self, text):
                        second_calls.append(text)
                        return _prediction(
                            self.detector_id,
                            execution="local",
                            verdict="human_like",
                            family="local-recording",
                        )

                with pytest.raises(EmergencyStopError):
                    build_forensic_bundle(TEXT, detectors=[First(), Second()])
                assert len(first_calls) == 1
                assert second_calls == []
            finally:
                os.environ.pop("TEXTFORENSICS_EMERGENCY_STOP", None)


@pytest.mark.skipif(not HAS_FASTAPI, reason="fastapi not installed")
class TestIf03WebSocket:
    @staticmethod
    def _drain(ws):
        types = []
        for _ in range(20):
            data = ws.receive_json()
            types.append(data.get("type"))
            if data.get("type") in {"error", "complete"}:
                break
        return types

    def _client(self):
        from fastapi.testclient import TestClient

        from textforensics.config import Settings
        from textforensics.web_ui.main import create_web_app

        app = create_web_app(
            Settings(
                host="127.0.0.1",
                port=8765,
                max_input_bytes=100_000,
                allow_remote=False,
                access_log=False,
                log_level="INFO",
            )
        )
        return TestClient(app, raise_server_exceptions=False)

    def test_stop_before_connect_prevents_analysis(self, tmp_path, monkeypatch):
        remote = RecordingRemoteDetector()
        registry = _registry(BuiltinHeuristicDetector(), remote)
        sentinel = tmp_path / "stop"
        sentinel.write_text("stop\n", encoding="utf-8")
        monkeypatch.setenv("TEXTFORENSICS_EMERGENCY_STOP", str(sentinel))
        with (
            _DiscoveryPatch(registry),
            self._client().websocket_connect("/ws/analyze") as ws,
        ):
            ws.send_json({"type": "analyze", "text": TEXT})
            types = self._drain(ws)
        # The dispatch gate (this worker) guarantees zero detector calls
        # and an error instead of results. The handshake/pre-"started"
        # refusal is Worker C's wiring on top of the same shared gate.
        assert "error" in types
        assert "complete" not in types
        assert "detector_result" not in types
        assert remote.calls == []

    def test_stop_after_connect_before_analyze_prevents_analysis(self, tmp_path, monkeypatch):
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
            types = self._drain(ws)
        assert "error" in types
        assert "complete" not in types
        assert "detector_result" not in types
        assert remote.calls == []


# ---------------------------------------------------------------------------
# IF-07 — API validation errors must not echo submitted text
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_FASTAPI, reason="fastapi not installed")
class TestIf07ApiErrors:
    def _client(self, max_input_bytes=1024):
        from fastapi.testclient import TestClient

        from textforensics.api import create_app
        from textforensics.config import Settings

        app = create_app(
            Settings(
                host="127.0.0.1",
                port=8765,
                max_input_bytes=max_input_bytes,
                allow_remote=False,
                access_log=False,
                log_level="INFO",
            )
        )
        return TestClient(app, raise_server_exceptions=False)

    def test_malformed_text_type_does_not_echo_input(self):
        response = self._client().post("/v1/report", json={"text": ["SENSITIVE-PROBE-INPUT"]})
        assert response.status_code == 422
        assert "SENSITIVE-PROBE-INPUT" not in response.text

    def test_oversize_text_is_413_without_echo(self):
        response = self._client().post("/v1/report", json={"text": "x" * 5000})
        assert response.status_code == 413
        assert "xxxxx" not in response.text


# ---------------------------------------------------------------------------
# S08 — take_snapshot honors the emergency stop
# ---------------------------------------------------------------------------


class TestS08ObservatoryStop(unittest.TestCase):
    def _observatory(self):
        from textforensics.observatory import DriftObservatory

        corpus = {
            "samples": [
                {
                    "id": f"sample-{i:02d}",
                    "text": (
                        "This is sample text number "
                        f"{i} that is long enough to trigger analysis. "
                        "It has more than enough words to meet minimum "
                        "length requirements for drift tracking."
                    ),
                    "metadata": {"label": "human", "domain": "general"},
                }
                for i in range(1, 4)
            ]
        }
        return DriftObservatory(corpus=corpus)

    def test_stop_active_prevents_snapshot_execution(self):
        import os
        import tempfile

        obs = self._observatory()
        local = RecordingLocalDetector()
        with tempfile.TemporaryDirectory() as tmp:
            sentinel = Path(tmp) / "stop"
            sentinel.write_text("stop\n", encoding="utf-8")
            os.environ["TEXTFORENSICS_EMERGENCY_STOP"] = str(sentinel)
            try:
                with pytest.raises(EmergencyStopError):
                    obs.take_snapshot(detectors=[local])
            finally:
                os.environ.pop("TEXTFORENSICS_EMERGENCY_STOP", None)
        assert local.calls == []
        assert obs.snapshots == []

    def test_stop_after_first_sample_blocks_rest(self):
        import os
        import tempfile

        obs = self._observatory()
        with tempfile.TemporaryDirectory() as tmp:
            sentinel = Path(tmp) / "stop"
            os.environ["TEXTFORENSICS_EMERGENCY_STOP"] = str(sentinel)
            try:
                calls: list[str] = []

                class ArmingDetector(RecordingLocalDetector):
                    def detect(self, text):
                        calls.append(text)
                        sentinel.write_text("stop\n", encoding="utf-8")
                        return _prediction(
                            self.detector_id,
                            execution="local",
                            verdict="human_like",
                            family="local-recording",
                        )

                with pytest.raises(EmergencyStopError):
                    obs.take_snapshot(detectors=[ArmingDetector()])
            finally:
                os.environ.pop("TEXTFORENSICS_EMERGENCY_STOP", None)
        assert len(calls) == 1
        assert obs.snapshots == []

    def test_stop_blocks_opted_in_remote_snapshot(self):
        import os
        import tempfile

        obs = self._observatory()
        remote = RecordingRemoteDetector()
        with tempfile.TemporaryDirectory() as tmp:
            sentinel = Path(tmp) / "stop"
            sentinel.write_text("stop\n", encoding="utf-8")
            os.environ["TEXTFORENSICS_EMERGENCY_STOP"] = str(sentinel)
            try:
                with pytest.raises(EmergencyStopError):
                    obs.take_snapshot(detectors=[remote], allow_remote=True)
            finally:
                os.environ.pop("TEXTFORENSICS_EMERGENCY_STOP", None)
        assert remote.calls == []
        assert obs.snapshots == []


# ---------------------------------------------------------------------------
# CORE-07 (W1 side) — failed probes must not yield supported stability
# ---------------------------------------------------------------------------


class TestCore07RobustnessCompleteness(unittest.TestCase):
    def test_failed_probes_never_yield_supported_stability(self):
        class Flaky:
            detector_id = "fake/flaky"
            detector_version = "1"
            detector_family = "flaky-family"

            def __init__(self):
                self.calls = 0

            def detect(self, text):
                self.calls += 1
                if self.calls > 1:
                    raise RuntimeError("probe failure")
                return DetectorPrediction(
                    schema="textforensics.detector-result/v1",
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    detector_family=self.detector_family,
                    execution="local",
                    score=0.5,
                    score_semantics="test",
                    verdict="ai_like",
                    threshold=0.5,
                )

        detector = Flaky()
        original = detector.detect(TEXT)
        row = _robustness_for_detector(detector, TEXT, original)
        completeness = row["completeness"]
        assert completeness == {
            "selected": 4,
            "attempted": 4,
            "succeeded": 1,
            "abstained": 0,
            "failed": 3,
            "is_complete": True,
            "support_eligible": False,
        }
        # Survivor-only stability is still visible, but it is NOT the
        # verdict_stability the Trust Map consumes.
        assert row["verdict_stability_survivors"] == 1.0
        assert row["verdict_stability"] is None

        bundle = build_forensic_bundle(TEXT, detectors=[Flaky()]).to_dict()
        benign = next(
            dim
            for dim in bundle["trust_map"]["dimensions"]
            if dim["dimension"] == "benign_stability"
        )
        assert benign["state"] != "supported"

    def test_complete_stable_probes_keep_stability(self):
        detector = RecordingLocalDetector()
        prediction = detector.detect(TEXT)
        row = _robustness_for_detector(detector, TEXT, prediction)
        assert row["completeness"]["support_eligible"] is True
        assert row["verdict_stability"] == 1.0

    def test_all_abstentions_never_yield_supported_stability(self):
        class Abstaining:
            detector_id = "fake/abstaining"
            detector_version = "1"
            detector_family = "abstain-family"

            def detect(self, text):
                return _prediction(
                    self.detector_id,
                    execution="local",
                    verdict="abstain",
                    family="abstain-family",
                )

        detector = Abstaining()
        original = detector.detect(TEXT)
        row = _robustness_for_detector(detector, TEXT, original)
        assert row["completeness"]["succeeded"] == 0
        assert row["completeness"]["abstained"] == 4
        assert row["completeness"]["support_eligible"] is False
        assert row["verdict_stability"] is None
