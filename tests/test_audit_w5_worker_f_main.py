"""Kill tests for the web_ui.main mutation survivors (audit wave W5, worker F).

Every test pins a behaviour that a surviving cosmic-ray mutant changes:
direct unit tests for ``_validate_shared_bundle`` / ``SessionManager`` /
``_calibrated_display`` / the report builders, and TestClient tests for the
history ring buffer and the websocket handler. The per-position
classification (which mutants each test kills) is recorded in
``hidden_files/audit-w5-f-triage-main.txt`` and in the worker-F part-report.
"""

import asyncio
import copy
import csv
import io
import json
import queue
import threading
from datetime import UTC, datetime, timedelta

import pytest

try:
    from fastapi.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect, WebSocketState

    HAS_FASTAPI = True
except ImportError:  # pragma: no cover - fastapi is an extra
    HAS_FASTAPI = False

from test_audit_w5_worker_a import _drain, _recv_or_none
from test_w1_consent_stop import TEXT

from textforensics.web_ui.main import (
    _MAX_HISTORY_ENTRY_BYTES,
    SessionManager,
    _build_comparison,
    _build_html_report,
    _calibrated_display,
    _validate_shared_bundle,
    _write_csv_report,
    _ws_error_body,
)

pytestmark = pytest.mark.skipif(not HAS_FASTAPI, reason="fastapi not installed")

CALIBRATION_ID = "ens-cal-2026-11-01"


# ── local client factory ─────────────────────────────────────────────


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


def _make_client_app(max_input_bytes: int = 100_000):
    """(TestClient, app) -- for tests that need app.state.session_manager."""
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
    return TestClient(app, raise_server_exceptions=False, base_url="http://testserver"), app


def _new_session(client) -> str:
    return client.post("/api/session").json()["session_id"]


def _join(ws, session_id, name="P"):
    ws.send_json({"type": "join_session", "session_id": session_id, "display_name": name})
    reply = ws.receive_json()
    assert reply["type"] == "session_joined", reply
    return reply


def _assert_error(reply, status: int):
    # Both the code and the message must match: the "Empty text
    # provided" error shares the 422 error_code ("invalid_request")
    # but has a different message, so the code alone cannot tell
    # a 422 from an analyze-branch empty-text error.
    expected = _ws_error_body(status)
    assert reply["type"] == "error", reply
    assert reply["error_code"] == expected["error_code"], reply
    assert reply["message"] == expected["message"], reply


def _follow_up(ws, payload, timeout: float = 10.0):
    """Send `payload` and return the reply, failing (not hanging) if the
    socket was closed.

    A `continue` -> `break` mutant closes the connection after the
    first error message; the next send/receive on the dead socket can
    block forever in the TestClient portal, so the follow-up runs in a
    daemon thread with a deadline. A timeout fails the test (a kill);
    a prompt WebSocketDisconnect is re-raised (also a kill).
    """
    box: queue.Queue = queue.Queue()

    def _run() -> None:
        try:
            ws.send_json(payload)
            box.put(ws.receive_json())
        except Exception as exc:  # noqa: BLE001 - report as a reply
            box.put(exc)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    try:
        item = box.get(timeout=timeout)
    except queue.Empty:
        pytest.fail("no reply to the follow-up message: the connection is closed")
    if isinstance(item, Exception):
        raise item
    return item


# ── _validate_shared_bundle ──────────────────────────────────────────


def _valid_bundle() -> dict:
    return {
        "consensus": {"verdict": "ai_like"},
        "detector_results": [
            {
                "verdict": "ai_like",
                "detector_id": "d1",
                "detector_version": "1",
                "detector_family": "fam",
                "score": 0.5,
            }
        ],
        "content_sha256": "ab" * 32,
    }


def _with_consensus(**kw) -> dict:
    data = _valid_bundle()
    data["consensus"].update(kw)
    return data


def _with_row(**kw) -> dict:
    data = _valid_bundle()
    data["detector_results"][0].update(kw)
    return data


def _bare_row_bundle() -> dict:
    """A bundle whose only detector row carries no optional fields."""
    data = _valid_bundle()
    data["detector_results"] = [{"verdict": "ai_like"}]
    return data


def _assert_valid(data) -> None:
    _validate_shared_bundle(data)  # must not raise


def _assert_invalid(data) -> None:
    with pytest.raises(ValueError):
        _validate_shared_bundle(data)


def _bundle_of_size(n: int) -> dict:
    """A valid bundle whose JSON size (ensure_ascii=False) is exactly n bytes."""
    data = _valid_bundle()
    data["padding"] = ""
    size = len(json.dumps(data, ensure_ascii=False).encode("utf-8"))
    data["padding"] = "x" * (n - size)
    assert len(json.dumps(data, ensure_ascii=False).encode("utf-8")) == n
    return data


class TestValidateSharedBundle:
    def test_valid_bundle_passes(self):
        _assert_valid(_valid_bundle())
        _assert_valid(_bare_row_bundle())

    def test_non_mapping_is_rejected(self):
        _assert_invalid(["not", "a", "dict"])

    def test_unserializable_bundle_is_rejected(self):
        data = _valid_bundle()
        data["tags"] = {"a", "b"}  # a set is not JSON-serializable (TypeError)
        _assert_invalid(data)

    def test_circular_bundle_is_rejected(self):
        data = _valid_bundle()
        data["self"] = data  # json.dumps raises ValueError on a cycle
        _assert_invalid(data)

    def test_non_ascii_counts_as_utf8_not_escaped(self):
        # UTF-8 size under the quota, escaped size over it: the validator
        # measures UTF-8 bytes (ensure_ascii=False).
        data = _valid_bundle()
        data["padding"] = "\u00e9" * 16000  # 2 bytes UTF-8, 6 escaped
        utf8 = len(json.dumps(data, ensure_ascii=False).encode("utf-8"))
        escaped = len(json.dumps(data, ensure_ascii=True).encode("utf-8"))
        assert utf8 <= _MAX_HISTORY_ENTRY_BYTES < escaped
        _assert_valid(data)

    def test_bundle_at_quota_is_accepted(self):
        _assert_valid(_bundle_of_size(_MAX_HISTORY_ENTRY_BYTES))

    def test_bundle_over_quota_is_rejected(self):
        _assert_invalid(_bundle_of_size(_MAX_HISTORY_ENTRY_BYTES + 1))

    def test_consensus_must_be_a_mapping(self):
        data = _valid_bundle()
        data["consensus"] = ["ai_like"]
        _assert_invalid(data)

    def test_consensus_verdict_must_be_known(self):
        for bad in (None, "bogus", 123):
            _assert_invalid(_with_consensus(verdict=bad))

    def test_legacy_ai_probability_is_rejected(self):
        _assert_invalid(_with_consensus(ai_probability=0.5))

    def test_calibrated_bool_is_rejected(self):
        # The calibration identity is present, so only the range/type
        # check can raise: without it the pair check would mask the mutant.
        _assert_invalid(
            _with_consensus(calibrated_ai_probability=True, ensemble_calibration_id=CALIBRATION_ID)
        )

    def test_calibrated_string_is_rejected(self):
        # "0.5" parses as a number but is not a number: the type check
        # must fire before any float() conversion.
        _assert_invalid(
            _with_consensus(calibrated_ai_probability="0.5", ensemble_calibration_id=CALIBRATION_ID)
        )

    def test_calibrated_below_zero_is_rejected(self):
        _assert_invalid(
            _with_consensus(calibrated_ai_probability=-0.5, ensemble_calibration_id=CALIBRATION_ID)
        )

    def test_calibrated_above_one_is_rejected(self):
        _assert_invalid(
            _with_consensus(calibrated_ai_probability=1.5, ensemble_calibration_id=CALIBRATION_ID)
        )

    def test_calibrated_boundaries_are_accepted(self):
        _assert_valid(
            _with_consensus(calibrated_ai_probability=0.0, ensemble_calibration_id=CALIBRATION_ID)
        )
        _assert_valid(
            _with_consensus(calibrated_ai_probability=1.0, ensemble_calibration_id=CALIBRATION_ID)
        )

    def test_calibrated_requires_its_identity(self):
        _assert_invalid(_with_consensus(calibrated_ai_probability=0.5))
        _assert_invalid(_with_consensus(ensemble_calibration_id=CALIBRATION_ID))

    def test_calibration_id_must_be_a_nonempty_string(self):
        _assert_invalid(_with_consensus(calibrated_ai_probability=0.5, ensemble_calibration_id=123))
        _assert_invalid(_with_consensus(calibrated_ai_probability=0.5, ensemble_calibration_id=""))

    def test_detector_results_must_be_a_list(self):
        data = _valid_bundle()
        data["detector_results"] = {"verdict": "ai_like"}
        _assert_invalid(data)

    def test_detector_row_must_be_a_mapping(self):
        data = _valid_bundle()
        data["detector_results"] = ["not-a-dict"]
        _assert_invalid(data)

    def test_detector_row_verdict_may_be_absent(self):
        _assert_valid(_bare_row_bundle())

    def test_detector_row_verdict_must_be_known(self):
        for bad in (123, "bogus"):
            _assert_invalid(_with_row(verdict=bad))

    def test_detector_field_must_be_a_short_string(self):
        for key in ("detector_id", "detector_version", "detector_family"):
            _assert_invalid(_with_row(**{key: 123}))
            _assert_invalid(_with_row(**{key: "x" * 257}))

    def test_detector_field_boundaries(self):
        # 255 chars: below the limit (kills the Lt/LtE/NotEq mutants);
        # 256: at the limit (kills Eq/GtE/Is); 257: over it (kills Eq).
        for key in ("detector_id", "detector_version", "detector_family"):
            _assert_valid(_with_row(**{key: "x" * 255}))
            _assert_valid(_with_row(**{key: "x" * 256}))
            _assert_invalid(_with_row(**{key: "x" * 257}))

    def test_detector_score_bool_is_rejected(self):
        _assert_invalid(_with_row(score=True))

    def test_detector_score_string_is_rejected(self):
        _assert_invalid(_with_row(score="0.5"))

    def test_detector_score_nonfinite_is_rejected(self):
        _assert_invalid(_with_row(score=float("nan")))
        _assert_invalid(_with_row(score=float("inf")))
        _assert_invalid(_with_row(score=float("-inf")))

    def test_detector_score_may_be_absent(self):
        _assert_valid(_bare_row_bundle())

    def test_row_calibrated_bool_is_rejected(self):
        _assert_invalid(_with_row(calibrated_ai_probability=True))

    def test_row_calibrated_string_is_rejected(self):
        _assert_invalid(_with_row(calibrated_ai_probability="0.5"))

    def test_row_calibrated_out_of_range_is_rejected(self):
        _assert_invalid(_with_row(calibrated_ai_probability=-0.5))
        _assert_invalid(_with_row(calibrated_ai_probability=1.5))

    def test_row_calibrated_boundaries_are_accepted(self):
        _assert_valid(_with_row(calibrated_ai_probability=0.0))
        _assert_valid(_with_row(calibrated_ai_probability=0.5))
        _assert_valid(_with_row(calibrated_ai_probability=1.0))

    def test_content_sha256_must_be_a_short_string(self):
        _assert_invalid(_valid_bundle() | {"content_sha256": 123})
        _assert_valid(_valid_bundle() | {"content_sha256": "x" * 255})
        _assert_valid(_valid_bundle() | {"content_sha256": "x" * 256})
        _assert_invalid(_valid_bundle() | {"content_sha256": "x" * 257})

    def test_content_sha256_may_be_absent(self):
        data = _valid_bundle()
        del data["content_sha256"]
        _assert_valid(data)


# ── SessionManager ───────────────────────────────────────────────────


class _FakeWS:
    """A stand-in websocket: records sends, optionally fails them."""

    def __init__(self, state=WebSocketState.CONNECTED, fail: bool = False):
        self.client_state = state
        self.sent: list = []
        self.fail = fail

    async def send_json(self, payload):
        if self.fail:
            raise RuntimeError("boom")
        self.sent.append(payload)


def _session_dict(users=None, last_activity: str | None = None) -> dict:
    now = datetime.now(UTC).isoformat()
    return {
        "created_at": now,
        "last_activity": last_activity or now,
        "users": users or {},
        "connections": {},
    }


class _FrozenDateTime:
    """datetime with a fixed now(): makes a session age exactly the timeout."""

    _now = datetime(2026, 11, 15, 12, 0, 0, tzinfo=UTC)

    @classmethod
    def now(cls, tz=None):
        return cls._now

    @classmethod
    def fromisoformat(cls, value):
        return datetime.fromisoformat(value)


class TestSessionManager:
    def test_create_session_at_max_raises(self):
        manager = SessionManager(max_sessions=2)
        for sid in ("s1", "s2"):
            manager.create_session(sid)
            manager.join_user(sid, "k-" + sid, _FakeWS())
        with pytest.raises(ValueError, match="Maximum sessions reached"):
            manager.create_session("s3")

    def test_create_session_over_max_raises(self):
        manager = SessionManager(max_sessions=2)
        for sid in ("s1", "s2"):
            manager.create_session(sid)
            manager.join_user(sid, "k-" + sid, _FakeWS())
        # Inject a third live session directly: the count is now over max.
        manager._sessions["s3"] = _session_dict(users={"k": {}})
        with pytest.raises(ValueError, match="Maximum sessions reached"):
            manager.create_session("s4")

    def test_create_session_evicts_empty_session_when_full(self):
        manager = SessionManager(max_sessions=1)
        manager.create_session("old")  # no users: reclaimable
        assert manager.create_session("new") == "new"
        assert "old" not in manager._sessions

    def test_create_session_returns_existing_id(self):
        manager = SessionManager(max_sessions=1)
        manager.create_session("s1")
        assert manager.create_session("s1") == "s1"

    def test_touch_refreshes_last_activity(self):
        manager = SessionManager()
        manager.create_session("s1")
        manager.join_user("s1", "k1", _FakeWS())
        manager._sessions["s1"]["last_activity"] = "2000-01-01T00:00:00+00:00"
        manager.touch("k1")
        assert manager._sessions["s1"]["last_activity"] != "2000-01-01T00:00:00+00:00"

    def test_touch_unknown_socket_is_a_noop(self):
        manager = SessionManager()
        manager.touch("no-such-key")  # must not raise

    def test_touch_stale_mapping_is_a_noop(self):
        manager = SessionManager()
        manager.create_session("s1")
        manager.join_user("s1", "k1", _FakeWS())
        manager._sessions.pop("s1")  # mapping now points at a gone session
        manager.touch("k1")  # must not raise

    def test_join_full_session_raises_for_a_new_socket(self):
        manager = SessionManager(max_users_per_session=2)
        manager.create_session("s1")
        manager.join_user("s1", "k1", _FakeWS())
        manager.join_user("s1", "k2", _FakeWS())
        with pytest.raises(ValueError, match="Session is full"):
            manager.join_user("s1", "k3", _FakeWS())

    def test_join_over_full_session_raises(self):
        manager = SessionManager(max_users_per_session=2)
        manager.create_session("s1")
        manager.join_user("s1", "k1", _FakeWS())
        manager.join_user("s1", "k2", _FakeWS())
        manager._sessions["s1"]["users"]["k3"] = {"ws_key": "k3"}
        with pytest.raises(ValueError, match="Session is full"):
            manager.join_user("s1", "k4", _FakeWS())

    def test_join_same_socket_when_full_is_allowed(self):
        manager = SessionManager(max_users_per_session=1)
        manager.create_session("s1")
        manager.join_user("s1", "k1", _FakeWS())
        manager.join_user("s1", "k1", _FakeWS())  # re-join: same socket
        assert len(manager._sessions["s1"]["users"]) == 1

    def test_join_missing_session_raises(self):
        manager = SessionManager()
        with pytest.raises(ValueError, match="not found"):
            manager.join_user("no-such-session", "k1", _FakeWS())

    @pytest.mark.parametrize("first,second", [("aaa", "zzz"), ("zzz", "aaa")])
    def test_join_other_session_leaves_the_previous_one(self, first, second):
        manager = SessionManager()
        manager.create_session(first)
        manager.create_session(second)
        ws = _FakeWS()
        manager.join_user(first, "k1", ws)
        manager.join_user(second, "k1", ws)
        assert manager.session_id_for("k1") == second
        assert first not in manager._sessions  # empty session removed on leave

    def test_leave_user_removes_empty_session(self):
        manager = SessionManager()
        manager.create_session("s1")
        manager.join_user("s1", "k1", _FakeWS())
        assert manager.leave_user("k1") == "s1"
        assert "s1" not in manager._sessions
        assert manager.leave_user("k1") is None

    @pytest.mark.asyncio
    async def test_broadcast_to_missing_session_returns_zero(self):
        manager = SessionManager()
        assert await manager.broadcast("nope", {"type": "x"}) == 0

    @pytest.mark.asyncio
    async def test_broadcast_accepts_keyword_arguments(self):
        manager = SessionManager()
        manager.create_session("s")
        ws = _FakeWS()
        manager.join_user("s", "k1", ws)
        # payload by keyword: kills the `*` -> `/` (Mul_Div) mutant,
        # which makes the preceding parameters positional-only.
        assert await manager.broadcast(session_id="s", payload={"type": "ping"}) == 1
        assert ws.sent == [{"type": "ping"}]

    @pytest.mark.asyncio
    async def test_broadcast_excludes_by_value_not_identity(self):
        manager = SessionManager()
        manager.create_session("s")
        a, b = _FakeWS(), _FakeWS()
        manager.join_user("s", "k1", a)
        manager.join_user("s", "k2", b)
        excluded = "".join(["k", "1"])
        # Deliberate identity check: a distinct equal string, so the
        # Eq_Is mutant (== instead of is) is killed. noqa: F632
        assert excluded == "k1" and excluded is not "k1"  # noqa: F632
        assert await manager.broadcast("s", {"type": "ping"}, exclude_ws_key=excluded) == 1
        assert a.sent == [] and len(b.sent) == 1

    @pytest.mark.asyncio
    async def test_broadcast_skips_disconnected_and_still_sends_to_live(self):
        manager = SessionManager()
        manager.create_session("s")
        dead = _FakeWS(state=WebSocketState.DISCONNECTED)
        live = _FakeWS()
        manager.join_user("s", "k-dead", dead)
        manager.join_user("s", "k-live", live)
        assert await manager.broadcast("s", {"type": "ping"}) == 1
        assert live.sent == [{"type": "ping"}]
        assert dead.sent == []
        assert "k-dead" not in manager._sessions["s"]["users"]  # pruned

    @pytest.mark.asyncio
    async def test_broadcast_prunes_failing_connection_and_sends_to_rest(self):
        manager = SessionManager()
        manager.create_session("s")
        bad = _FakeWS(fail=True)
        live = _FakeWS()
        manager.join_user("s", "k-bad", bad)
        manager.join_user("s", "k-live", live)
        assert await manager.broadcast("s", {"type": "ping"}) == 1
        assert live.sent == [{"type": "ping"}]
        assert "k-bad" not in manager._sessions["s"]["users"]

    @pytest.mark.asyncio
    async def test_broadcast_refreshes_last_activity(self):
        manager = SessionManager()
        manager.create_session("s")
        manager.join_user("s", "k", _FakeWS())
        manager._sessions["s"]["last_activity"] = "2000-01-01T00:00:00+00:00"
        await manager.broadcast("s", {"type": "ping"})
        assert manager._sessions["s"]["last_activity"] != "2000-01-01T00:00:00+00:00"


class TestEvictExpired:
    def test_empty_sessions_are_removed(self):
        manager = SessionManager(session_timeout_seconds=3600)
        manager.create_session("e1")
        manager.create_session("e2")
        assert manager.cleanup() == 2
        assert manager._sessions == {}

    def test_expired_session_with_users_is_removed_but_fresh_is_kept(self):
        manager = SessionManager(session_timeout_seconds=3600)
        old = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
        manager.create_session("old")
        manager.join_user("old", "k-old", _FakeWS())
        manager._sessions["old"]["last_activity"] = old
        manager.create_session("fresh")
        manager.join_user("fresh", "k-fresh", _FakeWS())
        assert manager.cleanup() == 1
        assert "old" not in manager._sessions
        assert "fresh" in manager._sessions

    def test_scan_continues_past_the_first_empty_session(self):
        # [439] break mutant stops after the first empty session.
        manager = SessionManager(session_timeout_seconds=3600)
        old = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
        manager.create_session("e1")
        manager.create_session("old")
        manager.join_user("old", "k-old", _FakeWS())
        manager._sessions["old"]["last_activity"] = old
        manager.create_session("e2")
        assert manager.cleanup() == 3

    def test_scan_continues_past_a_timeout_zero_session(self):
        # [442] break mutant stops after the first timeout-<=0 session.
        manager = SessionManager(session_timeout_seconds=0)
        manager.create_session("s1")
        manager.join_user("s1", "k1", _FakeWS())
        manager.create_session("e2")
        assert manager.cleanup() == 2

    def test_negative_timeout_evicts_live_sessions(self):
        manager = SessionManager(session_timeout_seconds=-1)
        manager.create_session("s1")
        manager.join_user("s1", "k1", _FakeWS())
        assert manager.cleanup() == 1

    def test_timeout_one_keeps_a_fresh_session(self):
        manager = SessionManager(session_timeout_seconds=1)
        manager.create_session("s1")
        manager.join_user("s1", "k1", _FakeWS())
        assert manager.cleanup() == 0

    def test_timeout_zero_evicts_a_session_with_no_timestamps(self):
        # last_activity and created_at both missing: the age check cannot
        # fire, so only the timeout <= 0 branch can evict it.
        manager = SessionManager(session_timeout_seconds=0)
        manager._sessions["s1"] = {
            "created_at": None,
            "last_activity": None,
            "users": {"k1": {}},
            "connections": {},
        }
        assert manager.cleanup() == 1

    def test_negative_timeout_evicts_a_session_with_no_timestamps(self):
        # timeout -1: `<= 0` evicts, but `== 0` does not -- and with no
        # timestamps the age check cannot evict it either.
        manager = SessionManager(session_timeout_seconds=-1)
        manager._sessions["s1"] = {
            "created_at": None,
            "last_activity": None,
            "users": {"k1": {}},
            "connections": {},
        }
        assert manager.cleanup() == 1

    def test_missing_last_activity_falls_back_to_created_at(self):
        manager = SessionManager(session_timeout_seconds=3600)
        old = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
        manager._sessions["s1"] = {
            "created_at": old,
            "last_activity": None,
            "users": {"k1": {}},
            "connections": {},
        }
        assert manager.cleanup() == 1

    def test_non_string_last_activity_is_kept_without_raising(self):
        manager = SessionManager(session_timeout_seconds=3600)
        manager._sessions["s1"] = _session_dict(users={"k1": {}})
        manager._sessions["s1"]["last_activity"] = 123
        assert manager.cleanup() == 0  # no raise, session kept

    def test_unparseable_last_activity_is_kept_without_raising(self):
        manager = SessionManager(session_timeout_seconds=3600)
        manager._sessions["s1"] = _session_dict(users={"k1": {}})
        manager._sessions["s1"]["last_activity"] = "not-a-date"
        assert manager.cleanup() == 0  # ValueError is caught, session kept

    def test_age_just_over_timeout_evicts(self):
        manager = SessionManager(session_timeout_seconds=3600)
        old = (datetime.now(UTC) - timedelta(seconds=3601)).isoformat()
        manager.create_session("s1")
        manager.join_user("s1", "k1", _FakeWS())
        manager._sessions["s1"]["last_activity"] = old
        assert manager.cleanup() == 1

    def test_age_exactly_at_timeout_is_kept(self, monkeypatch):
        # Frozen clock: the age is exactly the timeout. `>` keeps the
        # session; `==` and `>=` would evict it.
        monkeypatch.setattr("textforensics.web_ui.main.datetime", _FrozenDateTime)
        manager = SessionManager(session_timeout_seconds=3600)
        manager.create_session("s1")
        manager.join_user("s1", "k1", _FakeWS())
        manager._sessions["s1"]["last_activity"] = (
            _FrozenDateTime._now - timedelta(seconds=3600)
        ).isoformat()
        assert manager.cleanup() == 0
        assert "s1" in manager._sessions

    def test_evict_removes_socket_mappings_for_evicted_sessions(self):
        manager = SessionManager(session_timeout_seconds=3600)
        old = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
        for sid in ("aaa", "zzz"):  # kept sessions, one below / one above "mmm"
            manager.create_session(sid)
            manager.join_user(sid, "k-" + sid, _FakeWS())
        # Evicted session whose mapping value IS the iterated key object.
        manager.create_session("nnn")
        manager.join_user("nnn", "k-nnn", _FakeWS())
        manager._sessions["nnn"]["last_activity"] = old
        # Evicted session whose stored key is a distinct equal string:
        # the mapping value and the iterated key compare equal but are
        # not identical objects.
        manager.create_session("mmm")
        manager.join_user("mmm", "k-mmm", _FakeWS())
        manager._sessions["mmm"]["last_activity"] = old
        distinct = "".join(["m", "m", "m"])
        # Deliberate identity check: a distinct equal string, so the
        # Eq_Is mutant (== instead of is) is killed. noqa: F632
        assert distinct == "mmm" and distinct is not "mmm"  # noqa: F632
        manager._sessions[distinct] = manager._sessions.pop("mmm")
        assert manager.cleanup() == 2
        assert "mmm" not in manager._sessions and distinct not in manager._sessions
        assert "nnn" not in manager._sessions
        assert "k-mmm" not in manager._ws_map
        assert "k-nnn" not in manager._ws_map
        assert "k-aaa" in manager._ws_map
        assert "k-zzz" in manager._ws_map


# ── history ring buffer / query_history ──────────────────────────────


def _history_bundle(
    verdict: str = "ai_like",
    prob: float | None = None,
    families: list[str] | None = None,
    sha: str = "a" * 64,
    n_detectors: int = 1,
) -> dict:
    consensus: dict = {"verdict": verdict}
    if prob is not None:
        consensus["calibrated_ai_probability"] = prob
        consensus["ensemble_calibration_id"] = CALIBRATION_ID
    if families is not None:
        consensus["family_votes"] = [{"detector_family": f} for f in families]
    return {
        "consensus": consensus,
        "detector_results": [
            {
                "verdict": verdict,
                "detector_id": f"d{i}",
                "detector_version": "1",
                "detector_family": "fam",
            }
            for i in range(n_detectors)
        ],
        "content_sha256": sha,
    }


def _seeded_client(bundles, max_input_bytes: int = 100_000):
    """A client whose history holds exactly `bundles` (in share order)."""
    client = _make_client(max_input_bytes=max_input_bytes)
    session_id = _new_session(client)
    with client.websocket_connect("/ws/analyze") as ws:
        _join(ws, session_id, "Seeder")
        for bundle in bundles:
            ws.send_json({"type": "analysis_shared", "data": bundle})
            reply = ws.receive_json()
            assert reply["type"] == "analysis_shared", reply
    return client


def _history(client, query: str = "") -> dict:
    resp = client.get(f"/api/history{query}")
    assert resp.status_code == 200, resp.text
    return resp.json()


class TestQueryHistory:
    def test_verdict_filter(self):
        client = _seeded_client(
            [
                _history_bundle("ai_like", sha="a" * 64),
                _history_bundle("human_like", sha="b" * 64),
                _history_bundle("ai_like", sha="c" * 64),
            ]
        )
        entries = _history(client, "?verdict=ai_like")["entries"]
        assert [e["content_sha256"][:16] for e in entries] == ["c" * 16, "a" * 16]
        entries = _history(client, "?verdict=human_like")["entries"]
        assert [e["content_sha256"][:16] for e in entries] == ["b" * 16]

    def test_family_filter(self):
        client = _seeded_client(
            [
                _history_bundle("ai_like", families=["fam-a"], sha="a" * 64),
                _history_bundle("ai_like", families=["fam-b"], sha="b" * 64),
                _history_bundle("ai_like", families=["fam-a"], sha="c" * 64),
            ]
        )
        entries = _history(client, "?family=fam-a")["entries"]
        assert [e["content_sha256"][:16] for e in entries] == ["c" * 16, "a" * 16]
        assert _history(client, "?family=fam-missing")["entries"] == []

    def test_family_filter_skips_entries_without_family_votes(self):
        client = _seeded_client(
            [
                _history_bundle("ai_like", families=["fam-a"], sha="a" * 64),
                _history_bundle("ai_like", families=None, sha="b" * 64),
            ]
        )
        entries = _history(client, "?family=fam-a")["entries"]
        assert [e["content_sha256"][:16] for e in entries] == ["a" * 16]

    def test_min_score_filter(self):
        client = _seeded_client(
            [
                _history_bundle("ai_like", prob=0.2, sha="a" * 64),
                _history_bundle("ai_like", prob=0.5, sha="b" * 64),
                _history_bundle("ai_like", prob=0.8, sha="c" * 64),
                _history_bundle("ai_like", prob=None, sha="d" * 64),
            ]
        )
        entries = _history(client, "?min_score=0.5")["entries"]
        assert [e["calibrated_ai_probability"] for e in entries] == [0.8, 0.5]

    def test_max_score_filter(self):
        # The over-max entry comes first: the `continue` -> `break`
        # mutant stops the scan there and returns nothing.
        client = _seeded_client(
            [
                _history_bundle("ai_like", prob=0.8, sha="c" * 64),
                _history_bundle("ai_like", prob=0.2, sha="a" * 64),
                _history_bundle("ai_like", prob=0.5, sha="b" * 64),
                _history_bundle("ai_like", prob=None, sha="d" * 64),
            ]
        )
        entries = _history(client, "?max_score=0.5")["entries"]
        assert [e["calibrated_ai_probability"] for e in entries] == [0.5, 0.2]

    def test_history_is_sorted_newest_first(self):
        client = _seeded_client(
            [
                _history_bundle("ai_like", sha="a" * 64),
                _history_bundle("ai_like", sha="b" * 64),
                _history_bundle("ai_like", sha="c" * 64),
            ]
        )
        entries = _history(client)["entries"]
        assert [e["content_sha256"][:16] for e in entries] == ["c" * 16, "b" * 16, "a" * 16]

    def test_history_pagination(self):
        client = _seeded_client(
            [
                _history_bundle("ai_like", sha="a" * 64),
                _history_bundle("ai_like", sha="b" * 64),
                _history_bundle("ai_like", sha="c" * 64),
            ]
        )
        page = _history(client, "?limit=1&offset=1")
        assert page["returned"] == 1
        assert page["entries"][0]["content_sha256"][:16] == "b" * 16
        assert page["total"] == 3

    def test_history_hash_is_truncated_to_16_chars(self):
        sha = "0123456789abcdef" * 4
        client = _seeded_client([_history_bundle("ai_like", sha=sha)])
        entry = _history(client)["entries"][0]
        assert entry["content_sha256"] == sha[:16] + "…"

    def test_history_detector_count(self):
        client = _seeded_client(
            [
                _history_bundle("ai_like", sha="a" * 64, n_detectors=2),
                _history_bundle("ai_like", sha="b" * 64, n_detectors=0),
            ]
        )
        entries = _history(client)["entries"]
        assert {e["content_sha256"][:16]: e["detector_count"] for e in entries} == {
            "a" * 16: 2,
            "b" * 16: 0,
        }


class TestHistoryByteQuota:
    def _stored_entry_bytes(self, bundle: dict) -> int:
        entry = {
            "id": "0" * 36,
            "stored_at": datetime.now(UTC).isoformat(),
            "data": bundle,
        }
        return len(json.dumps(entry, ensure_ascii=False).encode("utf-8"))

    def test_two_entries_fit_the_real_quota_but_not_the_add_quota(self, monkeypatch):
        # max_history=2: real quota 131072; the `+`/`|`/`^` mutants make
        # it 65538. Two ~65 kB entries total ~130 kB: the real quota keeps
        # both, the mutant quota evicts down to one.
        monkeypatch.setenv("TEXTFORENSICS_HISTORY_MAX", "2")
        bundle = _bundle_of_size(65000)
        entry_bytes = self._stored_entry_bytes(bundle)
        assert entry_bytes <= _MAX_HISTORY_ENTRY_BYTES, entry_bytes
        assert 2 * entry_bytes > 65538, entry_bytes
        client = _seeded_client([bundle, copy.deepcopy(bundle)])
        assert _history(client)["total"] == 2

    def test_one_entry_fits_the_real_quota_but_not_the_pow_quota(self, monkeypatch):
        # max_history=1: real quota 65536; the `**` mutant makes it
        # 1**65536 == 1, so it evicts even a single entry.
        monkeypatch.setenv("TEXTFORENSICS_HISTORY_MAX", "1")
        bundle = _bundle_of_size(65000)
        entry_bytes = self._stored_entry_bytes(bundle)
        assert entry_bytes <= _MAX_HISTORY_ENTRY_BYTES, entry_bytes
        client = _seeded_client([bundle])
        assert _history(client)["total"] == 1


# ── websocket_analyze ────────────────────────────────────────────────


class TestWebSocketHandshake:
    def test_origin_refused_with_1008(self):
        client = _make_client()
        with (
            pytest.raises(WebSocketDisconnect) as excinfo,
            client.websocket_connect("/ws/analyze", headers={"Origin": "https://attacker.example"}),
        ):
            pass
        assert excinfo.value.code == 1008

    def test_stop_refused_with_1011(self, tmp_path, monkeypatch):
        sentinel = tmp_path / "stop"
        sentinel.write_text("stop\n", encoding="utf-8")
        monkeypatch.setenv("TEXTFORENSICS_EMERGENCY_STOP", str(sentinel))
        client = _make_client()
        with pytest.raises(WebSocketDisconnect) as excinfo, client.websocket_connect("/ws/analyze"):
            pass
        assert excinfo.value.code == 1011

    def test_frame_at_cap_is_accepted(self):
        # max_input_bytes=100_000 -> max_frame_bytes = 100_000 + 65_536.
        cap = 100_000 + 65_536
        client = _make_client()
        session_id = _new_session(client)
        with client.websocket_connect("/ws/analyze") as ws:
            msg = {
                "type": "join_session",
                "session_id": session_id,
                "display_name": "P",
                "pad": "",
            }
            base = len(json.dumps(msg).encode("utf-8"))
            msg["pad"] = "x" * (cap - base)
            assert len(json.dumps(msg).encode("utf-8")) == cap
            ws.send_text(json.dumps(msg))
            assert ws.receive_json()["type"] == "session_joined"

    def test_oversized_frame_is_closed_with_1009(self):
        client = _make_client()
        with client.websocket_connect("/ws/analyze") as ws:
            ws.send_text("x" * 200_000)
            with pytest.raises(WebSocketDisconnect) as excinfo:
                ws.receive_json()
            assert excinfo.value.code == 1009


class TestWebSocketMessages:
    def test_invalid_json_gets_422_and_connection_stays_open(self):
        client = _make_client()
        session_id = _new_session(client)
        with client.websocket_connect("/ws/analyze") as ws:
            ws.send_text("{not json")
            _assert_error(ws.receive_json(), 422)
            reply = _follow_up(
                ws, {"type": "join_session", "session_id": session_id, "display_name": "P"}
            )
            assert reply["type"] == "session_joined", reply

    def test_non_dict_message_gets_422_and_connection_stays_open(self):
        client = _make_client()
        session_id = _new_session(client)
        with client.websocket_connect("/ws/analyze") as ws:
            ws.send_json(["not", "a", "dict"])
            _assert_error(ws.receive_json(), 422)
            reply = _follow_up(
                ws, {"type": "join_session", "session_id": session_id, "display_name": "P"}
            )
            assert reply["type"] == "session_joined", reply

    @pytest.mark.parametrize(
        "bad",
        [
            {"session_id": ""},
            {"session_id": 123},
            {"session_id": "x" * 65},
            {"display_name": 123},
            {"display_name": "x" * 129},
        ],
    )
    def test_invalid_join_gets_422(self, bad):
        client = _make_client()
        session_id = _new_session(client)
        with client.websocket_connect("/ws/analyze") as ws:
            msg = {"type": "join_session", "session_id": session_id, "display_name": "P"}
            msg.update(bad)
            ws.send_json(msg)
            _assert_error(ws.receive_json(), 422)

    def test_join_at_length_limits_is_accepted(self):
        client, app = _make_client_app()
        sid = "s" * 64
        app.state.session_manager.create_session(sid)
        with client.websocket_connect("/ws/analyze") as ws:
            _join(ws, sid, "n" * 128)

    def test_invalid_join_does_not_close_connection(self):
        client = _make_client()
        session_id = _new_session(client)
        with client.websocket_connect("/ws/analyze") as ws:
            ws.send_json({"type": "join_session", "session_id": "", "display_name": "P"})
            _assert_error(ws.receive_json(), 422)
            reply = _follow_up(
                ws, {"type": "join_session", "session_id": session_id, "display_name": "P"}
            )
            assert reply["type"] == "session_joined", reply

    def test_join_missing_session_gets_404(self):
        client = _make_client()
        with client.websocket_connect("/ws/analyze") as ws:
            ws.send_json(
                {"type": "join_session", "session_id": "no-such-session", "display_name": "P"}
            )
            _assert_error(ws.receive_json(), 404)

    def test_unknown_message_types_get_422(self):
        client = _make_client()
        with client.websocket_connect("/ws/analyze") as ws:
            ws.send_json({"type": "zzz"})
            reply = _recv_or_none(ws)
            assert reply is not None, "no reply to an unknown message type"
            _assert_error(reply, 422)
            ws.send_json({"type": "aaa"})
            reply = _recv_or_none(ws)
            assert reply is not None, "no reply to an unknown message type"
            _assert_error(reply, 422)

    def test_leave_does_not_close_connection(self):
        client = _make_client()
        first = _new_session(client)
        second = _new_session(client)
        with client.websocket_connect("/ws/analyze") as ws:
            _join(ws, first)
            ws.send_json({"type": "leave_session"})
            assert ws.receive_json()["type"] == "session_left"
            reply = _follow_up(
                ws, {"type": "join_session", "session_id": second, "display_name": "P"}
            )
            assert reply["type"] == "session_joined", reply

    def test_share_without_session_gets_404_and_connection_stays_open(self):
        client = _make_client()
        session_id = _new_session(client)
        with client.websocket_connect("/ws/analyze") as ws:
            ws.send_json({"type": "analysis_shared", "data": _history_bundle()})
            _assert_error(ws.receive_json(), 404)
            reply = _follow_up(
                ws, {"type": "join_session", "session_id": session_id, "display_name": "P"}
            )
            assert reply["type"] == "session_joined", reply

    def test_share_unknown_analysis_id_gets_404_and_connection_stays_open(self):
        client = _make_client()
        session_id = _new_session(client)
        with client.websocket_connect("/ws/analyze") as ws:
            _join(ws, session_id)
            ws.send_json({"type": "analysis_shared", "analysis_id": "no-such-id"})
            _assert_error(ws.receive_json(), 404)
            reply = _follow_up(ws, {"type": "analysis_shared", "data": _history_bundle()})
            assert reply["type"] == "analysis_shared", reply

    def test_share_empty_analysis_id_gets_422(self):
        client = _make_client()
        session_id = _new_session(client)
        with client.websocket_connect("/ws/analyze") as ws:
            _join(ws, session_id)
            ws.send_json({"type": "analysis_shared", "analysis_id": ""})
            _assert_error(ws.receive_json(), 422)

    def test_share_invalid_bundle_gets_422(self):
        client = _make_client()
        session_id = _new_session(client)
        with client.websocket_connect("/ws/analyze") as ws:
            _join(ws, session_id)
            ws.send_json({"type": "analysis_shared", "data": {"consensus": {"verdict": "bogus"}}})
            _assert_error(ws.receive_json(), 422)

    def test_share_oversized_entry_gets_413_and_connection_stays_open(self):
        # The bundle itself is at the quota (valid), but the stored entry
        # wraps it with id + timestamp, so store_analysis refuses it.
        client = _make_client()
        session_id = _new_session(client)
        with client.websocket_connect("/ws/analyze") as ws:
            _join(ws, session_id)
            ws.send_json(
                {"type": "analysis_shared", "data": _bundle_of_size(_MAX_HISTORY_ENTRY_BYTES)}
            )
            _assert_error(ws.receive_json(), 413)
            reply = _follow_up(ws, {"type": "analysis_shared", "data": _history_bundle()})
            assert reply["type"] == "analysis_shared", reply

    def test_share_with_neither_id_nor_data_gets_422(self):
        client = _make_client()
        session_id = _new_session(client)
        with client.websocket_connect("/ws/analyze") as ws:
            _join(ws, session_id)
            ws.send_json({"type": "analysis_shared"})
            _assert_error(ws.receive_json(), 422)
            reply = _follow_up(ws, {"type": "analysis_shared", "data": _history_bundle()})
            assert reply["type"] == "analysis_shared", reply

    def _two_sockets(self, client, session_id):
        """Two joined sockets; returns (ws_a, ws_b) with queues drained."""
        ws_a = client.websocket_connect("/ws/analyze").__enter__()
        ws_b = client.websocket_connect("/ws/analyze").__enter__()
        _join(ws_a, session_id, "A")
        _join(ws_b, session_id, "B")
        # B's join broadcast a user_joined to A: drain it.
        assert ws_a.receive_json()["type"] == "user_joined"
        return ws_a, ws_b

    def test_shared_by_valid_name_is_broadcast_verbatim(self):
        client = _make_client()
        session_id = _new_session(client)
        ws_a, ws_b = self._two_sockets(client, session_id)
        try:
            ws_a.send_json(
                {"type": "analysis_shared", "data": _history_bundle(), "shared_by": "Alice"}
            )
            assert ws_a.receive_json()["type"] == "analysis_shared"
            msg = _recv_or_none(ws_b)
            assert msg is not None and msg["type"] == "analysis_shared"
            assert msg["shared_by"] == "Alice"
        finally:
            ws_a.__exit__(None, None, None)
            ws_b.__exit__(None, None, None)

    def test_shared_by_non_string_is_replaced_by_socket_key(self):
        client = _make_client()
        session_id = _new_session(client)
        ws_a, ws_b = self._two_sockets(client, session_id)
        try:
            ws_a.send_json({"type": "analysis_shared", "data": _history_bundle(), "shared_by": 123})
            assert ws_a.receive_json()["type"] == "analysis_shared"
            msg = _recv_or_none(ws_b)
            assert msg is not None and msg["type"] == "analysis_shared"
            assert isinstance(msg["shared_by"], str)
            assert len(msg["shared_by"]) <= 64
        finally:
            ws_a.__exit__(None, None, None)
            ws_b.__exit__(None, None, None)

    @pytest.mark.parametrize("length", [63, 64, 65])
    def test_shared_by_length_boundaries(self, length):
        client = _make_client()
        session_id = _new_session(client)
        ws_a, ws_b = self._two_sockets(client, session_id)
        try:
            name = "x" * length
            ws_a.send_json(
                {"type": "analysis_shared", "data": _history_bundle(), "shared_by": name}
            )
            assert ws_a.receive_json()["type"] == "analysis_shared"
            msg = _recv_or_none(ws_b)
            assert msg is not None and msg["type"] == "analysis_shared"
            if length <= 64:
                assert msg["shared_by"] == name
            else:
                assert isinstance(msg["shared_by"], str)
                assert len(msg["shared_by"]) <= 64
        finally:
            ws_a.__exit__(None, None, None)
            ws_b.__exit__(None, None, None)

    def test_empty_text_error_does_not_close_connection(self):
        client = _make_client()
        with client.websocket_connect("/ws/analyze") as ws:
            ws.send_json({"type": "analyze", "text": ""})
            reply = ws.receive_json()
            assert reply["type"] == "error", reply
            assert reply["message"] == "Empty text provided", reply
            follow = _follow_up(ws, {"type": "analyze", "text": TEXT})
            assert follow["type"] == "started", follow
            types = _drain(ws)
            assert "complete" in types

    def test_non_string_text_gets_422_and_connection_stays_open(self):
        client = _make_client()
        with client.websocket_connect("/ws/analyze") as ws:
            ws.send_json({"type": "analyze", "text": 0})
            _assert_error(ws.receive_json(), 422)
            reply = _follow_up(ws, {"type": "analyze", "text": TEXT})
            assert reply["type"] == "started", reply
            types = _drain(ws)
            assert "complete" in types

    def test_stop_error_does_not_close_connection(self, tmp_path, monkeypatch):
        sentinel = tmp_path / "stop"
        monkeypatch.setenv("TEXTFORENSICS_EMERGENCY_STOP", str(sentinel))
        client = _make_client()
        with client.websocket_connect("/ws/analyze") as ws:
            sentinel.write_text("stop\n", encoding="utf-8")
            ws.send_json({"type": "analyze", "text": TEXT})
            first = ws.receive_json()
            assert first["type"] == "error", first
            second = _follow_up(ws, {"type": "analyze", "text": TEXT})
            assert second["type"] == "error", second

    def test_streaming_delay_is_fifty_milliseconds(self, monkeypatch):
        real_sleep = asyncio.sleep
        calls: list = []

        async def spy(delay, *args, **kwargs):
            calls.append(delay)
            return await real_sleep(delay, *args, **kwargs)

        monkeypatch.setattr(asyncio, "sleep", spy)
        client = _make_client()
        with client.websocket_connect("/ws/analyze") as ws:
            ws.send_json({"type": "analyze", "text": TEXT})
            types = _drain(ws)
        assert "complete" in types
        assert 0.05 in calls
        assert 1.05 not in calls
        assert -0.95 not in calls

    def test_broadcast_condition_requires_a_real_session(self):
        # A session with id "" exists but can never be joined through the
        # API (join validation rejects an empty id), so the only socket
        # in it is the fake one planted here. An analysis from an
        # unjoined socket must not broadcast to it.
        client, app = _make_client_app()
        manager = app.state.session_manager
        manager.create_session("")
        fake = _FakeWS()
        manager._sessions[""]["connections"]["k-fake"] = fake
        manager._sessions[""]["users"]["k-fake"] = {
            "ws_key": "k-fake",
            "display_name": "Ghost",
            "joined_at": "2000-01-01T00:00:00+00:00",
        }
        with client.websocket_connect("/ws/analyze?session=") as ws:
            ws.send_json({"type": "analyze", "text": TEXT})
            types = _drain(ws)
        assert "complete" in types
        assert fake.sent == []


# ── _calibrated_display / report builders ────────────────────────────


def _report_bundle() -> dict:
    return {
        "consensus": {
            "verdict": "ai_like",
            "calibrated_ai_probability": 0.5,
            "ensemble_calibration_id": CALIBRATION_ID,
            "family_agreement": "high",
        },
        "detector_results": [
            {
                "detector_id": "d1",
                "detector_version": "1",
                "detector_family": "fam",
                "score": 0.5,
                "verdict": "ai_like",
            }
        ],
        "trust_map": {
            "overall": "supported",
            "dimensions": [
                {"dimension": "language", "state": "supported"},
                {"dimension": "length", "state": "partial"},
            ],
        },
        "generated_at_utc": "2026-11-15T12:00:00+00:00",
        "content_sha256": "0123456789abcdef" * 4,
        "input": {"word_count": 42},
    }


class TestCalibratedDisplay:
    def test_calibrated_value_is_shown(self):
        assert _calibrated_display(
            {"calibrated_ai_probability": 0.5, "ensemble_calibration_id": "cal-1"}
        ) == ("50.0%", "cal-1")

    def test_zero_is_shown(self):
        assert _calibrated_display(
            {"calibrated_ai_probability": 0.0, "ensemble_calibration_id": "cal-1"}
        ) == ("0.0%", "cal-1")

    def test_one_is_shown(self):
        assert _calibrated_display(
            {"calibrated_ai_probability": 1.0, "ensemble_calibration_id": "cal-1"}
        ) == ("100.0%", "cal-1")

    def test_below_zero_is_not_calibrated(self):
        assert _calibrated_display(
            {"calibrated_ai_probability": -0.5, "ensemble_calibration_id": "cal-1"}
        ) == ("Not calibrated", "Not calibrated")

    def test_above_one_is_not_calibrated(self):
        assert _calibrated_display(
            {"calibrated_ai_probability": 1.5, "ensemble_calibration_id": "cal-1"}
        ) == ("Not calibrated", "Not calibrated")

    def test_bool_is_not_calibrated(self):
        assert _calibrated_display(
            {"calibrated_ai_probability": True, "ensemble_calibration_id": "cal-1"}
        ) == ("Not calibrated", "Not calibrated")

    def test_string_is_not_calibrated(self):
        assert _calibrated_display(
            {"calibrated_ai_probability": "0.5", "ensemble_calibration_id": "cal-1"}
        ) == ("Not calibrated", "Not calibrated")

    def test_non_string_identity_is_not_calibrated(self):
        assert _calibrated_display(
            {"calibrated_ai_probability": 0.5, "ensemble_calibration_id": 123}
        ) == ("Not calibrated", "Not calibrated")

    def test_empty_identity_is_not_calibrated(self):
        assert _calibrated_display(
            {"calibrated_ai_probability": 0.5, "ensemble_calibration_id": ""}
        ) == ("Not calibrated", "Not calibrated")

    def test_invalid_value_with_valid_identity_is_not_calibrated(self):
        assert _calibrated_display(
            {"calibrated_ai_probability": 2.0, "ensemble_calibration_id": "cal-1"}
        ) == ("Not calibrated", "Not calibrated")

    def test_missing_fields_are_not_calibrated(self):
        assert _calibrated_display({}) == ("Not calibrated", "Not calibrated")


class TestReportBuilders:
    def _csv_rows(self, data) -> list[list[str]]:
        buf = io.StringIO()
        _write_csv_report(csv.writer(buf), data)
        return list(csv.reader(io.StringIO(buf.getvalue())))

    def test_csv_report_defaults_independent_families_to_zero(self):
        data = _report_bundle()
        assert "independent_families" not in data["consensus"]
        rows = self._csv_rows(data)
        fam = [r for r in rows if r[:2] == ["Consensus", "Independent Families"]]
        assert fam == [["Consensus", "Independent Families", "0"]]

    def test_csv_report_includes_trust_map_dimensions(self):
        rows = self._csv_rows(_report_bundle())
        assert ["Trust Map", "language", "supported"] in rows
        assert ["Trust Map", "length", "partial"] in rows

    def test_html_report_truncates_hash_to_16_chars(self):
        data = _report_bundle()
        html = _build_html_report(data)
        sha = data["content_sha256"]
        assert sha[:16] + "&hellip;" in html
        assert sha[:17] not in html

    def test_comparison_verdict_changed_for_different_verdicts(self):
        a = _report_bundle()
        b = _report_bundle()
        b["consensus"] = dict(b["consensus"], verdict="human_like")
        assert _build_comparison(a, b)["summary"]["verdict_changed"] is True

    def test_comparison_verdict_unchanged_for_same_verdicts(self):
        a = _report_bundle()
        assert _build_comparison(a, a)["summary"]["verdict_changed"] is False
