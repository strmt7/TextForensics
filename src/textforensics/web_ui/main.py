from __future__ import annotations

import asyncio
import csv
import html
import io
import json
import math
import os
import threading
import uuid
import webbrowser
from collections import OrderedDict
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any

try:
    from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
    from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates
    from pydantic import BaseModel
    from starlette.websockets import WebSocketState
except ImportError:  # pragma: no cover - optional dependency
    # The [api] extra is absent. The module must stay importable so
    # that the `textforensics-web` console script can fail with one
    # clean install hint (see main()) instead of a raw
    # ModuleNotFoundError traceback at import time; create_web_app()
    # raises the install hint instead (mirrors api.py).
    FastAPI = HTTPException = Request = WebSocket = WebSocketDisconnect = None  # type: ignore[assignment, misc]
    HTMLResponse = JSONResponse = StreamingResponse = None  # type: ignore[assignment, misc]
    StaticFiles = Jinja2Templates = None  # type: ignore[assignment, misc]
    BaseModel = None  # type: ignore[assignment, misc]
    WebSocketState = None  # type: ignore[assignment, misc]

from .._build_info import get_version
from ..config import (
    Settings,
    ensure_bind_allowed,
    is_loopback_host,
    is_unspecified_host,
    validate_text_input,
)
from ..detectors import list_detector_health, list_detector_metadata
from ..emergency_stop import EmergencyStopError
from ..execution_policy import (
    ExecutionCancelled,
    ExecutionPolicy,
    ExecutionPolicyError,
    assert_execution_allowed,
    error_status_for_exception,
    is_execution_stopped,
    new_request_id,
    public_error_body,
    public_message_for_status,
    register_redacting_handlers,
)
from ..report import build_forensic_bundle


def _escape(value: object) -> str:
    """Escape a value for safe inclusion in HTML output."""
    if value is None:
        return ""
    return html.escape(str(value))


# ── WebSocket trust boundary (IF-05) ─────────────────────────────────
#
# The web console is local-only by default (see
# docs/verification/deployment-policy.md): it serves the loopback
# interface, and a browser can only reach it from a same-origin page.
# A raw WebSocket client can forge any header, so these checks are a
# browser-origin (CSWSH / DNS-rebinding) boundary, not authentication
# for non-browser clients: a request with no Origin header (curl, a
# test harness, a non-browser client) is allowed, while a request
# carrying an Origin or Host outside the configured set is refused at
# the handshake, before accept. Binding a token/authenticated session
# to mutating operations is a human-only decision (deployment policy);
# it is NOT invented here.

# Known verdict enums (IF-05): shared bundles are validated against
# these before they may enter retained history. A verdict that is not
# in the enum -- markup, padding, an invented label -- is rejected.
_CONSENSUS_VERDICTS = frozenset(
    {"ai_like", "human_like", "abstain", "insufficient_evidence", "mixed"}
)
_DETECTOR_VERDICTS = frozenset({"ai_like", "human_like", "abstain"})

# Retained-history quotas (IF-05): separate from the input byte cap.
# A server-generated bundle is ~10 KiB regardless of input length
# (raw text is excluded by default), so 64 KiB per entry has ample
# headroom while the audit's 65,573-byte forged verdict is refused.
_MAX_HISTORY_ENTRY_BYTES = 65_536
# Extra bytes a WebSocket frame may carry over the configured input
# cap (JSON envelope around the text); mirrors the HTTP body cap.
_WS_FRAME_OVERHEAD_BYTES = 65_536
# Caller-supplied display/session strings carried in WS messages.
_MAX_WS_ID_CHARS = 64
_MAX_WS_DISPLAY_NAME_CHARS = 128
_MAX_BUNDLE_STRING_CHARS = 256

# "testserver" is the Starlette TestClient harness host (the default
# base_url of every in-repo TestClient). It is not a routable
# production hostname; it is allowed here only so the test harness
# can exercise the handshake. Production requests carry the
# configured host or a loopback host.
_TEST_HARNESS_HOSTS = frozenset({"testserver"})
_TEST_HARNESS_ORIGINS = frozenset({"http://testserver", "https://testserver"})


def _allowed_ws_origins(settings: Settings) -> frozenset[str]:
    """Exact origins the WebSocket handshake accepts.

    One origin per configured/loopback host, per scheme, at the
    configured port -- plus the test-harness origin. Matching is
    exact: no suffix, prefix or port-less match is accepted.
    """
    origins = set(_TEST_HARNESS_ORIGINS)
    for host in {settings.host, "127.0.0.1", "localhost", "::1"}:
        host_part = f"[{host}]" if ":" in host else host
        for scheme in ("http", "https"):
            origins.add(f"{scheme}://{host_part}:{settings.port}")
    return frozenset(origins)


def _allowed_ws_hosts(settings: Settings) -> frozenset[str]:
    """Host values (without port) the WebSocket handshake accepts."""
    hosts = {settings.host.lower(), "127.0.0.1", "localhost", "::1", "[::1]"}
    hosts.update(_TEST_HARNESS_HOSTS)
    return frozenset(hosts)


def _host_part(header_value: str) -> str:
    """Return the host part of a Host header value (no port)."""
    value = header_value.strip().lower()
    if value.startswith("["):
        end = value.find("]")
        return value[: end + 1] if end != -1 else value
    return value.split(":", 1)[0]


def _is_allowed_ws_handshake(websocket: WebSocket, settings: Settings) -> bool:
    """Check the WebSocket handshake Host/Origin boundary (IF-05).

    A present Origin must match an allowed origin exactly; a present
    Host must name an allowed host. Absent headers are allowed (a
    non-browser client sends no Origin). Returns False when the
    handshake must be refused before accept.
    """
    origin = websocket.headers.get("origin")
    if origin is not None and origin.strip().lower() not in _allowed_ws_origins(settings):
        return False
    host = websocket.headers.get("host")
    return not (host is not None and _host_part(host) not in _allowed_ws_hosts(settings))


def _validate_shared_bundle(data: Any) -> None:
    """Validate a caller-supplied bundle before it may enter history.

    Raises ValueError on any violation. The object is never trusted:
    it must be a mapping with a consensus verdict in the known enum,
    detector verdicts in the known enum, finite in-range probabilities
    and scores, short identifier strings, and a serialized size within
    the retained-history entry quota. A forged verdict (markup or
    oversized padding) fails the enum/size checks and is never
    retained or broadcast.
    """
    if not isinstance(data, dict):
        raise ValueError("Shared bundle must be a mapping.")
    try:
        entry_bytes = len(json.dumps(data, ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise ValueError("Shared bundle is not serializable.") from exc
    if entry_bytes > _MAX_HISTORY_ENTRY_BYTES:
        raise ValueError("Shared bundle exceeds the retained-history entry quota.")
    consensus = data.get("consensus")
    if not isinstance(consensus, dict):
        raise ValueError("Shared bundle requires a consensus mapping.")
    verdict = consensus.get("verdict")
    if not isinstance(verdict, str) or verdict not in _CONSENSUS_VERDICTS:
        raise ValueError("Shared bundle consensus verdict is not a known verdict.")
    # Canonical ensemble probability only (IF-04): a bare legacy
    # `ai_probability` field is not a calibrated probability -- it has
    # no calibration provenance -- so a shared bundle carrying it is
    # refused, never retained. A calibrated value requires its
    # ensemble calibration identity (both or neither).
    if "ai_probability" in consensus:
        raise ValueError("Shared bundle uses the legacy ai_probability field.")
    calibrated = consensus.get("calibrated_ai_probability")
    calibration_id = consensus.get("ensemble_calibration_id")
    if calibrated is not None and (
        isinstance(calibrated, bool)
        or not isinstance(calibrated, (int, float))
        or not 0.0 <= float(calibrated) <= 1.0
    ):
        raise ValueError("Shared bundle calibrated probability is out of range.")
    if (calibrated is None) != (calibration_id is None):
        raise ValueError("Shared bundle calibrated probability requires its calibration identity.")
    if calibration_id is not None and (not isinstance(calibration_id, str) or not calibration_id):
        raise ValueError("Shared bundle calibration identity is not a non-empty string.")
    detector_results = data.get("detector_results", [])
    if not isinstance(detector_results, list):
        raise ValueError("Shared bundle detector results must be a list.")
    for row in detector_results:
        if not isinstance(row, dict):
            raise ValueError("Shared bundle detector results must be mappings.")
        row_verdict = row.get("verdict")
        if row_verdict is not None and (
            not isinstance(row_verdict, str) or row_verdict not in _DETECTOR_VERDICTS
        ):
            raise ValueError("Shared bundle detector verdict is not a known verdict.")
        for key in ("detector_id", "detector_version", "detector_family"):
            value = row.get(key)
            if value is not None and (
                not isinstance(value, str) or len(value) > _MAX_BUNDLE_STRING_CHARS
            ):
                raise ValueError("Shared bundle detector field is not a short string.")
        score = row.get("score")
        if score is not None and (
            isinstance(score, bool)
            or not isinstance(score, (int, float))
            or not math.isfinite(float(score))
        ):
            raise ValueError("Shared bundle detector score is not finite.")
        calibrated = row.get("calibrated_ai_probability")
        if calibrated is not None and (
            isinstance(calibrated, bool)
            or not isinstance(calibrated, (int, float))
            or not 0.0 <= float(calibrated) <= 1.0
        ):
            raise ValueError("Shared bundle calibrated probability is out of range.")
    content_sha256 = data.get("content_sha256")
    if content_sha256 is not None and (
        not isinstance(content_sha256, str) or len(content_sha256) > _MAX_BUNDLE_STRING_CHARS
    ):
        raise ValueError("Shared bundle content hash is not a short string.")


def _ws_error_body(status: int) -> dict[str, Any]:
    """Build a WebSocket error message from the shared contract (IF-07).

    Only a stable generic message, a stable error code and a request
    ID -- never exception text, rejected input, tracebacks or paths.
    """
    request_id = new_request_id()
    body = public_error_body(status, request_id=request_id)
    return {
        "type": "error",
        "message": body["detail"],
        "error_code": body["error_code"],
        "request_id": request_id,
    }


# ── Session Manager for real-time collaboration ──────────────────────


class SessionManager:
    """In-memory session management for real-time collaboration.

    One typed mapping owns the socket-to-session relation
    (``_ws_map: ws_key -> session_id``). Only :meth:`join_user`
    writes it and only :meth:`leave_user` removes from it -- handlers
    never edit the private maps directly, so a disconnect can never
    strand a user entry (IF-10). ``last_activity`` is refreshed on
    every join and every message routed through the session, and
    :meth:`cleanup` expires sessions idle longer than
    ``session_timeout_seconds`` as well as empty ones. Each web
    application owns its own manager (``app.state.session_manager``);
    there is no shared global manager.
    """

    def __init__(
        self,
        max_sessions: int = 100,
        max_users_per_session: int = 10,
        session_timeout_seconds: int = 3600,
    ):
        self.max_sessions = max_sessions
        self.max_users_per_session = max_users_per_session
        self.session_timeout_seconds = session_timeout_seconds
        self._sessions: dict[str, dict[str, Any]] = {}
        self._ws_map: dict[str, str] = {}

    def generate_session_id(self) -> str:
        return uuid.uuid4().hex[:8]

    def create_session(self, session_id: str | None = None) -> str:
        if session_id is None:
            session_id = self.generate_session_id()
        if session_id in self._sessions:
            return session_id
        if len(self._sessions) >= self.max_sessions:
            self._evict_expired()
            if len(self._sessions) >= self.max_sessions:
                raise ValueError("Maximum sessions reached")
        now = datetime.now(UTC).isoformat()
        self._sessions[session_id] = {
            "created_at": now,
            "last_activity": now,
            "users": {},
            "connections": {},
        }
        return session_id

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        return self._sessions.get(session_id)

    def has_session(self, session_id: str) -> bool:
        return session_id in self._sessions

    def session_id_for(self, ws_key: str) -> str | None:
        """Return the session a socket belongs to, or None.

        The single read path for the ``ws_key -> session_id`` mapping;
        handlers use this instead of reading the private map.
        """
        return self._ws_map.get(ws_key)

    def touch(self, ws_key: str) -> None:
        """Refresh last-activity for the session a socket belongs to."""
        session_id = self._ws_map.get(ws_key)
        if session_id is None:
            return
        session = self._sessions.get(session_id)
        if session is not None:
            session["last_activity"] = datetime.now(UTC).isoformat()

    def join_user(
        self,
        session_id: str,
        ws_key: str,
        websocket: WebSocket,
        display_name: str = "Anonymous",
    ) -> dict[str, Any]:
        session = self._sessions.get(session_id)
        if session is None:
            raise ValueError(f"Session {session_id} not found")
        if len(session["users"]) >= self.max_users_per_session and ws_key not in session["users"]:
            raise ValueError("Session is full")
        # A socket belongs to at most one session: joining another
        # session first leaves the previous one, so a reconnect or a
        # duplicate join can never strand the old entry.
        previous = self._ws_map.get(ws_key)
        if previous is not None and previous != session_id:
            self.leave_user(ws_key)
        user_info = {
            "ws_key": ws_key,
            "display_name": display_name,
            "joined_at": datetime.now(UTC).isoformat(),
        }
        session["users"][ws_key] = user_info
        session["connections"][ws_key] = websocket
        session["last_activity"] = datetime.now(UTC).isoformat()
        self._ws_map[ws_key] = session_id
        return user_info

    def leave_user(self, ws_key: str) -> str | None:
        """Remove one socket from its session; exclusively owns removal.

        Returns the session ID the socket belonged to, or None. The
        last user's departure removes the session itself. Handlers
        must call this instead of editing the private maps.
        """
        session_id = self._ws_map.pop(ws_key, None)
        if session_id is None:
            return None
        session = self._sessions.get(session_id)
        if session is None:
            return session_id
        session["users"].pop(ws_key, None)
        session["connections"].pop(ws_key, None)
        if not session["users"]:
            self._sessions.pop(session_id, None)
        return session_id

    def list_users(self, session_id: str) -> list[dict[str, Any]]:
        session = self._sessions.get(session_id)
        if session is None:
            return []
        return list(session["users"].values())

    def get_connected(self, session_id: str) -> list[WebSocket]:
        session = self._sessions.get(session_id)
        if session is None:
            return []
        return list(session["connections"].values())

    async def broadcast(
        self, session_id: str, payload: dict[str, Any], *, exclude_ws_key: str | None = None
    ) -> int:
        """Send ``payload`` once to every live connection in the session.

        Connections whose client state is not CONNECTED are never
        sent to; a failed send prunes the socket via :meth:`leave_user`
        so a closed connection cannot linger or receive a second copy.
        Returns the number of deliveries.
        """
        session = self._sessions.get(session_id)
        if session is None:
            return 0
        # Local import: the starlette name is resolved here so this
        # method does not depend on the module-level optional import
        # (which is None when the [api] extra is absent).
        from starlette.websockets import WebSocketState

        dead: list[str] = []
        sent = 0
        for ws_key, conn in list(session["connections"].items()):
            if ws_key == exclude_ws_key:
                continue
            state = getattr(conn, "client_state", None)
            if state is not None and state is not WebSocketState.CONNECTED:
                dead.append(ws_key)
                continue
            try:
                await conn.send_json(payload)
            except Exception:
                dead.append(ws_key)
            else:
                sent += 1
        for ws_key in dead:
            self.leave_user(ws_key)
        if session_id in self._sessions:
            session["last_activity"] = datetime.now(UTC).isoformat()
        return sent

    def session_info(self, session_id: str) -> dict[str, Any] | None:
        session = self._sessions.get(session_id)
        if session is None:
            return None
        return {
            "session_id": session_id,
            "created_at": session["created_at"],
            "last_activity": session.get("last_activity"),
            "user_count": len(session["users"]),
            "users": session["users"],
        }

    def _evict_expired(self) -> int:
        """Remove empty sessions and sessions idle past the timeout.

        A session with no users is always reclaimable. A session with
        users is reclaimable only when its last activity is older than
        ``session_timeout_seconds`` (a zero timeout expires immediately).
        Socket mappings pointing at a removed session are dropped with it.
        Returns the number of sessions removed.
        """
        now = datetime.now(UTC)
        to_remove = []
        for sid, session in self._sessions.items():
            if not session["users"]:
                to_remove.append(sid)
                continue
            if self.session_timeout_seconds <= 0:
                to_remove.append(sid)
                continue
            last = session.get("last_activity") or session.get("created_at")
            try:
                last_dt = datetime.fromisoformat(last) if isinstance(last, str) else None
            except ValueError:
                last_dt = None
            if (
                last_dt is not None
                and (now - last_dt).total_seconds() > self.session_timeout_seconds
            ):
                to_remove.append(sid)
        for sid in to_remove:
            self._sessions.pop(sid, None)
            for ws_key in [k for k, v in self._ws_map.items() if v == sid]:
                self._ws_map.pop(ws_key, None)
        return len(to_remove)

    def cleanup(self) -> int:
        """Remove empty/expired sessions. Returns number removed."""
        return self._evict_expired()


if BaseModel is not None:

    class TextRequest(BaseModel):
        text: str

    class AnalyzeResponse(BaseModel):
        success: bool
        data: dict[str, Any] | None = None
        error: str | None = None

    class ExportRequest(BaseModel):
        data: dict[str, Any]
        format: str = "json"  # json | csv | html

    class CompareRequest(BaseModel):
        a: dict[str, Any]
        b: dict[str, Any]

    class HistoryQueryRequest(BaseModel):
        limit: int = 50
        offset: int = 0
        verdict: str | None = None
        family: str | None = None
        min_score: float | None = None
        max_score: float | None = None

else:  # pragma: no cover - optional dependency
    # The [api] extra is absent: keep the names importable (as None)
    # so the module stays importable; create_web_app() refuses to run.
    TextRequest = AnalyzeResponse = ExportRequest = None  # type: ignore[assignment]
    CompareRequest = HistoryQueryRequest = None  # type: ignore[assignment]


def _require_web() -> None:
    """Raise the install hint unless the [api] extra is present."""
    if FastAPI is None or BaseModel is None:
        raise RuntimeError("Install web UI support with: pip install 'textforensics[api]'")


def create_web_app(settings: Settings | None = None) -> FastAPI:
    """Create the FastAPI web application with WebSocket support."""
    _require_web()
    active_settings = settings or Settings.from_env()

    app = FastAPI(
        title="TextForensics Web UI",
        version=get_version(),
        description="Real-time AI-text detector analysis and visualization dashboard.",
    )
    app.state.textforensics_settings = active_settings

    # Application-scoped session manager (IF-10): each app instance
    # owns its sessions, so two apps (two TestClients, two servers)
    # never share users or socket references.
    manager = SessionManager()
    app.state.session_manager = manager

    # Shared redacting error handlers (IF-07): validation errors are
    # sanitized (loc/msg/type only), HTTPException status/detail are
    # preserved verbatim, unexpected errors are a generic 500. Never
    # raise HTTPException with a detail built from caller input or a
    # caught exception -- every string detail raised below is a
    # server-constructed constant.
    register_redacting_handlers(app)

    # Mount static files
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    # Templates
    templates_dir = os.path.join(os.path.dirname(__file__), "templates")
    templates = Jinja2Templates(directory=templates_dir)

    def checked(text: str) -> str:
        try:
            return validate_text_input(
                text,
                max_input_bytes=active_settings.max_input_bytes,
            )
        except ValueError as exc:
            from fastapi import HTTPException

            status = 413 if "exceeds" in str(exc) else 422
            raise HTTPException(
                status_code=status,
                detail="Invalid text input.",
            ) from exc

    # ── Server-side history ring buffer ──────────────────────────────
    max_history = int(os.environ.get("TEXTFORENSICS_HISTORY_MAX", "100"))
    # Total retained-history byte quota: count quota x per-entry quota.
    max_history_bytes = max_history * _MAX_HISTORY_ENTRY_BYTES
    history_buffer: OrderedDict[str, dict[str, Any]] = OrderedDict()

    def _history_entry_bytes(entry: dict[str, Any]) -> int:
        try:
            return len(json.dumps(entry, ensure_ascii=False).encode("utf-8"))
        except (TypeError, ValueError):
            return _MAX_HISTORY_ENTRY_BYTES + 1

    def store_analysis(data: dict[str, Any]) -> str | None:
        """Insert or update an analysis result in the ring buffer.

        Returns its server-side ID, or None when the entry exceeds the
        per-entry byte quota and is refused (never retained). The
        count quota (``max_history``) and the total byte quota evict
        the oldest entries first.
        """
        analysis_id = str(uuid.uuid4())
        entry = {
            "id": analysis_id,
            "stored_at": datetime.now(UTC).isoformat(),
            "data": data,
        }
        if _history_entry_bytes(entry) > _MAX_HISTORY_ENTRY_BYTES:
            return None
        history_buffer[analysis_id] = entry
        # Evict oldest entries beyond the count / total-byte quotas.
        while len(history_buffer) > max_history:
            history_buffer.popitem(last=False)
        while (
            history_buffer
            and sum(_history_entry_bytes(e) for e in history_buffer.values()) > max_history_bytes
        ):
            history_buffer.popitem(last=False)
        return analysis_id

    def query_history(
        limit: int = 50,
        offset: int = 0,
        verdict: str | None = None,
        family: str | None = None,
        min_score: float | None = None,
        max_score: float | None = None,
    ) -> list[dict[str, Any]]:
        """Return filtered, paginated history entries (metadata only, no full data)."""
        entries = list(history_buffer.values())
        # Apply filters
        filtered = []
        for entry in entries:
            data = entry.get("data", {})
            consensus = data.get("consensus", {})

            if verdict is not None and consensus.get("verdict") != verdict:
                continue
            if family is not None:
                families = [
                    v.get("detector_family", "") for v in (consensus.get("family_votes") or [])
                ]
                if family not in families:
                    continue
            if min_score is not None:
                score = consensus.get("calibrated_ai_probability")
                if score is None or score < min_score:
                    continue
            if max_score is not None:
                score = consensus.get("calibrated_ai_probability")
                if score is None or score > max_score:
                    continue

            filtered.append(
                {
                    "id": entry["id"],
                    "stored_at": entry["stored_at"],
                    "verdict": consensus.get("verdict"),
                    # Canonical ensemble probability only (IF-04):
                    # the calibrated value with its calibration identity;
                    # no legacy bare ai_probability field is emitted.
                    "calibrated_ai_probability": consensus.get("calibrated_ai_probability"),
                    "ensemble_calibration_id": consensus.get("ensemble_calibration_id"),
                    "independent_families": consensus.get("independent_families"),
                    "word_count": data.get("input", {}).get("word_count"),
                    "content_sha256": data.get("content_sha256", "")[:16] + "…",
                    "trust_overall": data.get("trust_map", {}).get("overall"),
                    "detector_count": len(data.get("detector_results") or []),
                }
            )
        # Sort by stored_at descending (newest first)
        filtered.sort(key=lambda e: e["stored_at"], reverse=True)
        return filtered[offset : offset + limit]

    def secure_response(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-TextForensics-Version"] = get_version()
        # Content-Security-Policy carried over from the former stdlib UI
        # (webapp.py), tightened for scripts: the page has no inline
        # <script> blocks or inline event handlers (all handlers are
        # addEventListener in /static/app.js), so script-src 'self' is
        # safe. style-src keeps 'unsafe-inline' because the template and
        # app.js-generated HTML use inline style attributes throughout.
        # Chart.js is vendored at /static/chart.umd.min.js, so no
        # third-party origin needs allowing (local-first).
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'unsafe-inline'; "
            "script-src 'self'; connect-src 'self'; "
            "img-src 'self' data:; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'"
        )
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

    @app.middleware("http")
    async def request_guard_and_security_headers(request: Request, call_next):
        # Emergency stop gate (shared check; see execution_policy).
        from ..execution_policy import is_execution_stopped

        if is_execution_stopped():
            return secure_response(
                JSONResponse(
                    status_code=503,
                    content={"detail": "Emergency stop is active. All API calls are blocked."},
                )
            )
        if request.method in {"POST", "PUT", "PATCH"}:
            if request.headers.get("transfer-encoding"):
                return secure_response(
                    JSONResponse(
                        status_code=411,
                        content={"detail": "Streaming request bodies are not accepted."},
                    )
                )
            raw_length = request.headers.get("content-length")
            if raw_length is None:
                return secure_response(
                    JSONResponse(
                        status_code=411,
                        content={"detail": "Content-Length is required."},
                    )
                )
            try:
                body_length = int(raw_length)
            except ValueError:
                return secure_response(
                    JSONResponse(
                        status_code=400,
                        content={"detail": "Invalid Content-Length."},
                    )
                )
            if body_length < 0:
                return secure_response(
                    JSONResponse(
                        status_code=400,
                        content={"detail": "Invalid Content-Length."},
                    )
                )
            max_body_bytes = active_settings.max_input_bytes * 2 + 65_536
            if body_length > max_body_bytes:
                return secure_response(
                    JSONResponse(
                        status_code=413,
                        content={"detail": "Request body is too large."},
                    )
                )

        return secure_response(await call_next(request))

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        session_id = request.query_params.get("session")
        return templates.TemplateResponse(
            request,
            "index.html",
            {"request": request, "version": get_version(), "session_id": session_id},
        )

    @app.get("/index.html", response_class=HTMLResponse)
    async def index_html(request: Request):
        """Alias for `/` (kept from the former stdlib UI)."""
        return await index(request)

    # ── Collaboration REST endpoints ─────────────────────────────────

    @app.get("/healthz", include_in_schema=False)
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    def ready() -> dict[str, str]:
        return {"status": "ready"}

    @app.get("/version")
    def version_info() -> dict[str, str]:
        return {"name": "TextForensics", "version": get_version()}

    @app.get("/v1/detectors")
    def detectors() -> dict[str, Any]:
        return {
            "detectors": list_detector_metadata(),
            "plugin_health": list_detector_health(),
        }

    # ── Collaboration REST endpoints ──────────────────────────────────────

    @app.post("/api/session")
    def create_session() -> dict[str, str]:
        """Create a new collaboration session."""
        session_id = manager.create_session()
        return {"session_id": session_id}

    @app.get("/api/session/{session_id}")
    def get_session_info(session_id: str) -> dict[str, Any]:
        """Get session info including connected users."""
        info = manager.session_info(session_id)
        if info is None:
            # Constant detail: the caller-supplied identifier is never
            # reflected in an error (IF-07).
            raise HTTPException(status_code=404, detail="Session not found")
        return info

    @app.get("/api/session/{session_id}/users")
    def get_session_users(session_id: str) -> list[dict[str, Any]]:
        """List users in a session."""
        return manager.list_users(session_id)

    @app.delete("/api/session")
    def cleanup_sessions() -> dict[str, int]:
        """Clean up empty/expired sessions."""
        removed = manager.cleanup()
        return {"removed": removed}

    @app.post("/api/analyze", response_model=AnalyzeResponse)
    def analyze(req: TextRequest):
        """Batch analysis endpoint - returns full forensic bundle.

        Error contract (IF-07): oversize text is 413, invalid input
        is 422, an active stop is 503, unexpected failures are 500 --
        each with a stable generic detail and no rejected input,
        exception text, traceback or path. HTTPException details are
        server-constructed constants, so they propagate unchanged to
        the shared redacting handler.
        """
        try:
            assert_execution_allowed()
            # Explicit default policy (IF-01): local-only unless a later
            # surface passes an explicitly consented policy.
            policy = ExecutionPolicy.default_local_only(
                max_input_bytes=active_settings.max_input_bytes
            )
            bundle = build_forensic_bundle(checked(req.text), execution_policy=policy)
            result = bundle.to_dict()
            store_analysis(result)
            return AnalyzeResponse(success=True, data=result)
        except HTTPException:
            raise
        except Exception as exc:
            status = error_status_for_exception(exc)
            raise HTTPException(
                status_code=status, detail=public_message_for_status(status)
            ) from exc

    @app.post("/api/report")
    async def report_compat(request: Request):
        """Compatibility alias for the former stdlib UI's POST /api/report.

        Returns the raw forensic bundle (no ``{success, data}`` wrapper),
        with the former endpoint's error shape (``400 {"error":
        "invalid request"}`` for malformed or invalid input). Unlike
        ``/api/analyze`` the result is not stored in the history ring
        buffer — the former endpoint had no history. The emergency-stop
        gate applies via the request middleware, closing the hole the
        stdlib UI had (it analysed text even while the stop was active).
        The assert below is a second, in-handler check for a stop
        raised between middleware and dispatch; it returns the same
        constant 503 as the middleware.
        """
        try:
            assert_execution_allowed()
        except EmergencyStopError:
            return JSONResponse(
                status_code=503,
                content={"detail": "Emergency stop is active."},
            )
        try:
            payload = await request.json()
        except Exception:
            return JSONResponse(status_code=400, content={"error": "invalid request"})
        if not isinstance(payload, dict):
            return JSONResponse(status_code=400, content={"error": "invalid request"})
        try:
            text = validate_text_input(
                payload.get("text"),
                max_input_bytes=active_settings.max_input_bytes,
            )
        except ValueError:
            return JSONResponse(status_code=400, content={"error": "invalid request"})
        try:
            policy = ExecutionPolicy.default_local_only(
                max_input_bytes=active_settings.max_input_bytes
            )
            bundle = build_forensic_bundle(text, execution_policy=policy)
        except ValueError:
            return JSONResponse(status_code=400, content={"error": "invalid request"})
        return JSONResponse(status_code=200, content=bundle.to_dict())

    # ── Export endpoint ─────────────────────────────────────────────

    @app.post("/api/export")
    def export_report(req: ExportRequest):
        """Export analysis results as JSON, CSV, or HTML report."""
        fmt = req.format.lower()
        if fmt not in ("json", "csv", "html"):
            # Constant detail: the caller-supplied format is never
            # reflected in an error (IF-07).
            return JSONResponse(
                status_code=400,
                content={"error": "Unsupported format. Use json, csv, or html."},
            )

        if fmt == "json":
            content = json.dumps(req.data, indent=2, ensure_ascii=False)
            return StreamingResponse(
                io.BytesIO(content.encode("utf-8")),
                media_type="application/json",
                headers={
                    "Content-Disposition": f'attachment; filename="textforensics-report-{_report_timestamp()}.json"',
                },
            )

        if fmt == "csv":
            csv_buf = io.StringIO()
            writer = csv.writer(csv_buf)
            _write_csv_report(writer, req.data)
            return StreamingResponse(
                io.BytesIO(csv_buf.getvalue().encode("utf-8")),
                media_type="text/csv",
                headers={
                    "Content-Disposition": f'attachment; filename="textforensics-report-{_report_timestamp()}.csv"',
                },
            )

        # html
        html_content = _build_html_report(req.data)
        return StreamingResponse(
            io.BytesIO(html_content.encode("utf-8")),
            media_type="text/html",
            headers={
                # codeql[py/reflective-xss] Timestamp is server-generated, not user input
                "Content-Disposition": f'attachment; filename="textforensics-report-{_report_timestamp()}.html"',
            },
        )

    # ── Compare endpoint ─────────────────────────────────────────────

    @app.post("/api/compare")
    def compare_analyses(req: CompareRequest):
        """Return a side-by-side diff of two analysis results."""
        return _build_comparison(req.a, req.b)

    # ── History endpoint ─────────────────────────────────────────────

    @app.get("/api/history")
    def get_history(
        limit: int = 50,
        offset: int = 0,
        verdict: str | None = None,
        family: str | None = None,
        min_score: float | None = None,
        max_score: float | None = None,
    ):
        """Return paginated, filtered analysis history (metadata only)."""
        entries = query_history(
            limit=limit,
            offset=offset,
            verdict=verdict,
            family=family,
            min_score=min_score,
            max_score=max_score,
        )
        return {
            "entries": entries,
            "total": len(history_buffer),
            "returned": len(entries),
        }

    @app.delete("/api/history")
    def clear_history():
        """Clear all stored analysis history."""
        history_buffer.clear()
        return {"status": "cleared", "count": 0}

    @app.get("/api/history/{analysis_id}")
    def get_history_item(analysis_id: str):
        """Return a single stored analysis result by ID."""
        entry = history_buffer.get(analysis_id)
        if entry is None:
            return JSONResponse(
                status_code=404,
                content={"error": "Analysis not found in history"},
            )
        return {"id": entry["id"], "stored_at": entry["stored_at"], "data": entry["data"]}

    @app.websocket("/ws/analyze")
    async def websocket_analyze(websocket: WebSocket):
        """WebSocket endpoint for real-time analysis streaming with collaboration support.

        Trust boundary (IF-05, W1 Worker C): the handshake validates
        the configured Host and the exact Origin before accept, so a
        cross-origin page cannot drive an analysis. Frames over the
        byte cap are closed before JSON parsing; every message must
        match its schema; shared bundles must pass enum/size
        validation, and sharing by server-side analysis ID is the
        trusted path (a caller-supplied bundle is validated, never
        trusted blindly).

        Stop gate (IF-03, W1 Worker C): the handshake refuses while
        stopped, every new analysis/share/join operation checks the
        shared stop before starting (no ``started`` is sent while
        stopped), and detector dispatch itself re-checks between
        steps, so a stop raised mid-run starts no further plugin
        step. Leaving (cleanup) is always allowed.

        Errors (IF-07, W1 Worker C): all WebSocket errors use the
        shared generic error body -- no exception text, rejected
        input, traceback or path is ever sent.
        """
        # Trust boundary first: an untrusted origin learns nothing
        # about the stop state. Refusal happens before accept, so no
        # frame -- not even "started" -- is ever sent to it.
        if not _is_allowed_ws_handshake(websocket, active_settings):
            await websocket.close(code=1008, reason="Origin or host not allowed.")
            return
        if is_execution_stopped():
            await websocket.close(code=1011, reason="Emergency stop is active.")
            return
        await websocket.accept()
        ws_key = str(uuid.uuid4())
        max_frame_bytes = active_settings.max_input_bytes + _WS_FRAME_OVERHEAD_BYTES

        # Optional session parameter from query string
        session_id = websocket.query_params.get("session")

        try:
            while True:
                # Receive message from client; reject oversized frames
                # BEFORE JSON parsing.
                raw = await websocket.receive_text()
                if len(raw.encode("utf-8")) > max_frame_bytes:
                    await websocket.close(code=1009, reason="Message too large.")
                    return
                try:
                    message = json.loads(raw)
                except ValueError:
                    await websocket.send_json(_ws_error_body(422))
                    continue
                if not isinstance(message, dict):
                    await websocket.send_json(_ws_error_body(422))
                    continue
                msg_type = message.get("type")
                # Session activity: any message from a joined socket
                # keeps its session live for the idle-expiry policy.
                manager.touch(ws_key)

                # ── Collaboration messages ────────────────────────
                if msg_type == "join_session":
                    # History/session mutation: refused while stopped.
                    try:
                        assert_execution_allowed()
                    except (
                        EmergencyStopError,
                        ExecutionCancelled,
                        ExecutionPolicyError,
                    ) as exc:
                        await websocket.send_json(_ws_error_body(error_status_for_exception(exc)))
                        continue
                    sess_id = message.get("session_id") or session_id
                    display_name = message.get("display_name", "Anonymous")
                    if (
                        not isinstance(sess_id, str)
                        or not sess_id
                        or len(sess_id) > _MAX_WS_ID_CHARS
                        or not isinstance(display_name, str)
                        or len(display_name) > _MAX_WS_DISPLAY_NAME_CHARS
                    ):
                        await websocket.send_json(_ws_error_body(422))
                        continue
                    try:
                        user_info = manager.join_user(sess_id, ws_key, websocket, display_name)
                        await websocket.send_json(
                            {
                                "type": "session_joined",
                                "session_id": sess_id,
                                "user": user_info,
                                "users": manager.list_users(sess_id),
                            }
                        )
                        # Broadcast to other users in the session
                        # (exactly once each; closed sockets are pruned).
                        await manager.broadcast(
                            sess_id,
                            {
                                "type": "user_joined",
                                "user": user_info,
                                "users": manager.list_users(sess_id),
                            },
                            exclude_ws_key=ws_key,
                        )
                    except ValueError:
                        # Constant: the session identifier is never
                        # reflected in an error (IF-07).
                        await websocket.send_json(_ws_error_body(404))
                    continue

                elif msg_type == "leave_session":
                    # Cleanup is always allowed, including while stopped.
                    # leave_user exclusively owns removal: no direct
                    # private-map edit here (IF-10).
                    sess_id = manager.leave_user(ws_key)
                    if sess_id:
                        with suppress(Exception):
                            await websocket.send_json(
                                {"type": "session_left", "session_id": sess_id}
                            )
                        # Broadcast to remaining users.
                        await manager.broadcast(
                            sess_id,
                            {"type": "user_left", "users": manager.list_users(sess_id)},
                        )
                    continue

                elif msg_type == "analysis_shared":
                    # History mutation: refused while stopped.
                    try:
                        assert_execution_allowed()
                    except (
                        EmergencyStopError,
                        ExecutionCancelled,
                        ExecutionPolicyError,
                    ) as exc:
                        await websocket.send_json(_ws_error_body(error_status_for_exception(exc)))
                        continue
                    sess_id = manager.session_id_for(ws_key)
                    if not sess_id:
                        await websocket.send_json(_ws_error_body(404))
                        continue
                    # Trusted path: share a server-side analysis by ID.
                    # Peers receive the server-stored object, and
                    # sharing never duplicates the retained entry.
                    analysis_id = message.get("analysis_id")
                    shared_data: dict[str, Any] | None = None
                    stored_id: str | None = None
                    if isinstance(analysis_id, str) and analysis_id:
                        entry = history_buffer.get(analysis_id)
                        if entry is None:
                            await websocket.send_json(_ws_error_body(404))
                            continue
                        stored_id = entry["id"]
                        shared_data = entry["data"]
                    elif "data" in message:
                        # Compatibility path: a caller-supplied bundle
                        # is validated (schema, verdict enums, size)
                        # before it may enter history -- never trusted
                        # blindly. Forged markup/oversized verdicts
                        # are rejected here.
                        try:
                            _validate_shared_bundle(message.get("data"))
                        except ValueError:
                            await websocket.send_json(_ws_error_body(422))
                            continue
                        stored_id = store_analysis(message["data"])
                        if stored_id is None:
                            await websocket.send_json(_ws_error_body(413))
                            continue
                        shared_data = message["data"]
                    else:
                        await websocket.send_json(_ws_error_body(422))
                        continue
                    shared_by = message.get("shared_by", ws_key)
                    if not isinstance(shared_by, str) or len(shared_by) > _MAX_WS_ID_CHARS:
                        shared_by = ws_key
                    await websocket.send_json({"type": "analysis_shared", "analysis_id": stored_id})
                    # Peers receive the share exactly once each; the
                    # sender already has the ack above.
                    await manager.broadcast(
                        sess_id,
                        {
                            "type": "analysis_shared",
                            "data": shared_data,
                            "analysis_id": stored_id,
                            "shared_by": shared_by,
                        },
                        exclude_ws_key=ws_key,
                    )
                    continue

                # ── Existing analysis protocol ────────────────────
                elif msg_type == "analyze":
                    text = message.get("text", "")
                    if not isinstance(text, str):
                        await websocket.send_json(_ws_error_body(422))
                        continue
                    if not text:
                        await websocket.send_json(
                            {
                                "type": "error",
                                "message": "Empty text provided",
                                "error_code": "invalid_request",
                                "request_id": new_request_id(),
                            }
                        )
                        continue

                    # Validate input (oversize -> 413, invalid -> 422;
                    # constant messages only, connection stays open).
                    try:
                        validated_text = checked(text)
                    except HTTPException as exc:
                        await websocket.send_json(_ws_error_body(exc.status_code))
                        continue
                    except ValueError:
                        await websocket.send_json(_ws_error_body(422))
                        continue

                    # Stop gate BEFORE "started" (IF-03): an active
                    # stop refuses the operation with zero detector
                    # calls and no "started" frame.
                    try:
                        assert_execution_allowed()
                    except (
                        EmergencyStopError,
                        ExecutionCancelled,
                        ExecutionPolicyError,
                    ) as exc:
                        await websocket.send_json(_ws_error_body(error_status_for_exception(exc)))
                        continue

                    # Send analysis started
                    await websocket.send_json({"type": "started", "message": "Analysis started"})

                    # Run analysis in thread pool to avoid blocking
                    loop = asyncio.get_event_loop()

                    # Stream detector results one by one, under the shared
                    # execution policy (default local-only; an active stop
                    # raises here with zero detector calls).
                    from ..detectors import run_all_detectors

                    policy = ExecutionPolicy.default_local_only(
                        max_input_bytes=active_settings.max_input_bytes
                    )
                    detector_results = await loop.run_in_executor(
                        None,
                        lambda text=validated_text, pol=policy: run_all_detectors(text, policy=pol),
                    )

                    for i, result in enumerate(detector_results):
                        await websocket.send_json(
                            {
                                "type": "detector_result",
                                "index": i,
                                "total": len(detector_results),
                                "data": result,
                            }
                        )
                        # Small delay to simulate streaming
                        await asyncio.sleep(0.05)

                    # Build and send final bundle (same policy: local-only
                    # unless an explicitly consented policy is passed).
                    # Exactly-once base observations (IF-06): the bundle
                    # reuses the detector rows already streamed above
                    # instead of running the base detectors a second time.
                    bundle = build_forensic_bundle(
                        validated_text,
                        execution_policy=policy,
                        observations=detector_results,
                    )
                    result_data = bundle.to_dict()
                    analysis_id = store_analysis(result_data)

                    # If in a session, broadcast to other collaborators.
                    # The joined session (via join_session) owns routing;
                    # the ?session= query parameter is the fallback for
                    # clients that connect already addressed to a room.
                    broadcast_session_id = manager.session_id_for(ws_key) or session_id
                    if (
                        broadcast_session_id
                        and analysis_id is not None
                        and manager.has_session(broadcast_session_id)
                    ):
                        await manager.broadcast(
                            broadcast_session_id,
                            {
                                "type": "analysis_result_shared",
                                "data": result_data,
                                "analysis_id": analysis_id,
                            },
                            exclude_ws_key=ws_key,
                        )

                    await websocket.send_json({"type": "complete", "data": result_data})

                else:
                    await websocket.send_json(_ws_error_body(422))
                    continue

        except WebSocketDisconnect:
            pass
        except Exception as exc:
            # Generic error only: never exception text, rejected input,
            # tracebacks or paths (IF-07). The socket closes after an
            # unexpected failure; content errors above keep it open.
            with suppress(Exception):
                await websocket.send_json(_ws_error_body(error_status_for_exception(exc)))
        finally:
            # Always clean up on disconnect; leave_user exclusively
            # owns removal (IF-10).
            manager.leave_user(ws_key)

    return app


app = None
# Lets `uvicorn textforensics.web_ui.main:app` work when extras are installed.
with suppress(RuntimeError, ValueError):
    from ..config import Settings

    app = create_web_app()


def serve_web(
    host: str | None = None,
    port: int | None = None,
    *,
    allow_remote: bool = False,
    access_log: bool = True,
    log_level: str = "info",
    max_input_bytes: int | None = None,
    open_browser: bool = False,
) -> None:
    """Serve the web UI application.

    ``host``/``port`` default to the environment (``TEXTFORENSICS_HOST`` /
    ``TEXTFORENSICS_PORT`` via :meth:`Settings.from_env`, falling back to
    127.0.0.1:8765); an explicit argument overrides the environment.
    """
    env_settings = Settings.from_env()
    settings = Settings(
        host=host if host is not None else env_settings.host,
        port=port if port is not None else env_settings.port,
        max_input_bytes=max_input_bytes
        if max_input_bytes is not None
        else env_settings.max_input_bytes,
        allow_remote=allow_remote,
        access_log=access_log,
        log_level=log_level,
    )
    ensure_bind_allowed(settings.host, allow_remote=settings.allow_remote)

    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError("Install web UI support with: pip install 'textforensics[api]'") from exc

    # URL print + browser auto-open carried over from the former stdlib
    # UI (webapp.py), which printed the URL and opened the browser for
    # the `textforensics web` command.
    display_host = "127.0.0.1" if is_unspecified_host(settings.host) else settings.host
    url = f"http://{display_host}:{settings.port}/"
    print(f"TextForensics UI: {url}")
    if not is_loopback_host(settings.host):
        print(
            "Warning: network-visible browser UI enabled explicitly. "
            "Place it behind appropriate access controls in shared environments."
        )
    print("Press Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.25, lambda: webbrowser.open(url)).start()

    uvicorn.run(
        create_web_app(settings),
        host=settings.host,
        port=settings.port,
        access_log=settings.access_log,
        log_level=settings.log_level.lower(),
    )


def _report_timestamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%S")


def _calibrated_display(consensus: dict[str, Any]) -> tuple[str, str]:
    """(probability display, calibration-ID display) for a consensus mapping.

    A top-level probability is shown only from the canonical
    ``calibrated_ai_probability`` field together with its
    ``ensemble_calibration_id``; anything else is "Not calibrated",
    never a number (IF-04).
    """
    value = consensus.get("calibrated_ai_probability")
    cal_id = consensus.get("ensemble_calibration_id")
    if (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and 0.0 <= float(value) <= 1.0
        and isinstance(cal_id, str)
        and cal_id
    ):
        return f"{float(value) * 100:.1f}%", cal_id
    return "Not calibrated", "Not calibrated"


def _csv_safe(value: object) -> object:
    """Neutralize spreadsheet-formula injection in a CSV cell (IF-14).

    A string cell whose first non-whitespace character could start a
    formula (``=``, ``+``, ``-``, ``@``) is prefixed with a single
    quote, the standard escaping; the quoted value round-trips through
    a CSV parser as literal text. Numbers pass through unchanged.
    """
    if not isinstance(value, str):
        return value
    if value.lstrip()[:1] in ("=", "+", "-", "@"):
        return "'" + value
    return value


def _write_csv_report(writer: csv.writer, data: dict[str, Any]) -> None:
    """Write a CSV report from a forensic bundle dict.

    Every cell passes through :func:`_csv_safe`, so detector metadata
    or limitation text can never start a spreadsheet formula. The
    report carries the canonical calibrated probability (never a
    legacy bare value), the trust map, the limitations and the
    provenance needed to match the JSON export of the same bundle.
    """
    consensus = data.get("consensus", {})
    prob_str, cal_id_str = _calibrated_display(consensus)

    def row(*cells: object) -> None:
        writer.writerow([_csv_safe(cell) for cell in cells])

    # Section: consensus
    row("Section", "Field", "Value")
    row("Consensus", "Verdict", consensus.get("verdict", ""))
    row("Consensus", "Calibrated AI Probability", prob_str)
    row("Consensus", "Ensemble Calibration ID", cal_id_str)
    row("Consensus", "Independent Families", consensus.get("independent_families", 0))
    row("Consensus", "Family Agreement", consensus.get("family_agreement", "N/A"))
    # Section: detectors
    for det in data.get("detector_results", []):
        row("Detector", det.get("detector_id", ""), "")
        row("Detector", "Version", det.get("detector_version", ""))
        row("Detector", "Family", det.get("detector_family", ""))
        row("Detector", "Score", det.get("score", ""))
        row("Detector", "Verdict", det.get("verdict", ""))
        row(
            "Detector",
            "Calibrated AI Probability",
            det.get("calibrated_ai_probability", "N/A"),
        )
        row("Detector", "Execution", det.get("execution", ""))
        row()
    # Section: trust map
    trust_map = data.get("trust_map", {})
    row("Trust Map", "Overall", trust_map.get("overall", ""))
    for dim in trust_map.get("dimensions", []):
        row("Trust Map", dim.get("dimension", ""), dim.get("state", ""))
        row("Trust Map", "Reason", dim.get("reason", ""))
    # Section: input
    inp = data.get("input", {})
    row("Input", "Word Count", inp.get("word_count", ""))
    row("Input", "Sentence Count", inp.get("sentence_count", ""))
    row("Input", "Paragraph Count", inp.get("paragraph_count", ""))
    row("Input", "Content SHA256", data.get("content_sha256", ""))
    row("Input", "Generated At", data.get("generated_at_utc", ""))
    # Section: limitations (abstention is preserved, not dropped).
    for limitation in data.get("limitations") or []:
        row("Limitations", "Limitation", limitation)
    # Section: provenance (matches the JSON export of this bundle).
    row("Provenance", "Schema", data.get("schema", ""))
    row("Provenance", "Content SHA256", data.get("content_sha256", ""))
    row("Provenance", "Generated At", data.get("generated_at_utc", ""))


def _build_html_report(data: dict[str, Any]) -> str:
    """Build a simple HTML report from a forensic bundle dict."""
    consensus = data.get("consensus", {})
    verdict = consensus.get("verdict", "unknown")
    verdict_labels = {
        "ai_like": "AI-like",
        "human_like": "Human-like",
        "abstain": "Abstain",
        "insufficient_evidence": "Insufficient Evidence",
        "mixed": "Mixed",
    }
    verdict_text = verdict_labels.get(verdict, verdict)
    prob_str, cal_id_str = _calibrated_display(consensus)

    trust_map = data.get("trust_map", {})
    trust_overall = trust_map.get("overall", "unknown")
    dims = trust_map.get("dimensions", [])

    detectors = data.get("detector_results", [])
    inp = data.get("input", {})

    detectors_html = "".join(
        f"""<tr>
            <td>{_escape(d.get("detector_id", ""))}</td>
            <td>{_escape(d.get("detector_version", ""))}</td>
            <td>{_escape(d.get("detector_family", ""))}</td>
            <td>{_escape(d.get("score", ""))}</td>
            <td>{_escape(d.get("verdict", ""))}</td>
            <td>{_escape(d.get("calibrated_ai_probability", "N/A"))}</td>
        </tr>"""
        for d in detectors
    )

    trust_dims_html = "".join(
        f"""<tr>
            <td>{_escape(dim.get("dimension", ""))}</td>
            <td>{_escape(dim.get("state", ""))}</td>
            <td>{_escape(dim.get("reason", ""))}</td>
        </tr>"""
        for dim in dims
    )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>TextForensics Report — {_escape(_report_timestamp())}</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }}
h1 {{ border-bottom: 2px solid #333; padding-bottom: 0.5rem; }}
h2 {{ margin-top: 2rem; color: #444; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
th, td {{ border: 1px solid #ccc; padding: 8px 12px; text-align: left; }}
th {{ background: #f5f5f5; }}
.verdict {{ font-size: 1.5rem; font-weight: bold; padding: 0.5rem 1rem; border-radius: 6px; display: inline-block; }}
.verdict-ai_like {{ background: #fee2e2; color: #991b1b; }}
.verdict-human_like {{ background: #dcfce7; color: #166534; }}
.verdict-abstain, .verdict-insufficient_evidence {{ background: #fef3c7; color: #92400e; }}
.meta {{ margin: 1rem 0; color: #666; }}
</style></head><body>
<h1>TextForensics — Forensic Bundle Report</h1>
<p class="meta">Generated: {_escape(data.get("generated_at_utc", "N/A"))} &middot; SHA256: {_escape(data.get("content_sha256", "")[:16])}&hellip;</p>

<h2>Consensus Verdict</h2>
<div class="verdict verdict-{_escape(verdict)}">{_escape(verdict_text)}</div>
<p>AI Probability: {_escape(prob_str)} &middot; Ensemble Calibration: {_escape(cal_id_str)} &middot; Independent Families: {_escape(consensus.get("independent_families", "N/A"))}</p>

<h2>Input Statistics</h2>
<p>Words: {_escape(inp.get("word_count", "N/A"))} &middot; Sentences: {_escape(inp.get("sentence_count", "N/A"))} &middot; Paragraphs: {_escape(inp.get("paragraph_count", "N/A"))}</p>

<h2>Detector Results</h2>
<table><tr><th>Detector</th><th>Version</th><th>Family</th><th>Score</th><th>Verdict</th><th>Cal. AI Prob.</th></tr>{detectors_html}</table>

<h2>Trust Map</h2>
<p>Overall: {_escape(trust_overall)}</p>
<table><tr><th>Dimension</th><th>State</th><th>Reason</th></tr>{trust_dims_html}</table>

<h2>Warnings &amp; Limitations</h2>
<ul>{"".join(f"<li>{_escape(w)}</li>" for w in (data.get("limitations") or []))}</ul>

</body></html>"""


def _build_comparison(data_a: dict[str, Any], data_b: dict[str, Any]) -> dict[str, Any]:
    """Build a side-by-side comparison of two forensic bundles."""
    consensus_a = data_a.get("consensus", {})
    consensus_b = data_b.get("consensus", {})

    def _compare_detectors(results_a: list[dict], results_b: list[dict]) -> list[dict[str, Any]]:
        """Pair detector results by detector_id and compute differences."""
        map_a = {d.get("detector_id"): d for d in results_a}
        map_b = {d.get("detector_id"): d for d in results_b}
        all_ids = sorted(set(map_a.keys()) | set(map_b.keys()))

        comparison = []
        for det_id in all_ids:
            a = map_a.get(det_id)
            b = map_b.get(det_id)
            score_a = a.get("calibrated_ai_probability") if a else None
            score_b = b.get("calibrated_ai_probability") if b else None

            diff = None
            if score_a is not None and score_b is not None:
                diff = round(score_b - score_a, 6)

            verdict_a = a.get("verdict") if a else None
            verdict_b = b.get("verdict") if b else None

            comparison.append(
                {
                    "detector_id": det_id,
                    "score_a": score_a,
                    "score_b": score_b,
                    "score_diff": diff,
                    "verdict_a": verdict_a,
                    "verdict_b": verdict_b,
                    "verdict_changed": verdict_a != verdict_b,
                    "family": (a.get("detector_family") if a else None),
                }
            )
        return comparison

    def _compare_trust(trust_a: dict, trust_b: dict) -> list[dict[str, Any]]:
        """Compare trust map dimensions."""
        dims_a = {d.get("dimension"): d for d in trust_a.get("dimensions", [])}
        dims_b = {d.get("dimension"): d for d in trust_b.get("dimensions", [])}
        all_dims = sorted(set(dims_a.keys()) | set(dims_b.keys()))

        comparison = []
        for dim in all_dims:
            a = dims_a.get(dim)
            b = dims_b.get(dim)
            comparison.append(
                {
                    "dimension": dim,
                    "state_a": a.get("state") if a else None,
                    "state_b": b.get("state") if b else None,
                    "state_changed": (a.get("state") if a else None)
                    != (b.get("state") if b else None),
                    "reason_a": a.get("reason") if a else None,
                    "reason_b": b.get("reason") if b else None,
                }
            )
        return comparison

    return {
        "summary": {
            "verdict_a": consensus_a.get("verdict"),
            "verdict_b": consensus_b.get("verdict"),
            "verdict_changed": consensus_a.get("verdict") != consensus_b.get("verdict"),
            # Canonical ensemble probability only (IF-04): the
            # calibrated value with its calibration identity; no legacy
            # bare ai_probability field is emitted.
            "calibrated_ai_probability_a": consensus_a.get("calibrated_ai_probability"),
            "calibrated_ai_probability_b": consensus_b.get("calibrated_ai_probability"),
            "ensemble_calibration_id_a": consensus_a.get("ensemble_calibration_id"),
            "ensemble_calibration_id_b": consensus_b.get("ensemble_calibration_id"),
            "families_a": consensus_a.get("independent_families"),
            "families_b": consensus_b.get("independent_families"),
            "trust_overall_a": data_a.get("trust_map", {}).get("overall"),
            "trust_overall_b": data_b.get("trust_map", {}).get("overall"),
        },
        "detector_comparison": _compare_detectors(
            data_a.get("detector_results", []),
            data_b.get("detector_results", []),
        ),
        "trust_map_comparison": _compare_trust(
            data_a.get("trust_map", {}),
            data_b.get("trust_map", {}),
        ),
        "content_hash_a": data_a.get("content_sha256", ""),
        "content_hash_b": data_b.get("content_sha256", ""),
        "generated_at_a": data_a.get("generated_at_utc", ""),
        "generated_at_b": data_b.get("generated_at_utc", ""),
    }


def main() -> None:
    # The [api] extra is absent: serve_web() raises the install hint as
    # a RuntimeError. Convert it to SystemExit (the MCP pattern) so the
    # `textforensics-web` console script prints one clean line on stderr
    # with exit 1 instead of a traceback. Any other RuntimeError is a
    # real failure and still propagates.
    try:
        serve_web()
    except RuntimeError as exc:
        if str(exc).startswith("Install web UI support"):
            raise SystemExit(str(exc)) from None
        raise


if __name__ == "__main__":
    main()
