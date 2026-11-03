from __future__ import annotations

import asyncio
import csv
import html
import io
import json
import os
import uuid
from collections import OrderedDict
from contextlib import suppress
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from ..config import Settings, ensure_bind_allowed, validate_text_input
from ..detectors import list_detector_health, list_detector_metadata
from ..report import build_forensic_bundle
from ..version import get_version


def _escape(value: object) -> str:
    """Escape a value for safe inclusion in HTML output."""
    if value is None:
        return ""
    return html.escape(str(value))

# ── Session Manager for real-time collaboration ──────────────────────


class SessionManager:
    """In-memory session management for real-time collaboration."""

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
        self._sessions[session_id] = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "users": {},
            "connections": {},
        }
        return session_id

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        return self._sessions.get(session_id)

    def has_session(self, session_id: str) -> bool:
        return session_id in self._sessions

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
        if len(session["users"]) >= self.max_users_per_session:
            raise ValueError("Session is full")
        user_info = {
            "ws_key": ws_key,
            "display_name": display_name,
            "joined_at": datetime.now(timezone.utc).isoformat(),
        }
        session["users"][ws_key] = user_info
        session["connections"][ws_key] = websocket
        self._ws_map[ws_key] = session_id
        return user_info

    def leave_user(self, ws_key: str) -> str | None:
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

    def session_info(self, session_id: str) -> dict[str, Any] | None:
        session = self._sessions.get(session_id)
        if session is None:
            return None
        return {
            "session_id": session_id,
            "created_at": session["created_at"],
            "user_count": len(session["users"]),
            "users": session["users"],
        }

    def _evict_expired(self) -> None:
        to_remove = []
        for sid, session in self._sessions.items():
            if not session["users"]:
                to_remove.append(sid)
        for sid in to_remove:
            self._sessions.pop(sid, None)

    def cleanup(self) -> int:
        """Remove empty/expired sessions. Returns number removed."""
        before = len(self._sessions)
        self._evict_expired()
        return before - len(self._sessions)


session_manager = SessionManager()


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


def create_web_app(settings: Settings | None = None) -> FastAPI:
    """Create the FastAPI web application with WebSocket support."""
    active_settings = settings or Settings.from_env()

    app = FastAPI(
        title="TextForensics Web UI",
        version=get_version(),
        description="Real-time AI-text detector analysis and visualization dashboard.",
    )
    app.state.textforensics_settings = active_settings

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
    history_buffer: OrderedDict[str, dict[str, Any]] = OrderedDict()

    def store_analysis(data: dict[str, Any]) -> str:
        """Insert or update an analysis result in the ring buffer. Returns its ID."""
        analysis_id = str(uuid.uuid4())
        entry = {
            "id": analysis_id,
            "stored_at": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }
        history_buffer[analysis_id] = entry
        # Evict oldest entries beyond max_history
        while len(history_buffer) > max_history:
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
                score = consensus.get("ai_probability")
                if score is None or score < min_score:
                    continue
            if max_score is not None:
                score = consensus.get("ai_probability")
                if score is None or score > max_score:
                    continue

            filtered.append(
                {
                    "id": entry["id"],
                    "stored_at": entry["stored_at"],
                    "verdict": consensus.get("verdict"),
                    "ai_probability": consensus.get("ai_probability"),
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
        return response

    @app.middleware("http")
    async def request_guard_and_security_headers(request: Request, call_next):
        # Emergency stop gate
        from ..emergency_stop import check_emergency_stop

        if check_emergency_stop():
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
            "index.html",
            {"request": request, "version": get_version(), "session_id": session_id},
        )

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
        session_id = session_manager.create_session()
        return {"session_id": session_id}

    @app.get("/api/session/{session_id}")
    def get_session_info(session_id: str) -> dict[str, Any]:
        """Get session info including connected users."""
        info = session_manager.session_info(session_id)
        if info is None:
            raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
        return info

    @app.get("/api/session/{session_id}/users")
    def get_session_users(session_id: str) -> list[dict[str, Any]]:
        """List users in a session."""
        return session_manager.list_users(session_id)

    @app.delete("/api/session")
    def cleanup_sessions() -> dict[str, int]:
        """Clean up empty/expired sessions."""
        removed = session_manager.cleanup()
        return {"removed": removed}

    @app.post("/api/analyze", response_model=AnalyzeResponse)
    def analyze(req: TextRequest):
        """Batch analysis endpoint - returns full forensic bundle."""
        from ..emergency_stop import assert_not_stopped

        assert_not_stopped()
        try:
            bundle = build_forensic_bundle(checked(req.text))
            result = bundle.to_dict()
            store_analysis(result)
            return AnalyzeResponse(success=True, data=result)
        except Exception as e:
            return AnalyzeResponse(success=False, error=str(e))

    # ── Export endpoint ─────────────────────────────────────────────

    @app.post("/api/export")
    def export_report(req: ExportRequest):
        """Export analysis results as JSON, CSV, or HTML report."""
        fmt = req.format.lower()
        if fmt not in ("json", "csv", "html"):
            return JSONResponse(
                status_code=400,
                content={"error": f"Unsupported format: {fmt}. Use json, csv, or html."},
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
        """WebSocket endpoint for real-time analysis streaming with collaboration support."""
        await websocket.accept()
        ws_key = str(uuid.uuid4())

        # Optional session parameter from query string
        session_id = websocket.query_params.get("session")

        try:
            while True:
                # Receive message from client
                data = await websocket.receive_text()
                message = json.loads(data)
                msg_type = message.get("type")

                # ── Collaboration messages ────────────────────────
                if msg_type == "join_session":
                    sess_id = message.get("session_id") or session_id
                    display_name = message.get("display_name", "Anonymous")
                    try:
                        user_info = session_manager.join_user(
                            sess_id, ws_key, websocket, display_name
                        )
                        await websocket.send_json(
                            {
                                "type": "session_joined",
                                "session_id": sess_id,
                                "user": user_info,
                                "users": session_manager.list_users(sess_id),
                            }
                        )
                        # Register ws_key for later cleanup
                        session_manager._ws_map[ws_key] = id(websocket)
                        # Broadcast to other users in the session
                        for conn_ws in session_manager.get_connected(sess_id):
                            if id(conn_ws) != id(websocket):
                                with suppress(Exception):
                                    await conn_ws.send_json(
                                        {
                                            "type": "user_joined",
                                            "user": user_info,
                                            "users": session_manager.list_users(sess_id),
                                        }
                                    )
                    except ValueError as e:
                        error_msg = {"type": "error", "message": str(e)}
                        await websocket.send_json(error_msg)
                    continue

                elif msg_type == "leave_session":
                    sess_id = session_manager._ws_map.pop(ws_key, None)
                    if sess_id:
                        session_manager.leave_user(ws_key)
                        with suppress(Exception):
                            await websocket.send_json(
                                {"type": "session_left", "session_id": sess_id}
                            )
                        # Broadcast to remaining users
                        for conn_ws in session_manager.get_connected(sess_id):
                            with suppress(Exception):
                                await conn_ws.send_json(
                                    {
                                        "type": "user_left",
                                        "users": session_manager.list_users(sess_id),
                                    }
                                )
                    continue

                elif msg_type == "analysis_shared":
                    sess_id = session_manager._ws_map.get(ws_key)
                    if sess_id:
                        analysis_data = message.get("data")
                        if analysis_data:
                            store_analysis(analysis_data)
                            for conn_ws in session_manager.get_connected(sess_id):
                                with suppress(Exception):
                                    await conn_ws.send_json(
                                        {
                                            "type": "analysis_shared",
                                            "data": analysis_data,
                                            "shared_by": message.get("shared_by", ws_key),
                                        }
                                    )
                    continue

                # ── Existing analysis protocol ────────────────────
                elif msg_type == "analyze":
                    text = message.get("text", "")
                    if not text:
                        await websocket.send_json(
                            {"type": "error", "message": "Empty text provided"}
                        )
                        continue

                    # Validate input
                    try:
                        validated_text = checked(text)
                    except ValueError as e:
                        error_msg = {"type": "error", "message": str(e)}
                        await websocket.send_json(error_msg)
                        continue

                    # Send analysis started
                    await websocket.send_json({"type": "started", "message": "Analysis started"})

                    # Run analysis in thread pool to avoid blocking
                    loop = asyncio.get_event_loop()

                    # Stream detector results one by one
                    from ..detectors import run_all_detectors

                    detector_results = await loop.run_in_executor(
                        None, run_all_detectors, validated_text
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

                    # Build and send final bundle
                    bundle = build_forensic_bundle(validated_text)
                    result_data = bundle.to_dict()
                    analysis_id = store_analysis(result_data)

                    # If in a session, broadcast to other collaborators
                    if session_id and session_manager.has_session(session_id):
                        for conn_ws in session_manager.get_connected(session_id):
                            if id(conn_ws) != id(websocket):
                                with suppress(Exception):
                                    await conn_ws.send_json(
                                        {
                                            "type": "analysis_result_shared",
                                            "data": result_data,
                                            "analysis_id": analysis_id,
                                        }
                                    )

                    await websocket.send_json({"type": "complete", "data": result_data})

        except WebSocketDisconnect:
            pass
        except Exception as e:
            with suppress(Exception):
                error_msg = {"type": "error", "message": str(e)}
                await websocket.send_json(error_msg)
        finally:
            # Always clean up on disconnect
            session_manager.leave_user(ws_key)

    return app


app = None
# Lets `uvicorn textforensics.web_ui.main:app` work when extras are installed.
with suppress(RuntimeError, ValueError):
    from ..config import Settings

    app = create_web_app()


def serve_web(
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    allow_remote: bool = False,
    access_log: bool = True,
    log_level: str = "info",
) -> None:
    """Serve the web UI application."""
    settings = Settings.from_env()
    settings = Settings(
        host=host,
        port=port,
        max_input_bytes=settings.max_input_bytes,
        allow_remote=allow_remote,
        access_log=access_log,
        log_level=log_level,
    )
    ensure_bind_allowed(settings.host, allow_remote=settings.allow_remote)

    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError("Install web UI support with: pip install 'textforensics[api]'") from exc

    uvicorn.run(
        create_web_app(settings),
        host=settings.host,
        port=settings.port,
        access_log=settings.access_log,
        log_level=settings.log_level.lower(),
    )


def _report_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")


def _write_csv_report(writer: csv.writer, data: dict[str, Any]) -> None:
    """Write a CSV report from a forensic bundle dict."""
    # Section: consensus
    consensus = data.get("consensus", {})
    writer.writerow(["Section", "Field", "Value"])
    writer.writerow(["Consensus", "Verdict", consensus.get("verdict", "")])
    writer.writerow(["Consensus", "AI Probability", consensus.get("ai_probability", "N/A")])
    writer.writerow(["Consensus", "Independent Families", consensus.get("independent_families", 0)])
    writer.writerow(["Consensus", "Family Agreement", consensus.get("family_agreement", "N/A")])
    # Section: detectors
    for det in data.get("detector_results", []):
        writer.writerow(["Detector", det.get("detector_id", ""), ""])
        writer.writerow(["Detector", "Version", det.get("detector_version", "")])
        writer.writerow(["Detector", "Family", det.get("detector_family", "")])
        writer.writerow(["Detector", "Score", det.get("score", "")])
        writer.writerow(["Detector", "Verdict", det.get("verdict", "")])
        writer.writerow(
            [
                "Detector",
                "Calibrated AI Probability",
                det.get("calibrated_ai_probability", "N/A"),
            ]
        )
        writer.writerow(["Detector", "Execution", det.get("execution", "")])
        writer.writerow([])
    # Section: trust map
    trust_map = data.get("trust_map", {})
    writer.writerow(["Trust Map", "Overall", trust_map.get("overall", "")])
    for dim in trust_map.get("dimensions", []):
        writer.writerow(["Trust Map", dim.get("dimension", ""), dim.get("state", "")])
        writer.writerow(["Trust Map", "Reason", dim.get("reason", "")])
    # Section: input
    inp = data.get("input", {})
    writer.writerow(["Input", "Word Count", inp.get("word_count", "")])
    writer.writerow(["Input", "Sentence Count", inp.get("sentence_count", "")])
    writer.writerow(["Input", "Paragraph Count", inp.get("paragraph_count", "")])
    writer.writerow(["Input", "Content SHA256", data.get("content_sha256", "")])
    writer.writerow(["Input", "Generated At", data.get("generated_at_utc", "")])


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
    ai_prob = consensus.get("ai_probability")
    ai_prob_str = f"{ai_prob * 100:.1f}%" if ai_prob is not None else "Not calibrated"

    trust_map = data.get("trust_map", {})
    trust_overall = trust_map.get("overall", "unknown")
    dims = trust_map.get("dimensions", [])

    detectors = data.get("detector_results", [])
    inp = data.get("input", {})

    detectors_html = "".join(
        f"""<tr>
            <td>{_escape(d.get('detector_id', ''))}</td>
            <td>{_escape(d.get('detector_version', ''))}</td>
            <td>{_escape(d.get('detector_family', ''))}</td>
            <td>{_escape(d.get('score', ''))}</td>
            <td>{_escape(d.get('verdict', ''))}</td>
            <td>{_escape(d.get('calibrated_ai_probability', 'N/A'))}</td>
        </tr>"""
        for d in detectors
    )

    trust_dims_html = "".join(
        f"""<tr>
            <td>{_escape(dim.get('dimension', ''))}</td>
            <td>{_escape(dim.get('state', ''))}</td>
            <td>{_escape(dim.get('reason', ''))}</td>
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
<p class="meta">Generated: {_escape(data.get('generated_at_utc', 'N/A'))} &middot; SHA256: {_escape(data.get('content_sha256', '')[:16])}&hellip;</p>

<h2>Consensus Verdict</h2>
<div class="verdict verdict-{_escape(verdict)}">{_escape(verdict_text)}</div>
<p>AI Probability: {_escape(ai_prob_str)} &middot; Independent Families: {_escape(consensus.get('independent_families', 'N/A'))}</p>

<h2>Input Statistics</h2>
<p>Words: {_escape(inp.get('word_count', 'N/A'))} &middot; Sentences: {_escape(inp.get('sentence_count', 'N/A'))} &middot; Paragraphs: {_escape(inp.get('paragraph_count', 'N/A'))}</p>

<h2>Detector Results</h2>
<table><tr><th>Detector</th><th>Version</th><th>Family</th><th>Score</th><th>Verdict</th><th>Cal. AI Prob.</th></tr>{detectors_html}</table>

<h2>Trust Map</h2>
<p>Overall: {_escape(trust_overall)}</p>
<table><tr><th>Dimension</th><th>State</th><th>Reason</th></tr>{trust_dims_html}</table>

<h2>Warnings &amp; Limitations</h2>
<ul>{"".join(f"<li>{_escape(w)}</li>" for w in (data.get('limitations') or []))}</ul>

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
            "ai_probability_a": consensus_a.get("ai_probability"),
            "ai_probability_b": consensus_b.get("ai_probability"),
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
    serve_web()


if __name__ == "__main__":
    main()
