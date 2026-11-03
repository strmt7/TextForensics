from __future__ import annotations

import asyncio
import json
import os
from contextlib import suppress
from typing import Any

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from ..config import Settings, ensure_bind_allowed, validate_text_input
from ..detectors import list_detector_health, list_detector_metadata
from ..report import build_forensic_bundle
from ..version import get_version


class TextRequest(BaseModel):
    text: str


class AnalyzeResponse(BaseModel):
    success: bool
    data: dict[str, Any] | None = None
    error: str | None = None


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
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "version": get_version()},
        )

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

    @app.post("/api/analyze", response_model=AnalyzeResponse)
    def analyze(req: TextRequest):
        """Batch analysis endpoint - returns full forensic bundle."""
        from ..emergency_stop import assert_not_stopped

        assert_not_stopped()
        try:
            bundle = build_forensic_bundle(checked(req.text))
            return AnalyzeResponse(success=True, data=bundle.to_dict())
        except Exception as e:
            return AnalyzeResponse(success=False, error=str(e))

    @app.websocket("/ws/analyze")
    async def websocket_analyze(websocket: WebSocket):
        """WebSocket endpoint for real-time analysis streaming."""
        await websocket.accept()
        try:
            while True:
                # Receive message from client
                data = await websocket.receive_text()
                message = json.loads(data)

                if message.get("type") == "analyze":
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
                        await websocket.send_json({"type": "error", "message": str(e)})
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
                    await websocket.send_json({"type": "complete", "data": bundle.to_dict()})

        except WebSocketDisconnect:
            pass
        except Exception as e:
            with suppress(Exception):
                await websocket.send_json({"type": "error", "message": str(e)})

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


def main() -> None:
    serve_web()


if __name__ == "__main__":
    main()
