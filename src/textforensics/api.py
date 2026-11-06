from __future__ import annotations

from contextlib import suppress
from typing import Any

from ._build_info import get_version
from .casefile import seal_case_file
from .config import Settings, ensure_bind_allowed, validate_text_input
from .detectors import list_detector_health, list_detector_metadata
from .emergency_stop import assert_not_stopped, check_emergency_stop

try:
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel
except ImportError:  # pragma: no cover - optional dependency
    # The [api] extra is absent. The module must stay importable so
    # that serve_api()'s remote-bind guard can run before any API
    # import fails; create_app() raises the install hint instead.
    FastAPI = HTTPException = Request = JSONResponse = BaseModel = None  # type: ignore[assignment, misc]


def _require_api() -> None:
    """Raise the install hint unless the [api] extra is present."""
    if FastAPI is None or BaseModel is None:
        raise RuntimeError("Install API support with: pip install 'textforensics[api]'")


if BaseModel is not None:

    class TextRequest(BaseModel):
        text: str

    class CompareRequest(BaseModel):
        before: str
        after: str


def create_app(settings: Settings | None = None):
    _require_api()
    from .engine import analyze_text, compare_texts
    from .features import audit_naturalness
    from .report import build_forensic_bundle

    active_settings = settings or Settings.from_env()
    app = FastAPI(
        title="TextForensics",
        version=get_version(),
        description=("Local-first AI-text detector evidence and reliability auditing API."),
    )
    app.state.textforensics_settings = active_settings

    def checked(text: str) -> str:
        try:
            return validate_text_input(
                text,
                max_input_bytes=active_settings.max_input_bytes,
            )
        except ValueError as exc:
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
        # Emergency stop gate: checked at dispatch entry for every request.
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

    @app.post("/v1/analyze")
    def analyze(req: TextRequest):
        assert_not_stopped()
        return analyze_text(checked(req.text)).to_dict()

    @app.post("/v1/report")
    def report(req: TextRequest):
        assert_not_stopped()
        return build_forensic_bundle(checked(req.text)).to_dict()

    @app.post("/v1/case")
    def case(req: TextRequest):
        assert_not_stopped()
        bundle = build_forensic_bundle(checked(req.text)).to_dict()
        return seal_case_file(bundle)

    @app.post("/v1/audit")
    def audit(req: TextRequest):
        assert_not_stopped()
        return audit_naturalness(checked(req.text))

    @app.post("/v1/compare")
    def compare(req: CompareRequest):
        assert_not_stopped()
        before = checked(req.before)
        after = checked(req.after)
        return compare_texts(before, after).to_dict()

    return app


app = None
# Lets `uvicorn textforensics.api:app` work when extras are installed.
with suppress(RuntimeError, ValueError):
    app = create_app()


# ---------------------------------------------------------------------------
# API server entry point (merged from server.py, Phase 2 wave e)
# ---------------------------------------------------------------------------


def serve_api(settings: Settings | None = None) -> None:
    settings = settings or Settings.from_env()
    ensure_bind_allowed(settings.host, allow_remote=settings.allow_remote)

    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("Install API support with: pip install 'textforensics[api]'") from exc

    uvicorn.run(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        access_log=settings.access_log,
        log_level=settings.log_level.lower(),
    )


def main() -> None:  # pragma: no cover - integration entry point
    serve_api()


if __name__ == "__main__":
    main()
