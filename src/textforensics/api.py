from __future__ import annotations

from contextlib import suppress
from typing import Any

from ._build_info import get_version
from .casefile import seal_case_file
from .config import Settings, ensure_bind_allowed, validate_text_input
from .detectors import list_detector_health, list_detector_metadata
from .execution_policy import (
    ExecutionPolicy,
    RemoteConsentError,
    assert_execution_allowed,
    is_execution_stopped,
    register_redacting_handlers,
)

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
        # Outbound remote-adapter consent (IF-01). Default is local-only:
        # remote detectors run only when their IDs are listed here AND
        # remote_consent is true. IDs without consent, consent without
        # IDs, and unknown IDs are all rejected with 422.
        remote_detector_ids: list[str] | None = None
        remote_consent: bool = False

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
    # Shared redacting error handlers (IF-07): request-validation failures
    # never echo rejected input; HTTPException statuses are preserved.
    register_redacting_handlers(app)

    def _policy_for_request(req: TextRequest) -> ExecutionPolicy:
        """Build the execution policy for a report/case request (IF-01)."""
        ids = list(req.remote_detector_ids or [])
        if ids and not req.remote_consent:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "remote_consent_required",
                    "message": "Explicit remote consent is required to run remote detectors.",
                },
            )
        if req.remote_consent and not ids:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "remote_detector_ids_required",
                    "message": "Remote consent requires at least one remote detector ID.",
                },
            )
        if ids:
            policy = ExecutionPolicy.with_remote_consent(
                ids, max_input_bytes=active_settings.max_input_bytes
            )
        else:
            policy = ExecutionPolicy.default_local_only(
                max_input_bytes=active_settings.max_input_bytes
            )
        try:
            # Resolved at call time (not bound at import) so the
            # canonical registry is always consulted.
            from .detectors import discover_detector_registry

            available = {detector_id for detector_id in discover_detector_registry().detectors}
            policy.resolve_against(available)
        except RemoteConsentError as exc:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "unknown_remote_detector",
                    "message": "Unknown remote detector ID.",
                },
            ) from exc
        return policy

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
        assert_execution_allowed()
        return analyze_text(checked(req.text)).to_dict()

    @app.post("/v1/report")
    def report(req: TextRequest):
        assert_execution_allowed()
        policy = _policy_for_request(req)
        return build_forensic_bundle(checked(req.text), execution_policy=policy).to_dict()

    @app.post("/v1/case")
    def case(req: TextRequest):
        assert_execution_allowed()
        policy = _policy_for_request(req)
        bundle = build_forensic_bundle(checked(req.text), execution_policy=policy).to_dict()
        return seal_case_file(bundle)

    @app.post("/v1/audit")
    def audit(req: TextRequest):
        assert_execution_allowed()
        return audit_naturalness(checked(req.text))

    @app.post("/v1/compare")
    def compare(req: CompareRequest):
        assert_execution_allowed()
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
