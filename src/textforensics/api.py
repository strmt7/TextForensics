from typing import Any

from .casefile import seal_case_file
from .config import Settings, validate_text_input
from .detectors import list_detector_health, list_detector_metadata
from .version import get_version


def create_app(settings: Settings | None = None):
    try:
        from fastapi import FastAPI, HTTPException
        from pydantic import BaseModel
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            "Install API support with: pip install 'textforensics[api]'"
        ) from exc

    from .compare import compare_texts
    from .engine import analyze_text
    from .naturalness import audit_naturalness
    from .report import build_forensic_bundle

    active_settings = settings or Settings.from_env()
    app = FastAPI(
        title="TextForensics",
        version=get_version(),
        description=(
            "Local-first AI-text detector evidence and reliability auditing API."
        ),
    )
    app.state.textforensics_settings = active_settings

    class TextRequest(BaseModel):
        text: str

    class CompareRequest(BaseModel):
        before: str
        after: str

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

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-TextForensics-Version"] = get_version()
        return response

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
        return analyze_text(checked(req.text)).to_dict()

    @app.post("/v1/report")
    def report(req: TextRequest):
        return build_forensic_bundle(checked(req.text)).to_dict()

    @app.post("/v1/case")
    def case(req: TextRequest):
        bundle = build_forensic_bundle(checked(req.text)).to_dict()
        return seal_case_file(bundle)

    @app.post("/v1/audit")
    def audit(req: TextRequest):
        return audit_naturalness(checked(req.text))

    @app.post("/v1/compare")
    def compare(req: CompareRequest):
        before = checked(req.before)
        after = checked(req.after)
        return compare_texts(before, after).to_dict()

    return app


app = None
try:  # Lets `uvicorn textforensics.api:app` work when extras are installed.
    app = create_app()
except (RuntimeError, ValueError):
    pass
