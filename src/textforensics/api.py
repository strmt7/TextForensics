from __future__ import annotations


def create_app():
    try:
        from fastapi import FastAPI
        from pydantic import BaseModel
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("Install API support with: pip install 'textforensics[api]'") from exc

    from .compare import compare_texts
    from .engine import analyze_text
    from .naturalness import audit_naturalness

    app = FastAPI(title="TextForensics", version="0.1.0")

    class TextRequest(BaseModel):
        text: str

    class CompareRequest(BaseModel):
        before: str
        after: str

    @app.post("/v1/analyze")
    def analyze(req: TextRequest):
        return analyze_text(req.text).to_dict()

    @app.post("/v1/audit")
    def audit(req: TextRequest):
        return audit_naturalness(req.text)

    @app.post("/v1/compare")
    def compare(req: CompareRequest):
        return compare_texts(req.before, req.after).to_dict()

    return app


app = None
try:  # Lets `uvicorn textforensics.api:app` work when extras are installed.
    app = create_app()
except RuntimeError:
    pass
