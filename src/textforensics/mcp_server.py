from __future__ import annotations

import json


def _server():
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise SystemExit("Install MCP support with: pip install 'textforensics[mcp]'") from exc

    from .compare import compare_texts
    from .engine import analyze_text
    from .naturalness import audit_naturalness
    from .localize import localize_text

    mcp = FastMCP("TextForensics")

    @mcp.tool()
    def analyze_ai_text(text: str) -> str:
        """Analyze text patterns, uncertainty, detector disagreement and robustness locally."""
        return json.dumps(analyze_text(text).to_dict(), indent=2, ensure_ascii=False)

    @mcp.tool()
    def localize_text_patterns(text: str, sentences_per_segment: int = 4) -> str:
        """Locate segments with different text-pattern scores and uncertainty."""
        return json.dumps(
            [r.to_dict() for r in localize_text(text, sentences_per_segment=sentences_per_segment)],
            indent=2,
            ensure_ascii=False,
        )

    @mcp.tool()
    def compare_text_versions(before: str, after: str) -> str:
        """Compare two versions and report textual similarity plus forensic score change."""
        return json.dumps(compare_texts(before, after).to_dict(), indent=2, ensure_ascii=False)

    @mcp.tool()
    def audit_writing_naturalness(text: str) -> str:
        """Identify formulaic writing patterns and provide transparent editing suggestions."""
        return json.dumps(audit_naturalness(text), indent=2, ensure_ascii=False)

    return mcp


def main() -> None:  # pragma: no cover - integration entry point
    _server().run()


if __name__ == "__main__":
    main()
