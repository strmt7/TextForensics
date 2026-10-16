from __future__ import annotations

import json
from typing import Any

from .casefile import seal_case_file
from .config import Settings, validate_text_input
from .detectors import (
    list_detector_health,
    list_detector_metadata,
    list_optional_detector_metadata,
)


def _server():
    try:
        from mcp.server import MCPServer
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise SystemExit(
            "Install MCP support with: pip install 'textforensics[mcp]'"
        ) from exc

    from .compare import compare_texts
    from .engine import analyze_text
    from .localize import localize_text
    from .naturalness import audit_naturalness
    from .report import build_forensic_bundle

    settings = Settings.from_env()
    from .version import get_version

    mcp = MCPServer("TextForensics", version=get_version())

    def checked(text: str) -> str:
        return validate_text_input(
            text,
            max_input_bytes=settings.max_input_bytes,
        )

    def dumped(payload: Any) -> str:
        return json.dumps(
            payload,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        )

    def detector_ids() -> tuple[str, ...] | None:
        return settings.detector_ids or None

    @mcp.tool()
    def analyze_ai_text(text: str) -> str:
        """Run the local alpha text-pattern baseline with explicit limitations."""
        return dumped(analyze_text(checked(text)).to_dict())

    @mcp.tool()
    def build_forensic_report(text: str) -> str:
        """Build detector observations, Trust Map, stability, and limitations."""
        return dumped(
            build_forensic_bundle(
                checked(text),
                detector_ids=detector_ids(),
            ).to_dict()
        )

    @mcp.tool()
    def build_case_file(text: str) -> str:
        """Build a sealed, raw-text-free case artifact for the supplied text."""
        bundle = build_forensic_bundle(
            checked(text),
            detector_ids=detector_ids(),
        ).to_dict()
        return dumped(seal_case_file(bundle))

    @mcp.tool()
    def detector_health() -> str:
        """List detector adapters and plugin-loading health without analyzing text."""
        return dumped(
            {
                "detectors": list_detector_metadata(),
                "optional_detectors": list_optional_detector_metadata(),
                "plugin_health": list_detector_health(),
            }
        )

    @mcp.tool()
    def localize_text_patterns(
        text: str,
        sentences_per_segment: int = 4,
    ) -> str:
        """Localize diagnostic baseline patterns; not sentence-level authorship."""
        if sentences_per_segment < 1:
            raise ValueError("sentences_per_segment must be at least 1.")
        return dumped(
            [
                row.to_dict()
                for row in localize_text(
                    checked(text),
                    sentences_per_segment=sentences_per_segment,
                )
            ]
        )

    @mcp.tool()
    def compare_text_versions(before: str, after: str) -> str:
        """Compare two versions and their diagnostic baseline scores."""
        return dumped(compare_texts(checked(before), checked(after)).to_dict())

    @mcp.tool()
    def audit_writing_naturalness(text: str) -> str:
        """Identify formulaic writing patterns without promising detector outcomes."""
        return dumped(audit_naturalness(checked(text)))

    return mcp


def main() -> None:  # pragma: no cover - integration entry point
    _server().run()


if __name__ == "__main__":
    main()
