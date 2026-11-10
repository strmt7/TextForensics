from __future__ import annotations

import json
from typing import Any

from . import mcp_tools
from .casefile import seal_case_file
from .config import Settings, validate_text_input
from .detectors import list_detector_health, list_detector_metadata
from .execution_policy import (
    ExecutionPolicy,
    RemoteConsentError,
    assert_execution_allowed,
)


def _policy_for_mcp(
    remote_detector_ids: list[str] | None,
    remote_consent: bool,
    settings: Settings,
) -> ExecutionPolicy:
    """Build the execution policy for an MCP report/case call (IF-01).

    Default is local-only. IDs without consent, consent without IDs,
    and unknown IDs are all rejected with ``ValueError`` (surfaced to
    the MCP caller as a tool error, with no submitted text).
    """
    ids = list(remote_detector_ids or [])
    if ids and not remote_consent:
        raise ValueError("Explicit remote consent is required to run remote detectors.")
    if remote_consent and not ids:
        raise ValueError("Remote consent requires at least one remote detector ID.")
    if ids:
        policy = ExecutionPolicy.with_remote_consent(ids, max_input_bytes=settings.max_input_bytes)
    else:
        policy = ExecutionPolicy.default_local_only(max_input_bytes=settings.max_input_bytes)
    try:
        # Resolved at call time (not bound at import) so the canonical
        # registry is always consulted.
        from .detectors import discover_detector_registry

        available = {detector_id for detector_id in discover_detector_registry().detectors}
        policy.resolve_against(available)
    except RemoteConsentError as exc:
        raise ValueError("Unknown remote detector ID.") from exc
    return policy


def _server():
    try:
        from mcp.server import MCPServer
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise SystemExit("Install MCP support with: pip install 'textforensics[mcp]'") from exc

    from .engine import analyze_text, compare_texts
    from .features import audit_naturalness
    from .localize import localize_text
    from .report import build_forensic_bundle

    settings = Settings.from_env()
    from ._build_info import get_version

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

    @mcp.tool()
    def analyze_ai_text(text: str) -> str:
        """Run the local alpha text-pattern baseline with explicit limitations."""
        assert_execution_allowed()
        return dumped(analyze_text(checked(text)).to_dict())

    @mcp.tool()
    def build_forensic_report(
        text: str,
        remote_detector_ids: list[str] | None = None,
        remote_consent: bool = False,
    ) -> str:
        """Build detector observations, Trust Map, stability, and limitations.

        Local-only by default. Remote detectors run only when their IDs
        are listed in ``remote_detector_ids`` AND ``remote_consent`` is
        true; anything else is rejected.
        """
        assert_execution_allowed()
        policy = _policy_for_mcp(remote_detector_ids, remote_consent, settings)
        return dumped(build_forensic_bundle(checked(text), execution_policy=policy).to_dict())

    @mcp.tool()
    def build_case_file(
        text: str,
        remote_detector_ids: list[str] | None = None,
        remote_consent: bool = False,
    ) -> str:
        """Build a sealed, raw-text-free case artifact for the supplied text.

        Local-only by default; see :func:`build_forensic_report` for
        the remote-consent contract.
        """
        assert_execution_allowed()
        policy = _policy_for_mcp(remote_detector_ids, remote_consent, settings)
        bundle = build_forensic_bundle(checked(text), execution_policy=policy).to_dict()
        return dumped(seal_case_file(bundle))

    @mcp.tool()
    def detector_health() -> str:
        """List detector adapters and plugin-loading health without analyzing text."""
        # Read-only introspection: not gated by emergency stop.
        return dumped(
            {
                "detectors": list_detector_metadata(),
                "plugin_health": list_detector_health(),
            }
        )

    @mcp.tool()
    def localize_text_patterns(
        text: str,
        sentences_per_segment: int = 4,
    ) -> str:
        """Localize diagnostic baseline patterns; not sentence-level authorship."""
        assert_execution_allowed()
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
        assert_execution_allowed()
        return dumped(compare_texts(checked(before), checked(after)).to_dict())

    @mcp.tool()
    def audit_writing_naturalness(text: str) -> str:
        """Identify formulaic writing patterns without promising detector outcomes."""
        assert_execution_allowed()
        return dumped(audit_naturalness(checked(text)))

    # --- Capability Ledger tools ---

    @mcp.tool()
    def capability_register(params: str) -> str:
        """Register a capability claim in the ledger."""
        return dumped(mcp_tools.capability_register(json.loads(params)))

    @mcp.tool()
    def capability_check(params: str) -> str:
        """Check if a capability is validated."""
        return dumped(mcp_tools.capability_check(json.loads(params)))

    @mcp.tool()
    def capability_list(params: str) -> str:
        """List all registered capabilities."""
        return dumped(mcp_tools.capability_list(json.loads(params)))

    # --- Verify tool ---

    @mcp.tool()
    def verify_case_file(params: str) -> str:
        """Run N-version integrity replay on a case file."""
        return dumped(mcp_tools.verify_case_file(json.loads(params)))

    # --- Drift Observatory tools ---

    @mcp.tool()
    def drift_snapshot(params: str) -> str:
        """Take a detector drift snapshot."""
        return dumped(mcp_tools.drift_snapshot(json.loads(params)))

    @mcp.tool()
    def drift_compare(params: str) -> str:
        """Compare two drift snapshots."""
        return dumped(mcp_tools.drift_compare(json.loads(params)))

    @mcp.tool()
    def drift_report(params: str) -> str:
        """Generate a drift report."""
        return dumped(mcp_tools.drift_report(json.loads(params)))

    # --- Benchmark fingerprint tools ---

    @mcp.tool()
    def fingerprint_dataset(params: str) -> str:
        """Create a dataset fingerprint."""
        return dumped(mcp_tools.fingerprint_dataset(json.loads(params)))

    @mcp.tool()
    def check_contamination(params: str) -> str:
        """Check for benchmark contamination."""
        return dumped(mcp_tools.check_contamination(json.loads(params)))

    return mcp


def main() -> None:  # pragma: no cover - integration entry point
    _server().run()


if __name__ == "__main__":
    main()
