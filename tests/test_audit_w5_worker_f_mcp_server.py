"""W5 Worker F kill tests for mcp_server (audit-w5-f).

Kill evidence for the one runtime survivor in textforensics.mcp_server:
``_server`` must raise SystemExit (not ImportError) when the optional
``mcp`` dependency cannot be imported. The mutant replaces the caught
``ImportError`` with ``CosmicRayTestingException``, so the real
ImportError propagates instead of the documented SystemExit.
"""

import sys

import pytest

from textforensics.mcp_server import _server


def test_server_raises_system_exit_when_mcp_unavailable(monkeypatch):
    """_server() exits with instructions when mcp.server cannot import."""
    # Block the optional import even though mcp IS installed in this venv:
    # a None entry in sys.modules makes the import raise ImportError.
    monkeypatch.setitem(sys.modules, "mcp.server", None)
    with pytest.raises(SystemExit, match="Install MCP support"):
        _server()
