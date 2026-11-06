"""Guard test: TextForensics contains no telemetry/metrics collection.

``telemetry.py`` was deleted in Phase 2 wave (f): it was load-bearing
(imported on every ``analyze_text()`` call and every CLI run) rather than
a clean optional extra, so keeping it contradicted AGENTS.md rule 8
("No silent telemetry"). There is no ``--metrics`` flag, no telemetry
module, and no OpenTelemetry import anywhere in ``src/``. These tests
fail if any of that comes back.

Note: ``adapter_scanner.py`` still *names* "telemetry" as a finding
category for third-party adapters (it flags adapters that import
telemetry); it collects nothing itself. ``web_ui/main.py`` contains the
user-facing string "Local-first · no telemetry". The import scan below
therefore checks imports, not words.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

import textforensics
from textforensics.cli import build_parser

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src" / "textforensics"

_FORBIDDEN_TOP_LEVEL_IMPORTS = {"telemetry", "opentelemetry"}


def _imported_top_level_names(path: Path) -> set[str]:
    """Top-level module names imported by one source file (AST-based)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module.split(".")[0])
            elif node.level:
                # e.g. `from . import telemetry` — the names carry the module.
                names.update(alias.name.split(".")[0] for alias in node.names)
    return names


class NoTelemetryTests(unittest.TestCase):
    """Tests for the absence of telemetry collection."""

    def test_telemetry_module_does_not_exist(self):
        """Test that textforensics.telemetry cannot be imported."""
        with self.assertRaises(ModuleNotFoundError):
            import textforensics.telemetry  # noqa: F401

    def test_package_does_not_export_telemetry_names(self):
        """Test that the old lazy telemetry names are gone from the package."""
        for name in (
            "AnalysisTimer",
            "initialize_telemetry",
            "is_telemetry_initialized",
            "record_analysis",
            "record_error",
            "shutdown_telemetry",
            "timed_analysis",
        ):
            self.assertFalse(hasattr(textforensics, name), f"textforensics.{name} still exists")

    def test_no_src_module_imports_telemetry(self):
        """Test that no src/ module imports telemetry or OpenTelemetry."""
        offenders: list[str] = []
        for path in sorted(SRC_ROOT.rglob("*.py")):
            imported = _imported_top_level_names(path)
            forbidden = imported & _FORBIDDEN_TOP_LEVEL_IMPORTS
            if forbidden:
                offenders.append(f"{path.relative_to(REPO_ROOT)}: {sorted(forbidden)}")
        self.assertEqual(offenders, [])

    def test_no_metrics_flag(self):
        """Test that the --metrics CLI flag is gone."""
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["--metrics", "scan"])


if __name__ == "__main__":
    unittest.main()
