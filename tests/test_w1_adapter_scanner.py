"""W1 Worker A scanner tests: IF-08.

The scanner must inspect adapter source WITHOUT importing it, must fail
closed on parse errors and uninspectable code, and must resolve dotted
imports/aliases instead of matching only top-level names.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from textforensics.adapter_scanner import (  # noqa: E402
    scan_adapter_entry_points,
    scan_adapter_source,
    verify_local_only,
)

CLEAN_SOURCE = '''from __future__ import annotations

def analyze(text: str) -> dict:
    """Local-only analysis, no imports."""
    return {"score": 0.5}
'''

SYNTAX_ERROR_SOURCE = """from __future__ import annotations

def broken(:
    pass
"""

SUBMODULE_NETWORK_SOURCE = """import httpx._client as h

def fetch(url):
    return h.Client().post(url)
"""

FROM_SUBMODULE_NETWORK_SOURCE = """from httpx._client import Client

def fetch(url):
    return Client().post(url)
"""

DYNAMIC_IMPORT_NONLITERAL_SOURCE = """import importlib

def load(name):
    return importlib.import_module(name)
"""

DYNAMIC_IMPORT_LITERAL_NETWORK_SOURCE = """import importlib

def load():
    return importlib.import_module("httpx")
"""

RELATIVE_IMPORT_SOURCE = """from .helpers import score

def analyze(text):
    return {"score": score(text)}
"""

TRANSITIVE_IMPORT_SOURCE = """import myplugin_helpers

def analyze(text):
    return {"score": myplugin_helpers.score(text)}
"""


class TestScannerSyntaxErrorFailsClosed:
    def test_syntax_error_is_not_verified_local(self):
        report = scan_adapter_source(SYNTAX_ERROR_SOURCE, "broken")
        assert any(f.rule_id == "DYN-999" for f in report.findings)
        assert report.local_only_verified is False

    def test_syntax_error_verify_local_only_is_false(self):
        assert verify_local_only(SYNTAX_ERROR_SOURCE) is False


class TestScannerSubmoduleAndAliases:
    def test_dotted_httpx_client_import_is_network(self):
        report = scan_adapter_source(SUBMODULE_NETWORK_SOURCE, "sub")
        assert any(f.category == "network" for f in report.findings), [
            f.to_dict() for f in report.findings
        ]
        assert report.local_only_verified is False

    def test_from_dotted_import_client_call_is_network(self):
        report = scan_adapter_source(FROM_SUBMODULE_NETWORK_SOURCE, "fromsub")
        assert any(f.category == "network" for f in report.findings)
        assert report.local_only_verified is False

    def test_plain_requests_import_still_flagged(self):
        report = scan_adapter_source(
            "import requests\n\ndef f(u):\n    return requests.get(u).text\n", "req"
        )
        assert any(f.category == "network" for f in report.findings)
        assert report.local_only_verified is False


class TestScannerDynamicAndTransitiveIsUnknown:
    def test_dynamic_import_with_unknown_target_is_unknown(self):
        report = scan_adapter_source(DYNAMIC_IMPORT_NONLITERAL_SOURCE, "dyn")
        assert report.local_only_verified is False
        assert any("dynamic" in reason for reason in report.unknown_reasons)

    def test_dynamic_import_of_network_module_is_network(self):
        report = scan_adapter_source(DYNAMIC_IMPORT_LITERAL_NETWORK_SOURCE, "dynlit")
        assert any(f.category == "network" for f in report.findings)
        assert report.local_only_verified is False

    def test_relative_import_is_unknown(self):
        report = scan_adapter_source(RELATIVE_IMPORT_SOURCE, "rel")
        assert report.local_only_verified is False
        assert any("relative" in reason for reason in report.unknown_reasons)

    def test_unscanned_transitive_import_is_unknown(self):
        report = scan_adapter_source(TRANSITIVE_IMPORT_SOURCE, "trans")
        assert report.local_only_verified is False
        assert any("transitive" in reason for reason in report.unknown_reasons)

    def test_clean_stdlib_only_source_stays_verified(self):
        report = scan_adapter_source(CLEAN_SOURCE, "clean")
        assert report.findings == []
        assert report.unknown_reasons == ()
        assert report.local_only_verified is True

    def test_dynamic_execution_is_not_verified(self):
        report = scan_adapter_source("def run(code):\n    return eval(code)\n", "ev")
        assert any(f.rule_id == "DYN-001" for f in report.findings)
        assert report.local_only_verified is False


class TestScannerDoesNotImportEntryPoints:
    def test_scan_entry_points_leaves_no_import_side_effect(self, tmp_path, monkeypatch):
        """A plugin whose import writes a marker must leave no marker
        after scanning, and the scanner must still see its file-write
        finding from source text alone."""
        marker = tmp_path / "imported.marker"
        plugin = tmp_path / "audit_plugin_side_effect.py"
        plugin.write_text(
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('imported', encoding='utf-8')\n"
            "VALUE = 1\n",
            encoding="utf-8",
        )

        class FakeFile:
            """Minimal importlib.metadata file entry for the plugin."""

            def __init__(self, path):
                self._path = path

            def __str__(self):
                return "audit_plugin_side_effect.py"

            @property
            def suffix(self):
                return ".py"

        class FakeDist:
            def __init__(self, path):
                self._path = path

            @property
            def files(self):
                return [FakeFile(self._path)]

            def locate_file(self, path):
                return self._path

        class FakeEntryPoint:
            name = "audit-side-effect"
            value = "audit_plugin_side_effect:VALUE"
            module = "audit_plugin_side_effect"

            def __init__(self, dist):
                self.dist = dist

        fake_ep = FakeEntryPoint(FakeDist(plugin))
        monkeypatch.setattr(
            "textforensics.adapter_scanner.importlib.metadata.entry_points",
            lambda: [fake_ep],
        )
        # The module must not be importable through the normal path either:
        # scanning must resolve the file from distribution metadata.
        reports = scan_adapter_entry_points()
        assert not marker.exists()
        assert "audit_plugin_side_effect" not in sys.modules
        assert len(reports) == 1
        assert reports[0].module_name == "plugin:audit-side-effect"
        assert any(f.rule_id == "FS-004" for f in reports[0].findings)

    def test_scan_entry_points_without_distribution_is_unknown(self, monkeypatch):
        class FakeEntryPoint:
            name = "audit-no-dist"
            value = "missing.module:Thing"
            module = "missing.module"
            dist = None

        monkeypatch.setattr(
            "textforensics.adapter_scanner.importlib.metadata.entry_points",
            lambda: [FakeEntryPoint()],
        )
        reports = scan_adapter_entry_points()
        assert len(reports) == 1
        assert reports[0].local_only_verified is False
        assert any(f.rule_id == "DYN-998" for f in reports[0].findings)
        assert reports[0].unknown_reasons
