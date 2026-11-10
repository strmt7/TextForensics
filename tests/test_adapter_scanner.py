"""Tests for adapter_scanner module."""

from __future__ import annotations

import pathlib
import tempfile

import pytest

from textforensics.adapter_scanner import (
    AdapterScanError,
    AdapterScanReport,
    SecurityFinding,
    scan_adapter_entry_points,
    scan_adapter_file,
    scan_adapter_source,
    verify_local_only,
)

# ---------------------------------------------------------------------------
# Test source snippets
# ---------------------------------------------------------------------------

CLEAN_SOURCE = '''from __future__ import annotations

def analyze(text: str) -> dict:
    """Local-only analysis, no imports."""
    return {"score": 0.5}
'''

NETWORK_URLLIB_SOURCE = """from __future__ import annotations
import urllib.request

def fetch(url: str) -> str:
    return urllib.request.urlopen(url).read().decode()
"""

NETWORK_REQUESTS_SOURCE = """from __future__ import annotations
import requests

def fetch(url: str) -> str:
    return requests.get(url).text
"""

NETWORK_HTTPCLIENT_SOURCE = """from __future__ import annotations
import http.client

def fetch(host: str) -> str:
    conn = http.client.HTTPConnection(host)
    conn.request("GET", "/")
    return conn.getresponse().read().decode()
"""

SUBPROCESS_SOURCE = """from __future__ import annotations
import os

def run_cmd(cmd: str) -> str:
    return os.system(cmd)
"""

SUBPROCESS_POPEN_SOURCE = """from __future__ import annotations
import subprocess

def run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout
"""

DYN_EVAL_SOURCE = """from __future__ import annotations

def run_code(code: str) -> Any:
    return eval(code)
"""

DYN_EXEC_SOURCE = """from __future__ import annotations

def run_code(code: str) -> None:
    exec(code)
"""

DYN_IMPORTLIB_SOURCE = """from __future__ import annotations
import importlib

def load(name: str):
    return importlib.import_module(name)
"""

FS_WRITE_SOURCE = """from __future__ import annotations

def write_file(path: str, data: str) -> None:
    with open(path, "w") as f:
        f.write(data)
"""

FS_WRITE_BINARY_SOURCE = """from __future__ import annotations

def write_binary(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)
"""

FS_WRITE_MODE_KW_SOURCE = """from __future__ import annotations

def write_file(path: str, data: str) -> None:
    with open(path, mode="w") as f:
        f.write(data)
"""

FS_READ_SOURCE = """from __future__ import annotations

def read_file(path: str) -> str:
    with open(path, "r") as f:
        return f.read()
"""

FS_OS_REMOVE_SOURCE = """from __future__ import annotations
import os

def delete(path: str) -> None:
    os.remove(path)
"""

FS_PATH_WRITE_SOURCE = """from __future__ import annotations
from pathlib import Path

def write(path: Path, data: str) -> None:
    path.write_text(data)
"""

TELEMETRY_SOURCE = """from __future__ import annotations
import sentry_sdk

def init() -> None:
    sentry_sdk.init("dsn")
"""

OBFUSCATION_SOURCE = """from __future__ import annotations
import base64

def decode_and_run(encoded: str) -> None:
    decoded = base64.b64decode(encoded).decode()
    exec(decoded)
"""

SYNTAX_ERROR_SOURCE = """from __future__ import annotations

def broken(:
    pass
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_clean_source_no_findings():
    """Clean local adapter produces zero findings and local_only_verified=True."""
    report = scan_adapter_source(CLEAN_SOURCE, "clean")
    assert len(report.findings) == 0
    assert report.local_only_verified is True
    assert report.module_name == "clean"
    assert report.lines_scanned > 0


def test_network_urlopen_critical():
    """Direct urllib.request.urlopen call -> critical."""
    report = scan_adapter_source(NETWORK_URLLIB_SOURCE, "urlib")
    findings = [f for f in report.findings if f.category == "network"]
    assert any(f.rule_id == "NET-010" and f.severity == "critical" for f in findings)


def test_network_requests_import_high():
    """requests import -> high."""
    report = scan_adapter_source(NETWORK_REQUESTS_SOURCE, "requests")
    findings = [f for f in report.findings if f.category == "network"]
    assert any(f.rule_id == "NET-002" and f.severity == "high" for f in findings)


def test_network_httpclient_import_medium():
    """http.client import -> medium."""
    report = scan_adapter_source(NETWORK_HTTPCLIENT_SOURCE, "httpclient")
    findings = [f for f in report.findings if f.category == "network"]
    assert any(f.rule_id == "NET-003" and f.severity == "medium" for f in findings)


def test_subprocess_os_system_high():
    """os.system call -> high."""
    report = scan_adapter_source(SUBPROCESS_SOURCE, "subprocess")
    findings = [f for f in report.findings if f.category == "subprocess"]
    assert any(f.rule_id == "SUB-002" and f.severity == "high" for f in findings)


def test_subprocess_run_high():
    """subprocess.run call -> high."""
    report = scan_adapter_source(SUBPROCESS_POPEN_SOURCE, "subprocess2")
    findings = [f for f in report.findings if f.category == "subprocess"]
    assert any(f.rule_id == "SUB-003" and f.severity == "high" for f in findings)


def test_dynamic_eval_high():
    """eval call -> high."""
    report = scan_adapter_source(DYN_EVAL_SOURCE, "dyn")
    findings = [f for f in report.findings if f.category == "dynamic_execution"]
    assert any(f.rule_id == "DYN-001" and f.severity == "high" for f in findings)


def test_dynamic_exec_high():
    """exec call -> high."""
    report = scan_adapter_source(DYN_EXEC_SOURCE, "dyn2")
    findings = [f for f in report.findings if f.category == "dynamic_execution"]
    assert any(f.rule_id == "DYN-002" and f.severity == "high" for f in findings)


def test_dynamic_importlib_medium():
    """importlib.import_module with non-literal -> medium."""
    report = scan_adapter_source(DYN_IMPORTLIB_SOURCE, "dyn3")
    findings = [f for f in report.findings if f.category == "dynamic_execution"]
    assert any(f.rule_id == "DYN-005" and f.severity == "medium" for f in findings)


def test_filesystem_open_write_medium():
    """open(..., 'w') -> medium."""
    report = scan_adapter_source(FS_WRITE_SOURCE, "fs")
    findings = [f for f in report.findings if f.category == "filesystem"]
    assert any(f.rule_id == "FS-001" and f.severity == "medium" for f in findings)


def test_filesystem_open_wb_medium():
    """open(..., 'wb') -> medium."""
    report = scan_adapter_source(FS_WRITE_BINARY_SOURCE, "fs2")
    findings = [f for f in report.findings if f.category == "filesystem"]
    assert any(f.rule_id == "FS-001" and f.severity == "medium" for f in findings)


def test_filesystem_open_mode_kw_medium():
    """open(path, mode='w') -> medium."""
    report = scan_adapter_source(FS_WRITE_MODE_KW_SOURCE, "fs3")
    findings = [f for f in report.findings if f.category == "filesystem"]
    assert any(f.rule_id == "FS-001" and f.severity == "medium" for f in findings)


def test_filesystem_open_read_no_finding():
    """open(path, 'r') -> no finding."""
    report = scan_adapter_source(FS_READ_SOURCE, "fs_read")
    findings = [f for f in report.findings if f.category == "filesystem"]
    assert len(findings) == 0


def test_filesystem_os_remove_medium():
    """os.remove -> medium."""
    report = scan_adapter_source(FS_OS_REMOVE_SOURCE, "fs4")
    findings = [f for f in report.findings if f.category == "filesystem"]
    assert any(f.rule_id == "FS-002" and f.severity == "medium" for f in findings)


def test_filesystem_path_write_medium():
    """Path.write_text -> medium."""
    report = scan_adapter_source(FS_PATH_WRITE_SOURCE, "fs5")
    findings = [f for f in report.findings if f.category == "filesystem"]
    assert any(f.rule_id == "FS-004" and f.severity == "medium" for f in findings)


def test_telemetry_sentry_medium():
    """sentry_sdk import -> medium."""
    report = scan_adapter_source(TELEMETRY_SOURCE, "telemetry")
    findings = [f for f in report.findings if f.category == "telemetry"]
    assert any(f.rule_id == "TEL-001" and f.severity == "medium" for f in findings)


def test_obfuscation_base64_exec_critical():
    """base64.b64decode + exec in same file -> critical."""
    report = scan_adapter_source(OBFUSCATION_SOURCE, "obf")
    findings = [f for f in report.findings if f.category == "obfuscation"]
    assert any(f.rule_id == "OBF-001" and f.severity == "critical" for f in findings)


def test_is_safe_thresholds():
    """is_safe respects severity thresholds."""
    # Clean source: safe at all levels
    clean_report = scan_adapter_source(CLEAN_SOURCE, "clean")
    assert clean_report.is_safe("info") is True
    assert clean_report.is_safe("low") is True
    assert clean_report.is_safe("medium") is True
    assert clean_report.is_safe("high") is True
    assert clean_report.is_safe("critical") is True

    # Network request import (high): safe at info/low, NOT safe at medium/high
    # IS safe at critical (high=3 < critical=4)
    net_report = scan_adapter_source(NETWORK_REQUESTS_SOURCE, "net")
    assert net_report.is_safe("info") is False  # info is lowest
    assert net_report.is_safe("low") is False
    assert net_report.is_safe("medium") is False  # high >= medium
    assert net_report.is_safe("high") is False  # high >= high
    assert net_report.is_safe("critical") is True  # high < critical

    # Medium finding (http.client): safe at info/low, NOT safe at medium/high/critical
    http_report = scan_adapter_source(NETWORK_HTTPCLIENT_SOURCE, "http")
    assert http_report.is_safe("info") is False
    assert http_report.is_safe("low") is False
    assert http_report.is_safe("medium") is False  # medium >= medium
    assert http_report.is_safe("high") is True  # medium < high
    assert http_report.is_safe("critical") is True  # medium < critical

    # Critical finding (obfuscation): not safe at any threshold
    obf_report = scan_adapter_source(OBFUSCATION_SOURCE, "obf")
    assert obf_report.is_safe("info") is False
    assert obf_report.is_safe("low") is False
    assert obf_report.is_safe("medium") is False
    assert obf_report.is_safe("high") is False
    assert obf_report.is_safe("critical") is False


def test_summary_counts():
    """summary() returns correct counts by severity and category."""
    report = scan_adapter_source(OBFUSCATION_SOURCE, "obf")
    summary = report.summary()
    assert summary["total"] >= 2  # At least OBF-001 and imports
    assert "critical" in summary["by_severity"]
    assert "obfuscation" in summary["by_category"]
    # OBFUSCATION_SOURCE imports base64 (not network)
    assert "dynamic_execution" in summary["by_category"] or "obfuscation" in summary["by_category"]


def test_scan_adapter_file_temp():
    """scan_adapter_file works on a temp file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(CLEAN_SOURCE)
        tmp_path = pathlib.Path(f.name)

    try:
        report = scan_adapter_file(tmp_path)
        assert report.module_name == tmp_path.stem
        assert report.local_only_verified is True
        assert len(report.findings) == 0
    finally:
        tmp_path.unlink()


def test_scan_adapter_file_missing_raises():
    """scan_adapter_file raises AdapterScanError for missing file."""
    with pytest.raises(AdapterScanError):
        scan_adapter_file(pathlib.Path("/nonexistent/adapter.py"))


def test_verify_local_only_true():
    """verify_local_only returns True for clean source."""
    assert verify_local_only(CLEAN_SOURCE) is True


def test_verify_local_only_false_network():
    """verify_local_only returns False when network imports exist."""
    assert verify_local_only(NETWORK_REQUESTS_SOURCE) is False


def test_verify_local_only_false_subprocess():
    """verify_local_only returns False when subprocess calls exist."""
    assert verify_local_only(SUBPROCESS_SOURCE) is False


def test_verify_local_only_false_telemetry():
    """verify_local_only returns False when telemetry imports exist."""
    assert verify_local_only(TELEMETRY_SOURCE) is False


def test_deduplication():
    """Same rule at same line should be deduplicated."""
    # Two open('w') calls on same line (artificial)
    source = """from __future__ import annotations
def f():
    open("a.txt", "w"); open("b.txt", "w")
"""
    report = scan_adapter_source(source, "dedup")
    fs_findings = [f for f in report.findings if f.category == "filesystem"]
    # Both calls on line 3 should produce one finding
    lines = [f.line for f in fs_findings]
    assert len(lines) == len(set(lines))


def test_report_to_dict_roundtrip():
    """to_dict contains all expected keys."""
    report = scan_adapter_source(CLEAN_SOURCE, "test")
    d = report.to_dict()
    assert set(d.keys()) == {
        "module_name",
        "findings",
        "scanned_at",
        "source_sha256",
        "lines_scanned",
        "local_only_verified",
        "unknown_reasons",
    }
    assert isinstance(d["findings"], list)
    assert isinstance(d["scanned_at"], str)
    assert isinstance(d["source_sha256"], str)


def test_finding_to_dict():
    """SecurityFinding.to_dict contains all fields."""
    f = SecurityFinding(
        rule_id="TEST-001",
        severity="high",
        category="network",
        message="test",
        line=10,
        snippet="import requests",
    )
    d = f.to_dict()
    assert d == {
        "rule_id": "TEST-001",
        "severity": "high",
        "category": "network",
        "message": "test",
        "line": 10,
        "snippet": "import requests",
    }


def test_scan_entry_points_returns_list():
    """scan_adapter_entry_points returns a list (may be empty) without raising."""
    reports = scan_adapter_entry_points()
    assert isinstance(reports, list)
    for r in reports:
        assert isinstance(r, AdapterScanReport)


def test_syntax_error_produces_critical_finding():
    """Syntax error in source produces a critical dynamic_execution finding."""
    report = scan_adapter_source(SYNTAX_ERROR_SOURCE, "broken")
    findings = [f for f in report.findings if f.category == "dynamic_execution"]
    assert any(f.rule_id == "DYN-999" and f.severity == "critical" for f in findings)
    # IF-08: a syntax error fails closed — uninspectable source can never
    # be verified local-only.
    assert report.local_only_verified is False
    assert report.unknown_reasons


def test_socket_create_connection_critical():
    """socket.create_connection -> critical."""
    source = """from __future__ import annotations
import socket
def conn(): socket.create_connection(("example.com", 80))
"""
    report = scan_adapter_source(source, "sock")
    findings = [f for f in report.findings if f.category == "network"]
    assert any(f.rule_id == "NET-011" and f.severity == "critical" for f in findings)


def test_socket_socket_critical():
    """socket.socket -> critical."""
    source = """from __future__ import annotations
import socket
def conn(): socket.socket()
"""
    report = scan_adapter_source(source, "sock2")
    findings = [f for f in report.findings if f.category == "network"]
    assert any(f.rule_id == "NET-012" and f.severity == "critical" for f in findings)


def test_codecs_decode_obfuscation():
    """codecs.decode -> obfuscation medium."""
    source = """from __future__ import annotations
import codecs
def decode(s): codecs.decode(s, "rot_13")
"""
    report = scan_adapter_source(source, "codecs")
    findings = [f for f in report.findings if f.category == "obfuscation"]
    assert any(f.rule_id == "OBF-003" for f in findings)


def test_long_string_exec_critical():
    """Long string literal passed to exec -> critical."""
    long_str = '"' + "x" * 250 + '"'
    source = f"""from __future__ import annotations
def run(): exec({long_str})
"""
    report = scan_adapter_source(source, "long")
    findings = [f for f in report.findings if f.category == "obfuscation"]
    assert any(f.rule_id == "OBF-002" and f.severity == "critical" for f in findings)


def test_long_string_eval_critical():
    """Long string literal passed to eval -> critical."""
    long_str = '"' + "x" * 250 + '"'
    source = f"""from __future__ import annotations
def run(): eval({long_str})
"""
    report = scan_adapter_source(source, "long2")
    findings = [f for f in report.findings if f.category == "obfuscation"]
    assert any(f.rule_id == "OBF-002" and f.severity == "critical" for f in findings)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
