"""Static security scanner for detector adapter source code.

Inspired by NVIDIA/SkillSpector, adapted for AI-text detector adapters.
Scans adapter Python source at import time — before an adapter is loaded or run — to flag
security risks such as network access, subprocess spawning, dynamic execution, file writes,
obfuscation and telemetry.

Enforces the project rule:
    "Core is local-first. No text leaves the machine unless the user explicitly selects
     an opt-in remote adapter."
"""

from __future__ import annotations

import ast
import hashlib
import importlib.metadata
import inspect
import pathlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

__all__ = [
    "AdapterScanError",
    "AdapterScanReport",
    "SecurityFinding",
    "scan_adapter_entry_points",
    "scan_adapter_file",
    "scan_adapter_source",
    "verify_local_only",
]

_SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SecurityFinding:
    """A single security finding from the static adapter scan."""

    rule_id: str
    severity: str
    category: str
    message: str
    line: int | None
    snippet: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
            "line": self.line,
            "snippet": self.snippet,
        }


@dataclass(frozen=True, slots=True)
class AdapterScanReport:
    """Report produced by scanning a single adapter source file."""

    module_name: str
    findings: list[SecurityFinding]
    scanned_at: str
    source_sha256: str
    lines_scanned: int
    local_only_verified: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_name": self.module_name,
            "findings": [f.to_dict() for f in self.findings],
            "scanned_at": self.scanned_at,
            "source_sha256": self.source_sha256,
            "lines_scanned": self.lines_scanned,
            "local_only_verified": self.local_only_verified,
        }

    def is_safe(self, max_severity: str = "high") -> bool:
        """Return True iff no finding at or above *max_severity* exists."""
        threshold = _SEVERITY_ORDER.get(max_severity, 2)
        for finding in self.findings:
            if _SEVERITY_ORDER.get(finding.severity, 0) >= threshold:
                return False
        return True

    def summary(self) -> dict[str, Any]:
        """Return counts grouped by severity and by category."""
        severity_counts: dict[str, int] = {}
        category_counts: dict[str, int] = {}
        for finding in self.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            category_counts[finding.category] = category_counts.get(finding.category, 0) + 1
        return {
            "total": len(self.findings),
            "by_severity": severity_counts,
            "by_category": category_counts,
        }


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class AdapterScanError(Exception):
    """Raised when an adapter source file cannot be read."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NETWORK_MODULES_CRITICAL = {
    "socket",
    "urllib.request",
}

_NETWORK_MODULES_HIGH = {
    "requests",
    "httpx",
    "aiohttp",
}

_NETWORK_MODULES_MEDIUM = {
    "http.client",
    "urllib",
    "ftplib",
    "smtplib",
    "telnetlib",
    "xmlrpc.client",
}

_TELEMETRY_MODULES = {
    "opentelemetry",
    "sentry_sdk",
    "datadog",
    "boto3",
}

_WRITE_MODE_PREFIXES = ("w", "a", "x", "+")


def _get_snippet(source_lines: list[str], lineno: int | None) -> str | None:
    if lineno is None or lineno < 1 or lineno > len(source_lines):
        return None
    line = source_lines[lineno - 1].rstrip()
    if len(line) > 120:
        line = line[:117] + "..."
    return line


def _resolve_import_name(name: str) -> str:
    """Return the top-level module name from a dotted import."""
    return name.split(".")[0]


def _is_write_mode(node: ast.expr) -> bool:
    """Check if a mode argument indicates write access."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        mode = node.value
        return any(mode.startswith(pfx) for pfx in _WRITE_MODE_PREFIXES)
    return False


# ---------------------------------------------------------------------------
# Scanning logic
# ---------------------------------------------------------------------------


def _scan(
    tree: ast.Module,
    source: str,
    module_name: str,
) -> list[SecurityFinding]:
    """Walk the AST and collect findings."""
    source_lines = source.splitlines()
    findings: list[SecurityFinding] = []
    seen: set[tuple[str, int | None]] = set()

    def _add(rule_id: str, severity: str, category: str, message: str, node: ast.AST) -> None:
        line = getattr(node, "lineno", None)
        key = (rule_id, line)
        if key in seen:
            return
        seen.add(key)
        findings.append(
            SecurityFinding(
                rule_id=rule_id,
                severity=severity,
                category=category,
                message=message,
                line=line,
                snippet=_get_snippet(source_lines, line),
            )
        )

    # Pre-collect: does the file contain both base64.b64decode?
    has_base64_decode = False

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "b64decode"
                and isinstance(func.value, ast.Name)
                and func.value.id == "base64"
            ):
                has_base64_decode = True

    for node in ast.walk(tree):
        # ----- Import statements -----
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name
                    if mod in _NETWORK_MODULES_CRITICAL:
                        _add(
                            "NET-001",
                            "high",
                            "network",
                            f"Import of network module '{mod}'",
                            node,
                        )
                    elif mod in _NETWORK_MODULES_HIGH:
                        _add(
                            "NET-002",
                            "high",
                            "network",
                            f"Import of network library '{mod}'",
                            node,
                        )
                    elif mod in _NETWORK_MODULES_MEDIUM:
                        _add(
                            "NET-003",
                            "medium",
                            "network",
                            f"Import of network module '{mod}'",
                            node,
                        )
                    elif mod in _TELEMETRY_MODULES:
                        _add(
                            "TEL-001",
                            "medium",
                            "telemetry",
                            f"Import of telemetry/cloud module '{mod}'",
                            node,
                        )
            elif isinstance(node, ast.ImportFrom):
                mod_name = node.module or ""
                top = _resolve_import_name(mod_name)
                if mod_name in _NETWORK_MODULES_CRITICAL:
                    _add(
                        "NET-001",
                        "high",
                        "network",
                        f"From-import of network module '{mod_name}'",
                        node,
                    )
                elif mod_name in _NETWORK_MODULES_HIGH:
                    _add(
                        "NET-002",
                        "high",
                        "network",
                        f"From-import of network library '{mod_name}'",
                        node,
                    )
                elif mod_name in _NETWORK_MODULES_MEDIUM or top in _NETWORK_MODULES_MEDIUM:
                    _add(
                        "NET-003",
                        "medium",
                        "network",
                        f"From-import of network module '{mod_name}'",
                        node,
                    )
                elif mod_name in _TELEMETRY_MODULES or top in _TELEMETRY_MODULES:
                    _add(
                        "TEL-001",
                        "medium",
                        "telemetry",
                        f"From-import of telemetry/cloud module '{mod_name}'",
                        node,
                    )
                elif mod_name == "subprocess" or top == "subprocess":
                    _add("SUB-001", "high", "subprocess", "Import of subprocess module", node)
                elif mod_name == "commands" or top == "commands":
                    _add("SUB-002", "high", "subprocess", "Import of commands module", node)

        # ----- Call nodes -----
        if isinstance(node, ast.Call):
            func = node.func

            # Direct call name check
            call_name = ""
            call_base = ""
            if isinstance(func, ast.Name):
                call_name = func.id
                call_base = func.id
            elif isinstance(func, ast.Attribute):
                call_name = func.attr
                if isinstance(func.value, ast.Name):
                    call_base = f"{func.value.id}.{func.attr}"

            # Network calls — critical
            # Handle chained attribute access like urllib.request.urlopen or socket.create_connection
            def _get_full_attr_name(func: ast.Attribute) -> str:
                parts = []
                current = func
                while isinstance(current, ast.Attribute):
                    parts.append(current.attr)
                    current = current.value
                if isinstance(current, ast.Name):
                    parts.append(current.id)
                return ".".join(reversed(parts))

            full_attr_name = ""
            if isinstance(func, ast.Attribute):
                full_attr_name = _get_full_attr_name(func)

            if full_attr_name == "urllib.request.urlopen" and call_name == "urlopen":
                _add("NET-010", "critical", "network", "Direct urlopen call", node)
            if full_attr_name == "socket.create_connection" and call_name == "create_connection":
                _add("NET-011", "critical", "network", "Direct socket.create_connection call", node)
            if full_attr_name == "socket.socket":
                _add("NET-012", "critical", "network", "Direct socket.socket call", node)

            # Subprocess calls
            if call_name in ("system", "popen") and call_base in ("os.system", "os.popen"):
                _add("SUB-002", "high", "subprocess", f"Call to {call_base}", node)
            if call_name in (
                "Popen",
                "run",
                "call",
                "check_output",
                "check_call",
            ) and call_base.startswith("subprocess."):
                _add("SUB-003", "high", "subprocess", f"Call to subprocess.{call_name}", node)
            elif isinstance(func, ast.Name) and func.id in (
                "Popen",
                "run",
                "call",
                "check_output",
                "check_call",
            ):
                # Could be from subprocess import Popen
                _add(
                    "SUB-003",
                    "high",
                    "subprocess",
                    f"Call to subprocess.{call_name} (from-import)",
                    node,
                )

            # Dynamic execution
            if call_name == "eval":
                # Check for obfuscation pattern: long string literal to eval
                arg_is_long_string = False
                if (
                    node.args
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                    and len(node.args[0].value) > 200
                ):
                    arg_is_long_string = True
                if arg_is_long_string and has_base64_decode:
                    _add(
                        "OBF-002",
                        "critical",
                        "obfuscation",
                        "Long string literal passed to eval combined with base64 decode in same file",
                        node,
                    )
                elif arg_is_long_string:
                    _add(
                        "OBF-002",
                        "critical",
                        "obfuscation",
                        "Long string literal passed to eval",
                        node,
                    )
                else:
                    _add("DYN-001", "high", "dynamic_execution", "Call to eval()", node)
            elif call_name == "exec":
                arg_is_long_string = False
                if (
                    node.args
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                    and len(node.args[0].value) > 200
                ):
                    arg_is_long_string = True
                # Obfuscation: base64 + exec in same file
                if has_base64_decode:
                    _add(
                        "OBF-001",
                        "critical",
                        "obfuscation",
                        "exec() used in file that also uses base64.b64decode",
                        node,
                    )
                if arg_is_long_string:
                    _add(
                        "OBF-002",
                        "critical",
                        "obfuscation",
                        "Long string literal passed to exec",
                        node,
                    )
                else:
                    _add("DYN-002", "high", "dynamic_execution", "Call to exec()", node)
            elif call_name == "compile":
                _add("DYN-003", "high", "dynamic_execution", "Call to compile()", node)
            elif call_base == "__import__" or call_name == "__import__":
                _add("DYN-004", "medium", "dynamic_execution", "Call to __import__", node)
            elif call_base == "importlib.import_module":
                # Check if argument is non-literal
                if node.args:
                    first_arg = node.args[0]
                    if not isinstance(first_arg, ast.Constant):
                        _add(
                            "DYN-005",
                            "medium",
                            "dynamic_execution",
                            "importlib.import_module with non-literal argument",
                            node,
                        )

            # Obfuscation: codecs.decode
            if call_base == "codecs.decode":
                _add("OBF-003", "medium", "obfuscation", "Use of codecs.decode", node)

            # Filesystem: open with write mode
            if call_name == "open" or call_base == "open":
                mode_arg = None
                # Check positional args for mode (2nd arg, index 1)
                if len(node.args) >= 2:
                    mode_arg = node.args[1]
                # Check keyword arg mode=
                for kw in node.keywords:
                    if kw.arg == "mode":
                        mode_arg = kw.value
                if mode_arg is not None and _is_write_mode(mode_arg):
                    _add("FS-001", "medium", "filesystem", "open() with write mode", node)

            # Filesystem: os.remove / os.unlink
            if call_base in ("os.remove", "os.unlink"):
                _add("FS-002", "medium", "filesystem", f"Call to {call_base}", node)

            # Filesystem: shutil.rmtree
            if call_base == "shutil.rmtree":
                _add("FS-003", "medium", "filesystem", "Call to shutil.rmtree", node)

            # Filesystem: Path.write_text / Path.write_bytes
            if isinstance(func, ast.Attribute) and func.attr in ("write_text", "write_bytes"):
                _add("FS-004", "medium", "filesystem", f"Call to Path.{func.attr}", node)

    return findings


def scan_adapter_source(
    source: str,
    module_name: str = "unknown",
) -> AdapterScanReport:
    """Perform static scanning of Python source using the AST module.

    Detects network access, subprocess spawning, dynamic execution, file writes,
    obfuscation patterns and telemetry imports.
    """
    source_sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
    source_lines = source.splitlines()
    lines_count = len(source_lines)

    try:
        tree = ast.parse(source)
        findings = _scan(tree, source, module_name)
    except SyntaxError as exc:
        line = getattr(exc, "lineno", None)
        snippet = _get_snippet(source_lines, line)
        findings = [
            SecurityFinding(
                rule_id="DYN-999",
                severity="critical",
                category="dynamic_execution",
                message=f"Source contains syntax errors and cannot be safely inspected: {exc.msg}",
                line=line,
                snippet=snippet,
            )
        ]

    has_unsafe = any(f.category in {"network", "subprocess", "telemetry"} for f in findings)

    return AdapterScanReport(
        module_name=module_name,
        findings=findings,
        scanned_at=datetime.now(timezone.utc).isoformat(),
        source_sha256=source_sha,
        lines_scanned=lines_count,
        local_only_verified=not has_unsafe,
    )


def scan_adapter_file(
    path: str | pathlib.Path,
) -> AdapterScanReport:
    """Read a file, compute its SHA-256, and scan the source."""
    p = pathlib.Path(path)
    if not p.exists():
        raise AdapterScanError(f"Adapter file not found: {path}")
    source = p.read_text(encoding="utf-8")
    module_name = p.stem
    return scan_adapter_source(source, module_name=module_name)


def verify_local_only(source: str) -> bool:
    """Return True iff no network, subprocess or telemetry findings exist."""
    report = scan_adapter_source(source)
    return report.local_only_verified


def scan_adapter_entry_points() -> list[AdapterScanReport]:
    """Discover installed detector plugin entry points and scan each."""
    reports: list[AdapterScanReport] = []
    try:
        eps = importlib.metadata.entry_points()
        selected = (
            eps.select(group="textforensics.detectors")
            if hasattr(eps, "select")
            else eps.get("textforensics.detectors", [])
        )
    except Exception:
        return reports

    for entry_point in selected:
        ep_name = getattr(entry_point, "name", "unknown")
        try:
            mod = entry_point.load()
            # If it's a class (typical detector plugin), get the module
            if inspect.isclass(mod):
                mod = inspect.getmodule(mod)
            if mod is None:
                raise AdapterScanError(f"Could not get module for entry point {ep_name}")
            source = inspect.getsource(mod)
            reports.append(scan_adapter_source(source, module_name=f"plugin:{ep_name}"))
        except Exception:
            # One failing plugin doesn't break the scan
            reports.append(
                AdapterScanReport(
                    module_name=f"plugin:{ep_name}",
                    findings=[
                        SecurityFinding(
                            rule_id="DYN-998",
                            severity="critical",
                            category="dynamic_execution",
                            message=f"Module could not be inspected: {ep_name}",
                            line=None,
                            snippet=None,
                        )
                    ],
                    scanned_at=datetime.now(timezone.utc).isoformat(),
                    source_sha256="",
                    lines_scanned=0,
                    local_only_verified=False,
                )
            )
    return reports
