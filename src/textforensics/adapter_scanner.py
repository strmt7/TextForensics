"""Static security scanner for detector adapter source code.

Inspired by NVIDIA/SkillSpector, adapted for AI-text detector adapters.
Scans adapter Python source WITHOUT importing it — before an adapter is loaded or run — to flag
security risks such as network access, subprocess spawning, dynamic execution, file writes,
obfuscation and telemetry. Importing the scanned module would execute plugin code as a side
effect of the inspection, so source is resolved from distribution metadata instead.

Enforces the project rule:
    "Core is local-first. No text leaves the machine unless the user explicitly selects
     an opt-in remote adapter."
"""

from __future__ import annotations

import ast
import hashlib
import importlib.metadata
import pathlib
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
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
    """Report produced by scanning a single adapter source file.

    ``local_only_verified`` is true only when the scanned file shows no
    network/subprocess/telemetry/dynamic-execution or critical finding,
    parses cleanly, and contains no uninspectable code (see
    ``unknown_reasons``). It is a statement about the inspected source
    text only — never proof of whole-package network isolation.
    """

    module_name: str
    findings: list[SecurityFinding]
    scanned_at: str
    source_sha256: str
    lines_scanned: int
    local_only_verified: bool
    unknown_reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_name": self.module_name,
            "findings": [f.to_dict() for f in self.findings],
            "scanned_at": self.scanned_at,
            "source_sha256": self.source_sha256,
            "lines_scanned": self.lines_scanned,
            "local_only_verified": self.local_only_verified,
            "unknown_reasons": list(self.unknown_reasons),
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


def _network_tier(dotted: str) -> str | None:
    """Return the network severity tier for a dotted module name.

    Matches the full name and every dotted prefix, so ``httpx._client``
    resolves through ``httpx`` and ``urllib.request`` through its own
    critical entry. The most severe matching tier wins.
    """
    parts = dotted.split(".")
    tier: str | None = None
    for index in range(1, len(parts) + 1):
        prefix = ".".join(parts[:index])
        if prefix in _NETWORK_MODULES_CRITICAL:
            return "critical"
        if prefix in _NETWORK_MODULES_HIGH:
            tier = "high"
        elif prefix in _NETWORK_MODULES_MEDIUM and tier is None:
            tier = "medium"
    return tier


def _telemetry_tier(dotted: str) -> str | None:
    """Return ``"medium"`` when a dotted module is a telemetry module."""
    parts = dotted.split(".")
    for index in range(1, len(parts) + 1):
        if ".".join(parts[:index]) in _TELEMETRY_MODULES:
            return "medium"
    return None


def _resolve_call_target(expr: ast.expr, aliases: dict[str, str]) -> str | None:
    """Resolve a call target to a dotted module path via the alias map.

    ``h.Client().post(...)`` with ``import httpx._client as h`` resolves
    to ``httpx._client.Client.post``; a bare ``Client()`` imported from
    ``httpx`` resolves to ``httpx.Client``. Returns ``None`` when the
    target cannot be resolved statically.
    """
    if isinstance(expr, ast.Name):
        return aliases.get(expr.id)
    if isinstance(expr, ast.Attribute):
        base = _resolve_call_target(expr.value, aliases)
        if base is None:
            return None
        return f"{base}.{expr.attr}"
    if isinstance(expr, ast.Call):
        return _resolve_call_target(expr.func, aliases)
    return None


_NETWORK_CALL_ATTRS = frozenset(
    {
        "get",
        "post",
        "put",
        "delete",
        "head",
        "patch",
        "options",
        "request",
        "urlopen",
        "create_connection",
        "connect",
        "send",
        "sendall",
        "recv",
        "Client",
        "AsyncClient",
        "Session",
        "HTTPConnection",
        "HTTPSConnection",
        "FTP",
        "SMTP",
    }
)


def _scan(
    tree: ast.Module,
    source: str,
    module_name: str,
) -> tuple[list[SecurityFinding], list[str]]:
    """Walk the AST and collect findings plus unknown-code reasons.

    Returns ``(findings, unknown_reasons)``. ``unknown_reasons`` names
    code that could not be inspected statically: relative imports,
    unscanned transitive imports, dynamic imports with unresolvable
    targets, and literal dynamic imports of uninspected modules. The
    scanner never imports the scanned module, so anything it cannot
    see is reported as unknown rather than assumed local.
    """
    source_lines = source.splitlines()
    findings: list[SecurityFinding] = []
    unknown_reasons: list[str] = []
    seen: set[tuple[str, int | None]] = set()
    seen_unknown: set[str] = set()

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

    def _unknown(reason: str) -> None:
        if reason not in seen_unknown:
            seen_unknown.add(reason)
            unknown_reasons.append(reason)

    # Pre-collect import aliases: local name -> dotted module path.
    # ``alias_names`` holds only bindings that hide the origin module
    # behind a local name (``import x as y`` / ``from x import y``);
    # plain ``import x.y`` keeps the dotted path visible in the source
    # and is already pinned by the import finding itself.
    aliases: dict[str, str] = {}
    alias_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                    alias_names.add(alias.asname)
                else:
                    aliases[alias.name.split(".")[0]] = alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            if node.level > 0 or not node.module:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
                alias_names.add(alias.asname or alias.name)

    def _flag_import(mod: str, node: ast.AST, *, from_import: bool) -> None:
        tier = _network_tier(mod)
        if tier == "critical":
            _add(
                "NET-001",
                "high",
                "network",
                f"{'From-import' if from_import else 'Import'} of network module '{mod}'",
                node,
            )
        elif tier == "high":
            _add(
                "NET-002",
                "high",
                "network",
                f"{'From-import' if from_import else 'Import'} of network library '{mod}'",
                node,
            )
        elif tier == "medium":
            _add(
                "NET-003",
                "medium",
                "network",
                f"{'From-import' if from_import else 'Import'} of network module '{mod}'",
                node,
            )
        elif _telemetry_tier(mod) is not None:
            _add(
                "TEL-001",
                "medium",
                "telemetry",
                f"{'From-import' if from_import else 'Import'} of telemetry/cloud module '{mod}'",
                node,
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
                    _flag_import(mod, node, from_import=False)
                    top = _resolve_import_name(mod)
                    if (
                        _network_tier(mod) is None
                        and _telemetry_tier(mod) is None
                        and top not in sys.stdlib_module_names
                    ):
                        _unknown(
                            f"transitive import: {top} (line {node.lineno}) — "
                            "module not inspected; network behaviour unknown"
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.level > 0 or not node.module:
                    _unknown(
                        f"relative import (line {node.lineno}) — target "
                        "cannot be resolved without package context; "
                        "network behaviour unknown"
                    )
                    continue
                mod_name = node.module or ""
                _flag_import(mod_name, node, from_import=True)
                top = _resolve_import_name(mod_name)
                if mod_name == "subprocess" or top == "subprocess":
                    _add("SUB-001", "high", "subprocess", "Import of subprocess module", node)
                elif mod_name == "commands" or top == "commands":
                    _add("SUB-002", "high", "subprocess", "Import of commands module", node)
                elif (
                    _network_tier(mod_name) is None
                    and _telemetry_tier(mod_name) is None
                    and top not in sys.stdlib_module_names
                ):
                    _unknown(
                        f"transitive import: {top} (line {node.lineno}) — "
                        "module not inspected; network behaviour unknown"
                    )

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

            matched_direct_network = False
            if full_attr_name == "urllib.request.urlopen" and call_name == "urlopen":
                _add("NET-010", "critical", "network", "Direct urlopen call", node)
                matched_direct_network = True
            if full_attr_name == "socket.create_connection" and call_name == "create_connection":
                _add("NET-011", "critical", "network", "Direct socket.create_connection call", node)
                matched_direct_network = True
            if full_attr_name == "socket.socket":
                _add("NET-012", "critical", "network", "Direct socket.socket call", node)
                matched_direct_network = True

            # Network calls via imported aliases / dotted submodules
            # (e.g. `import httpx._client as h; h.Client().post(...)` or
            # `from httpx import Client; Client().post(...)`). Fires only
            # when the network origin is hidden behind a local alias —
            # plain dotted calls are already pinned by the import
            # finding — and is skipped when a direct rule above already
            # fired on this call.
            if not matched_direct_network and isinstance(func, (ast.Attribute, ast.Name)):
                root = func
                while isinstance(root, ast.Attribute):
                    root = root.value
                root_name = root.id if isinstance(root, ast.Name) else None
                resolved = _resolve_call_target(func, aliases)
                if (
                    resolved is not None
                    and root_name in alias_names
                    and call_name in _NETWORK_CALL_ATTRS
                ):
                    module_part = ".".join(resolved.split(".")[:-1])
                    tier = _network_tier(module_part) or "high"
                    severity = (
                        "critical" if tier == "critical" else "high" if tier == "high" else "medium"
                    )
                    _add(
                        "NET-013",
                        severity,
                        "network",
                        f"Network call via imported alias '{resolved}'",
                        node,
                    )

            # Dynamic imports: literal network targets are network
            # findings; unresolvable targets are unknown.
            def _dynamic_import_target(args: list[ast.expr]) -> str | None:
                if args and isinstance(args[0], ast.Constant) and isinstance(args[0].value, str):
                    return args[0].value
                return None

            if call_name == "__import__" or call_base == "__import__":
                target = _dynamic_import_target(node.args)
                if target is not None:
                    if _network_tier(target) is not None:
                        _add(
                            "NET-002",
                            "high",
                            "network",
                            f"Dynamic import of network library '{target}'",
                            node,
                        )
                    elif _resolve_import_name(target) not in sys.stdlib_module_names:
                        _unknown(
                            f"dynamic import of '{target}' (line {node.lineno}) — "
                            "module not inspected; network behaviour unknown"
                        )
                else:
                    _unknown(
                        f"dynamic import target unknown (line {node.lineno}) — "
                        "imported module cannot be resolved statically"
                    )
            elif call_base == "importlib.import_module":
                target = _dynamic_import_target(node.args)
                if target is not None:
                    if _network_tier(target) is not None:
                        _add(
                            "NET-002",
                            "high",
                            "network",
                            f"Dynamic import of network library '{target}'",
                            node,
                        )
                    elif _resolve_import_name(target) not in sys.stdlib_module_names:
                        _unknown(
                            f"dynamic import of '{target}' (line {node.lineno}) — "
                            "module not inspected; network behaviour unknown"
                        )

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
            elif call_name == "__import__" or call_base == "__import__":
                _add("DYN-004", "medium", "dynamic_execution", "Call to __import__", node)
            elif (
                call_base == "importlib.import_module"
                and node.args
                and not isinstance(node.args[0], ast.Constant)
            ):
                # Check if argument is non-literal
                _add(
                    "DYN-005",
                    "medium",
                    "dynamic_execution",
                    "importlib.import_module with non-literal argument",
                    node,
                )
                _unknown(
                    f"dynamic import target unknown (line {node.lineno}) — "
                    "imported module cannot be resolved statically"
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

    return findings, unknown_reasons


def scan_adapter_source(
    source: str,
    module_name: str = "unknown",
) -> AdapterScanReport:
    """Perform static scanning of Python source using the AST module.

    Detects network access, subprocess spawning, dynamic execution, file writes,
    obfuscation patterns and telemetry imports.

    Fail-closed (IF-08): ``local_only_verified`` is true only when the
    file shows no network/subprocess/telemetry/dynamic-execution or
    critical finding, parses cleanly, and contains no uninspectable
    (``unknown``) code. A syntax error, a dynamic import with an
    unresolvable target, a relative import, or an unscanned transitive
    import all leave the report unverified — absence of a finding is
    never presented as proof of whole-package network isolation.
    """
    source_sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
    source_lines = source.splitlines()
    lines_count = len(source_lines)

    try:
        tree = ast.parse(source)
        findings, unknown_reasons = _scan(tree, source, module_name)
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
        unknown_reasons = ["source has syntax errors; cannot be safely inspected"]

    has_unsafe = any(
        f.category in {"network", "subprocess", "telemetry", "dynamic_execution"}
        or f.severity == "critical"
        for f in findings
    )

    return AdapterScanReport(
        module_name=module_name,
        findings=findings,
        scanned_at=datetime.now(UTC).isoformat(),
        source_sha256=source_sha,
        lines_scanned=lines_count,
        local_only_verified=not has_unsafe and not unknown_reasons,
        unknown_reasons=tuple(unknown_reasons),
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
    """Return True iff the source is verified local-only (see scan_adapter_source)."""
    report = scan_adapter_source(source)
    return report.local_only_verified


def _resolve_entry_point_source(
    entry_point: Any,
) -> tuple[str | None, str | None]:
    """Resolve an entry point's source text WITHOUT importing it.

    Returns ``(source, unknown_reason)``; exactly one is ``None``.
    The distribution file list maps the entry point's module to its
    ``.py`` source file, which is read as text. Importing the module
    (``entry_point.load()``) would execute plugin code as a side effect
    of the purported inspection, so it is never called here. Missing
    distribution metadata, a missing source file, or a bytecode/native
    only file all resolve to unknown — never to a verified claim.
    """
    dist = getattr(entry_point, "dist", None)
    if dist is None:
        return None, "distribution metadata unavailable; cannot resolve source without importing"
    module = getattr(entry_point, "module", None) or ""
    if not module:
        value = getattr(entry_point, "value", "") or ""
        module = value.split(":")[0].strip()
    if not module:
        return None, "entry point declares no module"
    parts = module.split(".")
    candidates = ["/".join(parts) + ".py", "/".join(parts) + "/__init__.py"]
    try:
        files = list(dist.files or [])
    except Exception:
        return None, "distribution file list unavailable"
    for entry_file in files:
        rel = str(entry_file).replace("\\", "/")
        if rel in candidates or any(rel.endswith("/" + c) for c in candidates):
            if not rel.endswith(".py"):
                return (
                    None,
                    f"only a non-source file is available for module {module}; "
                    "bytecode/native code cannot be inspected",
                )
            try:
                locate = getattr(dist, "locate_file", None)
                path = locate(entry_file) if locate is not None else None
                if path is None:
                    return None, f"source file for module {module} cannot be located"
                return pathlib.Path(path).read_text(encoding="utf-8"), None
            except Exception:
                return None, f"source file for module {module} cannot be read"
    return None, f"source for module {module} not found in distribution"


def scan_adapter_entry_points() -> list[AdapterScanReport]:
    """Discover installed detector plugin entry points and scan each.

    Source is resolved from distribution metadata without importing
    the entry-point module (see :func:`_resolve_entry_point_source`).
    One uninspectable plugin never breaks the scan of the others.
    """
    reports: list[AdapterScanReport] = []
    try:
        eps = importlib.metadata.entry_points()
        if hasattr(eps, "select"):
            selected = eps.select(group="textforensics.detectors")
        elif hasattr(eps, "get"):
            selected = eps.get("textforensics.detectors", [])
        else:
            selected = list(eps)
    except Exception:
        return reports

    for entry_point in selected:
        ep_name = getattr(entry_point, "name", "unknown")
        source, unknown = _resolve_entry_point_source(entry_point)
        if source is None:
            reports.append(
                AdapterScanReport(
                    module_name=f"plugin:{ep_name}",
                    findings=[
                        SecurityFinding(
                            rule_id="DYN-998",
                            severity="critical",
                            category="dynamic_execution",
                            message=(
                                f"Module could not be inspected without importing it: {unknown}"
                            ),
                            line=None,
                            snippet=None,
                        )
                    ],
                    scanned_at=datetime.now(UTC).isoformat(),
                    source_sha256="",
                    lines_scanned=0,
                    local_only_verified=False,
                    unknown_reasons=(unknown,) if unknown else (),
                )
            )
            continue
        reports.append(scan_adapter_source(source, module_name=f"plugin:{ep_name}"))
    return reports
