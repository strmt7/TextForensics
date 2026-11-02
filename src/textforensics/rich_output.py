from __future__ import annotations

from typing import TYPE_CHECKING, Any

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich.table import Table
    from rich.tree import Tree

    HAS_RICH = True
except ImportError:
    HAS_RICH = False

if TYPE_CHECKING:
    pass

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _console() -> Any:
    """Return a Rich Console that writes to stdout."""
    if HAS_RICH:
        return Console()
    return None


def _state_style(state: str) -> str:
    """Map a Trust Map state to a Rich style string."""
    mapping = {
        "supported": "green",
        "partial": "yellow",
        "unknown": "blue",
        "out_of_scope": "red",
    }
    return mapping.get(state, "default")


def _verdict_style(verdict: str) -> str:
    """Map a verdict string to a Rich style."""
    mapping = {
        "ai_like": "red",
        "machine_like": "red",
        "machine_like_patterns": "red",
        "human_like": "green",
        "human_like_patterns": "green",
        "abstain": "yellow",
        "unknown": "blue",
    }
    return mapping.get(verdict, "default")


# ---------------------------------------------------------------------------
# Public API — graceful no-op when Rich is not installed
# ---------------------------------------------------------------------------


def print_scan_results(
    results: Any,
    console: Any = None,
) -> None:
    """Print scan results as a Rich table.

    Accepts either an AnalysisResult object or a dict with ``analyzers``,
    ``verdict``, ``score``, ``confidence`` (or ``diagnostic_reliability``),
    ``disagreement``, ``robustness_stability``, ``word_count``, and
    ``warnings`` keys.
    """
    if not HAS_RICH:
        return None

    c = console or _console()

    # Normalise input to dict
    if hasattr(results, "to_dict"):
        data = results.to_dict()
    elif isinstance(results, dict):
        data = results
    else:
        return None

    # Top-level summary panel
    verdict = data.get("verdict", "unknown")
    score = data.get("score", 0.0)
    confidence = data.get("confidence", data.get("diagnostic_reliability", 0.0))
    disagreement = data.get("disagreement", 0.0)
    robustness = data.get("robustness_stability", 0.0)
    words = data.get("word_count", 0)

    verdict_style = _verdict_style(verdict)
    summary_text = (
        f"[bold]Verdict:[/] [{verdict_style}]{verdict}[/{verdict_style}]\n"
        f"[bold]Pattern score:[/] {score:.1%}\n"
        f"[bold]Diagnostic reliability:[/] {confidence:.1%}\n"
        f"[bold]Analyzer disagreement:[/] {disagreement:.1%}\n"
        f"[bold]Robustness stability:[/] {robustness:.1%}\n"
        f"[bold]Words:[/] {words}"
    )
    c.print(Panel(summary_text, title="TextForensics Scan", border_style="blue"))

    # Analyzer table
    analyzers = data.get("analyzers", [])
    if analyzers:
        table = Table(title="Analyzer Details", show_header=True, header_style="bold magenta")
        table.add_column("Detector", style="cyan", no_wrap=True)
        table.add_column("Score", justify="right")
        table.add_column("Verdict")
        table.add_column("Confidence", justify="right")

        for item in analyzers:
            name = (
                item.get("name", item.get("detector_id", "unknown"))
                if isinstance(item, dict)
                else getattr(item, "name", "unknown")
            )
            s = item.get("score", 0.0) if isinstance(item, dict) else getattr(item, "score", 0.0)
            v = (
                item.get("verdict", "-")
                if isinstance(item, dict)
                else getattr(item, "verdict", "-")
            )
            conf = (
                item.get("reliability", item.get("confidence", 0.0))
                if isinstance(item, dict)
                else getattr(item, "reliability", getattr(item, "confidence", 0.0))
            )

            verdict_style = _verdict_style(v)
            table.add_row(
                name,
                f"{s:.1%}",
                f"[{verdict_style}]{v}[/{verdict_style}]",
                f"{conf:.1%}",
            )
        c.print(table)

    # Warnings
    warnings = data.get("warnings", [])
    if warnings:
        c.print("\n[bold yellow]Warnings:[/]")
        for w in warnings:
            c.print(f"  [yellow]- {w}[/]")


def print_report_summary(
    report: Any,
    console: Any = None,
) -> None:
    """Print forensic bundle report as Rich panels.

    Accepts either a ForensicBundle object or its ``to_dict()`` output.
    """
    if not HAS_RICH:
        return None

    c = console or _console()

    if hasattr(report, "to_dict"):
        data = report.to_dict()
    elif isinstance(report, dict):
        data = report
    else:
        return None

    # Content hash & input info
    content_hash = data.get("content_sha256", "unknown")[:16] + "…"
    input_info = data.get("input", {})
    word_count = input_info.get("word_count", "-") if isinstance(input_info, dict) else "-"

    # Overall trust
    trust_map = data.get("trust_map", {})
    overall = trust_map.get("overall", "unknown") if isinstance(trust_map, dict) else "unknown"

    # Integrity
    integrity = data.get("verdict_integrity", {})
    grade = integrity.get("grade", "N/A") if isinstance(integrity, dict) else "N/A"
    int_score = integrity.get("score", 0.0) if isinstance(integrity, dict) else 0.0

    c.print(
        Panel(
            f"[bold]Content SHA-256:[/] {content_hash}\n"
            f"[bold]Word count:[/] {word_count}\n"
            f"[bold]Trust Map overall:[/] [bold]{overall}[/]\n"
            f"[bold]Integrity grade:[/] [bold]{grade}[/] (score {int_score:.2f})",
            title="Forensic Report Summary",
            border_style="blue",
        )
    )

    # Trust Map dimensions
    print_trust_map(trust_map, console=c)

    # Consensus panel
    consensus = data.get("consensus", {})
    if consensus:
        agreement = consensus.get("family_agreement", "-")
        families = consensus.get("family_count", "-")
        c.print(
            Panel(
                f"[bold]Family agreement:[/] {agreement}\n[bold]Families:[/] {families}",
                title="Consensus",
                border_style="green",
            )
        )

    # Provenance panel
    provenance = data.get("provenance")
    if provenance:
        prov_valid = provenance.get("valid", "-")
        c.print(
            Panel(
                f"[bold]Ledger valid:[/] {prov_valid}",
                title="Provenance",
                border_style="cyan",
            )
        )

    # Limitations
    limitations = data.get("limitations", [])
    if limitations:
        c.print("\n[bold red]Limitations:[/]")
        for lim in limitations:
            c.print(f"  [dim]- {lim}[/]")


def print_case_summary(
    case: Any,
    console: Any = None,
) -> None:
    """Print case file structure as a Rich tree.

    Accepts a dict representing a sealed case file.
    """
    if not HAS_RICH:
        return None

    c = console or _console()

    if not isinstance(case, dict):
        return None

    case_hash = case.get("case_sha256", "unknown")[:16] + "…"
    schema = case.get("schema", "unknown")
    tool = case.get("tool", {})
    tool_name = tool.get("name", "?") if isinstance(tool, dict) else "?"
    tool_version = tool.get("version", "?") if isinstance(tool, dict) else "?"

    root = Tree(f"[bold cyan]Case File[/] ({schema})")
    root.add(f"[dim]SHA-256:[/] {case_hash}")
    root.add(f"[dim]Tool:[/] {tool_name} v{tool_version}")

    # Forensic bundle
    bundle = case.get("forensic_bundle", {})
    if isinstance(bundle, dict):
        bundle_node = root.add("[bold blue]forensic_bundle[/]")
        content_hash = bundle.get("content_sha256", "?")[:12] + "…"
        bundle_node.add(f"[dim]content_sha256:[/] {content_hash}")

        # Detector results
        det_results = bundle.get("detector_results", [])
        if det_results:
            dr_node = bundle_node.add(f"[bold]detector_results[/] ({len(det_results)})")
            for dr in det_results:
                if isinstance(dr, dict):
                    det_id = dr.get("detector_id", "unknown")
                    dr_node.add(f"[cyan]{det_id}[/] → {dr.get('verdict', '?')}")

        # Detector failures
        det_failures = bundle.get("detector_failures", [])
        if det_failures:
            df_node = bundle_node.add(f"[bold red]detector_failures[/] ({len(det_failures)})")
            for df in det_failures:
                if isinstance(df, dict):
                    df_node.add(
                        f"[red]{df.get('detector_id', '?')}[/] ({df.get('error_type', '?')})"
                    )

        # Trust map
        tm = bundle.get("trust_map", {})
        if isinstance(tm, dict):
            tm_node = bundle_node.add("[bold green]trust_map[/]")
            overall = tm.get("overall", "?")
            tm_node.add(f"[dim]overall:[/] [bold]{overall}[/]")

        # Provenance
        prov = bundle.get("provenance")
        if prov:
            prov_node = bundle_node.add("[bold yellow]provenance[/]")
            prov_node.add(f"[dim]valid:[/] {prov.get('valid', '?')}")

        # Limitations
        lims = bundle.get("limitations", [])
        if lims:
            lim_node = bundle_node.add("[bold red]limitations[/]")
            for lim in lims[:3]:
                lim_node.add(f"[dim]{lim[:60]}[/]")

    c.print(root)


def print_trust_map(
    trust_map: Any,
    console: Any = None,
) -> None:
    """Print Trust Map dimensions as a Rich table.

    Accepts either a TrustMap object or a dict with ``dimensions``.
    """
    if not HAS_RICH:
        return None

    c = console or _console()

    if hasattr(trust_map, "to_dict"):
        data = trust_map.to_dict()
    elif isinstance(trust_map, dict):
        data = trust_map
    else:
        return None

    dimensions = data.get("dimensions", [])
    if not dimensions:
        return None

    table = Table(title="Trust Map", show_header=True, header_style="bold magenta")
    table.add_column("Dimension", style="cyan", no_wrap=True)
    table.add_column("State", style="yellow")
    table.add_column("Reason")

    for dim in dimensions:
        if isinstance(dim, dict):
            d_name = dim.get("dimension", "?")
            d_state = dim.get("state", "?")
            d_reason = dim.get("reason", "")
        else:
            d_name = getattr(dim, "dimension", "?")
            d_state = getattr(dim, "state", "?")
            d_reason = getattr(dim, "reason", "")

        style = _state_style(d_state)
        table.add_row(
            d_name,
            f"[{style}]{d_state}[/{style}]",
            d_reason,
        )

    c.print(table)

    c.print(table)


def print_detector_health(
    health: Any,
    console: Any = None,
) -> None:
    """Print detector health status as a Rich table.

    Accepts a list of health dicts (from ``list_detector_health()``).
    """
    if not HAS_RICH:
        return None

    c = console or _console()

    if not isinstance(health, list):
        return None

    table = Table(title="Detector Health", show_header=True, header_style="bold magenta")
    table.add_column("Entry Point", style="cyan", no_wrap=True)
    table.add_column("Status", style="yellow")
    table.add_column("Detector ID")
    table.add_column("Error")

    for item in health:
        if isinstance(item, dict):
            ep = item.get("entry_point", "?")
            status = item.get("status", "?")
            det_id = item.get("detector_id", "-") or "-"
            error = item.get("error_type", "") or ""
        else:
            ep = getattr(item, "entry_point", "?")
            status = getattr(item, "status", "?")
            det_id = getattr(item, "detector_id", "-") or "-"
            error = getattr(item, "error_type", "") or ""

        status_style = "green" if status == "ok" else "red"
        table.add_row(
            ep,
            f"[{status_style}]{status}[/{status_style}]",
            det_id,
            error,
        )

    c.print(table)


def print_diff(
    text1: str,
    text2: str,
    style: str = "side_by_side",
    console: Any = None,
) -> None:
    """Print a Rich diff between two texts.

    Falls back to plain text diff if Rich is not installed.
    """
    if not HAS_RICH:
        from .localize import visual_diff as _plain_diff

        print(_plain_diff(text1, text2, style=style))
        return None

    c = console or _console()

    from difflib import SequenceMatcher

    lines1 = text1.splitlines(keepends=False)
    lines2 = text2.splitlines(keepends=False)

    if style == "unified":
        from .localize import visual_diff as _plain_diff

        c.print(_plain_diff(text1, text2, style="unified"))
        return None

    # Side-by-side with Rich panel
    matcher = SequenceMatcher(None, lines1, lines2, autojunk=False)
    blocks = matcher.get_opcodes()

    table = Table(
        title="Diff: Original → Modified",
        show_header=True,
        header_style="bold magenta",
        box=None,
        padding=(0, 1),
    )
    table.add_column("Line", style="dim", justify="right", no_wrap=True)
    table.add_column("Original", overflow="fold")
    table.add_column("Status", justify="center", no_wrap=True)
    table.add_column("Modified", overflow="fold")

    for tag, i1, i2, j1, j2 in blocks:
        left_lines = lines1[i1:i2]
        right_lines = lines2[j1:j2]

        if tag == "equal":
            for k in range(max(len(left_lines), len(right_lines))):
                left = left_lines[k] if k < len(left_lines) else ""
                right = right_lines[k] if k < len(right_lines) else ""
                table.add_row(
                    str(i1 + k + 1),
                    left,
                    "  ",
                    right,
                )
        elif tag == "replace":
            for k in range(max(len(left_lines), len(right_lines))):
                left = left_lines[k] if k < len(left_lines) else ""
                right = right_lines[k] if k < len(right_lines) else ""
                table.add_row(
                    str(i1 + k + 1),
                    f"[red]{left}[/]" if left else "",
                    "~",
                    f"[green]{right}[/]" if right else "",
                )
        elif tag == "delete":
            for k, line in enumerate(left_lines):
                table.add_row(
                    str(i1 + k + 1),
                    f"[red]{line}[/]",
                    "-",
                    "",
                )
        elif tag == "insert":
            for _, line in enumerate(right_lines):
                table.add_row(
                    "",
                    "",
                    "+",
                    f"[green]{line}[/]",
                )

    c.print(table)


def create_progress_bar() -> Any:
    """Create a Rich Progress instance for long operations.

    Returns ``None`` when Rich is not installed.
    """
    if not HAS_RICH:
        return None

    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
    )


# ---------------------------------------------------------------------------
# Graceful import guard
# ---------------------------------------------------------------------------

__all__ = [
    "HAS_RICH",
    "print_scan_results",
    "print_report_summary",
    "print_case_summary",
    "print_trust_map",
    "print_detector_health",
    "print_diff",
    "create_progress_bar",
]
