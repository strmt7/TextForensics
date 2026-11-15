"""W5 Worker C regression tests: IF-18 (Rich diff parses text as markup).

Red-first tests, written from the audit's regression acceptance before
the source fix:

- Bare ``[/]``, nested brackets, Rich color/link tags, Unicode, and
  long lines render literally without exceptions.
- Trusted diff styling remains correct (status markers ``~``/``-``/
  ``+`` and both texts still appear; injected markup is shown
  literally, never interpreted).
- The same discipline is checked on every other Rich report printer
  in ``rich_output.py`` (scan results, report/case summaries, Trust
  Map, detector health), not only on ``print_diff``.

Plain output is captured with an in-memory ``Console`` and the
original content is asserted in the exported text.
"""

from __future__ import annotations

import pytest

from textforensics.rich_output import (
    HAS_RICH,
    print_case_summary,
    print_detector_health,
    print_diff,
    print_report_summary,
    print_scan_results,
    print_trust_map,
)

pytestmark = pytest.mark.skipif(not HAS_RICH, reason="Rich is not installed")

TRICKY_LINES = [
    "literal [/]",
    "nested [[bold]] brackets [[/bold]]",
    "[red]not actually red[/red]",
    "[link http://example.invalid]click me[/link]",
    "[bold green]styled?[/bold green]",
    "Unicode: héllo wörld — ünïcode ✓ λ ≥ 0 [x]",
    "unclosed [bold and [italic tags",
]

LONG_LINE = "x" * 500 + " [/] tail"


def _console():
    from rich.console import Console

    return Console(record=True, width=200, force_terminal=False)


def _text(console) -> str:
    return console.export_text()


class TestPrintDiffLiteral:
    @pytest.mark.parametrize("line", TRICKY_LINES)
    def test_tricky_original_renders_literally(self, line):
        console = _console()
        # Must not raise MarkupError. Newlines are stripped before
        # comparison because the table folds long lines.
        print_diff(line, "changed", console=console)
        assert line in _text(console).replace("\n", "")

    @pytest.mark.parametrize("line", TRICKY_LINES)
    def test_tricky_modified_renders_literally(self, line):
        console = _console()
        print_diff("original", line, console=console)
        assert line in _text(console).replace("\n", "")

    def test_long_line_renders_literally(self):
        # A 500-character line is folded by the table, so it is
        # checked in pieces: a long unbroken run survives folding and
        # the bracketed tail survives at the end of the last chunk.
        console = _console()
        print_diff(LONG_LINE, "changed", console=console)
        out = _text(console)
        flat = out.replace("\n", "").replace(" ", "")
        assert "x" * 50 in flat
        assert "[/] tail" in out
        console = _console()
        print_diff("original", LONG_LINE, console=console)
        out = _text(console)
        flat = out.replace("\n", "").replace(" ", "")
        assert "x" * 50 in flat
        assert "[/] tail" in out

    def test_audit_example(self):
        console = _console()
        print_diff("literal [/]", "changed", console=console)
        # export_text() clears the record buffer, so capture once.
        out = _text(console)
        assert "literal [/]" in out
        assert "changed" in out

    def test_trusted_diff_styling_remains(self):
        console = _console()
        print_diff("alpha\nbeta", "alpha\ngamma", console=console)
        out = _text(console)
        assert "alpha" in out and "beta" in out and "gamma" in out
        # Replace marker still rendered for the changed line.
        assert "~" in out

    def test_delete_and_insert_markers_remain(self):
        # Pure delete: the removed line is the only difference.
        console = _console()
        print_diff("keep\nremove me\nlast", "keep\nlast", console=console)
        out = _text(console)
        assert "remove me" in out
        assert "-" in out
        # Pure insert: the added line is the only difference.
        console = _console()
        print_diff("keep\nlast", "keep\nadded line\nlast", console=console)
        out = _text(console)
        assert "added line" in out
        assert "+" in out

    def test_injected_markup_is_not_interpreted(self):
        # If "[red]X[/red]" were parsed as markup, the exported plain
        # text would contain only "X". Literal rendering keeps it.
        console = _console()
        print_diff("[red]X[/red]", "[red]Y[/red]", console=console)
        out = _text(console)
        assert "[red]X[/red]" in out
        assert "[red]Y[/red]" in out

    def test_unified_style_renders_literally(self):
        console = _console()
        print_diff("literal [/]", "literal [/] changed", style="unified", console=console)
        assert "literal [/]" in _text(console)


class TestOtherPrintersLiteral:
    def test_scan_results_with_markup_verdict_and_warnings(self):
        console = _console()
        data = {
            "verdict": "ai_like [/]",
            "score": 0.7,
            "diagnostic_reliability": 0.6,
            "disagreement": 0.2,
            "robustness_stability": 0.8,
            "word_count": 300,
            "analyzers": [
                {
                    "name": "det[red]ector[/red]",
                    "score": 0.8,
                    "reliability": 0.7,
                    "verdict": "[bold]ai_like[/bold]",
                }
            ],
            "warnings": ["watch out [/] and [link http://example.invalid]here[/link]"],
        }
        print_scan_results(data, console=console)
        out = _text(console)
        assert "ai_like [/]" in out
        assert "det[red]ector[/red]" in out
        assert "[bold]ai_like[/bold]" in out
        assert "watch out [/]" in out

    def test_report_summary_with_markup_limitations(self):
        console = _console()
        data = {
            "content_sha256": "ab" * 32,
            "input": {"word_count": 250},
            "trust_map": {
                "overall": "mixed [/]",
                "dimensions": [
                    {
                        "dimension": "text_length",
                        "state": "supported",
                        "reason": "ok [/]",
                    }
                ],
            },
            "verdict_integrity": {"grade": "B[/]", "score": 0.75},
            "consensus": {"family_agreement": 0.8, "family_count": 2},
            "provenance": {"valid": True},
            "limitations": ["Text-only [red]cannot[/red] prove authorship [/]"],
        }
        print_report_summary(data, console=console)
        out = _text(console)
        assert "mixed [/]" in out
        assert "B[/]" in out
        assert "Text-only [red]cannot[/red] prove authorship [/]" in out

    def test_case_summary_with_markup_ids(self):
        console = _console()
        case = {
            "schema": "textforensics.case-file/v4",
            "tool": {"name": "Tool[/]", "version": "0.2.0[red]"},
            "forensic_bundle": {
                "content_sha256": "ab" * 32,
                "detector_results": [
                    {"detector_id": "det[bold]1[/bold]", "verdict": "ai_like [/]"}
                ],
                "detector_failures": [{"detector_id": "fail[/]", "error_type": "[red]boom[/red]"}],
                "trust_map": {"overall": "strong [/]"},
                "provenance": {"valid": True},
                "limitations": ["limit [link http://example.invalid]x[/link]"],
            },
            "case_sha256": "cd" * 32,
        }
        print_case_summary(case, console=console)
        out = _text(console)
        assert "Tool[/]" in out
        assert "det[bold]1[/bold]" in out
        assert "ai_like [/]" in out
        assert "[red]boom[/red]" in out

    def test_trust_map_with_markup_reason(self):
        console = _console()
        trust_map = {
            "dimensions": [
                {
                    "dimension": "language[/]",
                    "state": "unknown",
                    "reason": "No [red]language[/red] detection [/]",
                }
            ]
        }
        print_trust_map(trust_map, console=console)
        out = _text(console)
        assert "language[/]" in out
        assert "No [red]language[/red] detection [/]" in out

    def test_detector_health_with_markup_error(self):
        console = _console()
        health = [
            {
                "entry_point": "ep[/]",
                "status": "error",
                "detector_id": "det[/]",
                "error_type": "[bold]ImportError[/bold] [/]",
            }
        ]
        print_detector_health(health, console=console)
        out = _text(console)
        assert "ep[/]" in out
        assert "det[/]" in out
        assert "[bold]ImportError[/bold] [/]" in out
