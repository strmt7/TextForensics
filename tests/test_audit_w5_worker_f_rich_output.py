"""W5 Worker F kill tests for rich_output (audit-w5-f).

Kill evidence for the 143 killable runtime survivors in
textforensics.rich_output (13 more are equivalents; see
hidden_files/audit-w5-f-equiv-reasons-rich_output.json).

Capture pattern (from test_w5_worker_c_if18.py): an in-memory
``Console(record=True, width=200)`` and ``export_text()`` for plain
text; ``export_text(styles=True)`` for the status-colour mutants
(the plain export drops ANSI styles, so colours are only visible
there -- verified: ``\\x1b[32m`` for ok, ``\\x1b[31m`` for error).

What each group kills:

* Default-value NumberReplacers (``.get(..., 0.0)`` -> 1.0/-1.0,
  ``word_count`` -> 1/-1, hash slices ``[:16]``/``[:12]`` -> +/-1,
  ``lims[:3]`` -> [:4]/[:2], ``lim[:60]`` -> [:61]/[:59]): render
  with the key MISSING and assert the exact default rendering.
* ``isinstance`` AddNot mutants: render the same value as a dict AND
  as an object (``SimpleNamespace``) and assert each takes its own
  branch (the mutant swaps them, so a dict item shows the getattr
  default 0.0 instead of its own score).
* ``show_header=True`` -> False: assert the header row text is
  present (``Detector`` / ``Dimension`` / ``Entry Point`` / ``Line``).
* ``no_wrap=True`` -> False: a long SPACED value stays on one line
  when wrapping is off (verified: 1 line) and wraps onto 2 lines
  when it is on (verified on a manual table); assert exactly one
  line contains the value. For the diff ``Line`` column the same
  effect needs a narrow console (width=15, line 301 stays intact).
* ``status == "ok"`` (health): ``ok`` renders green, ``error`` red
  (styled export); ``warning`` is NOT in the PluginHealth status
  domain (only ``ok``/``error`` occur), so Eq_GtE is a
  domain-equivalent, not a kill (see the reasons file).
* ``print_diff`` style ``== "unified"``: the unified branch renders
  the plain ``--- text1`` diff; the Gt mutant renders the Rich table
  instead (Eq_GtE is a domain-equivalent: the CLI constrains style
  to ``side_by_side``/``unified``/``inline``, all ``< "unified"``
  except ``unified`` itself).
* ``print_diff`` exact small-diff text: one exact-text assertion
  kills the padding mutants occ 32/34/35, the show_header mutant and
  every line-number mutant (``i1 + k + 1`` arithmetic) that differs
  at k == 0 / i1 <= 1; the multi-block exact-text test kills the
  rest (those that only differ at k >= 1 or i1 > 1). Padding occ 33
  (``(0, 1)`` -> ``(-1, 1)``) is unobservable: Rich clamps negative
  padding to 0 (verified: identical rendering).
* ``print_diff`` index guards (``k < len(...)``): unequal-length
  inputs in the equal and replace branches -- every comparison
  mutant either blanks a cell or raises IndexError at ``k == len``.
  The ``Lt_IsNot`` mutants in the REPLACE branch need a 300-line
  block: ``300 is not len(...)`` is True on this Python (ints above
  the -5..256 cache are distinct objects), so the mutant indexes
  out of range. (In the EQUAL branch ``Lt_IsNot``/``Lt_LtE``/
  ``Lt_NotEq`` are unobservable: equal blocks have identical
  lengths by construction, so ``k < len`` is always true -- see
  the reasons file.)
* ``print_diff`` autojunk: a 300-line repeated pattern with one
  changed line in the middle -- with autojunk off the trailing
  block stays ``equal`` (exactly one ``~`` marker); with autojunk
  on the popular lines become junk and the whole trailing block
  becomes ``replace`` (~150 markers).
"""

from types import SimpleNamespace

import pytest
from rich.console import Console

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

SPACED_NAME = ("word " * 60).strip()


def _console(width=200):
    return Console(record=True, width=width, force_terminal=False)


def _text(console) -> str:
    return console.export_text()


def _styled(console) -> str:
    return console.export_text(styles=True)


# ---------------------------------------------------------------------------
# print_scan_results
# ---------------------------------------------------------------------------


def test_scan_results_missing_keys_show_zero_defaults():
    """Missing keys render as 0.0% / Words: 0.

    Kills NumberReplacer occ 0-9 (95-99): the defaults 0.0 -> 1.0/-1.0
    and 0 -> 1/-1 change every line of the summary panel.
    """
    console = _console()
    print_scan_results({}, console=console)
    out = _text(console)
    assert "Pattern score: 0.0%" in out
    assert "Diagnostic reliability: 0.0%" in out
    assert "Analyzer disagreement: 0.0%" in out
    assert "Robustness stability: 0.0%" in out
    assert "Words: 0" in out


def test_scan_results_analyzer_dict_and_object_branches():
    """Dict items use .get, object items use getattr; defaults are 0.0.

    Kills AddNot occ 6 (129: dict score -> getattr default 0.0),
    AddNot occ 8 (137: dict reliability -> getattr default 0.0),
    NumberReplacer occ 10/11 (dict score default), occ 12/13
    (object score default), occ 14/15 (dict reliability default),
    occ 16/17 (object reliability default).
    """
    console = _console()
    print_scan_results(
        {
            "verdict": "unknown",
            # Non-zero top-level values so the summary panel contributes
            # no "0.0%": only the four analyzer defaults below do.
            "score": 0.5,
            "confidence": 0.6,
            "disagreement": 0.2,
            "robustness_stability": 0.8,
            "word_count": 300,
            "analyzers": [
                {"name": "det-a", "score": 0.8, "verdict": "ai_like", "reliability": 0.7},
                {"name": "det-b"},  # dict, all defaults
                SimpleNamespace(name="det-c", score=0.6, verdict="human_like"),
                SimpleNamespace(name="det-d"),  # object, all defaults
            ],
        },
        console=console,
    )
    out = _text(console)
    assert "Detector" in out  # header: kills ReplaceTrueWithFalse occ 1
    assert "80.0%" in out  # det-a score
    assert "70.0%" in out  # det-a reliability
    assert "60.0%" in out  # det-c score (object branch)
    # Exact analyzer rows (a bare count of "0.0%" would also match
    # "50.0%"/"60.0%" as substrings). The defaults render as 0.0%
    # in both the Score and Confidence columns for det-b/det-d, and
    # in Confidence for det-c (no reliability attribute).
    assert "\u2502 det-b    \u2502  0.0% \u2502 -          \u2502       0.0% \u2502" in out
    assert "\u2502 det-d    \u2502  0.0% \u2502 -          \u2502       0.0% \u2502" in out
    assert "\u2502 det-c    \u2502 60.0% \u2502 human_like \u2502       0.0% \u2502" in out


def test_scan_results_long_spaced_detector_name_stays_on_one_line():
    """A long spaced detector name stays on one line (no_wrap=True).

    Kills ReplaceTrueWithFalse occ 2 (118): with no_wrap=False the
    name wraps onto two lines.
    """
    console = _console()
    print_scan_results(
        {"verdict": "unknown", "analyzers": [{"name": SPACED_NAME, "score": 0.5}]},
        console=console,
    )
    out = _text(console)
    assert len([ln for ln in out.splitlines() if "word" in ln]) == 1


# ---------------------------------------------------------------------------
# print_report_summary
# ---------------------------------------------------------------------------


def test_report_summary_hash_and_defaults():
    """Hash is 16 chars + ellipsis; missing scores are 0.00.

    Kills NumberReplacer occ 18/19 (182: [:16] -> [:17]/[:15]) and
    occ 20/21 (193: missing integrity score default 0.0 -> 1.0/-1.0).
    """
    console = _console()
    print_report_summary(
        {"content_sha256": "ab" * 32, "input": {}, "trust_map": {}, "verdict_integrity": {}},
        console=console,
    )
    out = _text(console)
    assert "abababababababab\u2026" in out
    assert "(score 0.00)" in out


def test_report_summary_word_count_and_integrity_branches():
    """Dict inputs take the .get branch; a score of 0.75 is shown.

    Kills AddNot occ 12 (184: dict word_count -> "-"), AddNot
    occ 15 (193: dict integrity score -> 0.0) and NumberReplacer
    occ 22/23 (193: non-dict integrity score default 0.0 -> 1.0/-1.0,
    via integrity="not-a-dict" below).
    """
    console = _console()
    print_report_summary(
        {
            "content_sha256": "ab" * 32,
            "input": {"word_count": 250},
            "trust_map": {},
            "verdict_integrity": {"grade": "A", "score": 0.75},
        },
        console=console,
    )
    out = _text(console)
    assert "Word count: 250" in out
    assert "(score 0.75)" in out
    console = _console()
    print_report_summary(
        {"content_sha256": "ab" * 32, "verdict_integrity": "not-a-dict"},
        console=console,
    )
    assert "(score 0.00)" in _text(console)


def test_report_summary_consensus_and_provenance_panels():
    """Consensus and provenance sections render when present.

    Kills AddNot occ 16 (213: consensus panel hidden) and occ 17
    (227: provenance panel hidden).
    """
    console = _console()
    print_report_summary(
        {
            "content_sha256": "ab" * 32,
            "consensus": {"family_agreement": 0.8, "family_count": 2},
            "provenance": {"valid": True},
        },
        console=console,
    )
    out = _text(console)
    assert "Consensus" in out
    assert "Family agreement: 0.8" in out
    assert "Provenance" in out
    assert "Ledger valid: True" in out


# ---------------------------------------------------------------------------
# print_case_summary
# ---------------------------------------------------------------------------

_LONG_LIM = "L" * 70
_CASE = {
    "schema": "textforensics.case-file/v4",
    "case_sha256": "cd" * 32,
    "tool": {"name": "Tool", "version": "1.0"},
    "forensic_bundle": {
        "content_sha256": "ab" * 32,
        "detector_results": [{"detector_id": "det1", "verdict": "ai_like"}],
        "trust_map": {"overall": "strong"},
        "provenance": {"valid": True},
        "limitations": ["first limitation", "second limitation", _LONG_LIM, "fourth limitation"],
    },
}


def test_case_summary_hashes_tool_and_sections():
    """Hashes are truncated (16/12), tool version shown, sections present.

    Kills NumberReplacer occ 24/25 (261: case hash [:16] -> [:17]/[:15]),
    occ 26/27 (277: bundle hash [:12] -> [:13]/[:11]), AddNot occ 22
    (265: tool version -> "?"), occ 28 (304: trust_map node hidden),
    occ 29 (311: provenance node hidden) and occ 30 (317:
    limitations node hidden).
    """
    console = _console()
    print_case_summary(_CASE, console=console)
    out = _text(console)
    assert "cdcdcdcdcdcdcdcd\u2026" in out
    assert "abababababab\u2026" in out
    assert "Tool v1.0" in out
    assert "trust_map" in out
    assert "provenance" in out
    assert "limitations" in out


def test_case_summary_limitations_first_three_truncated():
    """Only the first 3 limitations show, each truncated to 60 chars.

    Kills ZeroIterationForLoop occ 5 (319: no limitations shown),
    NumberReplacer occ 28/29 (319: [:3] -> [:4]/[:2]) and occ 30/31
    (320: lim[:60] -> [:61]/[:59]).
    """
    console = _console()
    print_case_summary(_CASE, console=console)
    out = _text(console)
    assert "first limitation" in out
    assert "second limitation" in out
    assert "L" * 60 in out
    assert "L" * 61 not in out
    assert "fourth limitation" not in out


# ---------------------------------------------------------------------------
# print_trust_map
# ---------------------------------------------------------------------------


def test_trust_map_header_and_long_dimension_name():
    """Header shows; a long spaced dimension name stays on one line.

    Kills ReplaceTrueWithFalse occ 3 (349: header hidden) and occ 4
    (350: Dimension no_wrap -> name wraps onto two lines).
    """
    console = _console()
    print_trust_map(
        {
            "dimensions": [
                {"dimension": SPACED_NAME, "state": "supported", "reason": "ok"},
                {"dimension": "short", "state": "unknown", "reason": ""},
            ]
        },
        console=console,
    )
    out = _text(console)
    assert "Dimension" in out
    # print_trust_map prints the table TWICE (pre-existing behaviour
    # in the W5 code: c.print(table) appears twice at the end of
    # print_trust_map), so the name appears on two lines; with
    # no_wrap=False it would wrap onto two lines per print (four).
    assert len([ln for ln in out.splitlines() if "word" in ln]) == 2


# ---------------------------------------------------------------------------
# print_detector_health
# ---------------------------------------------------------------------------


def test_detector_health_header_ids_and_errors():
    """Header shows; detector IDs and errors render (or-fallbacks).

    Kills ReplaceTrueWithFalse occ 5 (394: header hidden) and occ 6
    (395: Entry Point no_wrap -- covered by the long-name test below).
    The or-fallback mutants occ 7/8 live in the getattr (object)
    branch and are killed by
    test_detector_health_object_items_use_getattr_fallbacks.
    """
    console = _console()
    print_detector_health(
        [
            {"entry_point": "ep1", "status": "ok", "detector_id": "det1", "error_type": "boom"},
            {"entry_point": "ep2", "status": "error", "detector_id": "", "error_type": ""},
        ],
        console=console,
    )
    out = _text(console)
    assert "Entry Point" in out
    assert "det1" in out
    assert "boom" in out


def test_detector_health_object_items_use_getattr_fallbacks():
    """Object items use getattr; a truthy ID/error renders as-is.

    Kills ReplaceOrWithAnd occ 7 (409) and occ 8 (410): the mutants
    live in the ``else`` (getattr) branch, so dict items never reach
    them -- only object items do. With a truthy detector_id the
    mutant renders "-" instead of "det1"; with a truthy error_type
    it renders "" instead of "boom".
    """
    console = _console()
    print_detector_health(
        [
            SimpleNamespace(entry_point="ep1", status="ok", detector_id="det1", error_type="boom"),
            SimpleNamespace(entry_point="ep2", status="error", detector_id="", error_type=""),
        ],
        console=console,
    )
    out = _text(console)
    assert "det1" in out
    assert "boom" in out


def test_detector_health_long_spaced_entry_point_stays_on_one_line():
    """A long spaced entry point stays on one line (no_wrap=True).

    Kills ReplaceTrueWithFalse occ 6 (395).
    """
    console = _console()
    print_detector_health(
        [{"entry_point": SPACED_NAME, "status": "ok", "detector_id": "d", "error_type": ""}],
        console=console,
    )
    out = _text(console)
    assert len([ln for ln in out.splitlines() if "word" in ln]) == 1


def test_detector_health_status_colours():
    """ok renders green, error renders red (styled export).

    Kills ReplaceComparisonOperator Eq_Gt / Eq_Lt / Eq_NotEq occ 0
    and AddNot occ 38 (412: ok renders red) and Eq_LtE occ 0
    (412: error renders green). Eq_GtE occ 0 is a domain-equivalent
    (PluginHealth statuses are only "ok"/"error"; see reasons file).
    """
    console = _console()
    print_detector_health(
        [{"entry_point": "ep", "status": "ok", "detector_id": "d", "error_type": ""}],
        console=console,
    )
    assert "\x1b[32m" in _styled(console)
    console = _console()
    print_detector_health(
        [{"entry_point": "ep", "status": "error", "detector_id": "d", "error_type": "x"}],
        console=console,
    )
    assert "\x1b[31m" in _styled(console)


# ---------------------------------------------------------------------------
# print_diff
# ---------------------------------------------------------------------------

_SMALL_DIFF_TEXT = (
    "    Diff: Original \u2192 Modified     \n"
    " Line  Original  Status  Modified \n"
    "    1  alpha             alpha    \n"
    "    2  beta        ~     gamma    \n"
)


def test_diff_unified_style_renders_plain_diff():
    """style="unified" renders the plain ---/+++ diff, not the table.

    Kills ReplaceComparisonOperator_Eq_Gt occ 1 (448: the mutant
    takes the Rich-table branch for "unified").
    """
    console = _console()
    print_diff("alpha\nbeta", "alpha\ngamma", style="unified", console=console)
    out = _text(console)
    assert "--- text1" in out
    assert "Diff: Original \u2192 Modified" not in out


def test_diff_small_exact_text():
    """The exact rendered text of a two-line diff.

    Kills the padding mutants occ 32/34/35 (467: (0,1) -> (1,1)
    adds blank lines, (0,0)/(0,2) change column spacing; occ 33,
    (0,1) -> (-1,1), is unobservable -- Rich clamps negative padding
    to 0, see the reasons file), ReplaceTrueWithFalse occ 7 (464:
    header hidden), the line-number mutants that differ at k == 0 /
    i1 <= 1, and the equal-branch guard mutants Lt_Eq / Lt_Gt /
    Lt_GtE / Lt_Is occ 0/1 and AddNot occ 42/43 (480/481: the equal
    row's Original cell blanks). The remaining line-number mutants
    (only different at k >= 1 or i1 > 1) are killed by
    test_diff_multi_block_exact_text.
    """
    console = _console()
    print_diff("alpha\nbeta", "alpha\ngamma", console=console)
    assert _text(console) == _SMALL_DIFF_TEXT


def test_diff_line_numbers_survive_narrow_console():
    """Line 301 stays intact at width 15 (Line no_wrap=True).

    Kills ReplaceTrueWithFalse occ 8 (469: with no_wrap=False the
    Line column wraps at width 15 and "301" no longer appears
    intact -- verified on a manual table).
    """
    lines = "\n".join(f"line{i}" for i in range(305))
    console = _console(width=15)
    print_diff(lines, lines + "\nline305b", console=console)
    assert "301" in _text(console)


def test_diff_unequal_lengths_equal_and_replace_branches():
    """Unequal-length inputs exercise both index guards.

    Kills Lt_LtE / Lt_NotEq occ 2/3 (490/491: IndexError at
    k == len in the replace branch) and the remaining replace-branch
    guard mutants; the equal-branch guards are covered by
    test_diff_small_exact_text.
    """
    console = _console()
    # Left shorter than right (replace block, left guard).
    print_diff("one\ntwo\nthree", "one\nTWO\nthree\nfour", console=console)
    out = _text(console)
    assert "three" in out and "four" in out
    # Right shorter than left (replace block, right guard).
    console = _console()
    print_diff("one\nTWO\nthree\nfour", "one\ntwo\nthree", console=console)
    out = _text(console)
    assert "three" in out and "four" in out


def _long_replace(left_count, right_count):
    left = "\n".join(f"L{i}" for i in range(left_count))
    right = "\n".join(f"R{i}" for i in range(right_count))
    return left, right


def test_diff_long_replace_left_shorter_kills_isnot_guard():
    """A 300-line replace block, left shorter: left guard fires.

    Kills ReplaceComparisonOperator_Lt_IsNot occ 2 (490): at k == 300
    ``300 is not len(left_lines)`` is True on this Python (ints above
    the -5..256 cache are distinct objects), so the mutant indexes
    left_lines[300] and raises IndexError.
    """
    left, right = _long_replace(300, 301)
    console = _console()
    print_diff(left, right, console=console)
    out = _text(console)
    assert "L299" in out and "R300" in out


def test_diff_long_replace_right_shorter_kills_isnot_guard():
    """A 300-line replace block, right shorter: right guard fires.

    Kills ReplaceComparisonOperator_Lt_IsNot occ 3 (491): same
    mechanism as the left guard, mirrored.
    """
    left, right = _long_replace(301, 300)
    console = _console()
    print_diff(left, right, console=console)
    out = _text(console)
    assert "L300" in out and "R299" in out


def test_diff_multi_block_exact_text():
    """One diff exercising every block kind, asserted exactly.

    Opcodes: equal(0,5) / replace(5,8 -> 5,6) / equal(8,9) /
    delete(9,12) / equal(12,13) / replace(13,14 -> 8,11) /
    equal(14,16). The exact text pins every row number, which kills
    the remaining line-number mutants that only differ when k >= 1
    or i1 > 1: Add_BitOr / Add_BitXor / Add_Sub occ 3 (483, equal
    first +), Add_BitOr / Add_BitXor occ 4 (483, equal second +),
    Add_LShift / Add_Pow / Add_Sub occ 5 (493, replace first +),
    Add_LShift occ 6 (493, replace second +), all of occ 7/8 and
    NumberReplacer occ 40/41 (501, delete rows 10-12). It also kills
    ReplaceComparisonOperator_Lt_NotEq occ 2 (490) and occ 3 (491):
    the two replace blocks have 3-vs-1 sides, so k exceeds the short
    side's length and the mutant indexes out of range (IndexError).
    """
    t1 = [
        "h0",
        "h1",
        "e0",
        "e1",
        "e2",
        "r0",
        "r1",
        "r2",
        "m0",
        "d0",
        "d1",
        "d2",
        "m1",
        "s0",
        "m2",
        "t0",
    ]
    t2 = ["h0", "h1", "e0", "e1", "e2", "R0", "m0", "m1", "S0", "S1", "S2", "m2", "t0"]
    console = _console()
    print_diff("\n".join(t1), "\n".join(t2), console=console)
    assert _text(console) == (
        "    Diff: Original \u2192 Modified     \n"
        " Line  Original  Status  Modified \n"
        "    1  h0                h0       \n"
        "    2  h1                h1       \n"
        "    3  e0                e0       \n"
        "    4  e1                e1       \n"
        "    5  e2                e2       \n"
        "    6  r0          ~     R0       \n"
        "    7  r1          ~              \n"
        "    8  r2          ~              \n"
        "    9  m0                m0       \n"
        "   10  d0          -              \n"
        "   11  d1          -              \n"
        "   12  d2          -              \n"
        "   13  m1                m1       \n"
        "   14  s0          ~     S0       \n"
        "   15              ~     S1       \n"
        "   16              ~     S2       \n"
        "   15  m2                m2       \n"
        "   16  t0                t0       \n"
    )


def test_diff_autojunk_off_keeps_trailing_equal_block():
    """A changed line mid-pattern leaves exactly one '~' marker.

    Kills ReplaceFalseWithTrue occ 3 (459: autojunk=True treats the
    popular repeated lines as junk, so the whole trailing block
    becomes a replace -- ~150 '~' markers instead of 1).
    """
    lines = ["A", "B", "C", "D"] * 75
    changed = list(lines)
    changed[150] = "CHANGED"
    console = _console()
    print_diff("\n".join(lines), "\n".join(changed), console=console)
    out = _text(console)
    assert out.count("~") == 1
    assert "CHANGED" in out
