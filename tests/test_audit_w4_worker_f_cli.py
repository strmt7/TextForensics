"""Kill tests for the W4 mutation proof: ``textforensics.cli`` survivors.

Every test names the surviving mutant(s) it kills, by the inventory
``(start_pos, operator, occurrence)`` triple.  The tests call ``_run``
(or ``main``'s helpers) directly with real ``argparse`` Namespaces;
neighbouring command strings are set on a parsed Namespace, which is
how a dispatch mutant is reached without going through ``argparse``'s
``choices`` validation.

Equivalents (no kill test; reasons live in
``hidden_files/audit-w4-f-equiv-reasons-cli.json``) include the
``getattr(args, "rich", False)`` defaults (the parser always sets
``--rich`` for those subcommands and ``main`` is the only ``_run``
caller), the scan deterministic strip (an ``AnalysisResult`` payload
never carries ``detector_results``/``detector_failures``), the drift
rich block (``compare_snapshots`` never produces the ``trust_map`` /
``detector_health`` keys the block guards on), and the ``len(...) ==
0`` ``Lt``/``LtE`` mutants (a length is never negative).
"""

from __future__ import annotations

import contextlib
import copy
import json
import sys
from io import StringIO
from pathlib import Path
from unittest import mock

import pytest

from textforensics.cli import (
    EXIT_ERROR,
    EXIT_INCOMPLETE,
    EXIT_OK,
    _run,
    _sealed_bundle_paths,
    build_parser,
)
from textforensics.config import Settings

FORMULAIC = (
    "I ran this test yesterday. The first result looked odd, so I changed "
    "one cable, repeated it, and wrote down the second result."
)

BUILTIN_ID = "textforensics/builtin-heuristic"

# 64-hex fingerprints used as distinct corpus fingerprints in run manifests.
FP_A = "a" * 64
FP_B = "b" * 64
FP_C = "c" * 64


def _args(argv: list[str]):
    """Parse a real CLI argv (without the program name)."""
    return build_parser().parse_args(argv)


def _run_captured(args, stdin_text: str | None = None):
    """Run ``_run`` with stdout/stderr captured; return (code, out, err)."""
    settings = Settings.from_env()
    out, err = StringIO(), StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        if stdin_text is not None:
            with mock.patch.object(sys, "stdin", StringIO(stdin_text)):
                code = _run(args, settings)
        else:
            code = _run(args, settings)
    return code, out.getvalue(), err.getvalue()


def _write_text(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def _write_json(path: Path, payload) -> Path:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def _dataset_jsonl(tmp_path: Path) -> Path:
    """A tiny labelled-text dataset for benchmark/calibrate."""
    rows = [
        {"label": "human", "text": "I ran this test yesterday and wrote down the result."},
        {"label": "human", "text": "The meeting moved to Tuesday because the room was booked."},
        {
            "label": "ai",
            "text": "Furthermore, it is important to note that the comprehensive analysis demonstrates significant implications for future research directions.",
        },
        {
            "label": "ai",
            "text": "In conclusion, the aforementioned framework provides a robust foundation for leveraging synergistic paradigms in modern contexts.",
        },
    ]
    path = tmp_path / "dataset.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Emergency-stop gate
# ---------------------------------------------------------------------------


def test_emergency_stop_gate_blocks_neighbor_command(tmp_path, monkeypatch):
    """(1592,20) NotEq_Gt#6 + NotEq_GtE#6: with the stop active, a command
    that sorts below "emergency" must still be blocked."""
    sentinel = tmp_path / "stop"
    sentinel.write_text("", encoding="utf-8")
    monkeypatch.setenv("TEXTFORENSICS_EMERGENCY_STOP", str(sentinel))
    args = _args(["scan", "--json"])
    args.command = "a"
    code, _out, err = _run_captured(args, stdin_text=FORMULAIC)
    assert code == EXIT_ERROR
    assert "emergency stop is active" in err


# ---------------------------------------------------------------------------
# Scan / audit dispatch
# ---------------------------------------------------------------------------


def test_scan_rich_does_not_warn():
    """(1611,15) AddNot#84: ``scan --rich`` prints rich output, not the
    'Rich is not installed' fallback."""
    args = _args(["scan", "--rich"])
    _code, out, _err = _run_captured(args, stdin_text=FORMULAIC)
    assert "Warning: Rich is not installed" not in out


def test_audit_neighbor_command_is_silent():
    """(1625,22) Eq_LtE#17: a command sorting below "audit" must not run
    the audit branch."""
    args = _args(["audit"])
    args.command = "a"
    code, out, _err = _run_captured(args, stdin_text=FORMULAIC)
    assert code == EXIT_OK
    assert out == ""


def test_audit_anchor_neighbor_returns_ok():
    """(2250,22) Eq_Lt#68 + Eq_LtE#68: the duplicate audit branch below
    "audit" must not run the anchor command for a neighbour string."""
    args = _args(["audit"])
    args.command = "audi"
    code, out, _err = _run_captured(args, stdin_text=FORMULAIC)
    assert code == EXIT_OK
    assert out == ""


def test_emergency_neighbor_commands_are_silent():
    """(2253,22) Eq_GtE#69 + Eq_LtE#69: neighbour strings of "emergency"
    must not run the emergency command."""
    for neighbour in ("emergency0", "emergencx"):
        args = _args(["emergency", "status"])
        args.command = neighbour
        code, out, _err = _run_captured(args)
        assert code == EXIT_OK
        assert out == ""


# ---------------------------------------------------------------------------
# Localize
# ---------------------------------------------------------------------------


def _localize_files(tmp_path: Path):
    f1 = _write_text(tmp_path / "one.txt", "The cat sat on the mat. It was warm.")
    f2 = _write_text(tmp_path / "two.txt", "The dog lay on the rug. It was cold and dark.")
    f3 = _write_text(
        tmp_path / "three.txt",
        "I ran this test yesterday. The first result looked odd, so I "
        "changed one cable, repeated it, and wrote down the second result. "
        "The second run was cleaner and the numbers lined up.",
    )
    return f1, f2, f3


def test_localize_diff_with_file_stays_diff(tmp_path):
    """(1638,11) AddNot#86 + (1638,22) Is_IsNot#1: an explicit "diff"
    subcommand plus --file must still run the diff, not segments."""
    f1, f2, f3 = _localize_files(tmp_path)
    args = _args(["localize", "diff", str(f1), str(f2), "--file", str(f3)])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert not out.lstrip().startswith("[")


def test_localize_diff_rich_prints_diff_not_warning(tmp_path):
    """(1661,23) AddNot#91: ``localize diff --rich`` with Rich
    installed prints the rich diff, not the 'Rich is not installed'
    fallback."""
    f1, f2, _f3 = _localize_files(tmp_path)
    args = _args(["localize", "diff", str(f1), str(f2), "--rich"])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert "Warning: Rich is not installed" not in out


def test_localize_anomalies_with_file_stays_anomalies(tmp_path):
    """(1638,30) ReplaceAndWithOr#12: an explicit "anomalies" subcommand
    plus --file must not be rewritten to "segments".  At threshold 100
    no segment is anomalous, so the anomalies output is []."""
    _f1, _f2, f3 = _localize_files(tmp_path)
    args = _args(["localize", "anomalies", "--file", str(f3), "--threshold", "100"])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert json.loads(out) == []


def test_localize_segments_with_files_stays_segments(tmp_path):
    """(1641,24) Is_IsNot#2 + (1641,47) ReplaceAndWithOr#14: an explicit
    "segments" subcommand plus file1/file2 must not be rewritten to
    "diff"."""
    f1, f2, f3 = _localize_files(tmp_path)
    args = _args(["localize", "segments", str(f1), str(f2), "--file", str(f3)])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    parsed = json.loads(out)
    assert isinstance(parsed, list) and len(parsed) > 0


def test_localize_diff_missing_file2_raises(tmp_path):
    """(1648,30) ReplaceOrWithAnd#20: diff with file1 but no file2 must
    raise the diff-requires-files error, not proceed to read None."""
    f1, _f2, _f3 = _localize_files(tmp_path)
    args = _args(["localize", "diff", str(f1)])
    with pytest.raises(ValueError, match="diff requires file1 and file2"):
        _run_captured(args)


def test_localize_anomalies_neighbor_is_unknown(tmp_path):
    """(1670,24) Eq_LtE#20: a subcommand sorting below "anomalies" must
    not run the anomalies branch."""
    _f1, _f2, f3 = _localize_files(tmp_path)
    args = _args(["localize", "anomalies", "--file", str(f3)])
    args.subcommand = "anomalie"
    with pytest.raises(ValueError, match="Unknown localize command"):
        _run_captured(args)


def test_localize_anomalies_output_indent(tmp_path):
    """(1679,46) NumberReplacer#48/#49: the anomalies --output file uses
    indent=2."""
    _f1, _f2, f3 = _localize_files(tmp_path)
    out_path = tmp_path / "anomalies.json"
    args = _args(
        [
            "localize",
            "anomalies",
            "--file",
            str(f3),
            "--threshold",
            "0",
            "--output",
            str(out_path),
        ]
    )
    code, _out, _err = _run_captured(args)
    assert code == EXIT_OK
    content = out_path.read_text(encoding="utf-8")
    # A list of dicts at indent=2 puts object keys at 4 spaces.
    assert '\n    "segment_index"' in content
    assert '\n  "segment_index"' not in content
    assert '\n      "segment_index"' not in content


def test_localize_anomalies_output_keeps_unicode(tmp_path):
    """(1679,62) ReplaceFalseWithTrue#8: the anomalies --output file is
    written with ensure_ascii=False, so non-ASCII stays raw."""
    f3 = _write_text(
        tmp_path / "cafe.txt",
        "Le café était bon. The first result looked odd, so I changed one "
        "cable, repeated it, and wrote down the second result.",
    )
    out_path = tmp_path / "anomalies.json"
    args = _args(
        [
            "localize",
            "anomalies",
            "--file",
            str(f3),
            "--threshold",
            "0",
            "--output",
            str(out_path),
        ]
    )
    code, _out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert "café" in out_path.read_text(encoding="utf-8")


def test_localize_segments_neighbor_is_unknown(tmp_path):
    """(1685,24) Eq_GtE#21 + Eq_LtE#21: subcommands sorting either side
    of "segments" must not run the segments branch."""
    _f1, _f2, f3 = _localize_files(tmp_path)
    for neighbour in ("segment", "segments0"):
        args = _args(["localize", "segments", "--file", str(f3)])
        args.subcommand = neighbour
        with pytest.raises(ValueError, match="Unknown localize command"):
            _run_captured(args)


def test_localize_segments_one_sentence_allowed(tmp_path):
    """(1686,30) Lt_LtE#0 + (1686,32) NumberReplacer#50: --sentences 1
    is allowed (the guard is < 1, not <= 1 / < 2)."""
    _f1, _f2, f3 = _localize_files(tmp_path)
    args = _args(["localize", "segments", "--file", str(f3), "--sentences", "1"])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert isinstance(json.loads(out), list)


# ---------------------------------------------------------------------------
# Compare / snapshot / verify-ledger / calibrate / benchmark / fingerprint /
# check / select-threshold dispatch
# ---------------------------------------------------------------------------


def test_benchmark_neighbor_is_silent(tmp_path):
    """(1724,22) Eq_LtE#26: a command sorting below "benchmark" must not
    run the benchmark branch."""
    dataset = _dataset_jsonl(tmp_path)
    args = _args(["benchmark", str(dataset)])
    args.command = "benchmar"
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert out == ""


def test_benchmark_default_threshold_is_half(tmp_path):
    """(1735,76) NumberReplacer#52/#53: with no --threshold the benchmark
    uses 0.5."""
    dataset = _dataset_jsonl(tmp_path)
    args = _args(["benchmark", str(dataset)])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert json.loads(out)["threshold"] == 0.5


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------


def test_detectors_rich_does_not_warn():
    """(1785,15) AddNot#102: ``detectors --rich --health`` prints the rich
    health table, not the 'Rich is not installed' fallback."""
    args = _args(["detectors", "--rich", "--health"])
    _code, out, _err = _run_captured(args)
    assert "Warning: Rich is not installed" not in out


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def test_schema_list_correct_value():
    """(1802,31) Eq_Gt#32 + Eq_Lt#32 + Eq_NotEq#32: the "list" branch
    runs for the exact value."""
    args = _args(["schema", "list"])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert isinstance(json.loads(out)["schemas"], list)


def test_schema_list_greater_value_is_silent():
    """(1802,31) Eq_GtE#32: a schema_command sorting above "list" must
    not run the list branch."""
    args = _args(["schema", "list"])
    args.schema_command = "list0"
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert out == ""


def test_schema_list_lesser_value_is_silent():
    """(1802,31) Eq_LtE#32: a schema_command sorting below "list" must
    not run the list branch."""
    args = _args(["schema", "list"])
    args.schema_command = "lis"
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert out == ""


def test_schema_show_correct_value():
    """(1804,33) Eq_Gt#33 + Eq_Lt#33 + Eq_NotEq#33: the "show" branch
    runs for the exact value."""
    from textforensics.schema import list_schemas

    name = list_schemas()[0]
    args = _args(["schema", "show", name])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert "$schema" in out


def test_schema_show_greater_value_is_silent():
    """(1804,33) Eq_GtE#33: a schema_command sorting above "show" must
    not run the show branch."""
    from textforensics.schema import list_schemas

    args = _args(["schema", "show", list_schemas()[0]])
    args.schema_command = "show0"
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert out == ""


def test_schema_show_lesser_value_is_silent():
    """(1804,33) Eq_LtE#33: a schema_command sorting below "show" must
    not run the show branch."""
    from textforensics.schema import list_schemas

    args = _args(["schema", "show", list_schemas()[0]])
    args.schema_command = "sho"
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert out == ""


def test_schema_validate_correct_value(tmp_path):
    """(1807,33) Eq_Gt#34 + Eq_Lt#34 + Eq_NotEq#34: the "validate" branch
    runs for the exact value; an empty object fails validation."""
    bad = _write_json(tmp_path / "bad.json", {})
    args = _args(["schema", "validate", str(bad), "--type", "forensic-bundle"])
    code, out, _err = _run_captured(args)
    assert code == EXIT_INCOMPLETE
    assert json.loads(out)["valid"] is False


def test_schema_validate_greater_value_is_silent(tmp_path):
    """(1807,33) Eq_GtE#34: a schema_command sorting above "validate"
    must not run the validate branch."""
    bad = _write_json(tmp_path / "bad.json", {})
    args = _args(["schema", "validate", str(bad), "--type", "forensic-bundle"])
    args.schema_command = "validate0"
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert out == ""


def test_schema_validate_lesser_value_is_silent(tmp_path):
    """(1807,33) Eq_LtE#34: a schema_command sorting below "validate"
    must not run the validate branch."""
    bad = _write_json(tmp_path / "bad.json", {})
    args = _args(["schema", "validate", str(bad), "--type", "forensic-bundle"])
    args.schema_command = "validat"
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert out == ""


_SCHEMA_TYPES = [
    "forensic-bundle",
    "detector-result",
    "case-file",
    "trust-map",
    "enterprise-policy",
]


@pytest.mark.parametrize("schema_type", _SCHEMA_TYPES)
def test_schema_type_correct_value(tmp_path, schema_type):
    """(1811,25)/(1813,27)/(1815,27)/(1817,27)/(1819,27) Eq_Gt +
    Eq_Lt + Eq_NotEq: each --type value runs its own validator; an
    empty object fails validation."""
    bad = _write_json(tmp_path / "bad.json", {})
    args = _args(["schema", "validate", str(bad), "--type", schema_type])
    code, out, _err = _run_captured(args)
    assert code == EXIT_INCOMPLETE
    assert json.loads(out)["valid"] is False


@pytest.mark.parametrize("schema_type", _SCHEMA_TYPES)
def test_schema_type_greater_value_is_unknown(tmp_path, schema_type):
    """(1811,25)/(1813,27)/(1815,27)/(1817,27)/(1819,27) Eq_GtE: a
    --type sorting above the real value must raise 'Unknown schema
    type', not run the validator."""
    bad = _write_json(tmp_path / "bad.json", {})
    args = _args(["schema", "validate", str(bad), "--type", schema_type])
    args.type = schema_type + "0"
    with pytest.raises(ValueError, match="Unknown schema type"):
        _run_captured(args)


@pytest.mark.parametrize("schema_type", _SCHEMA_TYPES)
def test_schema_type_lesser_value_is_unknown(tmp_path, schema_type):
    """(1811,25)/(1813,27)/(1815,27)/(1817,27)/(1819,27) Eq_LtE: a
    --type sorting below the real value must raise 'Unknown schema
    type', not run the validator."""
    bad = _write_json(tmp_path / "bad.json", {})
    args = _args(["schema", "validate", str(bad), "--type", schema_type])
    args.type = schema_type[:-1]
    with pytest.raises(ValueError, match="Unknown schema type"):
        _run_captured(args)


def test_schema_validate_valid_bundle_is_valid(tmp_path):
    """(1825,37) Eq_Gt#40 + Eq_Lt#40 + Eq_NotEq#40 + (1825,40)
    NumberReplacer#54/#55: a real forensic bundle validates, so
    len(errors) == 0."""
    from textforensics.report import build_forensic_bundle

    bundle = build_forensic_bundle(FORMULAIC)
    good = _write_json(tmp_path / "good.json", bundle.to_dict())
    args = _args(["schema", "validate", str(good), "--type", "forensic-bundle"])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert json.loads(out)["valid"] is True


def test_schema_validate_errors_return_incomplete(tmp_path):
    """(1825,37) Eq_GtE#40 + (1829,15) AddNot#105: an invalid payload
    reports valid False AND returns EXIT_INCOMPLETE."""
    bad = _write_json(tmp_path / "bad.json", {})
    args = _args(["schema", "validate", str(bad), "--type", "forensic-bundle"])
    code, out, _err = _run_captured(args)
    assert code == EXIT_INCOMPLETE
    assert json.loads(out)["valid"] is False


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def test_report_deterministic_strips_runtime():
    """(1841,11) AddNot#106: ``report --deterministic`` strips runtime_ms
    from the bundle payload."""
    args = _args(["report", "--text", FORMULAIC, "--deterministic"])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert "runtime_ms" not in out


def test_report_without_deterministic_keeps_runtime():
    """(1841,11) AddNot#106 (twin direction): a plain ``report`` keeps
    runtime_ms in the bundle payload. The bundle is built with
    deterministic=args.deterministic, so the strip is a no-op in the
    --deterministic case; only the non-deterministic case shows the
    strip was skipped."""
    args = _args(["report", "--text", FORMULAIC])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert "runtime_ms" in out


def test_report_rich_does_not_warn():
    """(1848,15) AddNot#108: ``report --rich`` prints the rich summary,
    not the 'Rich is not installed' fallback."""
    args = _args(["report", "--text", FORMULAIC, "--rich"])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert "Warning: Rich is not installed" not in out


# ---------------------------------------------------------------------------
# Case export
# ---------------------------------------------------------------------------


def test_case_export_guard_rejects_timestamp_url(tmp_path):
    """(1857,45) ReplaceOrWithAnd#22 + (1857,85) Delete_Not#13: a
    --timestamp-url without --seal must be rejected."""
    out_path = tmp_path / "case.json"
    args = _args(
        [
            "case",
            "export",
            "--output",
            str(out_path),
            "--timestamp-url",
            "http://127.0.0.1:9",
            "--text",
            FORMULAIC,
        ]
    )
    with pytest.raises(ValueError, match="require --seal"):
        _run_captured(args)


def test_case_export_determinism_rejects_missing_colon(tmp_path):
    """(1877,15) AddNot#112: a --determinism item without ':' must be
    rejected."""
    out_path = tmp_path / "case.json"
    args = _args(
        [
            "case",
            "export",
            "--output",
            str(out_path),
            "--determinism",
            "nodcolon",
            "--text",
            FORMULAIC,
        ]
    )
    with pytest.raises(ValueError, match="--determinism expects"):
        _run_captured(args)


def test_case_export_determinism_applies_mapping(tmp_path):
    """(1880,24) ZeroIterationForLoop#12 + (1881,19) AddNot#113 +
    (1886,53) NumberReplacer#57 + (1889,19) Delete_Not#14 + AddNot#114 +
    (1898,19) AddNot#115 + (1898,31) Is_IsNot#4: a valid --determinism
    mapping lands on the builtin detector's observation."""
    out_path = tmp_path / "case.json"
    args = _args(
        [
            "case",
            "export",
            "--output",
            str(out_path),
            "--determinism",
            f"{BUILTIN_ID}:deterministic",
            "--text",
            FORMULAIC,
        ]
    )
    code, _out, _err = _run_captured(args)
    assert code == EXIT_OK
    case = json.loads(out_path.read_text(encoding="utf-8"))
    observations = case.get("detector_observations") or []
    assert any(o.get("determinism") == "deterministic" for o in observations)


def test_case_export_determinism_rejects_bad_value(tmp_path):
    """(1889,35) ReplaceOrWithAnd#24: a --determinism value outside the
    allowed set must be rejected."""
    out_path = tmp_path / "case.json"
    args = _args(
        [
            "case",
            "export",
            "--output",
            str(out_path),
            "--determinism",
            "det-x:bogus",
            "--text",
            FORMULAIC,
        ]
    )
    with pytest.raises(ValueError, match="--determinism expects"):
        _run_captured(args)


def test_case_export_determinism_rejects_empty_id(tmp_path):
    """(1889,19) Delete_Not#14 + AddNot#114 (second input): an empty
    detector id must be rejected."""
    out_path = tmp_path / "case.json"
    args = _args(
        [
            "case",
            "export",
            "--output",
            str(out_path),
            "--determinism",
            ":deterministic",
            "--text",
            FORMULAIC,
        ]
    )
    with pytest.raises(ValueError, match="--determinism expects"):
        _run_captured(args)


def test_case_export_determinism_rejects_extra_colon(tmp_path):
    """(1886,53) NumberReplacer#56: split(":", 1) keeps the rest of the
    value together, so a second colon makes the value invalid."""
    out_path = tmp_path / "case.json"
    args = _args(
        [
            "case",
            "export",
            "--output",
            str(out_path),
            "--determinism",
            "det-x:deterministic:extra",
            "--text",
            FORMULAIC,
        ]
    )
    with pytest.raises(ValueError, match="--determinism expects"):
        _run_captured(args)


def test_case_export_without_deterministic_keeps_runtime(tmp_path):
    """(1877,15) AddNot#112: a plain ``case export`` keeps runtime_ms
    in the case file. Same twin-direction argument as the report strip:
    the bundle is built with deterministic=args.deterministic, so the
    strip is a no-op in the --deterministic case."""
    case_file = _export_case(tmp_path)
    assert "runtime_ms" in case_file.read_text(encoding="utf-8")


def test_case_export_without_seal_writes_no_sealed_bundle(tmp_path):
    """(1912,15) AddNot#116: exporting without --seal must not write a
    sealed bundle or seal record."""
    out_path = tmp_path / "case.json"
    args = _args(["case", "export", "--output", str(out_path), "--text", FORMULAIC])
    code, _out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert out_path.exists()
    bundle_path, record_path = _sealed_bundle_paths(str(out_path))
    assert not bundle_path.exists()
    assert not record_path.exists()


def test_case_export_without_rich_prints_only_path(tmp_path):
    """(1914,15) AddNot#117: exporting without --rich prints only the
    output path, no rich summary."""
    out_path = tmp_path / "case.json"
    args = _args(["case", "export", "--output", str(out_path), "--text", FORMULAIC])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert out.strip() == str(out_path)


def test_case_export_rich_does_not_warn(tmp_path):
    """(1918,19) AddNot#118: ``case export --rich`` prints the rich case
    summary, not the 'Rich is not installed' fallback."""
    out_path = tmp_path / "case.json"
    args = _args(["case", "export", "--output", str(out_path), "--text", FORMULAIC, "--rich"])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert "Warning: Rich is not installed" not in out


def _export_case(tmp_path: Path) -> Path:
    out_path = tmp_path / "case.json"
    args = _args(["case", "export", "--output", str(out_path), "--text", FORMULAIC])
    code, _out, _err = _run_captured(args)
    assert code == EXIT_OK
    return out_path


def test_case_keygen_neighbor_verifies(tmp_path):
    """(1924,31) Eq_Lt#44 + Eq_LtE#44: a case_command sorting below
    "keygen" must not run keygen (it falls through to verify)."""
    case_file = _export_case(tmp_path)
    args = _args(["case", "verify", str(case_file)])
    args.case_command = "keyge"
    code, _out, _err = _run_captured(args)
    assert code == EXIT_OK


def test_case_export_neighbor_runs_verify(tmp_path):
    """(1856,29) Eq_LtE#43: a case_command sorting below "export"
    must not run the export branch (it falls through to verify). The
    mutant enters the export branch, which crashes on the verify args
    (no --output/--signing-key); the original verifies and returns
    EXIT_OK."""
    case_file = _export_case(tmp_path)
    args = _args(["case", "verify", str(case_file)])
    args.case_command = "expor"
    code, _out, _err = _run_captured(args)
    assert code == EXIT_OK


# ---------------------------------------------------------------------------
# Web / web-fastapi / serve (serve functions are stubbed: they would bind)
# ---------------------------------------------------------------------------


def test_web_neighbor_is_silent(monkeypatch):
    """(1929,22) Eq_GtE#45: a command sorting above "web" must not run
    the web branch."""
    calls = []
    monkeypatch.setattr(
        "textforensics.web_ui.main.serve_web",
        lambda *a, **k: calls.append((a, k)),
    )
    args = _args(["web"])
    args.command = "web0"
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert out == ""
    assert calls == []


def test_web_allow_remote_passes_remote_host(monkeypatch):
    """(1937,25) ReplaceTrueWithFalse#19: --allow-remote must reach the
    bind guard as allow_remote=True."""
    calls = []
    monkeypatch.setattr(
        "textforensics.web_ui.main.serve_web",
        lambda *a, **k: calls.append((a, k)),
    )
    args = _args(["web", "--host", "0.0.0.0", "--allow-remote"])
    code, _out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert len(calls) == 1
    assert calls[0][1]["allow_remote"] is True


def test_web_import_error_is_runtime_error(monkeypatch):
    """(1942,15) ExceptionReplacer#12: a failed web-UI import must raise
    the 'Install web UI support' RuntimeError."""
    monkeypatch.setitem(sys.modules, "textforensics.web_ui.main", None)
    args = _args(["web"])
    with pytest.raises(RuntimeError, match="Install web UI support"):
        _run_captured(args)


def test_web_fastapi_neighbor_is_silent(monkeypatch):
    """(1954,22) Eq_Gt#46 + Eq_GtE#46: a command sorting above
    "web-fastapi" must not run the web-fastapi branch."""
    calls = []
    monkeypatch.setattr(
        "textforensics.web_ui.main.serve_web",
        lambda *a, **k: calls.append((a, k)),
    )
    args = _args(["web-fastapi"])
    args.command = "web-fastapi0"
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert out == ""
    assert calls == []


def test_web_fastapi_allow_remote_passes_remote_host(monkeypatch):
    """(1959,25) ReplaceTrueWithFalse#20 + (1959,33) AddNot#120:
    --allow-remote must reach the bind guard as allow_remote=True."""
    calls = []
    monkeypatch.setattr(
        "textforensics.web_ui.main.serve_web",
        lambda *a, **k: calls.append((a, k)),
    )
    args = _args(["web-fastapi", "--host", "0.0.0.0", "--allow-remote"])
    code, _out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert len(calls) == 1
    assert calls[0][1]["allow_remote"] is True


def test_web_fastapi_access_log_is_passed(monkeypatch):
    """(1960,23) ReplaceTrueWithFalse#21 + (1960,31) AddNot#121:
    --access-log must reach serve_web as access_log=True."""
    calls = []
    monkeypatch.setattr(
        "textforensics.web_ui.main.serve_web",
        lambda *a, **k: calls.append((a, k)),
    )
    args = _args(["web-fastapi", "--access-log"])
    code, _out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert len(calls) == 1
    assert calls[0][1]["access_log"] is True


def test_web_fastapi_import_error_is_runtime_error(monkeypatch):
    """(1965,15) ExceptionReplacer#13: a failed web-UI import must raise
    the 'Install web UI support' RuntimeError."""
    monkeypatch.setitem(sys.modules, "textforensics.web_ui.main", None)
    args = _args(["web-fastapi"])
    with pytest.raises(RuntimeError, match="Install web UI support"):
        _run_captured(args)


def test_serve_allow_remote_passes_remote_host(monkeypatch):
    """(1982,25) ReplaceTrueWithFalse#22: --allow-remote must reach the
    bind guard as allow_remote=True."""
    calls = []
    monkeypatch.setattr("textforensics.api.serve_api", lambda a: calls.append(a))
    args = _args(["serve", "--host", "0.0.0.0", "--allow-remote"])
    code, _out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert len(calls) == 1
    assert calls[0].allow_remote is True


def test_serve_access_log_is_passed(monkeypatch):
    """(1983,23) ReplaceTrueWithFalse#23 + (1983,31) AddNot#123:
    --access-log must reach serve_api as access_log=True."""
    calls = []
    monkeypatch.setattr("textforensics.api.serve_api", lambda a: calls.append(a))
    args = _args(["serve", "--access-log"])
    code, _out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert len(calls) == 1
    assert calls[0].access_log is True


# ---------------------------------------------------------------------------
# Drift status
# ---------------------------------------------------------------------------


def _runs_dir(tmp_path: Path, runs: list[dict]) -> Path:
    """Write run manifests (built by the probe-runs test helper) into a
    run-history directory and return it."""
    from tests.test_probe_runs import _manifest, save_run

    runs_dir = tmp_path / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    for run in runs:
        # The manifest's metrics detector must match the run's detector.
        run = dict(run)
        run["metrics"] = {"detector_id": run["detector_id"]}
        save_run(_manifest(**run), runs_dir)
    return runs_dir


def _three_version_runs(detector_id: str = "det-a") -> list[dict]:
    return [
        {
            "run_id": "a" * 32,
            "run_at_utc": "2026-11-01T00:00:00+00:00",
            "detector_id": detector_id,
            "detector_version": "v1",
            "corpus_fingerprint": FP_A,
        },
        {
            "run_id": "b" * 32,
            "run_at_utc": "2026-11-02T00:00:00+00:00",
            "detector_id": detector_id,
            "detector_version": "v2",
            "corpus_fingerprint": FP_B,
        },
        {
            "run_id": "c" * 32,
            "run_at_utc": "2026-11-03T00:00:00+00:00",
            "detector_id": detector_id,
            "detector_version": "v3",
            "corpus_fingerprint": FP_C,
        },
    ]


def _registry_file(tmp_path: Path, records: list[dict]) -> Path:
    """Write a registry JSON for the given record dicts, with valid
    record signatures and a matching registry hash (built via the API)."""
    from textforensics.validation import ValidationRecord, ValidationRegistry

    registry = ValidationRegistry([ValidationRecord.from_dict(record) for record in records])
    return _write_json(tmp_path / "registry.json", registry.to_dict())


def _demoted_record(seed_index: int, detector_id: str, demoted_by: str | None) -> dict:
    """One seeded registry record, re-pointed at a detector and a
    demotion string (re-signed; the record_id stays valid and unique
    because each call uses a different seeded record)."""
    from textforensics.validation import compute_signature

    seed = json.loads(
        (
            Path(__file__).resolve().parent.parent / "docs" / "validation" / "registry.json"
        ).read_text(encoding="utf-8")
    )["records"][seed_index]
    record = copy.deepcopy(seed)
    record["detector_id"] = detector_id
    record["limits"]["demoted_by"] = demoted_by
    unsigned = {k: v for k, v in record.items() if k != "signature"}
    record["signature"] = compute_signature(unsigned)
    return record


def test_drift_status_no_runs_payload(tmp_path):
    """(1511,64) Eq_GtE#14 + Eq_IsNot#10 + Eq_LtE#14 + (1517,32)
    ReplaceFalseWithTrue#5: runs for other detectors only give the
    no_runs payload with temporal_support False."""
    runs_dir = _runs_dir(
        tmp_path,
        [
            {
                "run_id": "a" * 32,
                "run_at_utc": "2026-11-01T00:00:00+00:00",
                "detector_id": "aaa-detector",
                "detector_version": "v1",
                "corpus_fingerprint": FP_A,
            },
            {
                "run_id": "b" * 32,
                "run_at_utc": "2026-11-02T00:00:00+00:00",
                "detector_id": "zzz-detector",
                "detector_version": "v1",
                "corpus_fingerprint": FP_A,
            },
        ],
    )
    args = _args(["drift", "status", "--detector-id", "mmm-detector", "--runs-dir", str(runs_dir)])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    payload = json.loads(out)
    assert payload["status"] == "no_runs"
    assert payload["temporal_support"] is False
    assert payload["demotions"] == []


def test_drift_status_last_run_version(tmp_path):
    """(1525,66) Delete_USub#0 + USub_Invert#0 + USub_Not#0 + USub_UAdd#0
    + (1525,67) NumberReplacer#44/#45: the summary reports the LAST
    run's detector version."""
    runs_dir = _runs_dir(tmp_path, _three_version_runs())
    args = _args(["drift", "status", "--detector-id", "det-a", "--runs-dir", str(runs_dir)])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert json.loads(out)["detector_version"] == "v3"


def test_drift_status_last_run_fingerprint(tmp_path):
    """(1526,43) Delete_USub#1 + USub_Invert#1 + USub_Not#1 + USub_UAdd#1
    + (1526,44) NumberReplacer#46/#47: the summary reports the LAST
    run's corpus fingerprint."""
    runs_dir = _runs_dir(tmp_path, _three_version_runs())
    args = _args(["drift", "status", "--detector-id", "det-a", "--runs-dir", str(runs_dir)])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert json.loads(out)["corpus_fingerprint"] == FP_C


def test_drift_status_registry_filter(tmp_path):
    """(1540,34) NotEq_Gt#5 + NotEq_Is#2 + NotEq_Lt#5 + (1541,16)
    ReplaceContinueWithBreak#0: demoted records for OTHER detectors
    must not appear in this detector's demotions, while a matching
    record listed AFTER a non-matching one must still be found. The
    ordering is load-bearing: "aaa" sorts below "mmm" and "zzz" sorts
    above it (so the Lt sibling stays killed), and the matching record
    comes last (so a break in place of the continue skips it)."""
    runs_dir = _runs_dir(tmp_path, _three_version_runs("mmm-detector"))
    mmm = _demoted_record(2, "mmm-detector", "U3 probe run run-3")
    registry = _registry_file(
        tmp_path,
        [
            _demoted_record(0, "aaa-detector", "U3 probe run run-1"),
            _demoted_record(1, "zzz-detector", "U3 probe run run-2"),
            mmm,
        ],
    )
    args = _args(
        [
            "drift",
            "status",
            "--detector-id",
            "mmm-detector",
            "--runs-dir",
            str(runs_dir),
            "--registry",
            str(registry),
        ]
    )
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    demotions = json.loads(out)["demotions"]
    assert len(demotions) == 1
    assert demotions[0]["record_id"] == mmm["record_id"]
    assert demotions[0]["demoted_by"] == "U3 probe run run-3"


def test_drift_status_two_demotions(tmp_path):
    """Two matching demoted records both appear in demotions. (The
    ReplaceContinueWithBreak#0 mutant is killed by
    test_drift_status_registry_filter, where a non-matching record
    precedes the matching one.)"""
    runs_dir = _runs_dir(tmp_path, _three_version_runs(BUILTIN_ID))
    registry = _registry_file(
        tmp_path,
        [
            _demoted_record(0, BUILTIN_ID, "U3 probe run run-1"),
            _demoted_record(1, BUILTIN_ID, "U3 probe run run-2"),
        ],
    )
    args = _args(
        [
            "drift",
            "status",
            "--detector-id",
            BUILTIN_ID,
            "--runs-dir",
            str(runs_dir),
            "--registry",
            str(registry),
        ]
    )
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert len(json.loads(out)["demotions"]) == 2


def test_drift_status_non_u3_demoted_by_ignored(tmp_path):
    """(1542,40) ReplaceAndWithOr#9: a record whose demoted_by carries
    no U3 demotion must not appear in demotions."""
    runs_dir = _runs_dir(tmp_path, _three_version_runs(BUILTIN_ID))
    registry = _registry_file(
        tmp_path, [_demoted_record(0, BUILTIN_ID, "manual review: suspicious")]
    )
    args = _args(
        [
            "drift",
            "status",
            "--detector-id",
            BUILTIN_ID,
            "--runs-dir",
            str(runs_dir),
            "--registry",
            str(registry),
        ]
    )
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert json.loads(out)["demotions"] == []


def test_drift_status_cache_root_scan(tmp_path, monkeypatch):
    """(1506,11) AddNot#70 + (1507,31) ZeroIterationForLoop#10 +
    (1508,19) AddNot#71: with no --runs-dir the default cache root is
    scanned, version directories are entered, and non-directories are
    skipped."""
    from tests.test_probe_runs import _manifest, save_run

    cache_root = tmp_path / "probe-runs"
    version_dir = cache_root / "1.0.0"
    version_dir.mkdir(parents=True)
    (cache_root / "afile").write_text("not a directory", encoding="utf-8")
    for run in _three_version_runs():
        run = dict(run)
        run["metrics"] = {"detector_id": run["detector_id"]}
        save_run(_manifest(**run), version_dir)
    monkeypatch.setattr(
        "textforensics.probe_runs.default_probe_runs_dir",
        lambda *, corpus_version="1.0.0": cache_root / corpus_version,
    )
    args = _args(["drift", "status", "--detector-id", "det-a"])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert json.loads(out)["status"] == "ok"


def test_drift_dispatch_neighbor_is_silent(tmp_path):
    """(1999,32) Eq_LtE#50: a command sorting below "drift" must not run
    the drift branch."""
    runs_dir = _runs_dir(tmp_path, _three_version_runs())
    args = _args(["drift", "status", "--detector-id", "det-a", "--runs-dir", str(runs_dir)])
    args.command = "drif"
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert out == ""


# ---------------------------------------------------------------------------
# Drift report
# ---------------------------------------------------------------------------


def _snapshot_pair(tmp_path: Path):
    """Two drift snapshots over the repo's drift corpus."""
    from textforensics.detectors import BuiltinHeuristicDetector
    from textforensics.observatory import DriftObservatory

    corpus_path = Path(__file__).resolve().parent.parent / "testdata" / "drift_corpus.json"
    obs = DriftObservatory(corpus_path=corpus_path)
    baseline = obs.take_snapshot(
        detectors=[BuiltinHeuristicDetector()],
        snapshot_id="base-1",
        taken_at="2026-01-01T00:00:00+00:00",
    )
    current = obs.take_snapshot(
        detectors=[BuiltinHeuristicDetector()],
        snapshot_id="curr-1",
        taken_at="2026-01-02T00:00:00+00:00",
    )
    baseline_path = _write_json(tmp_path / "baseline.json", baseline)
    current_path = _write_json(tmp_path / "current.json", current)
    return baseline_path, current_path, corpus_path


def test_drift_run_neighbor_reports(tmp_path):
    """(2001,32) Eq_GtE#51 + Eq_LtE#51: a drift_command sorting either
    side of "status" must not run the status branch (it falls through
    to the report branch). "ru"/"run0" sort below "status" and kill the
    LtE sibling; "statusx" sorts above "status" and kills the GtE
    sibling."""
    baseline, current, corpus = _snapshot_pair(tmp_path)
    for neighbour in ("ru", "run0", "statusx"):
        out_path = tmp_path / f"report-{neighbour}.json"
        args = _args(
            [
                "drift",
                "report",
                str(baseline),
                str(current),
                "--corpus",
                str(corpus),
                "--output",
                str(out_path),
            ]
        )
        args.drift_command = neighbour
        code, _out, _err = _run_captured(args)
        assert code == EXIT_OK
        assert "overall" in json.loads(out_path.read_text(encoding="utf-8"))


def test_drift_report_rich_does_not_warn(tmp_path):
    """(2013,19) AddNot#126: ``drift report --rich`` must not print the
    'Rich is not installed' fallback."""
    baseline, current, corpus = _snapshot_pair(tmp_path)
    out_path = tmp_path / "report.json"
    args = _args(
        [
            "drift",
            "report",
            str(baseline),
            str(current),
            "--corpus",
            str(corpus),
            "--output",
            str(out_path),
            "--rich",
        ]
    )
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert "Warning: Rich is not installed" not in out


# ---------------------------------------------------------------------------
# Capability ledger
# ---------------------------------------------------------------------------


def _ledger_file(tmp_path: Path, claims) -> Path:
    """Write a capability ledger JSON from CapabilityClaim objects."""
    from textforensics.policy import CapabilityLedger

    ledger = CapabilityLedger()
    for claim in claims:
        ledger.register(claim)
    return _write_json(tmp_path / "ledger.json", ledger.to_dict())


def _claim(detector_id, capability, tier, label, *, evidence=True, valid_until="2099-01-01"):
    from textforensics.policy import CapabilityClaim, EvidenceLabel, EvidenceRef, EvidenceTier

    refs = (
        [
            EvidenceRef(
                label=EvidenceLabel[label],
                tier=EvidenceTier[tier],
                artifact="bench/run.json",
                detail="test evidence",
            )
        ]
        if evidence
        else []
    )
    return CapabilityClaim(
        detector_id=detector_id,
        capability=capability,
        tier=EvidenceTier[tier],
        evidence=refs,
        valid_until=valid_until,
    )


def test_capability_default_ledger_path():
    """(2030,58) Div_Add/BtAnd/BitOr/BitXor/FloorDiv/LShift/Mod/Mul/Pow/
    RShift/Sub#17 (11 mutants): with no --ledger the default
    capability_ledger.json path is built with Path / str."""
    args = _args(["capability", "list"])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert json.loads(out) == {}


def test_capability_corrupt_ledger_value_error(tmp_path):
    """(2036,20) ExceptionReplacer#14: a ledger whose tier is not a
    valid EvidenceTier is reported, not raised."""
    ledger = _write_json(
        tmp_path / "ledger.json",
        {"claims": {"det-a": [{"capability": "c", "tier": "bogus", "evidence": []}]}},
    )
    args = _args(["capability", "list", "--ledger", str(ledger)])
    code, _out, err = _run_captured(args)
    assert code == EXIT_ERROR
    assert "cannot load capability ledger" in err


def test_capability_corrupt_ledger_key_error(tmp_path):
    """(2036,32) ExceptionReplacer#15: a ledger claim missing its
    capability key is reported, not raised."""
    ledger = _write_json(
        tmp_path / "ledger.json",
        {"claims": {"det-a": [{"tier": "readable", "evidence": []}]}},
    )
    args = _args(["capability", "list", "--ledger", str(ledger)])
    code, _out, err = _run_captured(args)
    assert code == EXIT_ERROR
    assert "cannot load capability ledger" in err


def test_capability_corrupt_ledger_type_error(tmp_path):
    """(2036,42) ExceptionReplacer#16: a ledger claim that is not an
    object is reported, not raised."""
    ledger = _write_json(tmp_path / "ledger.json", {"claims": {"det-a": ["not-a-claim"]}})
    args = _args(["capability", "list", "--ledger", str(ledger)])
    code, _out, err = _run_captured(args)
    assert code == EXIT_ERROR
    assert "cannot load capability ledger" in err


def test_capability_corrupt_ledger_attribute_error(tmp_path):
    """(2036,53) ExceptionReplacer#17: a ledger whose claims value is
    not an object is reported, not raised."""
    ledger = _write_json(tmp_path / "ledger.json", {"claims": [1, 2]})
    args = _args(["capability", "list", "--ledger", str(ledger)])
    code, _out, err = _run_captured(args)
    assert code == EXIT_ERROR
    assert "cannot load capability ledger" in err


def test_capability_list_neighbor_is_silent(tmp_path):
    """(2047,35) Eq_Lt#54 + Eq_LtE#54: a capability_command sorting
    below "list" must not run the list branch."""
    ledger = _ledger_file(tmp_path, [_claim("det-a", "lang.en", "READABLE", "CALCULATED")])
    args = _args(["capability", "list", "--ledger", str(ledger)])
    args.capability_command = "lis"
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert out == ""


def test_capability_list_detector_filter(tmp_path):
    """(2049,15) AddNot#131: --detector filters the listed claims to
    that detector only."""
    ledger = _ledger_file(
        tmp_path,
        [
            _claim("det-a", "lang.en", "READABLE", "CALCULATED"),
            _claim("det-b", "lang.en", "READABLE", "CALCULATED"),
        ],
    )
    args = _args(["capability", "list", "--ledger", str(ledger), "--detector", "det-a"])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert list(json.loads(out)) == ["det-a"]


def test_capability_check_neighbor_is_silent(tmp_path):
    """(2052,37) Eq_Lt#55 + Eq_LtE#55: a capability_command sorting
    below "check" must not run the check branch."""
    ledger = _ledger_file(tmp_path, [_claim("det-a", "lang.en", "READABLE", "CALCULATED")])
    args = _args(["capability", "check", "det-a", "lang.en", "--ledger", str(ledger)])
    args.capability_command = "chec"
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert out == ""


def test_capability_check_validated(tmp_path):
    """(2054,35) Eq_Gt#56 + Eq_GtE#56 + Eq_Lt#56 + Eq_LtE#56 +
    Eq_IsNot#51 + Eq_NotEq#56 + (2072,15) AddNot#132 + Delete_Not#16:
    a VALIDATED claim with executed evidence checks as validated with
    no warning."""
    ledger = _ledger_file(tmp_path, [_claim("det-a", "lang.en", "VALIDATED", "EXECUTED")])
    args = _args(["capability", "check", "det-a", "lang.en", "--ledger", str(ledger)])
    code, out, err = _run_captured(args)
    assert code == EXIT_OK
    assert json.loads(out)["validated"] is True
    assert "not VALIDATED" not in err


def test_capability_export_neighbor_writes_nothing(tmp_path):
    """(2078,37) Eq_Lt#57 + Eq_LtE#57: a capability_command sorting
    below "export" must not run the export branch."""
    ledger = _ledger_file(tmp_path, [_claim("det-a", "lang.en", "READABLE", "CALCULATED")])
    out_path = tmp_path / "export.json"
    args = _args(["capability", "export", "--ledger", str(ledger), "--output", str(out_path)])
    args.capability_command = "expor"
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert out == ""
    assert not out_path.exists()


def test_capability_register_neighbor_writes_nothing(tmp_path):
    """(2080,37) Eq_GtE#58: a capability_command sorting above
    "register" must not run the register branch."""
    ledger_path = tmp_path / "ledger.json"
    args = _args(
        [
            "capability",
            "register",
            "det-a",
            "lang.en",
            "readable",
            "bench/run.json",
            "--ledger",
            str(ledger_path),
        ]
    )
    args.capability_command = "register0"
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert out == ""
    assert not ledger_path.exists()


def test_capability_register_payload(tmp_path):
    """(2099,45) ReplaceTrueWithFalse#24 + (2101,52) NumberReplacer#58/#59
    + (2101,68) ReplaceFalseWithTrue#14 + (2122,15) AddNot#133 +
    Delete_Not#17: a clean registration reports registered True, writes
    the ledger with indent=2 and raw Unicode, and warns about nothing.
    The ledger lives two missing directories deep, so mkdir needs
    parents=True; the indent assertion pins the exact file start, since
    nested keys alone cannot tell indent=1 from indent=2."""
    ledger_path = tmp_path / "nested" / "deep" / "ledger.json"
    args = _args(
        [
            "capability",
            "register",
            "det-a",
            "lang.en",
            "readable",
            "bench/run.json",
            "--ledger",
            str(ledger_path),
            "--detail",
            "café",
        ]
    )
    code, out, err = _run_captured(args)
    assert code == EXIT_OK
    # The register branch prints the payload JSON and then a
    # "Registered: ..." line, so parse only the first JSON value.
    payload, _end = json.JSONDecoder().raw_decode(out)
    assert payload["registered"] is True
    assert "not effective" not in err
    content = ledger_path.read_text(encoding="utf-8")
    assert content.startswith('{\n  "schema": "textforensics.capability-ledger/v1"')
    assert "café" in content


def test_capability_register_validated_without_executed_warns(tmp_path):
    """(2125,23) AddNot#134: registering a VALIDATED claim with only a
    CALCULATED evidence reference is ineffective, and the stderr
    warning carries the validation issue text, not the generic
    fallback detail. The mutant swaps the detail to the fallback
    message, which never mentions EXECUTED."""
    ledger_path = tmp_path / "ledger.json"
    args = _args(
        [
            "capability",
            "register",
            "det-a",
            "lang.en",
            "validated",
            "bench/run.json",
            "--ledger",
            str(ledger_path),
        ]
    )
    code, out, err = _run_captured(args)
    assert code == EXIT_OK
    payload, _end = json.JSONDecoder().raw_decode(out)
    assert payload["registered"] is True
    assert payload["effective"] is False
    assert "requires at least one EXECUTED evidence reference" in err


def test_capability_policy_known_policy_runs(tmp_path):
    """(2125,23) AddNot#134: a known policy name must not hit the
    unknown-policy error."""
    ledger = _ledger_file(tmp_path, [_claim("det-a", "lang.en", "READABLE", "CALCULATED")])
    args = _args(
        ["capability", "policy", "det-a", "--ledger", str(ledger), "--policy", "production"]
    )
    code, _out, err = _run_captured(args)
    assert code in (EXIT_OK, EXIT_INCOMPLETE)
    assert "unknown policy" not in err


def test_capability_policy_neighbor_is_silent(tmp_path):
    """(2133,37) Eq_GtE#59 + Eq_LtE#59: a capability_command sorting
    either side of "policy" must not run the policy branch."""
    ledger = _ledger_file(tmp_path, [_claim("det-a", "lang.en", "READABLE", "CALCULATED")])
    for neighbour in ("polic", "policy0"):
        args = _args(["capability", "policy", "det-a", "--ledger", str(ledger)])
        args.capability_command = neighbour
        code, out, _err = _run_captured(args)
        assert code == EXIT_OK
        assert out == ""


def test_capability_policy_prints_results(tmp_path):
    """(2162,31) ZeroIterationForLoop#15: the non-JSON policy output
    prints one line per evaluated rule, including the GAP line for a
    claim whose tier is below the required minimum. The ledger holds a
    READABLE language_coverage claim where production requires
    VALIDATED, so the prod-language-coverage rule records an evidence
    gap (and length_robustness, with no claim at all, records a
    MISSING line)."""
    ledger = _ledger_file(
        tmp_path, [_claim("det-a", "language_coverage", "READABLE", "CALCULATED")]
    )
    args = _args(["capability", "policy", "det-a", "--ledger", str(ledger)])
    code, out, _err = _run_captured(args)
    assert code == EXIT_INCOMPLETE
    assert "    GAP: language_coverage: claim tier=readable, required=validated+" in out
    assert "    MISSING: length_robustness (required: tool_backed+)" in out


# ---------------------------------------------------------------------------
# Bundle
# ---------------------------------------------------------------------------


def _bundle_files(tmp_path: Path):
    """A case file and the bundle packed from it."""
    from textforensics.bundle import pack_bundle

    case_file = _export_case(tmp_path)
    bundle_path = tmp_path / "bundle.zip"
    pack_bundle(str(case_file), str(bundle_path))
    return case_file, bundle_path


def test_bundle_pack_neighbor_writes_nothing(tmp_path):
    """(2167,31) Eq_Gt#61 + Eq_GtE#61: a bundle_command sorting above
    "pack" must not run the pack branch."""
    case_file, _bundle = _bundle_files(tmp_path)
    out_path = tmp_path / "other.zip"
    args = _args(["bundle", "pack", str(case_file), str(out_path)])
    args.bundle_command = "pack0"
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert out == ""
    assert not out_path.exists()


def test_bundle_verify_neighbor_is_silent(tmp_path):
    """(2170,33) Eq_Gt#62 + Eq_GtE#62: a bundle_command sorting above
    "verify" must not run the verify branch."""
    _case_file, bundle = _bundle_files(tmp_path)
    args = _args(["bundle", "verify", str(bundle)])
    args.bundle_command = "verify0"
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert out == ""


def test_bundle_verify_valid_returns_ok(tmp_path):
    """(2173,30) AddNot#140: verifying a valid bundle returns EXIT_OK."""
    _case_file, bundle = _bundle_files(tmp_path)
    args = _args(["bundle", "verify", str(bundle)])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert json.loads(out)["valid"] is True


def test_bundle_list_neighbor_is_silent(tmp_path):
    """(2174,33) Eq_Gt#63 + Eq_GtE#63: a bundle_command sorting above
    "list" must not run the list branch."""
    _case_file, bundle = _bundle_files(tmp_path)
    args = _args(["bundle", "list", str(bundle)])
    args.bundle_command = "list0"
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert out == ""


def test_bundle_check_neighbor_is_silent(tmp_path):
    """(2177,33) Eq_GtE#64 + Eq_LtE#64: a bundle_command sorting either
    side of "check" must not run the check branch."""
    _case_file, bundle = _bundle_files(tmp_path)
    for neighbour in ("chec", "check0"):
        args = _args(["bundle", "check", str(bundle)])
        args.bundle_command = neighbour
        code, out, _err = _run_captured(args)
        assert code == EXIT_OK
        assert out == ""


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


def test_verify_all_without_artifacts():
    """(2220,11) AddNot#148 + (2220,24) Delete_Not#18 + (2225,29)
    ReplaceFalseWithTrue#15: --all with no artifacts reports valid
    False with the no-artifacts error."""
    args = _args(["verify", "--all"])
    code, out, _err = _run_captured(args)
    assert code == EXIT_ERROR
    payload = json.loads(out)
    assert payload["valid"] is False
    assert payload["errors"] == ["No artifacts provided for verification"]


def test_verify_all_with_case_file(tmp_path):
    """(2220,20) ReplaceAndWithOr#17 + (2220,42) ReplaceOrWithAnd#29:
    --all with a case file runs verification, it does not report
    no-artifacts."""
    case_file = _export_case(tmp_path)
    args = _args(["verify", "--all", str(case_file)])
    code, out, _err = _run_captured(args)
    assert code in (EXIT_OK, EXIT_INCOMPLETE)
    assert "No artifacts provided" not in out


def test_verify_all_with_benchmark(tmp_path):
    """(2220,66) ReplaceOrWithAnd#30: --all with a benchmark result runs
    verification, it does not report no-artifacts."""
    dataset = _dataset_jsonl(tmp_path)
    args = _args(["benchmark", str(dataset)])
    _code, bench_out, _err = _run_captured(args)
    bench_path = _write_json(tmp_path / "bench.json", json.loads(bench_out))
    args = _args(["verify", "--all", "--benchmark", str(bench_path)])
    code, out, _err = _run_captured(args)
    assert code in (EXIT_OK, EXIT_INCOMPLETE)
    assert "No artifacts provided" not in out


# ---------------------------------------------------------------------------
# Build info
# ---------------------------------------------------------------------------


def test_build_info_verify_flag():
    """(2240,11) AddNot#150: --verify runs build-identity verification
    (a payload with a "valid" key), not plain build info."""
    args = _args(["build-info", "--verify"])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert '"valid"' in out


def test_build_info_verify_returns_ok():
    """(2243,30) AddNot#151: a valid build identity returns EXIT_OK."""
    args = _args(["build-info", "--verify"])
    code, _out, _err = _run_captured(args)
    assert code == EXIT_OK


# ---------------------------------------------------------------------------
# Enterprise policy command
# ---------------------------------------------------------------------------


def _policy_module():
    from textforensics.cli import _import_enterprise

    return _import_enterprise()


def _policy_dict(revision: int, digest: str):
    return {
        "revision": revision,
        "digest": digest,
        "settings": {},
        "rules": [{"id": "r1", "description": "d", "scope": "all", "action": "log"}],
    }


def _policy_file(tmp_path: Path, revision: int, digest: str | None = None):
    """Write a schema-valid enterprise policy file.  With digest None
    the digest is computed, so the file matches."""
    ep = _policy_module()
    rules = [{"id": "r1", "description": "d", "scope": "all", "action": "log"}]
    computed = ep.compute_policy_digest(
        ep.EnterprisePolicy(revision=revision, digest="", settings={}, rules=rules)
    )
    if digest is None:
        digest = computed
    path = _write_json(
        tmp_path / f"policy-{revision}-{digest[:8]}.json",
        _policy_dict(revision, digest),
    )
    return path, computed


def _floor_files(tmp_path: Path):
    """A (state_path, key_path) pair for a persisted revision floor."""
    from cryptography.fernet import Fernet

    state_path = tmp_path / "state.enc"
    key_path = tmp_path / "key"
    key_path.write_bytes(Fernet.generate_key())
    return state_path, key_path


def test_policy_load_neighbor_returns_error(tmp_path):
    """(2353,27) Eq_GtE#72: a policy_command sorting above "load" must
    not run the load branch."""
    policy, _computed = _policy_file(tmp_path, 1)
    state_path, key_path = _floor_files(tmp_path)
    args = _args(
        [
            "policy",
            "load",
            str(policy),
            "--state-path",
            str(state_path),
            "--key-path",
            str(key_path),
        ]
    )
    args.policy_command = "load0"
    code, out, _err = _run_captured(args)
    assert code == EXIT_ERROR
    assert out == ""


def test_policy_load_missing_file_returns_error(tmp_path):
    """(2357,38) ExceptionReplacer#24: a missing policy file is reported
    as a read failure, not raised."""
    state_path, key_path = _floor_files(tmp_path)
    args = _args(
        [
            "policy",
            "load",
            str(tmp_path / "missing.json"),
            "--state-path",
            str(state_path),
            "--key-path",
            str(key_path),
        ]
    )
    code, _out, err = _run_captured(args)
    assert code == EXIT_ERROR
    assert "failed to read policy file" in err


def test_policy_load_schema_errors_listed(tmp_path):
    """(2365,23) ZeroIterationForLoop#17: a schema-invalid policy lists
    its errors on stderr."""
    bad = _write_json(tmp_path / "bad.json", {})
    state_path, key_path = _floor_files(tmp_path)
    args = _args(
        [
            "policy",
            "load",
            str(bad),
            "--state-path",
            str(state_path),
            "--key-path",
            str(key_path),
        ]
    )
    code, _out, err = _run_captured(args)
    assert code == EXIT_INCOMPLETE
    assert "  - " in err


def test_policy_load_digest_mismatch_low(tmp_path):
    """(2380,61) NotEq_Eq#7 + NotEq_Gt#7 + NotEq_GtE#7 + NotEq_Is#4: a
    stored digest below the computed one is a mismatch."""
    policy, computed = _policy_file(tmp_path, 1, digest="0" * 64)
    assert "0" * 64 < computed < "f" * 64
    state_path, key_path = _floor_files(tmp_path)
    args = _args(
        [
            "policy",
            "load",
            str(policy),
            "--state-path",
            str(state_path),
            "--key-path",
            str(key_path),
        ]
    )
    code, _out, err = _run_captured(args)
    assert code == EXIT_ERROR
    assert "digest mismatch" in err


def test_policy_load_digest_mismatch_high(tmp_path):
    """(2380,61) NotEq_Eq#7 + NotEq_Lt#7 + NotEq_LtE#7 + NotEq_Is#4: a
    stored digest above the computed one is a mismatch."""
    policy, computed = _policy_file(tmp_path, 1, digest="f" * 64)
    assert "0" * 64 < computed < "f" * 64
    state_path, key_path = _floor_files(tmp_path)
    args = _args(
        [
            "policy",
            "load",
            str(policy),
            "--state-path",
            str(state_path),
            "--key-path",
            str(key_path),
        ]
    )
    code, _out, err = _run_captured(args)
    assert code == EXIT_ERROR
    assert "digest mismatch" in err


def test_policy_load_digest_match_accepted(tmp_path):
    """(2380,61) NotEq_IsNot#4 + (2408,24) ReplaceTrueWithFalse#28: a
    matching digest loads and reports accepted True."""
    policy, _computed = _policy_file(tmp_path, 1)
    state_path, key_path = _floor_files(tmp_path)
    args = _args(
        [
            "policy",
            "load",
            str(policy),
            "--state-path",
            str(state_path),
            "--key-path",
            str(key_path),
        ]
    )
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert json.loads(out)["accepted"] is True


def test_policy_load_digest_prefixes(tmp_path):
    """(2382,73) NumberReplacer#62/#63 + (2383,45) NumberReplacer#64/#65:
    the mismatch error shows the first 16 hex chars of each digest."""
    policy, computed = _policy_file(tmp_path, 1, digest="0" * 64)
    state_path, key_path = _floor_files(tmp_path)
    args = _args(
        [
            "policy",
            "load",
            str(policy),
            "--state-path",
            str(state_path),
            "--key-path",
            str(key_path),
        ]
    )
    code, _out, err = _run_captured(args)
    assert code == EXIT_ERROR
    assert "stored " + "0" * 16 + "..." in err
    assert "computed " + computed[:16] + "..." in err


def test_policy_load_rejected_returns_incomplete(tmp_path):
    """(2397,11) AddNot#164 + (2403,23) ZeroIterationForLoop#18: loading
    a policy below the persisted floor is rejected with its reasons
    listed."""
    state_path, key_path = _floor_files(tmp_path)
    rev1, _c = _policy_file(tmp_path, 1)
    args = _args(
        [
            "policy",
            "load",
            str(rev1),
            "--state-path",
            str(state_path),
            "--key-path",
            str(key_path),
        ]
    )
    code, _out, _err = _run_captured(args)
    assert code == EXIT_OK
    rev0, _c = _policy_file(tmp_path, 0)
    args = _args(
        [
            "policy",
            "load",
            str(rev0),
            "--state-path",
            str(state_path),
            "--key-path",
            str(key_path),
        ]
    )
    code, _out, err = _run_captured(args)
    assert code == EXIT_INCOMPLETE
    assert "  - " in err


def test_policy_check_missing_file_returns_error(tmp_path):
    """(2422,42) ExceptionReplacer#26: check with a missing policy file
    is reported as a read failure, not raised."""
    state_path, key_path = _floor_files(tmp_path)
    args = _args(
        [
            "policy",
            "check",
            str(tmp_path / "missing.json"),
            "--state-path",
            str(state_path),
            "--key-path",
            str(key_path),
        ]
    )
    code, _out, err = _run_captured(args)
    assert code == EXIT_ERROR
    assert "failed to read policy file" in err


def test_policy_check_rejected_valid_false(tmp_path):
    """(2449,41) Eq_GtE#74: checking a policy below the persisted floor
    reports valid False."""
    state_path, key_path = _floor_files(tmp_path)
    rev1, _c = _policy_file(tmp_path, 1)
    args = _args(
        [
            "policy",
            "load",
            str(rev1),
            "--state-path",
            str(state_path),
            "--key-path",
            str(key_path),
        ]
    )
    code, _out, _err = _run_captured(args)
    assert code == EXIT_OK
    rev0, _c = _policy_file(tmp_path, 0)
    args = _args(
        [
            "policy",
            "check",
            str(rev0),
            "--state-path",
            str(state_path),
            "--key-path",
            str(key_path),
        ]
    )
    code, out, _err = _run_captured(args)
    assert code == EXIT_INCOMPLETE
    assert json.loads(out)["valid"] is False


def test_policy_advance_neighbor_returns_error(tmp_path):
    """(2462,29) Eq_LtE#75: a policy_command sorting below "advance"
    must not run the advance branch."""
    policy, _computed = _policy_file(tmp_path, 1)
    state_path, key_path = _floor_files(tmp_path)
    args = _args(
        [
            "policy",
            "advance",
            str(policy),
            "--state-path",
            str(state_path),
            "--key-path",
            str(key_path),
        ]
    )
    args.policy_command = "advanc"
    code, out, _err = _run_captured(args)
    assert code == EXIT_ERROR
    assert out == ""


def test_policy_advance_missing_file_returns_error(tmp_path):
    """(2465,38) ExceptionReplacer#28: advance with a missing policy
    file is reported as a read failure, not raised."""
    state_path, key_path = _floor_files(tmp_path)
    args = _args(
        [
            "policy",
            "advance",
            str(tmp_path / "missing.json"),
            "--state-path",
            str(state_path),
            "--key-path",
            str(key_path),
        ]
    )
    code, _out, err = _run_captured(args)
    assert code == EXIT_ERROR
    assert "failed to read policy file" in err


def test_policy_advance_schema_errors_listed(tmp_path):
    """(2473,23) ZeroIterationForLoop#19: an advance of a schema-invalid
    policy lists its errors on stderr."""
    bad = _write_json(tmp_path / "bad.json", {})
    state_path, key_path = _floor_files(tmp_path)
    args = _args(
        [
            "policy",
            "advance",
            str(bad),
            "--state-path",
            str(state_path),
            "--key-path",
            str(key_path),
        ]
    )
    code, _out, err = _run_captured(args)
    assert code == EXIT_INCOMPLETE
    assert "  - " in err


def test_policy_advance_digest_mismatch_low(tmp_path):
    """(2487,61) NotEq_Eq#8 + NotEq_Gt#8 + NotEq_GtE#8 + NotEq_Is#5: a
    stored digest below the computed one is a mismatch on advance."""
    policy, computed = _policy_file(tmp_path, 1, digest="0" * 64)
    assert "0" * 64 < computed < "f" * 64
    state_path, key_path = _floor_files(tmp_path)
    args = _args(
        [
            "policy",
            "advance",
            str(policy),
            "--state-path",
            str(state_path),
            "--key-path",
            str(key_path),
        ]
    )
    code, _out, err = _run_captured(args)
    assert code == EXIT_ERROR
    assert "digest mismatch" in err


def test_policy_advance_digest_mismatch_high(tmp_path):
    """(2487,61) NotEq_Eq#8 + NotEq_Lt#8 + NotEq_LtE#8 + NotEq_Is#5: a
    stored digest above the computed one is a mismatch on advance."""
    policy, computed = _policy_file(tmp_path, 1, digest="f" * 64)
    assert "0" * 64 < computed < "f" * 64
    state_path, key_path = _floor_files(tmp_path)
    args = _args(
        [
            "policy",
            "advance",
            str(policy),
            "--state-path",
            str(state_path),
            "--key-path",
            str(key_path),
        ]
    )
    code, _out, err = _run_captured(args)
    assert code == EXIT_ERROR
    assert "digest mismatch" in err


def test_policy_advance_digest_match_accepted(tmp_path):
    """(2487,61) NotEq_IsNot#5 + (2512,24) ReplaceTrueWithFalse#30: a
    matching digest advances and reports advanced True."""
    policy, _computed = _policy_file(tmp_path, 1)
    state_path, key_path = _floor_files(tmp_path)
    args = _args(
        [
            "policy",
            "advance",
            str(policy),
            "--state-path",
            str(state_path),
            "--key-path",
            str(key_path),
        ]
    )
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert json.loads(out)["advanced"] is True


def test_policy_advance_digest_prefixes(tmp_path):
    """(2489,73) NumberReplacer#68/#69 + (2490,45) NumberReplacer#70/#71:
    the advance mismatch error shows the first 16 hex chars of each
    digest."""
    policy, computed = _policy_file(tmp_path, 1, digest="0" * 64)
    state_path, key_path = _floor_files(tmp_path)
    args = _args(
        [
            "policy",
            "advance",
            str(policy),
            "--state-path",
            str(state_path),
            "--key-path",
            str(key_path),
        ]
    )
    code, _out, err = _run_captured(args)
    assert code == EXIT_ERROR
    assert "stored " + "0" * 16 + "..." in err
    assert "computed " + computed[:16] + "..." in err


def test_policy_advance_rejected_lists_reasons(tmp_path):
    """(2507,23) ZeroIterationForLoop#20: advancing a policy below the
    persisted floor is rejected with its reasons listed."""
    state_path, key_path = _floor_files(tmp_path)
    rev1, _c = _policy_file(tmp_path, 1)
    args = _args(
        [
            "policy",
            "load",
            str(rev1),
            "--state-path",
            str(state_path),
            "--key-path",
            str(key_path),
        ]
    )
    code, _out, _err = _run_captured(args)
    assert code == EXIT_OK
    rev0, _c = _policy_file(tmp_path, 0)
    args = _args(
        [
            "policy",
            "advance",
            str(rev0),
            "--state-path",
            str(state_path),
            "--key-path",
            str(key_path),
        ]
    )
    code, _out, err = _run_captured(args)
    assert code == EXIT_INCOMPLETE
    assert "  - " in err


def test_policy_export_neighbor_returns_error(tmp_path):
    """(2521,29) Eq_GtE#76 + Eq_LtE#76: a policy_command sorting either
    side of "export" must not run the export branch."""
    for neighbour in ("expor", "export0"):
        state_path, key_path = _floor_files(tmp_path)
        args = _args(
            [
                "policy",
                "export",
                "--state-path",
                str(state_path),
                "--key-path",
                str(key_path),
            ]
        )
        args.policy_command = neighbour
        code, out, _err = _run_captured(args)
        assert code == EXIT_ERROR
        assert out == ""
