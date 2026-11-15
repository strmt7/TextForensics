"""Kill tests for the W5 mutation proof: ``textforensics.cli`` survivors.

Every test names the surviving mutant(s) it kills, by the inventory
``(start_pos, operator, occurrence)`` triple.  The tests call ``_run``
(or ``build_parser``) directly with real ``argparse`` Namespaces;
neighbouring command strings are set on a parsed Namespace, which is
how a dispatch mutant is reached without going through ``argparse``'s
``choices`` validation.

Equivalents (no kill test; reasons live in
``hidden_files/audit-w5-f-equiv-reasons-cli.json``) include the scan
deterministic strip (an ``AnalysisResult`` payload never carries the
``detector_results``/``detector_failures`` keys the strip removes), the
six ``getattr(args, "rich", False)`` defaults (the parser always sets
``--rich`` for those subcommands and ``main`` is the only ``_run``
caller), the anomalies ``allow_nan=False`` (the payload is finite by
construction), the ``len(...) == 0`` ``LtE`` mutant (a length is never
negative), the drift-report ``or``/``and`` mutants (``compare_snapshots``
never produces the ``trust_map``/``detector_health`` keys), the
``EvidenceTier`` ``==``/``is`` mutant (plain Enum), the ledger ``is``/
``==`` mutant (``get`` returns the identical stored object or ``None``),
and the register ``issues or not effective`` mutant (the two predicates
coincide on every CLI-registerable claim).
"""

from __future__ import annotations

import contextlib
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
    build_parser,
)
from textforensics.config import Settings

FORMULAIC = (
    "I ran this test yesterday. The first result looked odd, so I changed "
    "one cable, repeated it, and wrote down the second result."
)

BUILTIN_ID = "textforensics/builtin-heuristic"


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


def _dataset_jsonl(tmp_path: Path, name: str = "dataset.jsonl") -> Path:
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
    path = tmp_path / name
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return path


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


# ---------------------------------------------------------------------------
# build_parser: required subcommands / options
# ---------------------------------------------------------------------------


def test_top_level_command_is_required():
    """(454,20) ReplaceTrueWithFalse#2: no command at all must fail."""
    with pytest.raises(SystemExit):
        _args([])


def test_schema_subcommand_is_required():
    """(667,20) ReplaceTrueWithFalse#5: ``schema`` with no subcommand
    must fail."""
    with pytest.raises(SystemExit):
        _args(["schema"])


def test_case_subcommand_is_required():
    """(714,20) ReplaceTrueWithFalse#7: ``case`` with no subcommand
    must fail."""
    with pytest.raises(SystemExit):
        _args(["case"])


def test_bundle_subcommand_is_required():
    """(806,20) ReplaceTrueWithFalse#10: ``bundle`` with no subcommand
    must fail."""
    with pytest.raises(SystemExit):
        _args(["bundle"])


def test_drift_subcommand_is_required():
    """(877,20) ReplaceTrueWithFalse#11: ``drift`` with no subcommand
    must fail."""
    with pytest.raises(SystemExit):
        _args(["drift"])


def test_capability_subcommand_is_required():
    """(1010,20) ReplaceTrueWithFalse#16: ``capability`` with no
    subcommand must fail."""
    with pytest.raises(SystemExit):
        _args(["capability"])


def test_policy_subcommand_is_required():
    """(1096,20) ReplaceTrueWithFalse#17: ``policy`` with no subcommand
    must fail."""
    with pytest.raises(SystemExit):
        _args(["policy"])


def test_emergency_subcommand_is_required():
    """(1180,20) ReplaceTrueWithFalse#18: ``emergency`` with no
    subcommand must fail."""
    with pytest.raises(SystemExit):
        _args(["emergency"])


def test_fingerprint_name_is_required():
    """(610,20) ReplaceTrueWithFalse#3: ``fingerprint`` without --name
    must fail."""
    with pytest.raises(SystemExit):
        _args(["fingerprint", "dataset.jsonl"])


def test_schema_validate_type_is_required():
    """(681,20) ReplaceTrueWithFalse#6: ``schema validate`` without
    --type must fail."""
    with pytest.raises(SystemExit):
        _args(["schema", "validate", "file.json"])


def test_case_export_output_is_required():
    """(721,20) ReplaceTrueWithFalse#8: ``case export`` without --output
    must fail."""
    with pytest.raises(SystemExit):
        _args(["case", "export", "--file", "x.txt"])


def test_case_keygen_output_is_required():
    """(792,20) ReplaceTrueWithFalse#9: ``case keygen`` without --output
    must fail."""
    with pytest.raises(SystemExit):
        _args(["case", "keygen"])


def test_drift_run_manifest_is_required():
    """(931,20) ReplaceTrueWithFalse#12: ``drift run`` without
    --manifest must fail (the other required options are present)."""
    with pytest.raises(SystemExit):
        _args(["drift", "run", "--texts", "texts.jsonl", "--holdback", "hold.jsonl"])


def test_drift_run_texts_is_required():
    """(936,20) ReplaceTrueWithFalse#13: ``drift run`` without --texts
    must fail (the other required options are present)."""
    with pytest.raises(SystemExit):
        _args(["drift", "run", "--manifest", "m.json", "--holdback", "hold.jsonl"])


def test_drift_run_holdback_is_required():
    """(941,20) ReplaceTrueWithFalse#14: ``drift run`` without
    --holdback must fail (the other required options are present)."""
    with pytest.raises(SystemExit):
        _args(["drift", "run", "--manifest", "m.json", "--texts", "texts.jsonl"])


def test_drift_status_detector_id_is_required():
    """(992,20) ReplaceTrueWithFalse#15: ``drift status`` without
    --detector-id must fail."""
    with pytest.raises(SystemExit):
        _args(["drift", "status"])


# ---------------------------------------------------------------------------
# build_parser: defaults
# ---------------------------------------------------------------------------


def test_localize_sentences_default_is_four():
    """(529,30) NumberReplacer#18/#19: ``localize`` --sentences defaults
    to 4."""
    args = _args(["localize", "segments", "--file", "x.txt"])
    assert args.sentences == 4


def test_localize_threshold_default_is_two():
    """(549,30) NumberReplacer#20/#21: ``localize`` --threshold defaults
    to 2.0."""
    args = _args(["localize", "anomalies", "--file", "x.txt"])
    assert args.threshold == 2.0


def test_calibrate_target_fpr_default_is_one_percent():
    """(576,30) NumberReplacer#22/#23: ``calibrate`` --target-fpr
    defaults to 0.01."""
    args = _args(["calibrate", "dataset.jsonl"])
    assert args.target_fpr == 0.01


def test_fingerprint_strict_default_is_true():
    """(614,30) ReplaceTrueWithFalse#4: ``fingerprint`` --strict
    defaults to True."""
    args = _args(["fingerprint", "dataset.jsonl", "--name", "x"])
    assert args.strict is True


def test_select_threshold_target_fpr_default_is_one_percent():
    """(637,30) NumberReplacer#24/#25: ``select-threshold``
    --target-fpr defaults to 0.01."""
    args = _args(["select-threshold", "dataset.jsonl"])
    assert args.target_fpr == 0.01


# ---------------------------------------------------------------------------
# Emergency-stop gate
# ---------------------------------------------------------------------------


def test_emergency_stop_gate_blocks_later_command(tmp_path, monkeypatch):
    """(1602,20) NotEq_Lt#6 + NotEq_LtE#6: with the stop active, a
    command sorting ABOVE "emergency" ("scan") must still be blocked.
    Both mutants say "scan" is below/equal to "emergency" and let it
    through."""
    sentinel = tmp_path / "stop"
    sentinel.write_text("", encoding="utf-8")
    monkeypatch.setenv("TEXTFORENSICS_EMERGENCY_STOP", str(sentinel))
    args = _args(["scan", "--json"])
    code, _out, err = _run_captured(args, stdin_text=FORMULAIC)
    assert code == EXIT_ERROR
    assert "emergency stop is active" in err


def test_emergency_stop_gate_allows_emergency_itself(tmp_path, monkeypatch):
    """(1602,20) NotEq_LtE#6: with the stop active, the "emergency"
    command itself must NOT be blocked — the LtE mutant blocks it
    ("emergency" <= "emergency")."""
    sentinel = tmp_path / "stop"
    sentinel.write_text("", encoding="utf-8")
    monkeypatch.setenv("TEXTFORENSICS_EMERGENCY_STOP", str(sentinel))
    args = _args(["emergency", "status"])
    code, _out, err = _run_captured(args)
    assert code == EXIT_OK
    assert "emergency stop is active" not in err


# ---------------------------------------------------------------------------
# Audit anchor dispatch
# ---------------------------------------------------------------------------


def test_audit_export_writes_anchor(tmp_path):
    """(1637,22) AddNot#85: ``audit export`` must run the anchor export
    (write the anchor file, print the path, EXIT_OK). The mutant skips
    the anchor branch and runs a naturalness audit instead, so no
    anchor file is written."""
    out_path = tmp_path / "anchor.json"
    args = _args(["audit", "export", str(out_path)])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert out.strip() == str(out_path)
    assert out_path.exists()
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert "schema_version" in payload
    assert "detector_versions" in payload


def test_audit_without_anchor_runs_naturalness_audit():
    """(1637,22) AddNot#85 (twin direction): a plain ``audit`` (no
    anchor subcommand) must run the naturalness audit and emit JSON.
    The mutant routes it into the anchor handler, which returns None
    and emits nothing."""
    args = _args(["audit", "--text", FORMULAIC])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    payload = json.loads(out)
    # The naturalness audit returns a list of issue dicts.
    assert isinstance(payload, list)


# ---------------------------------------------------------------------------
# Localize
# ---------------------------------------------------------------------------


def test_localize_diff_rich_prints_rich_table(tmp_path):
    """(1667,22) AddNot#90: ``localize diff --rich`` prints the Rich
    diff table (titled " Diff: Original → Modified "); without --rich
    it prints the plain visual diff, which carries no such title."""
    f1, f2, _f3 = _localize_files(tmp_path)
    args = _args(["localize", "diff", str(f1), str(f2), "--rich"])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert " Diff: Original → Modified" in out
    args = _args(["localize", "diff", str(f1), str(f2)])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert " Diff: Original → Modified" not in out


def test_localize_segments_zero_sentences_rejected(tmp_path):
    """(1696,30) NumberReplacer#51: ``localize segments --sentences 0``
    must raise (the guard is < 1, not < 0)."""
    _f1, _f2, f3 = _localize_files(tmp_path)
    args = _args(["localize", "segments", "--file", str(f3), "--sentences", "0"])
    with pytest.raises(ValueError, match="--sentences must be at least 1"):
        _run_captured(args)


# ---------------------------------------------------------------------------
# Compare / verify-ledger
# ---------------------------------------------------------------------------


def test_compare_without_json_prints_result_repr(tmp_path):
    """(1714,22) AddNot#95: ``compare`` without --json prints the
    ComparisonResult repr; with --json it writes JSON."""
    f1 = _write_text(tmp_path / "before.txt", "The cat sat on the mat. It was warm.")
    f2 = _write_text(tmp_path / "after.txt", "The cat sat on the rug. It was cold.")
    args = _args(["compare", str(f1), str(f2)])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert out.startswith("ComparisonResult(")
    args = _args(["compare", "--json", str(f1), str(f2)])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert isinstance(json.loads(out)["similarity"], float)


def test_verify_ledger_valid_returns_ok(tmp_path):
    """(1725,22) AddNot#96: ``verify-ledger`` on a valid ledger returns
    EXIT_OK; on a missing ledger it returns EXIT_INCOMPLETE."""
    from textforensics.ledger import snapshot_file

    text_file = _write_text(tmp_path / "text.txt", FORMULAIC)
    ledger_path = tmp_path / "ledger.jsonl"
    snapshot_file(str(text_file), str(ledger_path))
    args = _args(["verify-ledger", str(ledger_path)])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert json.loads(out)["valid"] is True
    args = _args(["verify-ledger", str(tmp_path / "missing.jsonl")])
    code, out, _err = _run_captured(args)
    assert code == EXIT_INCOMPLETE
    assert json.loads(out)["valid"] is False


# ---------------------------------------------------------------------------
# Benchmark calibration fingerprint
# ---------------------------------------------------------------------------


def test_benchmark_calibration_fingerprint_mismatch_rejected(tmp_path):
    """(1747,20) NotEq_Gt#7: ``benchmark --calibration-dataset`` with a
    calibration artifact whose fingerprint does not match the dataset
    must raise. The tampered fingerprint is "0"*64, the smallest hex
    string, so it is strictly less than the dataset's real sha256 and
    the ``>`` mutant does not raise (the original ``!=`` does)."""
    from textforensics.benchmark import calibrate_threshold_jsonl

    cal = _dataset_jsonl(tmp_path, "cal.jsonl")
    evl = _dataset_jsonl(tmp_path, "eval.jsonl")
    artifact = calibrate_threshold_jsonl(str(cal))
    artifact["calibration_dataset_sha256"] = "0" * 64
    artifact_path = _write_json(tmp_path / "artifact.json", artifact)
    args = _args(
        [
            "benchmark",
            str(evl),
            "--calibration-dataset",
            str(cal),
            "--calibration",
            str(artifact_path),
        ]
    )
    with pytest.raises(ValueError, match="fingerprint does not match"):
        _run_captured(args)


# ---------------------------------------------------------------------------
# Select-threshold / detectors / report
# ---------------------------------------------------------------------------


def test_select_threshold_output_writes_artifact(tmp_path):
    """(1817,22) AddNot#102: ``select-threshold --output`` writes the
    artifact file and prints its path; without --output it writes the
    result JSON to stdout."""
    dataset = _dataset_jsonl(tmp_path)
    out_path = tmp_path / "threshold.json"
    args = _args(["select-threshold", str(dataset), "--output", str(out_path)])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert out.strip() == str(out_path)
    assert out_path.exists()
    assert isinstance(json.loads(out_path.read_text(encoding="utf-8"))["threshold"], float)
    args = _args(["select-threshold", str(dataset)])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert isinstance(json.loads(out)["threshold"], float)


def test_detectors_health_flag_controls_plugin_health():
    """(1826,22) AddNot#103: ``detectors`` without --health reports an
    empty plugin_health list; with --health it reports the live
    detector health (one row: the builtin detector)."""
    args = _args(["detectors"])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert json.loads(out)["plugin_health"] == []
    args = _args(["detectors", "--health"])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    health = json.loads(out)["plugin_health"]
    assert len(health) == 1
    assert health[0]["detector_id"] == BUILTIN_ID


def test_detectors_rich_prints_health_table():
    """(1829,22) AddNot#104: ``detectors --rich`` prints the Rich
    "Detector Health" table; without --rich the output is pure JSON."""
    args = _args(["detectors", "--health", "--rich"])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert "Detector Health" in out
    args = _args(["detectors", "--health"])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert json.loads(out)["plugin_health"][0]["detector_id"] == BUILTIN_ID


def test_report_rich_prints_summary_panel():
    """(1883,22) AddNot#110: ``report --rich`` prints the Rich
    "Forensic Report Summary" panel; without --rich the output is
    pure JSON."""
    args = _args(["report", "--text", FORMULAIC, "--rich"])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert "Forensic Report Summary" in out
    args = _args(["report", "--text", FORMULAIC])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert json.loads(out)["schema"].startswith("textforensics.forensic-bundle/")


# ---------------------------------------------------------------------------
# Web
# ---------------------------------------------------------------------------


def test_web_no_browser_flag_reaches_serve_web(monkeypatch):
    """(1990,25) Delete_Not#15: ``web --no-browser`` must reach
    serve_web as open_browser=False; plain ``web`` as True."""
    calls = []
    monkeypatch.setattr(
        "textforensics.web_ui.main.serve_web",
        lambda *a, **k: calls.append((a, k)),
    )
    args = _args(["web", "--no-browser"])
    code, _out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert len(calls) == 1
    assert calls[0][1]["open_browser"] is False
    calls.clear()
    args = _args(["web"])
    code, _out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert len(calls) == 1
    assert calls[0][1]["open_browser"] is True


# ---------------------------------------------------------------------------
# Drift report rich block
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


def _drift_report_args(tmp_path, baseline, current, corpus, *, rich: bool):
    out_path = tmp_path / "report.json"
    argv = [
        "drift",
        "report",
        str(baseline),
        str(current),
        "--corpus",
        str(corpus),
        "--output",
        str(out_path),
    ]
    if rich:
        argv.append("--rich")
    return _args(argv)


def test_drift_report_rich_branch_entered(tmp_path, monkeypatch):
    """(2048,22) AddNot#128 + Eq_Gt#48 + Eq_Lt#48 + Eq_NotEq#48 and
    (2048,24) ReplaceAndWithOr#16: ``drift report --rich`` must enter
    the rich branch. With Rich patched away the branch prints the
    'Rich is not installed' warning; without --rich it must not. The
    condition mutants skip the branch (no warning with --rich) and the
    ``or`` mutant enters it without --rich (warning without --rich)."""
    baseline, current, corpus = _snapshot_pair(tmp_path)
    monkeypatch.setattr("textforensics.rich_output.HAS_RICH", False)
    args = _drift_report_args(tmp_path, baseline, current, corpus, rich=True)
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert "Warning: Rich is not installed" in out
    args = _drift_report_args(tmp_path, baseline, current, corpus, rich=False)
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert "Warning: Rich is not installed" not in out


def test_drift_report_rich_neighbor_commands(tmp_path, monkeypatch):
    """(2048,22) Eq_GtE#48 + Eq_LtE#48: neighbour drift_command strings
    must not enter the rich branch. "ru" sorts above "report" (kills
    the ``>=`` mutant) and "repor" sorts below it (kills the ``<=``
    mutant); both are caught by the same HAS_RICH warning probe."""
    baseline, current, corpus = _snapshot_pair(tmp_path)
    monkeypatch.setattr("textforensics.rich_output.HAS_RICH", False)
    for neighbour in ("ru", "repor"):
        args = _drift_report_args(tmp_path, baseline, current, corpus, rich=True)
        args.drift_command = neighbour
        code, out, _err = _run_captured(args)
        assert code == EXIT_OK
        assert "Warning: Rich is not installed" not in out


def test_drift_report_rich_printers_not_called_without_data(tmp_path, monkeypatch):
    """(2055,22) AddNot#130 + (2059,22) AddNot#131: ``drift report
    --rich`` must NOT call print_trust_map / print_detector_health,
    because compare_snapshots never produces those keys. The mutants
    call them with None; the spies record the call."""
    baseline, current, corpus = _snapshot_pair(tmp_path)
    trust_calls = []
    health_calls = []
    monkeypatch.setattr(
        "textforensics.rich_output.print_trust_map",
        lambda *a, **k: trust_calls.append((a, k)),
    )
    monkeypatch.setattr(
        "textforensics.rich_output.print_detector_health",
        lambda *a, **k: health_calls.append((a, k)),
    )
    args = _drift_report_args(tmp_path, baseline, current, corpus, rich=True)
    code, _out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert trust_calls == []
    assert health_calls == []


# ---------------------------------------------------------------------------
# Capability policy
# ---------------------------------------------------------------------------


def _ledger_file(tmp_path: Path, claims) -> Path:
    """Write a capability ledger JSON from CapabilityClaim objects."""
    from textforensics.policy import CapabilityLedger

    ledger = CapabilityLedger()
    for claim in claims:
        ledger.register(claim)
    return _write_json(tmp_path / "ledger.json", ledger.to_dict())


def _claim(detector_id, capability, tier, label, *, valid_until="2099-01-01"):
    from textforensics.policy import CapabilityClaim, EvidenceLabel, EvidenceRef, EvidenceTier

    return CapabilityClaim(
        detector_id=detector_id,
        capability=capability,
        tier=EvidenceTier[tier],
        evidence=[
            EvidenceRef(
                label=EvidenceLabel[label],
                tier=EvidenceTier[tier],
                artifact="bench/run.json",
                detail="test evidence",
            )
        ],
        valid_until=valid_until,
    )


def test_capability_policy_status_labels_pass_and_fail(tmp_path):
    """(2197,31) AddNot#140: the non-JSON policy output labels a
    passing rule "[PASS]" and a failing rule with its rule id in
    upper case. The ledger holds a VALIDATED+EXECUTED
    language_coverage claim (prod-language-coverage passes) and no
    length_robustness claim (prod-length-robustness fails)."""
    ledger = _ledger_file(tmp_path, [_claim("det-a", "language_coverage", "VALIDATED", "EXECUTED")])
    args = _args(
        ["capability", "policy", "det-a", "--ledger", str(ledger), "--policy", "production"]
    )
    code, out, _err = _run_captured(args)
    assert code == EXIT_INCOMPLETE
    assert "  [PASS]" in out
    assert "  [PROD-LENGTH-ROBUSTNESS]" in out


# ---------------------------------------------------------------------------
# Bundle check
# ---------------------------------------------------------------------------


AI_LIKE_TEXT = (
    "Furthermore, it is important to note that the comprehensive analysis "
    "demonstrates significant implications for future research directions. "
    "In conclusion, the aforementioned framework provides a robust "
    "foundation for leveraging synergistic paradigms in modern contexts. "
    "Moreover, the intricate interplay of various factors underscores the "
    "paramount importance of a holistic approach."
)


def _export_case(tmp_path: Path, text: str = FORMULAIC) -> Path:
    out_path = tmp_path / "case.json"
    args = _args(["case", "export", "--output", str(out_path), "--text", text])
    code, _out, _err = _run_captured(args)
    assert code == EXIT_OK
    return out_path


def _bundle_files(tmp_path: Path, text: str = FORMULAIC):
    """A case file and the bundle packed from it."""
    from textforensics.bundle import pack_bundle

    case_file = _export_case(tmp_path, text)
    bundle_path = tmp_path / "bundle.zip"
    pack_bundle(str(case_file), str(bundle_path))
    return case_file, bundle_path


def _inconsistent_bundle(tmp_path: Path) -> Path:
    """A forensic-bundle JSON whose word_count is negative, so
    check_bundle_consistency reports an issue."""
    bundle_path = tmp_path / "bundle.json"
    args = _args(["report", "--text", FORMULAIC, "--output", str(bundle_path)])
    code, _out, _err = _run_captured(args)
    assert code == EXIT_OK
    payload = json.loads(bundle_path.read_text(encoding="utf-8"))
    payload["input"]["word_count"] = -5
    bundle_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return bundle_path


def test_bundle_check_text_output(tmp_path):
    """(2236,22) AddNot#144 + (2239,22) AddNot#145 + (2240,22)
    AddNot#146 + (2241,22) ZeroIterationForLoop#16 + (2245,22)
    AddNot#147: ``bundle check`` on a consistent bundle with no issues
    prints "Bundle consistency: PASS" and "No issues found." and
    returns EXIT_OK; on a consistent bundle WITH a warning issue it
    prints the issue line instead; on an inconsistent bundle it prints
    FAIL, the issue line, and returns EXIT_INCOMPLETE."""
    # Consistent, zero issues: the AI-like text scores with high
    # reliability, so check_bundle_consistency reports no issues.
    _case_file, bundle = _bundle_files(tmp_path, AI_LIKE_TEXT)
    args = _args(["bundle", "check", str(bundle)])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert "Bundle consistency: PASS" in out
    assert "  No issues found." in out
    args = _args(["bundle", "check", str(bundle), "--json"])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert json.loads(out)["is_consistent"] is True
    # Consistent, one warning issue: the FORMULAIC text triggers the
    # low-reliability warning, so the issue line is printed and "No
    # issues found." is not.
    _case_file, warn_bundle = _bundle_files(tmp_path, FORMULAIC)
    args = _args(["bundle", "check", str(warn_bundle)])
    code, out, _err = _run_captured(args)
    assert code == EXIT_OK
    assert "Bundle consistency: PASS" in out
    assert "[WARNING] detector_results[0].reliability" in out
    assert "No issues found." not in out
    # Inconsistent: a negative word_count is flagged.
    bad = _inconsistent_bundle(tmp_path)
    args = _args(["bundle", "check", str(bad)])
    code, out, _err = _run_captured(args)
    assert code == EXIT_INCOMPLETE
    assert "Bundle consistency: FAIL" in out
    assert "word_count" in out
