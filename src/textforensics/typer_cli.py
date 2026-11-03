"""Typer-based CLI for TextForensics — optional alternative to argparse CLI.

Install with: pip install textforensics[cli-typer]
Run with: textforensics-typer
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Literal

import typer

from .config import Settings, read_text_file, validate_text_input
from .constants import EXIT_ERROR, EXIT_INCOMPLETE, EXIT_OK
from .version import get_version

app = typer.Typer(
    name="textforensics-typer",
    help="Audit AI-text detector evidence and reliability locally.",
    add_completion=False,
    invoke_without_command=True,
)

# Sub-commands groups
scan_app = typer.Typer(help="Run AI-text detection and analysis.")
case_app = typer.Typer(help="Export or verify sealed case files.")
bundle_app = typer.Typer(help="Pack, verify, and list forensic bundles.")
drift_app = typer.Typer(help="Longitudinal detector reliability tracking.")
capability_app = typer.Typer(help="Manage detector capability claims.")
verify_app = typer.Typer(help="N-version integrity verification.")
localize_app = typer.Typer(help="Diagnostic localization, diffs, anomaly detection.")
benchmark_app = typer.Typer(help="Benchmark evaluation and calibration.")
schema_app = typer.Typer(help="Validate and inspect JSON schemas.")

app.add_typer(scan_app, name="scan")
app.add_typer(case_app, name="case")
app.add_typer(bundle_app, name="bundle")
app.add_typer(drift_app, name="drift")
app.add_typer(capability_app, name="capability")
app.add_typer(verify_app, name="verify")
app.add_typer(localize_app, name="localize")
app.add_typer(benchmark_app, name="benchmark")
app.add_typer(schema_app, name="schema")


def _read_text_from_input(text: str | None, file: Path | None) -> str:
    """Read text from --file, --text, or stdin."""
    if file:
        return read_text_file(str(file), max_input_bytes=Settings.from_env().max_input_bytes)
    if text:
        return text
    if sys.stdin.isatty():
        raise typer.BadParameter("Provide --file or --text, or pipe text through stdin.")
    raw = sys.stdin.read(Settings.from_env().max_input_bytes + 1)
    return validate_text_input(raw, max_input_bytes=Settings.from_env().max_input_bytes)


def _write_json(path: str | None, payload: Any) -> None:
    rendered = json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False)
    if path:
        Path(path).write_text(rendered + "\n", encoding="utf-8")
        typer.echo(path)
    else:
        typer.echo(rendered)


def _strip_runtime_ms(data: dict) -> dict:
    """Remove runtime_ms from all detector results."""
    if "detector_results" in data and isinstance(data["detector_results"], list):
        for result in data["detector_results"]:
            if isinstance(result, dict):
                result.pop("runtime_ms", None)
    if "detector_failures" in data and isinstance(data["detector_failures"], list):
        for failure in data["detector_failures"]:
            if isinstance(failure, dict):
                failure.pop("runtime_ms", None)
    return data


@app.callback()
def version_callback(
    ctx: typer.Context, version: bool = typer.Option(False, "--version", "-V", help="Show version.")
):
    if version:
        typer.echo(f"textforensics {get_version()}")
        ctx.exit(0)


@scan_app.command()
def analyze(
    text: str | None = typer.Option(None, "--text", "-t", help="Input text to analyze."),
    file: Path | None = typer.Option(None, "--file", "-f", help="Path to text file to analyze."),
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
    rich: bool = typer.Option(False, "--rich", help="Use Rich-formatted terminal output."),
    deterministic: bool = typer.Option(
        False, "--deterministic", help="Use fixed timestamp for reproducible output."
    ),
    fixed_timestamp: str | None = typer.Option(
        None, "--fixed-timestamp", help="Fixed ISO timestamp."
    ),
):
    """Run the local alpha pattern baseline analysis on text."""
    try:
        from .engine import analyze_text

        result = analyze_text(_read_text_from_input(text, file))
        if json or deterministic:
            data = result.to_dict()
            if deterministic:
                data = _strip_runtime_ms(data)
            _write_json(None, data)
        elif rich:
            try:
                from .rich_output import HAS_RICH, print_scan_results

                if HAS_RICH:
                    print_scan_results(result)
                else:
                    data = result.to_dict()
                    _write_json(None, data)
            except ImportError:
                data = result.to_dict()
                _write_json(None, data)
        else:
            data = result.to_dict()
            _write_json(None, data)
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@app.command()
def report(
    text: str | None = typer.Option(None, "--text", "-t", help="Input text."),
    file: Path | None = typer.Option(None, "--file", "-f", help="Path to text file."),
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
    rich: bool = typer.Option(False, "--rich", help="Use Rich-formatted terminal output."),
    ledger: Path | None = typer.Option(None, "--ledger", help="Path to a provenance ledger."),
    deterministic: bool = typer.Option(
        False, "--deterministic", help="Use fixed timestamp for reproducible output."
    ),
    fixed_timestamp: str | None = typer.Option(
        None, "--fixed-timestamp", help="Fixed ISO timestamp."
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="Path to write JSON output."),
):
    """Build a reproducible detector-evidence forensic bundle."""
    try:
        from .report import build_forensic_bundle

        bundle = build_forensic_bundle(
            _read_text_from_input(text, file),
            ledger_path=str(ledger) if ledger else None,
            deterministic=deterministic,
            fixed_timestamp=fixed_timestamp,
        )
        data = bundle.to_dict()
        if deterministic:
            data = _strip_runtime_ms(data)
        _write_json(str(output) if output else None, data)
        if rich:
            try:
                from .rich_output import HAS_RICH, print_report_summary

                if HAS_RICH:
                    print_report_summary(bundle)
            except ImportError:
                pass
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@case_app.command("export")
def case_export(
    text: str | None = typer.Option(None, "--text", "-t", help="Input text."),
    file: Path | None = typer.Option(None, "--file", "-f", help="Path to text file."),
    ledger: Path | None = typer.Option(None, "--ledger", help="Path to a provenance ledger."),
    output: Path = typer.Option(..., "--output", "-o", help="Output case file path."),
    rich: bool = typer.Option(False, "--rich", help="Use Rich-formatted terminal output."),
    deterministic: bool = typer.Option(
        False, "--deterministic", help="Use fixed timestamp for reproducible output."
    ),
    fixed_timestamp: str | None = typer.Option(
        None, "--fixed-timestamp", help="Fixed ISO timestamp."
    ),
):
    """Export a sealed case file."""
    try:
        from .casefile import write_case_file
        from .report import build_forensic_bundle

        bundle = build_forensic_bundle(
            _read_text_from_input(text, file),
            ledger_path=str(ledger) if ledger else None,
            deterministic=deterministic,
            fixed_timestamp=fixed_timestamp,
        )
        bundle_dict = bundle.to_dict()
        if deterministic:
            bundle_dict = _strip_runtime_ms(bundle_dict)
        write_case_file(
            str(output), bundle_dict, deterministic=deterministic, fixed_timestamp=fixed_timestamp
        )
        typer.echo(str(output))
        if rich:
            try:
                from .rich_output import HAS_RICH, print_case_summary

                if HAS_RICH:
                    case_data = json.loads(output.read_text(encoding="utf-8"))
                    print_case_summary(case_data)
            except ImportError:
                pass
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@case_app.command("verify")
def case_verify(
    case_file: Path = typer.Argument(..., help="Path to the sealed case file."),
    rich: bool = typer.Option(False, "--rich", help="Use Rich-formatted terminal output."),
):
    """Verify case-file integrity."""
    try:
        from .casefile import verify_case_file_path

        result = verify_case_file_path(str(case_file))
        _write_json(None, result)
        raise typer.Exit(EXIT_OK if result.get("valid") else EXIT_INCOMPLETE)
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@bundle_app.command("pack")
def bundle_pack(
    case_file: Path = typer.Argument(..., help="Path to a case file or directory."),
    output: Path = typer.Argument(..., help="Output bundle path (.tar.gz or .zip)."),
):
    """Pack a case file into a portable bundle."""
    try:
        from .bundle import pack_bundle

        manifest = pack_bundle(str(case_file), str(output))
        _write_json(None, manifest.to_dict())
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@bundle_app.command("verify")
def bundle_verify(
    bundle: Path = typer.Argument(..., help="Path to the bundle archive."),
    expected_digest: str | None = typer.Option(
        None, "--expect-digest", help="Expected SHA-256 digest."
    ),
    rich: bool = typer.Option(False, "--rich", help="Use Rich-formatted terminal output."),
):
    """Verify bundle integrity."""
    try:
        from .bundle import verify_bundle

        result = verify_bundle(str(bundle), expected_digest=expected_digest)
        _write_json(None, result.to_dict())
        raise typer.Exit(EXIT_OK if result.valid else EXIT_INCOMPLETE)
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@bundle_app.command("list")
def bundle_list(
    bundle: Path = typer.Argument(..., help="Path to the bundle archive."),
):
    """List contents of a bundle."""
    try:
        from .bundle import list_bundle

        entries = list_bundle(str(bundle))
        _write_json(None, entries)
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@bundle_app.command("check")
def bundle_check(
    bundle: Path = typer.Argument(..., help="Path to the bundle archive or JSON file."),
    json: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
):
    """Check internal consistency of a forensic bundle.

    Validates field relationships, types, and value ranges to detect
    potentially corrupted or incorrectly constructed bundles.
    """
    try:
        from .bundle import read_bundle
        from .bundle_consistency import check_bundle_consistency

        data = read_bundle(str(bundle))
        report = check_bundle_consistency(data)
        result = {
            "is_consistent": report.is_consistent,
            "issues": [
                {"field": i.field, "type": i.issue_type, "message": i.message, "severity": i.severity}
                for i in report.issues
            ],
            "checked_fields": report.checked_fields,
        }
        if json:
            _write_json(None, result)
        else:
            typer.echo(f"Bundle consistency: {'PASS' if report.is_consistent else 'FAIL'}")
            if report.issues:
                for issue in report.issues:
                    typer.echo(f"  [{issue.severity.upper()}] {issue.field}: {issue.message}")
            else:
                typer.echo("  No issues found.")
        raise typer.Exit(EXIT_OK if report.is_consistent else EXIT_INCOMPLETE)
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@drift_app.command("snapshot")
def drift_snapshot(
    corpus: Path = typer.Option(
        Path(__file__).resolve().parent.parent.parent / "testdata" / "drift_corpus.json",
        "--corpus",
        help="Path to a drift corpus JSON file.",
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write the snapshot to this JSON file."
    ),
    label: str | None = typer.Option(
        None, "--label", help="Optional human-readable snapshot label."
    ),
    allow_remote: bool = typer.Option(
        False, "--allow-remote", help="Allow remote detector adapters."
    ),
    snapshot_id: str | None = typer.Option(
        None, "--snapshot-id", help="Optional explicit snapshot ID."
    ),
    detector_ids: list[str] | None = typer.Option(
        None, "--detector-ids", help="Comma-separated detector IDs."
    ),
):
    """Take a detector snapshot for drift tracking."""
    try:
        from .drift import DriftObservatory

        observatory = DriftObservatory(corpus_path=str(corpus))
        snapshot = observatory.take_snapshot(
            allow_remote=allow_remote, snapshot_id=snapshot_id, label=label
        )
        _write_json(str(output) if output else None, snapshot)
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@drift_app.command("compare")
def drift_compare(
    baseline: Path = typer.Argument(..., help="Path to the baseline snapshot JSON."),
    current: Path = typer.Argument(..., help="Path to the current snapshot JSON."),
    corpus: Path = typer.Option(
        Path(__file__).resolve().parent.parent.parent / "testdata" / "drift_corpus.json",
        "--corpus",
        help="Path to a drift corpus JSON file.",
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write the drift report to this JSON file."
    ),
    rich: bool = typer.Option(False, "--rich", help="Use Rich-formatted terminal output."),
):
    """Compare two drift snapshots."""
    try:
        from .drift import DriftObservatory

        observatory = DriftObservatory(corpus_path=str(corpus))
        baseline_data = DriftObservatory.read_snapshot_file(str(baseline))
        current_data = DriftObservatory.read_snapshot_file(str(current))
        report_data = observatory.compare_snapshots(baseline_data, current_data)
        _write_json(str(output) if output else None, report_data)
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@drift_app.command("report")
def drift_report(
    snapshots: list[Path] = typer.Argument(..., help="Paths to snapshot JSON files."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write the drift report to this JSON file."
    ),
    corpus: Path = typer.Option(
        Path(__file__).resolve().parent.parent.parent / "testdata" / "drift_corpus.json",
        "--corpus",
        help="Path to a drift corpus JSON file.",
    ),
    rich: bool = typer.Option(False, "--rich", help="Use Rich-formatted terminal output."),
):
    """Generate a drift report from multiple snapshots."""
    try:
        from .drift import DriftObservatory

        observatory = DriftObservatory(corpus_path=str(corpus))
        reports = []
        for i, snap_path in enumerate(snapshots[:-1]):
            baseline = DriftObservatory.read_snapshot_file(str(snap_path))
            current = DriftObservatory.read_snapshot_file(str(snapshots[i + 1]))
            report_data = observatory.compare_snapshots(baseline, current)
            reports.append(report_data)
        if len(reports) == 1:
            _write_json(str(output) if output else None, reports[0])
        else:
            _write_json(str(output) if output else None, reports)
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@capability_app.command("register")
def capability_register(
    detector: str = typer.Argument(..., help="Detector ID."),
    capability: str = typer.Argument(..., help="Capability name."),
    tier: Literal["readable", "tool_backed", "validated"] = typer.Argument(
        ..., help="Evidence tier."
    ),
    artifact: str = typer.Argument(..., help="Evidence artifact path or run ID."),
    label: Literal["reported", "calculated", "proposed", "executed"] = typer.Argument(
        "executed", help="Evidence label."
    ),
    detail: str | None = typer.Option(None, "--detail", help="Optional detail about the evidence."),
    valid_until: str | None = typer.Option(
        None, "--valid-until", help="Optional expiration date (ISO format)."
    ),
    ledger: Path | None = typer.Option(
        None, "--ledger", help="Path to the capability ledger JSON file."
    ),
):
    """Register a capability claim in the ledger."""
    try:
        from .capability_ledger import (
            CapabilityClaim,
            CapabilityLedger,
            EvidenceLabel,
            EvidenceRef,
            EvidenceTier,
        )

        ledger_path = (
            ledger or Path(__file__).resolve().parent.parent.parent / "capability_ledger.json"
        )
        if ledger_path.exists():
            try:
                data = json.loads(ledger_path.read_text(encoding="utf-8"))
                ledger_obj = CapabilityLedger.from_dict(data)
            except (json.JSONDecodeError, KeyError):
                ledger_obj = CapabilityLedger()
        else:
            ledger_obj = CapabilityLedger()
        evidence_tier = EvidenceTier[tier.upper()]
        claim = CapabilityClaim(
            detector_id=detector,
            capability=capability,
            tier=evidence_tier,
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel[label.upper()],
                    tier=evidence_tier,
                    artifact=artifact,
                    detail=detail,
                )
            ],
            valid_until=valid_until,
        )
        ledger_obj.register(claim)
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
        ledger_path.write_text(
            json.dumps(ledger_obj.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        payload = {
            "detector_id": detector,
            "capability": capability,
            "tier": tier,
            "artifact": artifact,
            "registered": True,
        }
        _write_json(None, payload)
        typer.echo(f"Registered: {detector}/{capability} ({tier})")
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@capability_app.command("check")
def capability_check(
    detector: str = typer.Argument(..., help="Detector ID."),
    capability: str = typer.Argument(..., help="Capability name."),
    ledger: Path | None = typer.Option(
        None, "--ledger", help="Path to the capability ledger JSON file."
    ),
):
    """Check whether a capability claim is validated."""
    try:
        from .capability_ledger import CapabilityLedger

        ledger_path = (
            ledger or Path(__file__).resolve().parent.parent.parent / "capability_ledger.json"
        )
        if ledger_path.exists():
            try:
                data = json.loads(ledger_path.read_text(encoding="utf-8"))
                ledger_obj = CapabilityLedger.from_dict(data)
            except (json.JSONDecodeError, KeyError):
                ledger_obj = CapabilityLedger()
        else:
            ledger_obj = CapabilityLedger()
        claim = ledger_obj.enforce(detector, capability)
        validated = claim.tier.value == "validated"
        payload = {
            "detector_id": detector,
            "capability": capability,
            "tier": claim.tier.value,
            "validated": validated,
            "evidence": [
                {
                    "label": e.label.value,
                    "tier": e.tier.value,
                    "artifact": e.artifact,
                    "detail": e.detail,
                }
                for e in claim.evidence
            ],
            "valid_until": claim.valid_until,
        }
        _write_json(None, payload)
        if not validated:
            typer.echo(
                f"warning: {detector}/{capability} is {claim.tier.value}, not VALIDATED.", err=True
            )
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@capability_app.command("list")
def capability_list(
    detector: str | None = typer.Option(None, "--detector", help="Filter by detector ID."),
    ledger: Path | None = typer.Option(
        None, "--ledger", help="Path to the capability ledger JSON file."
    ),
):
    """List all registered capabilities."""
    try:
        from .capability_ledger import CapabilityLedger

        ledger_path = (
            ledger or Path(__file__).resolve().parent.parent.parent / "capability_ledger.json"
        )
        if ledger_path.exists():
            try:
                data = json.loads(ledger_path.read_text(encoding="utf-8"))
                ledger_obj = CapabilityLedger.from_dict(data)
            except (json.JSONDecodeError, KeyError):
                ledger_obj = CapabilityLedger()
        else:
            ledger_obj = CapabilityLedger()
        claims = ledger_obj.to_dict()["claims"]
        if detector:
            claims = {detector: claims.get(detector, [])}
        _write_json(None, claims)
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@capability_app.command("export")
def capability_export(
    ledger: Path | None = typer.Option(
        None, "--ledger", help="Path to the capability ledger JSON file."
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="Path to write JSON."),
):
    """Export the capability ledger as JSON."""
    try:
        from .capability_ledger import CapabilityLedger

        ledger_path = (
            ledger or Path(__file__).resolve().parent.parent.parent / "capability_ledger.json"
        )
        if ledger_path.exists():
            try:
                data = json.loads(ledger_path.read_text(encoding="utf-8"))
                ledger_obj = CapabilityLedger.from_dict(data)
            except (json.JSONDecodeError, KeyError):
                ledger_obj = CapabilityLedger()
        else:
            ledger_obj = CapabilityLedger()
        _write_json(str(output) if output else None, ledger_obj.to_dict())
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@capability_app.command("policy")
def capability_policy(
    detector: str = typer.Argument(..., help="Detector ID to check policies for."),
    ledger: Path | None = typer.Option(
        None, "--ledger", help="Path to the capability ledger JSON file."
    ),
    policy: str = typer.Option(
        "production",
        "--policy",
        "-p",
        help="Policy bundle: production, report, calibration, minimum.",
    ),
    json: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
):
    """Evaluate capability ledger policies for a detector.

    Policy bundles:
      production  - requires VALIDATED language coverage, TOOL_BACKED length/domain
      report      - requires trust map claims
      calibration - requires EXECUTED calibration evidence
      minimum     - requires READABLE documentation
    """
    try:
        from .capability_ledger import CapabilityLedger
        from .capability_policy import (
            create_calibration_policy,
            create_minimum_viable_policy,
            create_production_policy,
            create_report_generation_policy,
        )

        ledger_path = (
            ledger or Path(__file__).resolve().parent.parent.parent / "capability_ledger.json"
        )
        if ledger_path.exists():
            try:
                data = json.loads(ledger_path.read_text(encoding="utf-8"))
                ledger_obj = CapabilityLedger.from_dict(data)
            except (json.JSONDecodeError, KeyError):
                ledger_obj = CapabilityLedger()
        else:
            ledger_obj = CapabilityLedger()

        policy_map = {
            "production": create_production_policy,
            "report": create_report_generation_policy,
            "calibration": create_calibration_policy,
            "minimum": create_minimum_viable_policy,
        }
        if policy not in policy_map:
            typer.echo(f"error: unknown policy '{policy}'. Use one of: {', '.join(policy_map.keys())}", err=True)
            raise typer.Exit(EXIT_ERROR)

        engine = policy_map[policy]()
        results = engine.evaluate(ledger_obj, detector)

        if json:
            _write_json(None, [r.to_dict() for r in results])
        else:
            typer.echo(f"Policy evaluation: {policy} for {detector}")
            all_passed = True
            for result in results:
                status = "PASS" if result.passed else result.rule_id.upper()
                typer.echo(f"  [{status}] {result.message}")
                if result.missing_claims:
                    for m in result.missing_claims:
                        typer.echo(f"    MISSING: {m}")
                if result.evidence_gaps:
                    for g in result.evidence_gaps:
                        typer.echo(f"    GAP: {g}")
                if not result.passed:
                    all_passed = False

        raise typer.Exit(EXIT_OK if all_passed else EXIT_INCOMPLETE)
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@verify_app.command("case")
def verify_case(
    case_file: Path = typer.Argument(..., help="Path to a sealed case file."),
    rich: bool = typer.Option(False, "--rich", help="Use Rich-formatted terminal output."),
):
    """Verify a case file through N-version replay."""
    try:
        from .verify import verify_all

        case_payload = json.loads(case_file.read_text(encoding="utf-8"))
        report = verify_all(case_payload=case_payload)
        _write_json(None, report.to_dict())
        raise typer.Exit(EXIT_OK if report.overall_valid else EXIT_INCOMPLETE)
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@verify_app.command("all")
def verify_all_cmd(
    case_file: Path | None = typer.Option(None, "--case-file", help="Path to a sealed case file."),
    calibration_artifact: Path | None = typer.Option(
        None, "--calibration", help="Path to a calibration artifact."
    ),
    benchmark_result: Path | None = typer.Option(
        None, "--benchmark", help="Path to a benchmark result."
    ),
):
    """Run all available verifications and report."""
    try:
        from .verify import verify_all

        case_payload = None
        cal_artifact = None
        bench_result = None
        if case_file:
            case_payload = json.loads(case_file.read_text(encoding="utf-8"))
        if calibration_artifact:
            cal_artifact = json.loads(calibration_artifact.read_text(encoding="utf-8"))
        if benchmark_result:
            bench_result = json.loads(benchmark_result.read_text(encoding="utf-8"))
        if not (case_payload or cal_artifact or bench_result):
            _write_json(
                None, {"valid": False, "errors": ["No artifacts provided for verification"]}
            )
            raise typer.Exit(EXIT_ERROR)
        report = verify_all(
            case_payload=case_payload,
            calibration_artifact=cal_artifact,
            benchmark_result=bench_result,
        )
        _write_json(None, report.to_dict())
        raise typer.Exit(EXIT_OK if report.overall_valid else EXIT_INCOMPLETE)
    except SystemExit:
        raise
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@localize_app.command("diff")
def localize_diff(
    file1: Path = typer.Argument(..., help="Path to the original text file."),
    file2: Path = typer.Argument(..., help="Path to the modified text file."),
    style: Literal["side_by_side", "unified", "inline"] = typer.Option(
        "side_by_side", "--style", help="Diff rendering style."
    ),
    rich: bool = typer.Option(False, "--rich", help="Use Rich-formatted terminal output."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Path to write the diff output."
    ),
):
    """Show a diff between two text files."""
    try:
        text1 = Path(file1).read_text(encoding="utf-8")
        text2 = Path(file2).read_text(encoding="utf-8")
        if output:
            from .localize import visual_diff

            diff_text = visual_diff(text1, text2, style=style)
            output.write_text(diff_text, encoding="utf-8")
            typer.echo(str(output))
        else:
            from .localize import visual_diff

            diff_text = visual_diff(text1, text2, style=style)
            typer.echo(diff_text)
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@localize_app.command("anomalies")
def localize_anomalies(
    file: Path = typer.Argument(..., help="Path to the text file to analyze."),
    threshold: float = typer.Option(2.0, "--threshold", help="Z-score threshold."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Path to write JSON output."),
    rich: bool = typer.Option(False, "--rich", help="Use Rich-formatted terminal output."),
):
    """Detect anomalous segments in text."""
    try:
        from .localize import detect_anomalous_segments

        text = Path(file).read_text(encoding="utf-8")
        result = detect_anomalous_segments(text, threshold=threshold)
        if output:
            output.write_text(
                json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
                encoding="utf-8",
            )
            typer.echo(str(output))
        else:
            _write_json(None, result)
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@localize_app.command("segments")
def localize_segments(
    file: Path = typer.Argument(..., help="Path to the text file to segment."),
    sentences: int = typer.Option(4, "--sentences", help="Sentences per segment."),
):
    """Score consecutive text segments for diagnostic localization."""
    try:
        from .localize import localize_text, segment_to_dict

        text = Path(file).read_text(encoding="utf-8")
        if sentences < 1:
            raise typer.BadParameter("--sentences must be at least 1.")
        result = [
            segment_to_dict(row) for row in localize_text(text, sentences_per_segment=sentences)
        ]
        _write_json(None, result)
    except typer.BadParameter:
        raise
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@benchmark_app.command("jsonl")
def benchmark_jsonl(
    path: Path = typer.Argument(..., help="Path to labeled JSONL dataset."),
    threshold: float = typer.Option(0.5, "--threshold", help="Classification threshold."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Path to write results."),
):
    """Evaluate the built-in baseline on labeled JSONL."""
    try:
        from .benchmark import benchmark_jsonl as _bench

        result = _bench(str(path), threshold=threshold)
        _write_json(str(output) if output else None, result)
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@benchmark_app.command("calibrate")
def benchmark_calibrate(
    path: Path = typer.Argument(..., help="Path to calibration JSONL dataset."),
    target_fpr: float = typer.Option(0.01, "--target-fpr", help="Target false positive rate."),
    output: Path = typer.Option(..., "--output", "-o", help="Path to write calibration artifact."),
):
    """Fit a threshold artifact on calibration-only JSONL."""
    try:
        from .benchmark import calibrate_threshold_jsonl

        artifact = calibrate_threshold_jsonl(str(path), target_fpr=target_fpr)
        _write_json(str(output), artifact)
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@benchmark_app.command("compare")
def benchmark_compare(
    cal_path: Path = typer.Argument(..., help="Path to calibration dataset."),
    eval_path: Path = typer.Argument(..., help="Path to evaluation dataset."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Path to write results."),
):
    """Compare calibration and evaluation results for drift detection."""
    try:
        from .benchmark import benchmark_jsonl as _bench

        cal_result = _bench(str(cal_path))
        eval_result = _bench(str(eval_path))
        comparison = {"calibration": cal_result, "evaluation": eval_result}
        _write_json(str(output) if output else None, comparison)
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@benchmark_app.command("select-threshold")
def select_threshold_cli(
    cal_path: Path = typer.Argument(..., help="Path to calibration JSONL dataset."),
    target_fpr: float = typer.Option(0.01, "--target-fpr", help="Target false positive rate."),
    output: Path = typer.Option(..., "--output", "-o", help="Path to write threshold artifact."),
    detector_id: str = typer.Option(
        "textforensics/builtin-heuristic", "--detector-id", help="Detector ID."
    ),
    detector_version: str = typer.Option("1.0.0", "--detector-version", help="Detector version."),
):
    """Select operating threshold on calibration-only data."""
    try:
        from .threshold_selection import create_calibration_artifact as _create_artifact
        from .threshold_selection import select_threshold as _select_threshold

        result = _select_threshold(
            str(cal_path),
            target_fpr=target_fpr,
            detector_id=detector_id,
            detector_version=detector_version,
        )
        _create_artifact(result, str(output))
        typer.echo(str(output))
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@schema_app.command("validate")
def schema_validate(
    file: Path = typer.Argument(..., help="Path to the JSON file to validate."),
    type: Literal["forensic-bundle", "detector-result", "case-file", "trust-map"] = typer.Option(
        ..., "--type", help="Schema type to validate against."
    ),
):
    """Validate a JSON file against a schema."""
    try:
        from .schema import (
            validate_case_file,
            validate_detector_result,
            validate_forensic_bundle,
            validate_trust_map,
        )

        with open(file, encoding="utf-8") as f:
            data = json.load(f)
        if type == "forensic-bundle":
            errors = validate_forensic_bundle(data)
        elif type == "detector-result":
            errors = validate_detector_result(data)
        elif type == "case-file":
            errors = validate_case_file(data)
        elif type == "trust-map":
            errors = validate_trust_map(data)
        else:
            raise ValueError(f"Unknown schema type: {type}")
        result = {"valid": len(errors) == 0, "errors": errors}
        _write_json(None, result)
        if errors:
            raise typer.Exit(EXIT_INCOMPLETE)
    except SystemExit:
        raise
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@schema_app.command("list")
def schema_list_cmd():
    """List available schemas."""
    try:
        from .schema import list_schemas

        _write_json(None, {"schemas": list_schemas()})
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@schema_app.command("show")
def schema_show(
    name: str = typer.Argument(..., help="Schema name (e.g., forensic-bundle)."),
):
    """Show a schema definition."""
    try:
        from .schema import load_schema

        schema = load_schema(name)
        _write_json(None, schema)
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@app.command()
def fingerprint(
    path: Path = typer.Argument(..., help="Path to the JSONL dataset file."),
    name: str = typer.Argument(..., help="Dataset identifier."),
    version: str = typer.Option("1.0.0", "--version", help="Dataset version."),
    split: str = typer.Option("test", "--split", help="Dataset split."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Path to write fingerprint JSON."
    ),
):
    """Create a dataset fingerprint for contamination tracking."""
    try:
        from .benchmark_fingerprint import fingerprint_dataset as _fp

        fp = _fp(str(path), name=name, version=version, split=split, strict=True)
        _write_json(str(output) if output else None, fp.to_dict())
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@app.command()
def check(
    cal_path: Path = typer.Argument(..., help="Path to calibration dataset."),
    eval_path: Path = typer.Argument(..., help="Path to evaluation dataset."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Path to write check result."),
):
    """Check for benchmark contamination between datasets."""
    try:
        from .benchmark_fingerprint import check_disjointness
        from .benchmark_fingerprint import fingerprint_dataset as _fp

        cal_fp = _fp(str(cal_path), name="calibration", split="calibration")
        eval_fp = _fp(str(eval_path), name="evaluation", split="evaluation")
        result = check_disjointness(str(cal_path), cal_fp, str(eval_path), eval_fp)
        _write_json(str(output) if output else None, result)
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@app.command("select-threshold")
def select_threshold_cmd(
    cal_path: Path = typer.Argument(..., help="Path to calibration JSONL dataset."),
    target_fpr: float = typer.Option(0.01, "--target-fpr", help="Target false positive rate."),
    output: Path = typer.Option(..., "--output", "-o", help="Path to write threshold artifact."),
):
    """Select operating threshold on calibration-only data."""
    try:
        from .threshold_selection import create_calibration_artifact as _create_artifact
        from .threshold_selection import select_threshold as _select_threshold

        result = _select_threshold(
            str(cal_path),
            target_fpr=target_fpr,
            detector_id="textforensics/builtin-heuristic",
            detector_version="1.0.0",
        )
        _create_artifact(result, str(output))
        typer.echo(str(output))
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@app.command()
def web(
    host: str | None = typer.Option(None, "--host", help="Host to bind to."),
    port: int | None = typer.Option(None, "--port", help="Port to bind to."),
    no_browser: bool = typer.Option(False, "--no-browser", help="Don't open browser."),
    allow_remote: bool = typer.Option(False, "--allow-remote", help="Allow remote connections."),
):
    """Run the zero-dependency browser UI."""
    try:
        from .config import Settings
        from .webapp import serve as serve_webapp

        settings = Settings.from_env()
        serve_webapp(
            host or settings.host,
            port if port is not None else settings.port,
            open_browser=not no_browser,
            allow_remote=allow_remote or settings.allow_remote,
            max_input_bytes=settings.max_input_bytes,
        )
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@app.command("web-fastapi")
def web_fastapi(
    host: str | None = typer.Option(None, "--host", help="Host to bind to."),
    port: int | None = typer.Option(None, "--port", help="Port to bind to."),
    allow_remote: bool = typer.Option(False, "--allow-remote", help="Allow remote connections."),
    access_log: bool = typer.Option(False, "--access-log", help="Enable access log."),
):
    """Run the FastAPI WebSocket UI with real-time analysis and visualization."""
    try:
        from .config import Settings
        from .web_ui.main import serve_web

        settings = Settings.from_env()
        serve_web(
            host or settings.host,
            port if port is not None else settings.port,
            allow_remote=allow_remote or settings.allow_remote,
            access_log=access_log or settings.access_log,
            log_level=settings.log_level,
        )
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@app.command()
def serve(
    host: str | None = typer.Option(None, "--host", help="Host to bind to."),
    port: int | None = typer.Option(None, "--port", help="Port to bind to."),
    allow_remote: bool = typer.Option(False, "--allow-remote", help="Allow remote connections."),
    access_log: bool = typer.Option(False, "--access-log", help="Enable access log."),
):
    """Run the optional ASGI API server."""
    try:
        from .config import Settings
        from .server import serve_api

        settings = Settings.from_env()
        active = Settings(
            host=host or settings.host,
            port=port if port is not None else settings.port,
            max_input_bytes=settings.max_input_bytes,
            allow_remote=allow_remote or settings.allow_remote,
            access_log=access_log or settings.access_log,
            log_level=settings.log_level,
        )
        serve_api(active)
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@app.command()
def detectors(
    health: bool = typer.Option(False, "--health", help="Include plugin health check."),
    rich: bool = typer.Option(False, "--rich", help="Use Rich-formatted terminal output."),
):
    """List installed detector adapters."""
    try:
        from .detectors import list_detector_health, list_detector_metadata

        payload = {
            "detectors": list_detector_metadata(),
            "plugin_health": list_detector_health() if health else [],
        }
        _write_json(None, payload)
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@app.command()
def compare(
    before: Path = typer.Argument(..., help="Path to the before text file."),
    after: Path = typer.Argument(..., help="Path to the after text file."),
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
):
    """Compare two text versions."""
    try:
        from .compare import compare_texts

        result = compare_texts(
            before.read_text(encoding="utf-8"), after.read_text(encoding="utf-8")
        )
        if json:
            _write_json(None, result.to_dict())
        else:
            typer.echo(str(result))
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@app.command()
def snapshot(
    file: Path = typer.Argument(..., help="Path to the file to snapshot."),
    ledger: Path | None = typer.Option(None, "--ledger", help="Path to the provenance ledger."),
):
    """Append a tamper-evident draft snapshot to a local ledger."""
    try:
        from .provenance import snapshot_file

        result = snapshot_file(str(file), str(ledger or ".textforensics-ledger.jsonl"))
        _write_json(None, result)
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@app.command("verify-ledger")
def verify_ledger_cmd(
    ledger: Path | None = typer.Option(None, "--ledger", help="Path to the provenance ledger."),
):
    """Verify the local provenance ledger hash chain."""
    try:
        from .provenance import verify_ledger

        result = verify_ledger(str(ledger or ".textforensics-ledger.jsonl"))
        _write_json(None, result)
        raise typer.Exit(EXIT_OK if result.get("valid") else EXIT_INCOMPLETE)
    except SystemExit:
        raise
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@app.command()
def audit(
    text: str | None = typer.Option(None, "--text", "-t", help="Input text."),
    file: Path | None = typer.Option(None, "--file", "-f", help="Path to text file."),
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
):
    """Audit formulaic/naturalness patterns without rewriting."""
    try:
        from .naturalness import audit_naturalness

        result = audit_naturalness(_read_text_from_input(text, file))
        _write_json(None, result)
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


@app.command()
def calibrate(
    dataset: Path = typer.Argument(..., help="Path to calibration JSONL dataset."),
    target_fpr: float = typer.Option(0.01, "--target-fpr", help="Target false positive rate."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Path to write artifact."),
):
    """Fit a threshold artifact on calibration-only JSONL."""
    try:
        from .benchmark import calibrate_threshold_jsonl

        artifact = calibrate_threshold_jsonl(str(dataset), target_fpr=target_fpr)
        _write_json(str(output) if output else None, artifact)
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR)


def main() -> int:
    """Main entry point for the Typer CLI."""
    try:
        app()
        return EXIT_OK
    except typer.Exit as e:
        return e.exit_code
    except (ValueError, OSError, json.JSONDecodeError, RuntimeError) as exc:
        typer.echo(f"error: {exc}", err=True)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
