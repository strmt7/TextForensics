from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from ._build_info import (
    get_build_info,
    verify_build_identity,
)
from .benchmark import (
    benchmark_jsonl,
    benchmark_with_calibration_jsonl,
    calibrate_threshold_jsonl,
    load_calibration_artifact,
)
from .benchmark_fingerprint import (
    check_disjointness,
    fingerprint_dataset,
)
from .bundle import list_bundle, pack_bundle, verify_bundle
from .capability_ledger import (
    CapabilityClaim,
    CapabilityLedger,
    EvidenceLabel,
    EvidenceRef,
    EvidenceTier,
)
from .casefile import verify_case_file_path, write_case_file
from .compare import compare_texts
from .config import Settings, read_text_file, validate_text_input
from .constants import (
    EXIT_DOWNGRADED,
    EXIT_ERROR,
    EXIT_INCOMPLETE,
    EXIT_OK,
)
from .detectors import list_detector_health, list_detector_metadata
from .drift import DriftObservatory
from .enterprise_policy import (
    EnterprisePolicy,
    EnterprisePolicyEngine,
    PolicyRevisionFloor,
    compute_policy_digest,
    validate_enterprise_policy,
)
from .audit_anchor import (
    AuditAnchor,
    CalibrationChain,
    RollbackError,
    export_audit_anchor,
    verify_audit_anchor,
)
from .emergency_stop import (
    EmergencyStopError,
    EmergencyStopSentinel,
    check_emergency_stop,
)
from .engine import analyze_text
from .localize import (
    detect_anomalous_segments,
    localize_text,
    segment_to_dict,
    visual_diff,
)
from .naturalness import audit_naturalness
from .provenance import snapshot_file, verify_ledger
from .report import build_forensic_bundle
from .verify import verify_all
from .version import get_version
from .webapp import serve as serve_webapp


def _read_text(path: str | None, settings: Settings) -> str:
    if path:
        return read_text_file(
            path,
            max_input_bytes=settings.max_input_bytes,
        )
    if sys.stdin.isatty():
        raise ValueError("Provide --file or pipe text through stdin.")
    text = sys.stdin.read(settings.max_input_bytes + 1)
    return validate_text_input(
        text,
        max_input_bytes=settings.max_input_bytes,
    )


def _read_file_text(path: str, settings: Settings) -> str:
    return read_text_file(
        path,
        max_input_bytes=settings.max_input_bytes,
    )


def _write_json(path: str | None, payload: Any) -> None:
    rendered = json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False)
    if path:
        Path(path).write_text(rendered + "\n", encoding="utf-8")
        print(path)
    else:
        print(rendered)


def _pretty_analysis(result) -> None:
    print("TextForensics")
    print("=" * 60)
    print(f"Verdict                {result.verdict}")
    print(f"Pattern score          {result.score:.1%}")
    print(f"Diagnostic reliability {result.diagnostic_reliability:.1%}")
    print(f"Analyzer disagreement  {result.disagreement:.1%}")
    print(f"Robustness stability   {result.robustness_stability:.1%}")
    print(f"Words                  {result.word_count}")
    print("\nAnalyzers")
    for item in result.analyzers:
        print(f"  {item.name:24s} {item.score:.1%}  diagnostic reliability {item.reliability:.1%}")
    if result.warnings:
        print("\nWarnings")
        for warning in result.warnings:
            print(f"  - {warning}")


def _strip_runtime_ms(data: dict) -> dict:
    """Remove runtime_ms from all dicts in detector_results recursively."""
    if "detector_results" in data and isinstance(data["detector_results"], list):
        for result in data["detector_results"]:
            if isinstance(result, dict):
                result.pop("runtime_ms", None)
    if "detector_failures" in data and isinstance(data["detector_failures"], list):
        for failure in data["detector_failures"]:
            if isinstance(failure, dict):
                failure.pop("runtime_ms", None)
    return data


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="textforensics",
        description="Audit AI-text detector evidence and reliability locally.",
    )
    parser.add_argument(
        "--typer",
        action="store_true",
        help="Use the Typer-based CLI instead of argparse (requires textforensics[cli-typer]).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {get_version()}",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run the local alpha pattern baseline.")
    scan.add_argument("--file", "-f")
    scan.add_argument("--json", action="store_true")
    scan.add_argument("--rich", action="store_true", help="Use Rich-formatted terminal output")
    scan.add_argument(
        "--deterministic",
        action="store_true",
        help="Use fixed timestamp and remove runtime_ms for reproducible output",
    )

    natural = sub.add_parser(
        "audit",
        help="Audit formulaic/naturalness patterns, or manage audit anchors via subcommands (export/verify).",
    )
    natural.add_argument("--file", "-f")
    natural.add_argument("--json", action="store_true")
    # Optional subcommand for audit-anchor management (backward compatible:
    # no subcommand keeps the legacy naturalness-audit behavior)
    natural.add_argument(
        "anchor_command",
        nargs="?",
        choices=["export", "verify"],
        help=argparse.SUPPRESS,  # Hide from help, handled manually
    )
    natural.add_argument("anchor_arg", nargs="?", help=argparse.SUPPRESS)
    natural.add_argument("--base-dir", help="Override the project root directory.")
    natural.add_argument(
        "--chain",
        help="Path to a calibration chain JSON file.",
    )

    localize = sub.add_parser(
        "localize",
        help="Score consecutive text segments for diagnostic localization, diff texts, and detect anomalous segments.",
    )
    # Add old-style arguments for backward compatibility
    localize.add_argument("--file", "-f")
    localize.add_argument("--sentences", type=int, default=4)
    # Add new subcommand as optional positional
    localize.add_argument(
        "subcommand",
        nargs="?",
        choices=["diff", "anomalies", "segments"],
        help=argparse.SUPPRESS,  # Hide from help, handled manually
    )
    # Diff arguments
    localize.add_argument("file1", nargs="?", help=argparse.SUPPRESS)
    localize.add_argument("file2", nargs="?", help=argparse.SUPPRESS)
    localize.add_argument(
        "--style",
        choices=["side_by_side", "unified", "inline"],
        default="side_by_side",
        help="Diff rendering style (default: side_by_side).",
    )
    localize.add_argument("--output", "-o", help="Path to write the diff output.")
    # Anomalies arguments
    localize.add_argument(
        "--threshold", type=float, default=2.0, help="Z-score threshold (default: 2.0)."
    )
    localize.add_argument("--rich", action="store_true", help="Use Rich-formatted terminal output")

    compare = sub.add_parser("compare", help="Compare two text versions.")
    compare.add_argument("before")
    compare.add_argument("after")
    compare.add_argument("--json", action="store_true")

    snapshot = sub.add_parser(
        "snapshot",
        help="Append a tamper-evident draft snapshot to a local ledger.",
    )
    snapshot.add_argument("file")
    snapshot.add_argument("--ledger", default=".textforensics-ledger.jsonl")

    verify = sub.add_parser(
        "verify-ledger",
        help="Verify the local provenance ledger hash chain.",
    )
    verify.add_argument("ledger", nargs="?", default=".textforensics-ledger.jsonl")

    calibrate = sub.add_parser(
        "calibrate",
        help="Fit a threshold artifact on calibration-only JSONL.",
    )
    calibrate.add_argument("dataset")
    calibrate.add_argument("--target-fpr", type=float, default=0.01)
    calibrate.add_argument("--output", "-o")

    # Original benchmark command (backward compatible)
    bench = sub.add_parser(
        "benchmark",
        help="Evaluate the built-in baseline on labeled JSONL.",
    )
    bench.add_argument("dataset")
    group = bench.add_mutually_exclusive_group()
    group.add_argument("--threshold", type=float)
    group.add_argument("--calibration", help="Calibration artifact JSON.")
    bench.add_argument(
        "--allow-same-dataset",
        action="store_true",
        help="Diagnostic only: permit evaluation on the calibration dataset.",
    )

    # Separate commands for contamination prevention (AGENTS.md #12)
    # These are distinct commands to avoid argparse positional/subparser conflicts
    fp_cmd = sub.add_parser(
        "fingerprint",
        help="Create a dataset fingerprint for contamination tracking.",
    )
    fp_cmd.add_argument("dataset", help="Path to the JSONL dataset file.")
    fp_cmd.add_argument("--name", required=True, help="Dataset identifier.")
    fp_cmd.add_argument("--version", default="1.0.0", help="Dataset version.")
    fp_cmd.add_argument("--split", default="test", help="Dataset split.")
    fp_cmd.add_argument("--output", "-o", help="Path to write fingerprint JSON (default: stdout).")
    fp_cmd.add_argument("--strict", action="store_true", default=True)
    fp_cmd.add_argument("--no-strict", dest="strict", action="store_false")

    check_cmd = sub.add_parser(
        "check",
        help="Check for benchmark contamination between datasets.",
    )
    check_cmd.add_argument("calibration", help="Path to calibration dataset.")
    check_cmd.add_argument("evaluation", help="Path to evaluation dataset.")
    check_cmd.add_argument(
        "--output",
        "-o",
        help="Path to write check result JSON (default: stdout).",
    )

    select_cmd = sub.add_parser(
        "select-threshold",
        help="Select operating threshold on calibration-only data.",
    )
    select_cmd.add_argument("dataset", help="Path to calibration JSONL dataset.")
    select_cmd.add_argument(
        "--target-fpr",
        type=float,
        default=0.01,
        help="Target false positive rate (default: 0.01).",
    )
    select_cmd.add_argument(
        "--detector-id",
        default="textforensics/builtin-heuristic",
        help="Detector identifier for provenance.",
    )
    select_cmd.add_argument(
        "--detector-version",
        default="1.0.0",
        help="Detector version for provenance.",
    )
    select_cmd.add_argument(
        "--output",
        "-o",
        help="Path to write threshold artifact JSON (default: stdout).",
    )

    detectors = sub.add_parser(
        "detectors",
        help="List installed detector adapters.",
    )
    detectors.add_argument("--health", action="store_true")
    detectors.add_argument("--rich", action="store_true", help="Use Rich-formatted terminal output")

    # Schema validation commands
    schema_cmd = sub.add_parser("schema", help="Validate and inspect JSON schemas.")
    schema_sub = schema_cmd.add_subparsers(dest="schema_command", required=True)

    schema_validate = schema_sub.add_parser(
        "validate", help="Validate a JSON file against a schema."
    )
    schema_validate.add_argument("file", help="Path to the JSON file to validate.")
    schema_validate.add_argument(
        "--type",
        choices=["forensic-bundle", "detector-result", "case-file", "trust-map", "enterprise-policy"],
        required=True,
        help="Schema type to validate against.",
    )

    schema_sub.add_parser("list", help="List available schemas.")

    schema_show = schema_sub.add_parser("show", help="Show a schema definition.")
    schema_show.add_argument("name", help="Schema name (e.g., forensic-bundle).")

    report = sub.add_parser(
        "report",
        help="Build a reproducible detector-evidence bundle.",
    )
    report.add_argument("--file", "-f")
    report.add_argument("--ledger")
    report.add_argument("--output", "-o")
    report.add_argument(
        "--deterministic", action="store_true", help="Use fixed timestamp for reproducible output"
    )
    report.add_argument("--fixed-timestamp", help="Fixed ISO timestamp for reproducible output")
    report.add_argument("--rich", action="store_true", help="Use Rich-formatted terminal output")

    case = sub.add_parser("case", help="Export or verify a sealed case file.")
    case_sub = case.add_subparsers(dest="case_command", required=True)
    case_export = case_sub.add_parser("export", help="Export a sealed case file.")
    case_export.add_argument("--file", "-f")
    case_export.add_argument("--ledger")
    case_export.add_argument("--output", "-o", required=True)
    case_export.add_argument(
        "--deterministic", action="store_true", help="Use fixed timestamp for reproducible output"
    )
    case_export.add_argument(
        "--fixed-timestamp", help="Fixed ISO timestamp for reproducible output"
    )
    case_export.add_argument(
        "--rich", action="store_true", help="Use Rich-formatted terminal output"
    )
    case_verify = case_sub.add_parser("verify", help="Verify case-file integrity.")
    case_verify.add_argument("case_file")

    bundle_cmd = sub.add_parser(
        "bundle",
        help="Pack, verify, and list case file bundles.",
    )
    bundle_sub = bundle_cmd.add_subparsers(dest="bundle_command", required=True)

    bundle_pack = bundle_sub.add_parser("pack", help="Pack a case file into a bundle.")
    bundle_pack.add_argument("case_file", help="Path to a case file or case file directory.")
    bundle_pack.add_argument("output", help="Output bundle path (.tar.gz or .zip).")

    bundle_verify = bundle_sub.add_parser("verify", help="Verify bundle integrity.")
    bundle_verify.add_argument("bundle", help="Path to the bundle archive.")
    bundle_verify.add_argument(
        "--expect-digest",
        help="Expected SHA-256 digest of the bundle archive.",
    )

    bundle_list = bundle_sub.add_parser("list", help="List contents of a bundle.")
    bundle_list.add_argument("bundle", help="Path to the bundle archive.")

    verify_cmd = sub.add_parser(
        "verify",
        help="N-version integrity replay: re-derive Trust Map, calibration, and benchmark metrics.",
    )
    verify_cmd.add_argument(
        "case_file",
        nargs="?",
        help="Path to a sealed case file to verify.",
    )
    verify_cmd.add_argument(
        "--calibration",
        help="Path to a calibration artifact JSON to verify.",
    )
    verify_cmd.add_argument(
        "--benchmark",
        help="Path to a benchmark result JSON to verify.",
    )
    verify_cmd.add_argument(
        "--all",
        action="store_true",
        help="Run all available verifications and report.",
    )

    web = sub.add_parser("web", help="Run the zero-dependency browser UI.")
    web.add_argument("--host")
    web.add_argument("--port", type=int)
    web.add_argument("--no-browser", action="store_true")
    web.add_argument("--allow-remote", action="store_true")

    serve = sub.add_parser("serve", help="Run the optional ASGI API server.")
    serve.add_argument("--host")
    serve.add_argument("--port", type=int)
    serve.add_argument("--allow-remote", action="store_true")
    serve.add_argument("--access-log", action="store_true")

    drift = sub.add_parser(
        "drift",
        help="Run the drift observatory: longitudinal detector reliability tracking.",
    )
    drift_sub = drift.add_subparsers(dest="drift_command", required=True)

    drift_snapshot = drift_sub.add_parser("snapshot", help="Take a detector snapshot.")
    drift_snapshot.add_argument(
        "--corpus",
        default=str(
            Path(__file__).resolve().parent.parent.parent / "testdata" / "drift_corpus.json"
        ),
        help="Path to a drift corpus JSON file.",
    )
    drift_snapshot.add_argument("--label", help="Optional human-readable snapshot label.")
    drift_snapshot.add_argument(
        "--allow-remote",
        action="store_true",
        help="Allow remote detector adapters to run during snapshotting.",
    )
    drift_snapshot.add_argument("--output", "-o", help="Write the snapshot to this JSON file.")
    drift_snapshot.add_argument("--snapshot-id", help="Optional explicit snapshot ID.")

    drift_compare = drift_sub.add_parser("compare", help="Compare two drift snapshots.")
    drift_compare.add_argument("baseline", help="Path to the baseline snapshot JSON.")
    drift_compare.add_argument("current", help="Path to the current snapshot JSON.")
    drift_compare.add_argument(
        "--corpus",
        default=str(
            Path(__file__).resolve().parent.parent.parent / "testdata" / "drift_corpus.json"
        ),
        help="Path to a drift corpus JSON file.",
    )
    drift_compare.add_argument("--output", "-o", help="Write the drift report to this JSON file.")

    drift_report = drift_sub.add_parser(
        "report", help="Generate a drift report from two snapshots."
    )
    drift_report.add_argument("baseline", help="Path to the baseline snapshot JSON.")
    drift_report.add_argument("current", help="Path to the current snapshot JSON.")
    drift_report.add_argument(
        "--corpus",
        default=str(
            Path(__file__).resolve().parent.parent.parent / "testdata" / "drift_corpus.json"
        ),
        help="Path to a drift corpus JSON file.",
    )
    drift_report.add_argument("--output", "-o", help="Write the drift report to this JSON file.")
    drift_report.add_argument(
        "--rich", action="store_true", help="Use Rich-formatted terminal output"
    )

    cap = sub.add_parser(
        "capability",
        help="Inspect detector capability claims in the capability ledger.",
    )
    cap_sub = cap.add_subparsers(dest="capability_command", required=True)

    cap_list = cap_sub.add_parser("list", help="List all registered capabilities.")
    cap_list.add_argument("--detector", help="Filter by detector ID.")
    cap_list.add_argument("--ledger", help="Path to the capability ledger JSON file.")

    cap_check = cap_sub.add_parser(
        "check",
        help="Check whether a capability claim is validated.",
    )
    cap_check.add_argument("detector", help="Detector ID.")
    cap_check.add_argument("capability", help="Capability name.")
    cap_check.add_argument("--ledger", help="Path to the capability ledger JSON file.")

    cap_export = cap_sub.add_parser(
        "export",
        help="Export the capability ledger as JSON.",
    )
    cap_export.add_argument(
        "--output",
        "-o",
        help="Path to write JSON (default: stdout).",
    )
    cap_export.add_argument("--ledger", help="Path to the capability ledger JSON file.")

    cap_register = cap_sub.add_parser(
        "register",
        help="Register a capability claim in the ledger.",
    )
    cap_register.add_argument("detector", help="Detector ID.")
    cap_register.add_argument("capability", help="Capability name (e.g., language_coverage.en).")
    cap_register.add_argument(
        "tier",
        choices=["validated", "tool_backed", "readable"],
        help="Evidence tier: validated, tool_backed, or readable.",
    )
    cap_register.add_argument("artifact", help="Evidence artifact path or run ID.")
    cap_register.add_argument(
        "--ledger",
        default=str(Path(__file__).resolve().parent.parent.parent / "capability_ledger.json"),
        help="Path to the capability ledger JSON file (default: ./capability_ledger.json).",
    )
    cap_register.add_argument(
        "--label",
        choices=["reported", "calculated", "proposed", "executed"],
        default="calculated",
        help="Evidence label (default: calculated).",
    )
    cap_register.add_argument("--detail", help="Optional detail about the evidence.")
    cap_register.add_argument("--valid-until", help="Optional expiration date (ISO format).")

    build_info_cmd = sub.add_parser(
        "build-info",
        help="Display embedded build identity information (source commit, dependencies hash, contract info).",
    )
    build_info_cmd.add_argument(
        "--verify",
        action="store_true",
        help="Verify build identity against expected values.",
    )
    build_info_cmd.add_argument(
        "--expected-commit",
        default=None,
        help="Expected source commit hash for verification.",
    )

    # Enterprise policy commands
    policy_cmd = sub.add_parser(
        "policy",
        help="Enterprise policy management with revision-floor enforcement.",
    )
    policy_sub = policy_cmd.add_subparsers(dest="policy_command", required=True)

    policy_load = policy_sub.add_parser(
        "load",
        help="Load and validate an enterprise policy file.",
    )
    policy_load.add_argument(
        "file",
        help="Path to the enterprise policy JSON file.",
    )
    policy_load.add_argument(
        "--state-path",
        help="Path to the encrypted policy state file.",
    )
    policy_load.add_argument(
        "--key-path",
        help="Path to the Fernet key file.",
    )
    policy_load.add_argument(
        "--no-advance",
        action="store_true",
        help="Validate the policy but do not advance the revision floor.",
    )

    policy_check = policy_sub.add_parser(
        "check",
        help="Check the current policy against the revision floor.",
    )
    policy_check.add_argument(
        "file",
        nargs="?",
        help="Path to the enterprise policy JSON file (optional).",
    )
    policy_check.add_argument(
        "--state-path",
        help="Path to the encrypted policy state file.",
    )
    policy_check.add_argument(
        "--key-path",
        help="Path to the Fernet key file.",
    )

    policy_advance = policy_sub.add_parser(
        "advance",
        help="Advance the revision floor to the given policy.",
    )
    policy_advance.add_argument(
        "file",
        help="Path to the enterprise policy JSON file.",
    )
    policy_advance.add_argument(
        "--state-path",
        help="Path to the encrypted policy state file.",
    )
    policy_advance.add_argument(
        "--key-path",
        help="Path to the Fernet key file.",
    )

    policy_export = policy_sub.add_parser(
        "export",
        help="Export the current policy state.",
    )
    policy_export.add_argument(
        "--state-path",
        help="Path to the encrypted policy state file.",
    )
    policy_export.add_argument(
        "--key-path",
        help="Path to the Fernet key file.",
    )
    policy_export.add_argument(
        "--policy-file",
        help="Path to the enterprise policy JSON file.",
    )

    # Audit anchor subcommands are handled via the existing "audit" parser
    # (optional anchor_command positional for backward compatibility).

    # --- Emergency stop commands ---
    emergency = sub.add_parser(
        "emergency",
        help="Manage the out-of-band emergency stop sentinel.",
    )
    emergency_sub = emergency.add_subparsers(dest="emergency_command", required=True)

    emergency_status = emergency_sub.add_parser(
        "status",
        help="Check the current emergency stop status.",
    )
    emergency_status.add_argument(
        "--path",
        help="Override the sentinel path (defaults to $TEXTFORENSICS_EMERGENCY_STOP).",
    )

    emergency_activate = emergency_sub.add_parser(
        "activate",
        help="Activate the emergency stop by creating the sentinel file.",
    )
    emergency_activate.add_argument(
        "--path",
        help="Override the sentinel path (defaults to $TEXTFORENSICS_EMERGENCY_STOP).",
    )

    emergency_deactivate = emergency_sub.add_parser(
        "deactivate",
        help="Deactivate the emergency stop by removing the sentinel file.",
    )
    emergency_deactivate.add_argument(
        "--path",
        help="Override the sentinel path (defaults to $TEXTFORENSICS_EMERGENCY_STOP).",
    )

    return parser


def _settings_with_overrides(
    base: Settings,
    *,
    host: str | None = None,
    port: int | None = None,
    allow_remote: bool | None = None,
    access_log: bool | None = None,
) -> Settings:
    return Settings(
        host=host or base.host,
        port=port if port is not None else base.port,
        max_input_bytes=base.max_input_bytes,
        allow_remote=(allow_remote if allow_remote is not None else base.allow_remote),
        access_log=access_log if access_log is not None else base.access_log,
        log_level=base.log_level,
    )


def _load_default_ledger() -> CapabilityLedger:
    """Load the default capability ledger from disk, or return an empty one."""
    ledger_path = Path(__file__).resolve().parent.parent.parent / "capability_ledger.json"
    if ledger_path.exists():
        try:
            data = json.loads(ledger_path.read_text(encoding="utf-8"))
            return CapabilityLedger.from_dict(data)
        except (json.JSONDecodeError, KeyError):
            pass
    return CapabilityLedger()


def _trust_map_exit_code(bundle: dict[str, Any]) -> int:
    """Map a forensic bundle's Trust Map to an exit code.

    Returns EXIT_OK (0) when coverage is sufficient,
    EXIT_DOWNGRADED (1) when partial, and EXIT_INCOMPLETE (2)
    when detectors abstained or coverage is insufficient.
    """
    trust_map = bundle.get("trust_map")
    if not isinstance(trust_map, dict):
        return EXIT_INCOMPLETE

    overall = trust_map.get("overall", "unknown")
    if overall in ("insufficient", "mixed"):
        return EXIT_INCOMPLETE
    if overall == "mixed":
        return EXIT_DOWNGRADED
    if overall == "insufficient":
        return EXIT_INCOMPLETE
    if overall == "strong":
        return EXIT_OK

    # Fallback: inspect dimensions
    dimensions = trust_map.get("dimensions", [])
    if not isinstance(dimensions, list) or not dimensions:
        return EXIT_INCOMPLETE

    states = [d.get("state", "") for d in dimensions if isinstance(d, dict)]
    if any(s == "out_of_scope" for s in states):
        return EXIT_INCOMPLETE
    if any(s == "unknown" for s in states):
        return EXIT_INCOMPLETE
    if any(s == "partial" for s in states):
        return EXIT_DOWNGRADED
    return EXIT_OK


def _run(args: argparse.Namespace, settings: Settings) -> int:
    # Emergency stop gate: checked at dispatch entry for all analysis
    # commands. The emergency management command bypasses this gate so
    # the sentinel can always be inspected/removed.
    if args.command != "emergency" and check_emergency_stop():
        print(
            "error: emergency stop is active. All analysis, report, "
            "audit, compare, benchmark, drift, and serve commands are blocked.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    if args.command == "scan":
        result = analyze_text(_read_text(args.file, settings))
        if args.json:
            data = result.to_dict()
            if hasattr(args, "deterministic") and args.deterministic:
                data = _strip_runtime_ms(data)
            _write_json(None, data)
        elif getattr(args, "rich", False):
            from .rich_output import HAS_RICH as _has_rich
            from .rich_output import print_scan_results

            if _has_rich:
                print_scan_results(result)
            else:
                print(
                    "Warning: Rich is not installed. Install with: pip install textforensics[cli-rich]"
                )
                print("Falling back to plain output.\n")
                _pretty_analysis(result)
        else:
            _pretty_analysis(result)

    elif args.command == "audit":
        anchor_command = getattr(args, "anchor_command", None)
        if anchor_command in ("export", "verify"):
            return _run_audit_anchor_command(args)
        result = audit_naturalness(_read_text(args.file, settings))
        _write_json(None, result)

    elif args.command == "localize":
        # Determine which subcommand to run
        # Check if subcommand is explicitly given
        subcommand = args.subcommand

        # Backward compatibility: if --file is provided without subcommand, use segments
        if subcommand is None and args.file:
            subcommand = "segments"
        # If file1 and file2 are provided without subcommand, use diff
        elif subcommand is None and args.file1 and args.file2:
            subcommand = "diff"
        # Default to segments
        elif subcommand is None:
            subcommand = "segments"

        if subcommand == "diff":
            if not args.file1 or not args.file2:
                raise ValueError("diff requires file1 and file2 arguments")
            text1 = _read_file_text(args.file1, settings)
            text2 = _read_file_text(args.file2, settings)
            diff_text = visual_diff(text1, text2, style=args.style)
            if args.output:
                Path(args.output).write_text(diff_text, encoding="utf-8")
                print(args.output)
            else:
                if getattr(args, "rich", False):
                    from .rich_output import HAS_RICH as _has_rich
                    from .rich_output import print_diff

                    if _has_rich:
                        print_diff(text1, text2, style=args.style)
                    else:
                        print(
                            "Warning: Rich is not installed. Install with: pip install textforensics[cli-rich]"
                        )
                        print(diff_text)
                else:
                    print(diff_text)
        elif subcommand == "anomalies":
            # Use --file or positional file
            file_arg = args.file or args.file1
            if not file_arg:
                raise ValueError("anomalies requires --file or positional file argument")
            text = _read_text(file_arg, settings)
            result = detect_anomalous_segments(text, threshold=args.threshold)
            if args.output:
                Path(args.output).write_text(
                    json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
                    encoding="utf-8",
                )
                print(args.output)
            else:
                _write_json(None, result)
        elif subcommand == "segments":
            if args.sentences < 1:
                raise ValueError("--sentences must be at least 1.")
            result = [
                segment_to_dict(row)
                for row in localize_text(
                    _read_text(args.file, settings),
                    sentences_per_segment=args.sentences,
                )
            ]
            _write_json(None, result)
        else:
            raise ValueError(f"Unknown localize command: {subcommand}")

    elif args.command == "compare":
        result = compare_texts(
            _read_file_text(args.before, settings),
            _read_file_text(args.after, settings),
        )
        if args.json:
            _write_json(None, result.to_dict())
        else:
            print(result)

    elif args.command == "snapshot":
        _write_json(None, snapshot_file(args.file, args.ledger))

    elif args.command == "verify-ledger":
        result = verify_ledger(args.ledger)
        _write_json(None, result)
        return EXIT_OK if result.get("valid") else EXIT_INCOMPLETE

    elif args.command == "calibrate":
        artifact = calibrate_threshold_jsonl(
            args.dataset,
            target_fpr=args.target_fpr,
        )
        _write_json(args.output, artifact)

    elif args.command == "benchmark":
        if args.calibration:
            calibration = load_calibration_artifact(args.calibration)
            result = benchmark_with_calibration_jsonl(
                args.dataset,
                calibration,
                allow_same_dataset=args.allow_same_dataset,
            )
        else:
            result = benchmark_jsonl(
                args.dataset,
                threshold=args.threshold if args.threshold is not None else 0.5,
            )
        _write_json(None, result)

    elif args.command == "fingerprint":
        fp = fingerprint_dataset(
            args.dataset,
            name=args.name,
            version=args.version,
            split=args.split,
            strict=args.strict,
        )
        _write_json(args.output, fp.to_dict())

    elif args.command == "check":
        result = check_disjointness(
            args.calibration,
            fingerprint_dataset(args.calibration, name="calibration", split="calibration"),
            args.evaluation,
            fingerprint_dataset(args.evaluation, name="evaluation", split="evaluation"),
        )
        _write_json(args.output, result)

    elif args.command == "select-threshold":
        from .threshold_selection import create_calibration_artifact as _create_artifact
        from .threshold_selection import select_threshold as _select_threshold

        result = _select_threshold(
            args.dataset,
            target_fpr=args.target_fpr,
            detector_id=args.detector_id,
            detector_version=args.detector_version,
        )

        if args.output:
            _create_artifact(result, args.output)
            print(args.output)
        else:
            _write_json(None, result.to_dict())

    elif args.command == "detectors":
        payload = {
            "detectors": list_detector_metadata(),
            "plugin_health": list_detector_health() if args.health else [],
        }
        _write_json(None, payload)
        if getattr(args, "rich", False):
            from .rich_output import HAS_RICH as _has_rich
            from .rich_output import print_detector_health

            if _has_rich:
                print_detector_health(payload["plugin_health"])
            else:
                print(
                    "Warning: Rich is not installed. Install with: pip install textforensics[cli-rich]"
                )

    elif args.command == "schema":
        from .schema import (
            list_schemas,
            load_schema,
            validate_case_file,
            validate_detector_result,
            validate_forensic_bundle,
            validate_trust_map,
        )

        if args.schema_command == "list":
            _write_json(None, {"schemas": list_schemas()})
        elif args.schema_command == "show":
            schema = load_schema(args.name)
            _write_json(None, schema)
        elif args.schema_command == "validate":
            with open(args.file, encoding="utf-8") as f:
                data = json.load(f)

            if args.type == "forensic-bundle":
                errors = validate_forensic_bundle(data)
            elif args.type == "detector-result":
                errors = validate_detector_result(data)
            elif args.type == "case-file":
                errors = validate_case_file(data)
            elif args.type == "trust-map":
                errors = validate_trust_map(data)
            elif args.type == "enterprise-policy":
                errors = validate_enterprise_policy(data)
            else:
                raise ValueError(f"Unknown schema type: {args.type}")

            result = {
                "valid": len(errors) == 0,
                "errors": errors,
            }
            _write_json(None, result)
            if errors:
                return EXIT_INCOMPLETE

    elif args.command == "report":
        bundle = build_forensic_bundle(
            _read_text(args.file, settings),
            ledger_path=args.ledger,
            deterministic=args.deterministic,
            fixed_timestamp=args.fixed_timestamp,
        )
        data = bundle.to_dict()
        if args.deterministic:
            data = _strip_runtime_ms(data)
        _write_json(args.output, data)
        if getattr(args, "rich", False):
            from .rich_output import HAS_RICH as _has_rich
            from .rich_output import print_report_summary

            if _has_rich:
                print_report_summary(bundle)
            else:
                print(
                    "Warning: Rich is not installed. Install with: pip install textforensics[cli-rich]"
                )

    elif args.command == "case":
        if args.case_command == "export":
            bundle = build_forensic_bundle(
                _read_text(args.file, settings),
                ledger_path=args.ledger,
                deterministic=args.deterministic,
                fixed_timestamp=args.fixed_timestamp,
            )
            bundle_dict = bundle.to_dict()
            if args.deterministic:
                bundle_dict = _strip_runtime_ms(bundle_dict)
            write_case_file(
                args.output,
                bundle_dict,
                deterministic=args.deterministic,
                fixed_timestamp=args.fixed_timestamp,
            )
            print(args.output)
            if getattr(args, "rich", False):
                from .rich_output import HAS_RICH as _has_rich
                from .rich_output import print_case_summary

                if _has_rich:
                    # Need to read back the case file to show structure
                    case_data = json.loads(Path(args.output).read_text(encoding="utf-8"))
                    print_case_summary(case_data)
                else:
                    print(
                        "Warning: Rich is not installed. Install with: pip install textforensics[cli-rich]"
                    )
        else:
            result = verify_case_file_path(args.case_file)
            _write_json(None, result)
            return EXIT_OK if result.get("valid") else EXIT_INCOMPLETE

    elif args.command == "web":
        active = _settings_with_overrides(
            settings,
            host=args.host,
            port=args.port,
            allow_remote=True if args.allow_remote else settings.allow_remote,
        )
        serve_webapp(
            active.host,
            active.port,
            open_browser=not args.no_browser,
            allow_remote=active.allow_remote,
            max_input_bytes=active.max_input_bytes,
        )

    elif args.command == "serve":
        from .server import serve_api

        active = _settings_with_overrides(
            settings,
            host=args.host,
            port=args.port,
            allow_remote=True if args.allow_remote else settings.allow_remote,
            access_log=True if args.access_log else settings.access_log,
        )
        serve_api(active)

    elif args.command == "drift":
        if args.drift_command == "snapshot":
            observatory = DriftObservatory(corpus_path=args.corpus)
            snapshot = observatory.take_snapshot(
                allow_remote=bool(args.allow_remote),
                snapshot_id=args.snapshot_id,
                label=args.label,
            )
            _write_json(args.output, snapshot)
        else:
            observatory = DriftObservatory(corpus_path=args.corpus)
            baseline = DriftObservatory.read_snapshot_file(args.baseline)
            current = DriftObservatory.read_snapshot_file(args.current)
            report = observatory.compare_snapshots(baseline, current)
            _write_json(args.output, report)
            if args.drift_command == "report" and getattr(args, "rich", False):
                from .rich_output import HAS_RICH as _has_rich
                from .rich_output import print_detector_health, print_trust_map

                if _has_rich:
                    # Print trust map if present in drift report
                    trust_map = report.get("trust_map") or report.get("trust_map_comparison")
                    if trust_map:
                        print_trust_map(trust_map)
                    # Print detector health
                    detector_health = report.get("detector_health") or report.get("plugin_health")
                    if detector_health:
                        print_detector_health(detector_health)
                else:
                    print(
                        "Warning: Rich is not installed. Install with: pip install textforensics[cli-rich]"
                    )

    elif args.command == "capability":
        # Load ledger from specified path or default location
        ledger_path = getattr(args, "ledger", None) or str(
            Path(__file__).resolve().parent.parent.parent / "capability_ledger.json"
        )
        if Path(ledger_path).exists():
            try:
                data = json.loads(Path(ledger_path).read_text(encoding="utf-8"))
                ledger = CapabilityLedger.from_dict(data)
            except (json.JSONDecodeError, KeyError):
                ledger = CapabilityLedger()
        else:
            ledger = CapabilityLedger()
        if args.capability_command == "list":
            claims = ledger.to_dict()["claims"]
            if args.detector:
                claims = {args.detector: claims.get(args.detector, [])}
            _write_json(None, claims)
        elif args.capability_command == "check":
            claim = ledger.enforce(args.detector, args.capability)
            validated = claim.tier == EvidenceTier.VALIDATED
            payload = {
                "detector_id": args.detector,
                "capability": args.capability,
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
                print(
                    f"warning: {args.detector}/{args.capability} is "
                    f"{claim.tier.value}, not VALIDATED.",
                    file=sys.stderr,
                )
        elif args.capability_command == "export":
            _write_json(args.output, ledger.to_dict())
        elif args.capability_command == "register":
            tier = EvidenceTier[args.tier.upper()]
            claim = CapabilityClaim(
                detector_id=args.detector,
                capability=args.capability,
                tier=tier,
                evidence=[
                    EvidenceRef(
                        label=EvidenceLabel[args.label.upper()],
                        tier=tier,
                        artifact=args.artifact,
                        detail=args.detail,
                    )
                ],
                valid_until=args.valid_until,
            )
            ledger.register(claim)
            # Save the ledger back to disk
            ledger_path = Path(args.ledger)
            ledger_path.parent.mkdir(parents=True, exist_ok=True)
            ledger_path.write_text(
                json.dumps(ledger.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
            payload = {
                "detector_id": args.detector,
                "capability": args.capability,
                "tier": tier.value,
                "artifact": args.artifact,
                "registered": True,
            }
            _write_json(None, payload)
            print(f"Registered: {args.detector}/{args.capability} ({tier.value})")

    elif args.command == "bundle":
        if args.bundle_command == "pack":
            manifest = pack_bundle(args.case_file, args.output)
            _write_json(None, manifest.to_dict())
        elif args.bundle_command == "verify":
            result = verify_bundle(args.bundle, expected_digest=args.expect_digest)
            _write_json(None, result.to_dict())
            return EXIT_OK if result.valid else EXIT_INCOMPLETE
        elif args.bundle_command == "list":
            entries = list_bundle(args.bundle)
            _write_json(None, entries)

    elif args.command == "verify":
        case_payload = None
        calibration_artifact = None
        benchmark_result = None

        if args.case_file:
            case_payload = json.loads(Path(args.case_file).read_text(encoding="utf-8"))
        if args.calibration:
            calibration_artifact = json.loads(Path(args.calibration).read_text(encoding="utf-8"))
        if args.benchmark:
            benchmark_result = json.loads(Path(args.benchmark).read_text(encoding="utf-8"))

        if args.all and not (case_payload or calibration_artifact or benchmark_result):
            # --all without explicit paths: verify every artifact we can find
            _write_json(
                None,
                {
                    "valid": False,
                    "errors": ["No artifacts provided for verification"],
                },
            )
            return EXIT_ERROR

        report = verify_all(
            case_payload=case_payload,
            calibration_artifact=calibration_artifact,
            benchmark_result=benchmark_result,
        )
        _write_json(None, report.to_dict())
        return EXIT_OK if report.overall_valid else EXIT_INCOMPLETE

    elif args.command == "build-info":
        if args.verify:
            result = verify_build_identity(expected_commit=args.expected_commit)
            _write_json(None, result)
            return EXIT_OK if result.get("valid") else EXIT_INCOMPLETE
        else:
            _write_json(None, get_build_info())

    elif args.command == "policy":
        return _run_policy_command(args)

    elif args.command == "audit":
        return _run_audit_command(args)

    elif args.command == "emergency":
        return _run_emergency_command(args)

    return EXIT_OK


def _run_audit_anchor_command(args: argparse.Namespace) -> int:
    """Handle audit anchor CLI commands (export/verify) for rollback detection."""
    base_dir = Path(args.base_dir) if getattr(args, "base_dir", None) else None

    if args.anchor_command == "export":
        output = args.anchor_arg
        if not output:
            print("error: audit export requires an output path", file=sys.stderr)
            return EXIT_ERROR

        chain = None
        if getattr(args, "chain", None):
            chain = CalibrationChain()
            chain.load_from_file(Path(args.chain))

        anchor = export_audit_anchor(
            base_dir=base_dir,
            calibration_chain=chain.hashes if chain else None,
        )
        anchor_data = anchor.to_dict()
        Path(output).write_text(
            json.dumps(anchor_data, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(output)
        return EXIT_OK

    elif args.anchor_command == "verify":
        anchor_path = args.anchor_arg
        if not anchor_path:
            print("error: audit verify requires an anchor file path", file=sys.stderr)
            return EXIT_ERROR

        try:
            anchor_data = json.loads(Path(anchor_path).read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            print(f"error: failed to read anchor file: {exc}", file=sys.stderr)
            return EXIT_ERROR

        anchor = AuditAnchor.from_dict(anchor_data)

        current_chain = None
        if getattr(args, "chain", None):
            current_chain = CalibrationChain()
            current_chain.load_from_file(Path(args.chain))

        try:
            status = verify_audit_anchor(
                anchor,
                current_chain=current_chain,
                base_dir=base_dir,
            )
        except RollbackError as exc:
            print(f"error: rollback detected: {exc}", file=sys.stderr)
            _write_json(
                None,
                {
                    "valid": False,
                    "error": str(exc),
                    "anchor": anchor_data,
                },
            )
            return EXIT_ERROR

        result = {
            "valid": True,
            "status": status,
            "anchor": anchor_data,
        }
        _write_json(None, result)
        return EXIT_OK

    return EXIT_ERROR


def _run_policy_command(args: argparse.Namespace) -> int:
    """Handle enterprise policy CLI commands."""
    state_path = Path(args.state_path) if getattr(args, "state_path", None) else None
    key_path = Path(args.key_path) if getattr(args, "key_path", None) else None

    floor = PolicyRevisionFloor(
        state_path=state_path,
        key_path=key_path,
    )

    if args.policy_command == "load":
        # Read and validate the policy file
        try:
            policy_data = json.loads(Path(args.file).read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            print(f"error: failed to read policy file: {exc}", file=sys.stderr)
            return EXIT_ERROR

        # Schema validation
        schema_errors = validate_enterprise_policy(policy_data)
        if schema_errors:
            print("error: policy schema validation failed:", file=sys.stderr)
            for err in schema_errors:
                print(f"  - {err}", file=sys.stderr)
            return EXIT_INCOMPLETE

        # Compute digest
        computed_digest = hashlib.sha256(
            json.dumps(
                {
                    "revision": policy_data["revision"],
                    "settings": policy_data.get("settings", {}),
                    "rules": [
                        {
                            "id": r["id"],
                            "description": r["description"],
                            "action": r["action"],
                            "scope": r["scope"],
                        }
                        for r in policy_data.get("rules", [])
                    ],
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()

        # Check digest if provided
        if "digest" in policy_data and policy_data["digest"] != computed_digest:
            print(
                f"error: digest mismatch: stored {policy_data['digest'][:16]}... "
                f"computed {computed_digest[:16]}...",
                file=sys.stderr,
            )
            return EXIT_ERROR

        policy = EnterprisePolicy(
            revision=int(policy_data["revision"]),
            digest=computed_digest,
            settings=dict(policy_data.get("settings", {})),
            rules=[dict(r) for r in policy_data.get("rules", [])],
        )

        # Check floor
        rejections = floor.check_policy(policy)
        if rejections:
            print("error: policy rejected by revision floor:", file=sys.stderr)
            for rej in rejections:
                print(f"  - {rej}", file=sys.stderr)
            return EXIT_INCOMPLETE

        if not args.no_advance:
            floor.advance_floor(policy)

        payload = {
            "accepted": True,
            "revision": policy.revision,
            "digest": policy.digest,
            "floor_revision": floor.floor_revision,
            "floor_digest": floor.floor_digest,
        }
        _write_json(None, payload)
        return EXIT_OK

    elif args.policy_command == "check":
        # Check current floor against a provided policy (if any)
        if args.file:
            try:
                policy_data = json.loads(Path(args.file).read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                print(f"error: failed to read policy file: {exc}", file=sys.stderr)
                return EXIT_ERROR

            # Compute digest
            computed_digest = hashlib.sha256(
                json.dumps(
                    {
                        "revision": policy_data["revision"],
                        "settings": policy_data.get("settings", {}),
                        "rules": [
                            {
                                "id": r["id"],
                                "description": r["description"],
                                "action": r["action"],
                                "scope": r["scope"],
                            }
                            for r in policy_data.get("rules", [])
                        ],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("utf-8")
            ).hexdigest()

            policy = EnterprisePolicy(
                revision=int(policy_data["revision"]),
                digest=computed_digest,
                settings=dict(policy_data.get("settings", {})),
                rules=[dict(r) for r in policy_data.get("rules", [])],
            )
            rejections = floor.check_policy(policy)
            result = {
                "floor_revision": floor.floor_revision,
                "floor_digest": floor.floor_digest,
                "policy_revision": policy.revision,
                "policy_digest": policy.digest,
                "rejections": rejections,
                "valid": len(rejections) == 0,
            }
        else:
            result = {
                "floor_revision": floor.floor_revision,
                "floor_digest": floor.floor_digest,
                "rejections": [],
                "valid": True,
            }

        _write_json(None, result)
        return EXIT_OK if result["valid"] else EXIT_INCOMPLETE

    elif args.policy_command == "advance":
        try:
            policy_data = json.loads(Path(args.file).read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            print(f"error: failed to read policy file: {exc}", file=sys.stderr)
            return EXIT_ERROR

        # Schema validation
        schema_errors = validate_enterprise_policy(policy_data)
        if schema_errors:
            print("error: policy schema validation failed:", file=sys.stderr)
            for err in schema_errors:
                print(f"  - {err}", file=sys.stderr)
            return EXIT_INCOMPLETE

        # Compute digest
        computed_digest = hashlib.sha256(
            json.dumps(
                {
                    "revision": policy_data["revision"],
                    "settings": policy_data.get("settings", {}),
                    "rules": [
                        {
                            "id": r["id"],
                            "description": r["description"],
                            "action": r["action"],
                            "scope": r["scope"],
                        }
                        for r in policy_data.get("rules", [])
                    ],
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()

        if "digest" in policy_data and policy_data["digest"] != computed_digest:
            print(
                f"error: digest mismatch: stored {policy_data['digest'][:16]}... "
                f"computed {computed_digest[:16]}...",
                file=sys.stderr,
            )
            return EXIT_ERROR

        policy = EnterprisePolicy(
            revision=int(policy_data["revision"]),
            digest=computed_digest,
            settings=dict(policy_data.get("settings", {})),
            rules=[dict(r) for r in policy_data.get("rules", [])],
        )

        # Check floor
        rejections = floor.check_policy(policy)
        if rejections:
            print("error: cannot advance floor:", file=sys.stderr)
            for rej in rejections:
                print(f"  - {rej}", file=sys.stderr)
            return EXIT_INCOMPLETE

        # Advance
        floor.advance_floor(policy)

        payload = {
            "advanced": True,
            "revision": policy.revision,
            "digest": policy.digest,
            "floor_revision": floor.floor_revision,
            "floor_digest": floor.floor_digest,
        }
        _write_json(None, payload)
        return EXIT_OK

    elif args.policy_command == "export":
        result = {
            "floor_revision": floor.floor_revision,
            "floor_digest": floor.floor_digest,
            "history": floor.state.history,
        }
        _write_json(None, result)
        return EXIT_OK

    return EXIT_ERROR


def _run_emergency_command(args: argparse.Namespace) -> int:
    """Handle emergency stop CLI subcommands (status/activate/deactivate)."""
    sentinel = EmergencyStopSentinel()
    if getattr(args, "path", None):
        sentinel.configure(args.path)

    if args.emergency_command == "status":
        active = sentinel.is_active()
        payload = {
            "active": active,
            "path": str(sentinel._resolve()) if sentinel._resolve() else None,
            "env_var": "TEXTFORENSICS_EMERGENCY_STOP",
        }
        _write_json(None, payload)
        print(
            "EMERGENCY STOP: ACTIVE"
            if active
            else "Emergency stop: not active"
        )
        return EXIT_OK

    elif args.emergency_command == "activate":
        try:
            path = sentinel.activate()
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        payload = {
            "activated": True,
            "path": str(path),
            "active": True,
        }
        _write_json(None, payload)
        print(f"Emergency stop activated: {path}")
        return EXIT_OK

    elif args.emergency_command == "deactivate":
        try:
            removed = sentinel.deactivate()
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        payload = {
            "deactivated": True,
            "removed": removed,
            "active": sentinel.is_active(),
        }
        _write_json(None, payload)
        print(
            "Emergency stop deactivated."
            if removed
            else "No sentinel file was present."
        )
        return EXIT_OK

    return EXIT_ERROR


def main() -> int:
    """Main entry point for the argparse-based CLI.

    Delegates to the Typer CLI if --typer flag is used or TEXTFORENSICS_CLI=typer env var is set.
    """
    import os

    # Check if Typer CLI should be used
    use_typer = os.environ.get("TEXTFORENSICS_CLI") == "typer"

    # Check for --typer flag early (before full parsing)
    if "--typer" in sys.argv:
        use_typer = True
        sys.argv = [a for a in sys.argv if a != "--typer"]

    if use_typer:
        try:
            from .typer_cli import main as typer_main

            return typer_main()
        except ImportError:
            print(
                "error: Typer CLI not available. Install with: pip install textforensics[cli-typer]",
                file=sys.stderr,
            )
            return EXIT_ERROR

    parser = build_parser()
    args = parser.parse_args()
    try:
        settings = Settings.from_env()
        return _run(args, settings)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
