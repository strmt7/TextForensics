from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .benchmark import (
    benchmark_jsonl,
    benchmark_with_calibration_jsonl,
    calibrate_threshold_jsonl,
    load_calibration_artifact,
)
from .capability_ledger import (
    CapabilityClaim,
    CapabilityLedger,
    EvidenceLabel,
    EvidenceRef,
    EvidenceTier,
)
from .benchmark_fingerprint import (
    check_disjointness,
    fingerprint_dataset,
)
from .casefile import verify_case_file_path, write_case_file
from .compare import compare_texts
from .config import Settings, read_text_file, validate_text_input
from .detectors import list_detector_health, list_detector_metadata
from .drift import DriftObservatory
from .engine import analyze_text
from .localize import localize_text
from .naturalness import audit_naturalness
from .provenance import snapshot_file, verify_ledger
from .report import build_forensic_bundle
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
        print(
            f"  {item.name:24s} {item.score:.1%}  "
            f"diagnostic reliability {item.reliability:.1%}"
        )
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
        "--version",
        action="version",
        version=f"%(prog)s {get_version()}",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run the local alpha pattern baseline.")
    scan.add_argument("--file", "-f")
    scan.add_argument("--json", action="store_true")
    scan.add_argument("--deterministic", action="store_true", help="Use fixed timestamp and remove runtime_ms for reproducible output")

    natural = sub.add_parser(
        "audit",
        help="Audit formulaic/naturalness patterns without rewriting.",
    )
    natural.add_argument("--file", "-f")
    natural.add_argument("--json", action="store_true")

    localize = sub.add_parser(
        "localize",
        help="Score consecutive text segments for diagnostic localization.",
    )
    localize.add_argument("--file", "-f")
    localize.add_argument("--sentences", type=int, default=4)

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
    fp_cmd.add_argument(
        "--output", "-o", help="Path to write fingerprint JSON (default: stdout)."
    )
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

    report = sub.add_parser(
        "report",
        help="Build a reproducible detector-evidence bundle.",
    )
    report.add_argument("--file", "-f")
    report.add_argument("--ledger")
    report.add_argument("--output", "-o")
    report.add_argument("--deterministic", action="store_true", help="Use fixed timestamp for reproducible output")
    report.add_argument("--fixed-timestamp", help="Fixed ISO timestamp for reproducible output")

    case = sub.add_parser("case", help="Export or verify a sealed case file.")
    case_sub = case.add_subparsers(dest="case_command", required=True)
    case_export = case_sub.add_parser("export", help="Export a sealed case file.")
    case_export.add_argument("--file", "-f")
    case_export.add_argument("--ledger")
    case_export.add_argument("--output", "-o", required=True)
    case_export.add_argument("--deterministic", action="store_true", help="Use fixed timestamp for reproducible output")
    case_export.add_argument("--fixed-timestamp", help="Fixed ISO timestamp for reproducible output")
    case_verify = case_sub.add_parser("verify", help="Verify case-file integrity.")
    case_verify.add_argument("case_file")

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
        default=str(Path(__file__).resolve().parent.parent.parent / "testdata" / "drift_corpus.json"),
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
        default=str(Path(__file__).resolve().parent.parent.parent / "testdata" / "drift_corpus.json"),
        help="Path to a drift corpus JSON file.",
    )
    drift_compare.add_argument("--output", "-o", help="Write the drift report to this JSON file.")

    drift_report = drift_sub.add_parser("report", help="Generate a drift report from two snapshots.")
    drift_report.add_argument("baseline", help="Path to the baseline snapshot JSON.")
    drift_report.add_argument("current", help="Path to the current snapshot JSON.")
    drift_report.add_argument(
        "--corpus",
        default=str(Path(__file__).resolve().parent.parent.parent / "testdata" / "drift_corpus.json"),
        help="Path to a drift corpus JSON file.",
    )
    drift_report.add_argument("--output", "-o", help="Write the drift report to this JSON file.")

    cap = sub.add_parser(
        "capability",
        help="Inspect detector capability claims in the capability ledger.",
    )
    cap_sub = cap.add_subparsers(dest="capability_command", required=True)

    cap_list = cap_sub.add_parser("list", help="List all registered capabilities.")
    cap_list.add_argument("--detector", help="Filter by detector ID.")

    cap_check = cap_sub.add_parser(
        "check",
        help="Check whether a capability claim is validated.",
    )
    cap_check.add_argument("detector", help="Detector ID.")
    cap_check.add_argument("capability", help="Capability name.")

    cap_export = cap_sub.add_parser(
        "export",
        help="Export the capability ledger as JSON.",
    )
    cap_export.add_argument(
        "--output",
        "-o",
        help="Path to write JSON (default: stdout).",
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
        allow_remote=(
            allow_remote if allow_remote is not None else base.allow_remote
        ),
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


def _run(args: argparse.Namespace, settings: Settings) -> int:
    if args.command == "scan":
        result = analyze_text(_read_text(args.file, settings))
        if args.json:
            data = result.to_dict()
            if hasattr(args, "deterministic") and args.deterministic:
                data = _strip_runtime_ms(data)
            _write_json(None, data)
        else:
            _pretty_analysis(result)

    elif args.command == "audit":
        result = audit_naturalness(_read_text(args.file, settings))
        _write_json(None, result)

    elif args.command == "localize":
        if args.sentences < 1:
            raise ValueError("--sentences must be at least 1.")
        result = [
            row.to_dict()
            for row in localize_text(
                _read_text(args.file, settings),
                sentences_per_segment=args.sentences,
            )
        ]
        _write_json(None, result)

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
        return 0 if result.get("valid") else 1

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
            write_case_file(args.output, bundle_dict, deterministic=args.deterministic, fixed_timestamp=args.fixed_timestamp)
            print(args.output)
        else:
            result = verify_case_file_path(args.case_file)
            _write_json(None, result)
            return 0 if result.get("valid") else 1

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

    elif args.command == "capability":
        ledger = _load_default_ledger()
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

    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        settings = Settings.from_env()
        return _run(args, settings)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
