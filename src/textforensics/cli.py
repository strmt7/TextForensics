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
from .casefile import verify_case_file_path, write_case_file
from .compare import compare_texts
from .config import Settings, read_text_file, validate_text_input
from .detectors import (
    list_detector_health,
    list_detector_metadata,
    list_optional_detector_metadata,
    load_detector,
)
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


def _configured_detector_ids(
    cli_ids: list[str] | None,
    settings: Settings,
) -> tuple[str, ...] | None:
    if cli_ids:
        return tuple(cli_ids)
    return settings.detector_ids or None


def _benchmark_detector(
    detector_id: str | None,
    settings: Settings,
):
    selected = detector_id
    if selected is None and len(settings.detector_ids) == 1:
        selected = settings.detector_ids[0]
    elif selected is None and len(settings.detector_ids) > 1:
        raise ValueError(
            "Benchmark/calibrate operate on one detector at a time. "
            "Pass --detector explicitly."
        )
    return load_detector(selected) if selected else None


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
    calibrate.add_argument("--detector")
    calibrate.add_argument("--output", "-o")

    bench = sub.add_parser(
        "benchmark",
        help="Evaluate one detector on labeled JSONL.",
    )
    bench.add_argument("dataset")
    bench.add_argument("--detector")
    group = bench.add_mutually_exclusive_group()
    group.add_argument("--threshold", type=float)
    group.add_argument("--calibration", help="Calibration artifact JSON.")
    bench.add_argument(
        "--allow-same-dataset",
        action="store_true",
        help="Diagnostic only: permit evaluation on the calibration dataset.",
    )

    detectors = sub.add_parser(
        "detectors",
        help="List installed and optional detector adapters.",
    )
    detectors.add_argument("--health", action="store_true")

    report = sub.add_parser(
        "report",
        help="Build a reproducible detector-evidence bundle.",
    )
    report.add_argument("--file", "-f")
    report.add_argument("--ledger")
    report.add_argument("--detector", action="append")
    report.add_argument("--output", "-o")

    case = sub.add_parser("case", help="Export or verify a sealed case file.")
    case_sub = case.add_subparsers(dest="case_command", required=True)
    case_export = case_sub.add_parser("export", help="Export a sealed case file.")
    case_export.add_argument("--file", "-f")
    case_export.add_argument("--ledger")
    case_export.add_argument("--detector", action="append")
    case_export.add_argument("--output", "-o", required=True)
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
        detector_ids=base.detector_ids,
    )


def _run(args: argparse.Namespace, settings: Settings) -> int:
    if args.command == "scan":
        result = analyze_text(_read_text(args.file, settings))
        if args.json:
            _write_json(None, result.to_dict())
        else:
            _pretty_analysis(result)

    elif args.command == "audit":
        result = audit_naturalness(_read_text(args.file, settings))
        if args.json:
            _write_json(None, result)
        else:
            for item in result:
                print(f"- {item['issue']}: {item['suggestion']}")

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
        _write_json(None, result.to_dict()) if args.json else print(result)

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
            detector=_benchmark_detector(args.detector, settings),
        )
        _write_json(args.output, artifact)

    elif args.command == "benchmark":
        explicit = _benchmark_detector(args.detector, settings)
        if args.calibration:
            calibration = load_calibration_artifact(args.calibration)
            result = benchmark_with_calibration_jsonl(
                args.dataset,
                calibration,
                detector=explicit,
                allow_same_dataset=args.allow_same_dataset,
            )
        else:
            result = benchmark_jsonl(
                args.dataset,
                threshold=args.threshold if args.threshold is not None else 0.5,
                detector=explicit,
            )
        _write_json(None, result)

    elif args.command == "detectors":
        payload = {
            "detectors": list_detector_metadata(),
            "optional_detectors": list_optional_detector_metadata(),
            "plugin_health": list_detector_health() if args.health else [],
        }
        _write_json(None, payload)

    elif args.command == "report":
        bundle = build_forensic_bundle(
            _read_text(args.file, settings),
            detector_ids=_configured_detector_ids(args.detector, settings),
            ledger_path=args.ledger,
        )
        _write_json(args.output, bundle.to_dict())

    elif args.command == "case":
        if args.case_command == "export":
            bundle = build_forensic_bundle(
                _read_text(args.file, settings),
                detector_ids=_configured_detector_ids(args.detector, settings),
                ledger_path=args.ledger,
            )
            write_case_file(args.output, bundle.to_dict())
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
            detector_ids=active.detector_ids or None,
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
