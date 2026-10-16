from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .benchmark import benchmark_jsonl, calibrate_threshold_jsonl
from .compare import compare_texts
from .engine import analyze_text
from .detectors import list_detector_metadata
from .report import build_forensic_bundle
from .naturalness import audit_naturalness
from .localize import localize_text
from .provenance import snapshot_file, verify_ledger
from .webapp import serve as serve_webapp


def _read_text(path: str | None) -> str:
    if path:
        return Path(path).read_text(encoding="utf-8")
    if sys.stdin.isatty():
        raise SystemExit("Provide --file or pipe text through stdin.")
    return sys.stdin.read()


def _pretty_analysis(result) -> None:
    print("TextForensics")
    print("=" * 56)
    print(f"Verdict              {result.verdict}")
    print(f"Pattern score        {result.score:.1%}")
    print(f"Confidence           {result.confidence:.1%}")
    print(f"Analyzer disagreement {result.disagreement:.1%}")
    print(f"Robustness stability {result.robustness_stability:.1%}")
    print(f"Words                {result.word_count}")
    print("\nAnalyzers")
    for item in result.analyzers:
        print(f"  {item.name:24s} {item.score:.1%}  reliability {item.reliability:.1%}")
    if result.warnings:
        print("\nWarnings")
        for warning in result.warnings:
            print(f"  - {warning}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="textforensics")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Analyze text with the local evidence ensemble.")
    scan.add_argument("--file", "-f")
    scan.add_argument("--json", action="store_true")

    natural = sub.add_parser("audit", help="Audit formulaic/naturalness patterns without rewriting.")
    natural.add_argument("--file", "-f")
    natural.add_argument("--json", action="store_true")

    localize = sub.add_parser("localize", help="Score consecutive text segments to locate heterogeneous regions.")
    localize.add_argument("--file", "-f")
    localize.add_argument("--sentences", type=int, default=4)

    compare = sub.add_parser("compare", help="Compare two text versions.")
    compare.add_argument("before")
    compare.add_argument("after")
    compare.add_argument("--json", action="store_true")

    snapshot = sub.add_parser("snapshot", help="Append a tamper-evident draft snapshot to a local ledger.")
    snapshot.add_argument("file")
    snapshot.add_argument("--ledger", default=".textforensics-ledger.jsonl")

    verify = sub.add_parser("verify-ledger", help="Verify the local provenance ledger hash chain.")
    verify.add_argument("ledger", nargs="?", default=".textforensics-ledger.jsonl")

    calibrate = sub.add_parser("calibrate", help="Choose a threshold for a target false-positive rate.")
    calibrate.add_argument("dataset")
    calibrate.add_argument("--target-fpr", type=float, default=0.01)

    bench = sub.add_parser("benchmark", help="Evaluate the baseline detector on labeled JSONL.")
    bench.add_argument("dataset")
    bench.add_argument("--threshold", type=float, default=0.5)

    detectors = sub.add_parser("detectors", help="List installed TFDP/1 detector adapters.")

    report = sub.add_parser("report", help="Build a reproducible forensic evidence bundle.")
    report.add_argument("--file", "-f")
    report.add_argument("--ledger", help="Optional provenance ledger to verify and include.")
    report.add_argument("--output", "-o", help="Write JSON bundle to a file instead of stdout.")

    web = sub.add_parser("web", help="Open the zero-dependency local browser UI.")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8765)
    web.add_argument("--no-browser", action="store_true")

    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "scan":
        result = analyze_text(_read_text(args.file))
        if args.json:
            print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        else:
            _pretty_analysis(result)
    elif args.command == "audit":
        result = audit_naturalness(_read_text(args.file))
        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            for item in result:
                print(f"- {item['issue']}: {item['suggestion']}")
    elif args.command == "localize":
        result = [r.to_dict() for r in localize_text(_read_text(args.file), sentences_per_segment=args.sentences)]
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.command == "compare":
        result = compare_texts(Path(args.before).read_text(encoding="utf-8"), Path(args.after).read_text(encoding="utf-8"))
        print(json.dumps(result.to_dict(), indent=2) if args.json else result)
    elif args.command == "snapshot":
        print(json.dumps(snapshot_file(args.file, args.ledger), indent=2))
    elif args.command == "verify-ledger":
        print(json.dumps(verify_ledger(args.ledger), indent=2))
    elif args.command == "calibrate":
        print(json.dumps(calibrate_threshold_jsonl(args.dataset, target_fpr=args.target_fpr), indent=2))
    elif args.command == "benchmark":
        print(json.dumps(benchmark_jsonl(args.dataset, threshold=args.threshold), indent=2))
    elif args.command == "detectors":
        print(json.dumps(list_detector_metadata(), indent=2, ensure_ascii=False))
    elif args.command == "report":
        bundle = build_forensic_bundle(_read_text(args.file), ledger_path=args.ledger)
        payload = json.dumps(bundle.to_dict(), indent=2, ensure_ascii=False)
        if args.output:
            Path(args.output).write_text(payload + "\n", encoding="utf-8")
            print(args.output)
        else:
            print(payload)
    elif args.command == "web":
        serve_webapp(args.host, args.port, open_browser=not args.no_browser)


if __name__ == "__main__":
    main()
