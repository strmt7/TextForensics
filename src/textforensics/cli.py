from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from ._build_info import (
    get_build_info,
    get_version,
    verify_build_identity,
)
from .benchmark import (
    benchmark_jsonl,
    benchmark_with_calibration_jsonl,
    calibrate_threshold_jsonl,
    check_disjointness,
    fingerprint_dataset,
    load_calibration_artifact,
)
from .bundle import list_bundle, pack_bundle, read_bundle, verify_bundle
from .bundle_consistency import check_bundle_consistency
from .casefile import write_case_file
from .config import Settings, ensure_bind_allowed, read_text_file, validate_text_input
from .constants import (
    EXIT_DOWNGRADED,
    EXIT_ERROR,
    EXIT_INCOMPLETE,
    EXIT_OK,
)
from .detectors import list_detector_health, list_detector_metadata
from .emergency_stop import (
    EmergencyStopSentinel,
    check_emergency_stop,
)
from .engine import analyze_text, compare_texts
from .features import audit_naturalness
from .ledger import (
    AuditAnchor,
    CalibrationChain,
    RollbackError,
    export_audit_anchor,
    snapshot_file,
    verify_audit_anchor,
    verify_ledger,
)
from .localize import (
    detect_anomalous_segments,
    localize_text,
    segment_to_dict,
    visual_diff,
)
from .observatory import DriftObservatory
from .policy import (
    CapabilityClaim,
    CapabilityLedger,
    EvidenceLabel,
    EvidenceRef,
    EvidenceTier,
    create_calibration_policy,
    create_minimum_viable_policy,
    create_production_policy,
    create_report_generation_policy,
)
from .report import build_forensic_bundle
from .verify import verify_all, verify_case_file_path_combined


# Lazy imports for enterprise features (dependency optional)
def _import_enterprise():
    """Lazily import enterprise policy module."""
    from . import policy as ep

    return ep


def _read_text(path: str | None, settings: Settings, text: str | None = None) -> str:
    """Read input text from --file, --text, or stdin (in that order).

    ``--text`` is validated like file/stdin input (non-empty, within the
    configured byte limit). Kept from the former Typer CLI, which offered
    the same convenience flag on scan/report/case export/audit.
    """
    if path:
        return read_text_file(
            path,
            max_input_bytes=settings.max_input_bytes,
        )
    if text is not None:
        return validate_text_input(
            text,
            max_input_bytes=settings.max_input_bytes,
        )
    if sys.stdin.isatty():
        raise ValueError("Provide --file, --text, or pipe text through stdin.")
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


# ---------------------------------------------------------------------------
# Sealed case files (Phase 3 U2): key loading, scope statement, verify/seal
# ---------------------------------------------------------------------------

_SEAL_SCOPE_TEMPLATE = (
    "seal: integrity since sealing only — origin: {origin} — "
    "time: {time_part} — replay: {replay_status}"
)


def _load_public_key_arg(value: str) -> bytes:
    """Load a 32-byte Ed25519 public key for ``case verify --public-key``.

    Accepts, in order:

    - a sealing-key file (``textforensics.sealing-key/v1`` JSON — the
      seed is validated against the public key on load, and only the
      public half is used),
    - a public-key file (JSON with a ``public_key_b64`` field, as
      written by ``case keygen --public-out``),
    - a file holding 64 hex characters or exactly 32 raw bytes,
    - a bare 64-hex-character string.

    Raises ``ValueError`` on anything else.  A private key is never
    printed or returned — only the 32 public bytes.
    """
    import base64

    candidate = value.strip()
    if Path(candidate).exists():
        raw = Path(candidate).read_bytes()
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            parsed = None
        if isinstance(parsed, dict) and parsed.get("public_key_b64"):
            try:
                key = base64.b64decode(parsed["public_key_b64"], validate=True)
            except (ValueError, TypeError) as exc:
                raise ValueError(
                    f"public key file {candidate} has an invalid public_key_b64"
                ) from exc
            if len(key) != 32:
                raise ValueError(f"public key file {candidate} does not hold a 32-byte key")
            if parsed.get("seed_b64"):
                # A full sealing-key file: validate seed/public/keyid
                # (and the POSIX mode) before trusting the public half.
                from .sealing import load_sealing_key

                load_sealing_key(candidate)
            return key
        if len(raw) == 32:
            return raw
        candidate = raw.decode("ascii", "ignore").strip()
    try:
        key = bytes.fromhex(candidate)
    except ValueError as exc:
        raise ValueError(
            "--public-key must be a sealing-key file, a public-key file, "
            "a file holding 64 hex characters, or a 64-hex-character string"
        ) from exc
    if len(key) != 32:
        raise ValueError("--public-key must hold a 32-byte Ed25519 public key")
    return key


def _case_scope_statement(
    case: dict[str, Any],
    result: dict[str, Any],
    *,
    token_report: dict[str, Any] | None = None,
    replay_status: str = "not requested",
) -> str:
    """One-line scope statement for a bare case-file verification.

    Same shape as the standalone verifier's statement: the seal proves
    integrity since sealing only (never authorship, never that the
    analysis was run), the origin is authenticated only when a T2
    signature verified, and the time is a local claim unless a
    timestamp token verified.
    """
    primary = result.get("primary") or {}
    warnings = primary.get("warnings") or []
    errors = primary.get("errors") or []
    seal = case.get("seal") or {}
    if any(str(w).startswith("signature_invalid") for w in errors):
        origin = "signature failed"
    elif any(str(w).startswith("signature_present_public_key_not_supplied") for w in warnings):
        origin = "not checked (no public key supplied)"
    elif seal.get("signature") is not None:
        origin = "signature verified"
    else:
        origin = "T1 hash seal only (origin not authenticated)"
    if token_report is not None and token_report.get("valid"):
        time_part = "RFC 3161 genTime {} (non-qualified)".format(token_report.get("gen_time"))
    else:
        time_part = "local claim only"
    return _SEAL_SCOPE_TEMPLATE.format(
        origin=origin, time_part=time_part, replay_status=replay_status
    )


def _verify_case_cli(args: argparse.Namespace, settings: Settings) -> int:
    """``case verify``: bare case file or sealed bundle.

    Exit codes follow the MPL contract: 0 = seal verified, 1 = seal
    failed (tamper, mismatch, invalid token), 2 = checks could not run
    (signature present but no public key supplied, replay unavailable).
    """
    import hashlib

    from .casefile import replay_case_file_path
    from .sealed_bundle import canonical_json_bytes, verify_sealed_bundle
    from .timestamp import verify_timestamp_token

    path = Path(args.case_file)
    data = path.read_bytes()
    public_key = _load_public_key_arg(args.public_key) if args.public_key else None
    replay_text: str | None = None
    if args.text is not None and args.text_file is not None:
        raise ValueError("Use only one of --text and --text-file.")
    if args.text is not None:
        replay_text = validate_text_input(args.text, max_input_bytes=settings.max_input_bytes)
    elif args.text_file is not None:
        replay_text = _read_file_text(args.text_file, settings)

    if data[:4] == b"PK\x03\x04":
        if args.timestamp_token is not None:
            raise ValueError(
                "--timestamp-token is for bare case files; a sealed bundle "
                "carries its token inside."
            )
        report = verify_sealed_bundle(
            data,
            expected_digest=args.expect_digest,
            public_key=public_key,
            text=replay_text,
        )
        _write_json(None, report)
        return report["exit_code"]

    # Bare case file (JSON).
    if args.expect_digest is not None:
        digest = args.expect_digest.strip().lower()
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("--expect-digest must be a 64-character hex digest")
        if hashlib.sha256(data).hexdigest() != digest:
            result = verify_case_file_path_combined(path, public_key=public_key)
            result["errors"] = [
                "expected digest mismatch: the case file bytes do not match --expect-digest"
            ] + list(result.get("errors") or [])
            result["valid"] = False
            _write_json(None, result)
            return EXIT_DOWNGRADED
    result = verify_case_file_path_combined(path, public_key=public_key)
    try:
        case = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        case = {}
    if not isinstance(case, dict):
        case = {}
    gaps = case.get("gaps") if isinstance(case.get("gaps"), list) else []

    token_report: dict[str, Any] | None = None
    if args.timestamp_token is not None:
        token = Path(args.timestamp_token).read_bytes()
        token_report = verify_timestamp_token(
            token,
            expected_digest=hashlib.sha256(canonical_json_bytes(case)).digest(),
        )
        result["timestamp"] = token_report
        if not token_report["valid"]:
            result["valid"] = False
            result["errors"] = list(result.get("errors") or []) + [
                "timestamp token does not verify: " + "; ".join(token_report["errors"])
            ]

    replay_status = "not requested"
    if replay_text is not None:
        replay = replay_case_file_path(path, text=replay_text)
        result["replay"] = replay
        replay_status = "verified" if replay.get("valid") else "failed"
        if not replay.get("valid"):
            result["valid"] = False
            result["errors"] = list(result.get("errors") or []) + list(replay.get("errors") or [])
    result["gaps"] = gaps
    result["scope"] = _case_scope_statement(
        case, result, token_report=token_report, replay_status=replay_status
    )
    _write_json(None, result)
    if not result.get("valid"):
        return EXIT_DOWNGRADED
    primary = result.get("primary") or {}
    warnings = primary.get("warnings") or []
    if any(str(w).startswith("signature_present_public_key_not_supplied") for w in warnings):
        return EXIT_INCOMPLETE
    if replay_text is not None and replay_status == "failed":
        return EXIT_DOWNGRADED
    return EXIT_OK


def _sealed_bundle_paths(output: str) -> tuple[Path, Path]:
    """Bundle + seal-record paths derived from a ``case export`` output."""
    out = Path(output)
    bundle = (
        out.with_suffix(".sealed.zip") if out.suffix == ".json" else Path(str(out) + ".sealed.zip")
    )
    return bundle, Path(str(bundle) + ".seal.json")


def _seal_exported_case(
    args: argparse.Namespace,
    case: dict[str, Any],
    *,
    signing_seed: bytes | None = None,
    signer: dict[str, Any] | None = None,
) -> None:
    """Pack the just-exported case into a sealed bundle (``--seal``)."""
    import hashlib

    from .sealed_bundle import canonical_json_bytes, write_sealed_bundle
    from .timestamp import request_timestamp

    bundle_path, record_path = _sealed_bundle_paths(args.output)
    token: bytes | None = None
    if args.timestamp_url is not None:
        # Fail closed: a requested timestamp that cannot be obtained is
        # an error, never a silent T1/T2 bundle the user thinks is T3.
        report = request_timestamp(
            hashlib.sha256(canonical_json_bytes(case)).digest(),
            args.timestamp_url,
        )
        token = report["token_der"]
    write_sealed_bundle(
        case,
        bundle_path,
        record_path,
        signing_seed=signing_seed,
        signer=signer,
        timestamp_token=token,
        tsa_url=args.timestamp_url,
    )
    print(str(bundle_path))
    print(str(record_path))


def _keygen_cli(args: argparse.Namespace) -> int:
    """``case keygen``: generate a sealing-key file (Ed25519, mode 0600)."""
    import base64
    import getpass

    from .sealing import generate_sealing_key, public_key_info, save_sealing_key

    identity = args.identity or getpass.getuser()
    key = generate_sealing_key(identity, args.role)
    save_sealing_key(args.output, key)
    public_out = getattr(args, "public_out", None)
    if public_out is not None:
        info = public_key_info(key)
        Path(public_out).write_text(
            json.dumps(info, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    _write_json(
        None,
        {
            "key_file": args.output,
            "keyid": key["keyid"],
            "public_key_hex": base64.b64decode(key["public_key_b64"]).hex(),
            "identity": key["identity"],
            "role": key["role"],
            "public_key_file": public_out,
        },
    )
    return EXIT_OK


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
    scan.add_argument("--text", "-t", help="Provide text directly instead of --file or stdin.")
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
    natural.add_argument("--text", "-t", help="Provide text directly instead of --file or stdin.")
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
        # Default matches the live builtin detector's version
        # (detectors.BuiltinHeuristicDetector.detector_version).
        default="0.1.0",
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
        choices=[
            "forensic-bundle",
            "detector-result",
            "case-file",
            "trust-map",
            "enterprise-policy",
        ],
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
    report.add_argument("--text", "-t", help="Provide text directly instead of --file or stdin.")
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
    case_export.add_argument(
        "--text", "-t", help="Provide text directly instead of --file or stdin."
    )
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
    case_export.add_argument(
        "--seal",
        action="store_true",
        help="Also pack a sealed MPL bundle next to the case file.",
    )
    case_export.add_argument(
        "--signing-key",
        help="Path to a sealing-key file (Ed25519, T2 signature for the "
        "case and the bundle). Requires --seal.",
    )
    case_export.add_argument(
        "--timestamp-url",
        help="RFC 3161 TSA URL for a T3 timestamp token. Requires --seal; "
        "a token that cannot be obtained fails the seal.",
    )
    case_verify = case_sub.add_parser("verify", help="Verify case-file integrity.")
    case_verify.add_argument("case_file")
    case_verify.add_argument(
        "--expect-digest",
        help="Expected SHA-256 digest: the bundle archive for a sealed "
        "bundle, the case-file bytes for a bare case file.",
    )
    case_verify.add_argument("--text", "-t", help="Holder-supplied text for replay.")
    case_verify.add_argument("--text-file", help="File holding holder-supplied text for replay.")
    case_verify.add_argument(
        "--public-key",
        help="Path to a sealing-key file, a public-key file, or a hex "
        "public key (verifies a T2 signature).",
    )
    case_verify.add_argument(
        "--timestamp-token",
        help="Path to a DER RFC 3161 token to verify against the case file (bare case files only).",
    )
    case_keygen = case_sub.add_parser(
        "keygen", help="Generate a sealing-key file (Ed25519, mode 0600)."
    )
    case_keygen.add_argument(
        "--output",
        "-o",
        required=True,
        help="Path for the new sealing-key file (refuses to overwrite).",
    )
    case_keygen.add_argument("--identity", help="Key holder identity (default: current username).")
    case_keygen.add_argument("--role", default="sealer", help="Key role (default: sealer).")
    case_keygen.add_argument(
        "--public-out",
        help="Also write the public half (public key + keyid) to this path.",
    )

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

    bundle_check = bundle_sub.add_parser(
        "check", help="Check internal consistency of a forensic bundle."
    )
    bundle_check.add_argument(
        "bundle", help="Path to the bundle JSON file, sealed case file, or bundle archive."
    )
    bundle_check.add_argument("--json", "-j", action="store_true", help="Output as JSON.")

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

    web = sub.add_parser("web", help="Run the browser UI.")
    web.add_argument("--host")
    web.add_argument("--port", type=int)
    web.add_argument("--no-browser", action="store_true")
    web.add_argument("--allow-remote", action="store_true")

    web_fastapi = sub.add_parser(
        "web-fastapi", help="Run the FastAPI WebSocket UI with real-time analysis."
    )
    web_fastapi.add_argument("--host")
    web_fastapi.add_argument("--port", type=int)
    web_fastapi.add_argument("--allow-remote", action="store_true")
    web_fastapi.add_argument("--access-log", action="store_true")

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

    drift_run = drift_sub.add_parser(
        "run",
        help="Run one U3 probe run over the frozen probe corpus.",
    )
    drift_run.add_argument(
        "--manifest",
        required=True,
        help="Path to the probe-corpus v1 manifest JSON.",
    )
    drift_run.add_argument(
        "--texts",
        required=True,
        help="Path to the corpus JSONL file (item_id -> text).",
    )
    drift_run.add_argument(
        "--holdback",
        required=True,
        help="Path to the holdback JSONL file (item_id -> label). Labels are read only after scoring.",
    )
    drift_run.add_argument(
        "--scope",
        choices=["full", "monthly-attacked", "monthly-current-generator", "event-driven"],
        default="full",
        help="Run scope (default: full). Monthly scopes score only their slices.",
    )
    drift_run.add_argument(
        "--detector-id",
        default="textforensics/builtin-heuristic",
        help="Detector to score with (default: textforensics/builtin-heuristic).",
    )
    drift_run.add_argument(
        "--detector-version",
        help="Expected detector version; fails if it does not match the detector.",
    )
    drift_run.add_argument(
        "--runs-dir",
        help="Run-history directory (default: ~/.cache/textforensics/probe-runs/<corpus version>).",
    )
    drift_run.add_argument(
        "--registry",
        help="U1 validation registry path (default: docs/validation/registry.json).",
    )
    drift_run.add_argument(
        "--output",
        "-o",
        help="Also write the run manifest to this JSON file.",
    )
    drift_run.add_argument(
        "--allow-remote",
        action="store_true",
        help="Allow remote detector adapters to run (off by default; core is local-first).",
    )
    drift_run.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute and report only; do not save the run or apply demotions.",
    )
    drift_run.add_argument(
        "--fail-on-tier1",
        action="store_true",
        help="Exit 1 when a Tier-1 alert fires (for scheduled runs).",
    )

    drift_status = drift_sub.add_parser(
        "status",
        help="Show U3 longitudinal status for a detector.",
    )
    drift_status.add_argument("--detector-id", required=True, help="Detector ID.")
    drift_status.add_argument(
        "--detector-version",
        help="Detector version (default: the latest run's version for the detector).",
    )
    drift_status.add_argument(
        "--runs-dir",
        help="Run-history directory (default: ~/.cache/textforensics/probe-runs/<corpus version>).",
    )
    drift_status.add_argument(
        "--registry",
        help="U1 validation registry path (default: docs/validation/registry.json).",
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

    cap_policy = cap_sub.add_parser(
        "policy",
        help="Evaluate capability ledger policies for a detector.",
    )
    cap_policy.add_argument("detector", help="Detector ID to check policies for.")
    cap_policy.add_argument("--ledger", help="Path to the capability ledger JSON file.")
    cap_policy.add_argument(
        "--policy",
        "-p",
        default="production",
        choices=["production", "report", "calibration", "minimum"],
        help="Policy bundle (default: production).",
    )
    cap_policy.add_argument("--json", "-j", action="store_true", help="Output as JSON.")

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


def _drift_run(args: argparse.Namespace) -> int:
    """Run one U3 probe run (``tf drift run``).

    Exit codes: 0 the run completed (a Tier-1 demotion is an expected
    outcome, not a failure); 1 with ``--fail-on-tier1`` when a Tier-1
    alert fired; 2 when the probe-corpus module is not available yet
    (the corpus half merges separately); 3 on input errors (raised
    ValueError/OSError/RuntimeError are converted by ``main``).
    """
    import hashlib

    try:
        from . import probe_corpus
    except ImportError:
        print(
            "error: the probe-corpus module (textforensics.probe_corpus) "
            "is not available yet — the frozen probe corpus is built on "
            "branch u3-corpus and merges separately. Run 'tf drift run' "
            "again after that merge.",
            file=sys.stderr,
        )
        return EXIT_INCOMPLETE

    manifest_path = Path(args.manifest)
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    corpus_manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    parsed = probe_corpus.ProbeCorpusManifest.from_dict(manifest)
    problems = probe_corpus.verify_corpus_files(Path(args.texts), Path(args.holdback), parsed)
    if problems:
        print("error: probe corpus verification failed:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return EXIT_ERROR

    from .detectors import discover_detector_registry
    from .probe_runs import (
        default_probe_runs_dir,
        load_run_history,
        perform_probe_run,
        summarize_longitudinal,
    )

    registry = discover_detector_registry()
    detector = registry.detectors.get(args.detector_id)
    if detector is None:
        print(
            f"error: unknown detector {args.detector_id!r}; "
            f"known detectors: {sorted(registry.detectors)}",
            file=sys.stderr,
        )
        return EXIT_ERROR
    if args.detector_version is not None and args.detector_version != detector.detector_version:
        print(
            f"error: detector {args.detector_id} is version "
            f"{detector.detector_version}, not {args.detector_version!r}.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    repo_root = Path(__file__).resolve().parent.parent.parent
    registry_path = args.registry or str(repo_root / "docs" / "validation" / "registry.json")
    runs_dir = args.runs_dir or str(default_probe_runs_dir(corpus_version=parsed.version))
    run = perform_probe_run(
        manifest=manifest,
        texts=probe_corpus.load_corpus_texts(Path(args.texts)),
        holdback_loader=lambda: probe_corpus.load_holdback(Path(args.holdback)),
        detector=detector,
        scope=args.scope,
        runs_dir=runs_dir,
        registry_path=registry_path,
        corpus_manifest_sha256=corpus_manifest_sha256,
        dry_run=bool(args.dry_run),
        allow_remote=bool(args.allow_remote),
    )
    if args.output:
        _write_json(args.output, run)

    history = load_run_history(runs_dir)
    summary = summarize_longitudinal(
        history,
        detector_id=run["detector_id"],
        detector_version=run["detector_version"],
        corpus_fingerprint=run["corpus_fingerprint"],
    )
    tier1 = [a for a in run["alerts"] if a["tier"] == 1]
    tier2 = [a for a in run["alerts"] if a["tier"] == 2]
    tier3 = [a for a in run["alerts"] if a["tier"] == 3]
    print(
        f"Probe run {run['run_id']} ({run['scope']}, {run['detector_id']} {run['detector_version']})"
    )
    print(
        f"  baseline: {'yes' if run['is_baseline'] else 'no'}"
        f"{' (rebaselined from ' + run['rebaselined_from'] + ')' if run.get('rebaselined_from') else ''}"
    )
    print(f"  alerts: {len(tier1)} Tier-1, {len(tier2)} Tier-2, {len(tier3)} Tier-3")
    for alert in run["alerts"]:
        print(f"  - Tier {alert['tier']} {alert['rule']} on {alert['slice']}: {alert['detail']}")
    if run["demotions_applied"]:
        print(f"  demotions applied: {run['demotions_applied'].get('demoted_record_ids')}")
    if run["demotions_cleared"]:
        print(f"  demotions cleared: {run['demotions_cleared'].get('cleared_record_ids')}")
    print(
        f"  longitudinal: {summary['consecutive_clean_full_runs']} consecutive clean full run(s)"
        f" (temporal support needs {summary['clean_full_runs_needed_for_temporal_support']})"
    )
    if summary["watch"]:
        print(f"  active watch: {summary['watch']['run_id']}")
    print(f"  manifest: {runs_dir}/run-{run['run_id']}.json")
    if args.dry_run:
        print("  dry run: nothing was saved and no demotion was applied.")
    if tier1 and args.fail_on_tier1:
        return EXIT_DOWNGRADED
    return EXIT_OK


def _drift_status(args: argparse.Namespace) -> int:
    """Show U3 longitudinal status for a detector (``tf drift status``)."""
    from datetime import UTC, datetime

    from .probe_runs import (
        default_probe_runs_dir,
        load_run_history,
        summarize_longitudinal,
    )
    from .validation import ValidationRegistry, effective_status

    runs_dir = args.runs_dir
    history: list[dict] = []
    if runs_dir is not None:
        history = load_run_history(runs_dir)
    else:
        # Search the default run-history dirs for every corpus version
        # present under the cache root.
        cache_root = default_probe_runs_dir(corpus_version="1.0.0").parent
        if cache_root.is_dir():
            for version_dir in sorted(cache_root.iterdir()):
                if version_dir.is_dir():
                    history.extend(load_run_history(version_dir))
            history.sort(key=lambda r: str(r.get("run_at_utc", "")))
    detector_runs = [r for r in history if r.get("detector_id") == args.detector_id]
    if not detector_runs:
        payload = {
            "detector_id": args.detector_id,
            "status": "no_runs",
            "consecutive_clean_full_runs": 0,
            "temporal_support": False,
            "watch": None,
            "demotions": [],
        }
        _write_json(None, payload)
        print(f"No probe runs recorded for detector {args.detector_id!r}.", file=sys.stderr)
        return EXIT_OK

    detector_version = args.detector_version or str(detector_runs[-1].get("detector_version"))
    corpus_fingerprint = str(detector_runs[-1].get("corpus_fingerprint"))
    summary = summarize_longitudinal(
        history,
        detector_id=args.detector_id,
        detector_version=detector_version,
        corpus_fingerprint=corpus_fingerprint,
    )
    demotions: list[dict] = []
    repo_root = Path(__file__).resolve().parent.parent.parent
    registry_path = args.registry or str(repo_root / "docs" / "validation" / "registry.json")
    if Path(registry_path).exists():
        registry = ValidationRegistry.load(registry_path)
        now = datetime.now(UTC)
        for record in registry.records:
            if record.detector_id != args.detector_id:
                continue
            if record.limits.demoted_by and record.limits.demoted_by.startswith("U3 probe run "):
                demotions.append(
                    {
                        "record_id": record.record_id,
                        "demoted_by": record.limits.demoted_by,
                        "effective_status": effective_status(
                            record, detector_version=detector_version, now=now
                        ),
                    }
                )
    payload = {**summary, "status": "ok", "demotions": demotions}
    _write_json(None, payload)
    # Human summary goes to stderr so stdout stays pure JSON.
    print(
        f"Detector {args.detector_id} {detector_version}: "
        f"{summary['consecutive_clean_full_runs']} consecutive clean full run(s), "
        f"temporal support: {'yes' if summary['temporal_support'] else 'no'}, "
        f"{summary['total_runs']} run(s) total, last run {summary['last_run_at_utc']}.",
        file=sys.stderr,
    )
    if summary["watch"]:
        print(f"Active watch from run {summary['watch']['run_id']}.", file=sys.stderr)
    if demotions:
        print(f"Active U3 demotions: {len(demotions)} record(s) stale.", file=sys.stderr)
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
        result = analyze_text(_read_text(args.file, settings, text=args.text))
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
        result = audit_naturalness(_read_text(args.file, settings, text=args.text))
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
        from .calibration import create_threshold_selection_artifact as _create_artifact
        from .calibration import select_threshold as _select_threshold

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
                errors = _import_enterprise().validate_enterprise_policy(data)
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
            _read_text(args.file, settings, text=args.text),
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
            if (args.signing_key is not None or args.timestamp_url is not None) and (not args.seal):
                raise ValueError("--signing-key and --timestamp-url require --seal")
            signing_seed: bytes | None = None
            signer: dict[str, Any] | None = None
            if args.signing_key is not None:
                import base64

                from .sealing import load_sealing_key

                key = load_sealing_key(args.signing_key)
                signing_seed = base64.b64decode(key["seed_b64"])
                signer = {"identity": key["identity"], "role": key["role"]}
            bundle = build_forensic_bundle(
                _read_text(args.file, settings, text=args.text),
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
                signing_seed=signing_seed,
                signer=signer,
            )
            print(args.output)
            case_data = json.loads(Path(args.output).read_text(encoding="utf-8"))
            if args.seal:
                _seal_exported_case(args, case_data, signing_seed=signing_seed, signer=signer)
            if getattr(args, "rich", False):
                from .rich_output import HAS_RICH as _has_rich
                from .rich_output import print_case_summary

                if _has_rich:
                    print_case_summary(case_data)
                else:
                    print(
                        "Warning: Rich is not installed. Install with: pip install textforensics[cli-rich]"
                    )
        elif args.case_command == "keygen":
            return _keygen_cli(args)
        else:
            return _verify_case_cli(args, settings)

    elif args.command == "web":
        # The remote-bind guard runs before the optional web-UI import:
        # in a core-only install the import fails, and the guard error
        # (exit 3, "Refusing to bind") must surface first.
        active = _settings_with_overrides(
            settings,
            host=args.host,
            port=args.port,
            allow_remote=True if args.allow_remote else settings.allow_remote,
        )
        ensure_bind_allowed(active.host, allow_remote=active.allow_remote)
        try:
            from .web_ui.main import serve_web
        except ImportError as exc:
            raise RuntimeError(
                "Install web UI support with: pip install 'textforensics[api]'"
            ) from exc
        serve_web(
            active.host,
            active.port,
            allow_remote=active.allow_remote,
            max_input_bytes=active.max_input_bytes,
            open_browser=not args.no_browser,
        )

    elif args.command == "web-fastapi":
        active = _settings_with_overrides(
            settings,
            host=args.host,
            port=args.port,
            allow_remote=True if args.allow_remote else settings.allow_remote,
            access_log=True if args.access_log else settings.access_log,
        )
        ensure_bind_allowed(active.host, allow_remote=active.allow_remote)
        try:
            from .web_ui.main import serve_web
        except ImportError as exc:
            raise RuntimeError(
                "Install web UI support with: pip install 'textforensics[api]'"
            ) from exc
        serve_web(
            active.host,
            active.port,
            allow_remote=active.allow_remote,
            access_log=active.access_log,
            log_level=active.log_level,
        )

    elif args.command == "serve":
        active = _settings_with_overrides(
            settings,
            host=args.host,
            port=args.port,
            allow_remote=True if args.allow_remote else settings.allow_remote,
            access_log=True if args.access_log else settings.access_log,
        )
        ensure_bind_allowed(active.host, allow_remote=active.allow_remote)
        from .api import serve_api

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
        elif args.drift_command == "run":
            return _drift_run(args)
        elif args.drift_command == "status":
            return _drift_status(args)
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
        elif args.capability_command == "policy":
            # Ported from the former Typer CLI (capability policy). The Typer
            # version computed all_passed only in the non-JSON branch, so
            # --json always crashed with NameError and exited EXIT_ERROR;
            # all_passed is computed up front here.
            policy_map = {
                "production": create_production_policy,
                "report": create_report_generation_policy,
                "calibration": create_calibration_policy,
                "minimum": create_minimum_viable_policy,
            }
            if args.policy not in policy_map:  # pragma: no cover - argparse choices= guards this
                print(
                    f"error: unknown policy '{args.policy}'. Use one of: {', '.join(policy_map)}",
                    file=sys.stderr,
                )
                return EXIT_ERROR
            engine = policy_map[args.policy]()
            results = engine.evaluate(ledger, args.detector)
            all_passed = all(result.passed for result in results)
            if args.json:
                _write_json(None, [result.to_dict() for result in results])
            else:
                print(f"Policy evaluation: {args.policy} for {args.detector}")
                for result in results:
                    status = "PASS" if result.passed else result.rule_id.upper()
                    print(f"  [{status}] {result.message}")
                    for missing in result.missing_claims:
                        print(f"    MISSING: {missing}")
                    for gap in result.evidence_gaps:
                        print(f"    GAP: {gap}")
            return EXIT_OK if all_passed else EXIT_INCOMPLETE

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
        elif args.bundle_command == "check":
            # Ported from the former Typer CLI (bundle check). The Typer
            # version imported a read_bundle that never existed, so the
            # command crashed on every invocation; bundle.read_bundle is
            # the implementation that was missing.
            data = read_bundle(args.bundle)
            report = check_bundle_consistency(data)
            result = {
                "is_consistent": report.is_consistent,
                "issues": [
                    {
                        "field": issue.field,
                        "type": issue.issue_type,
                        "message": issue.message,
                        "severity": issue.severity,
                    }
                    for issue in report.issues
                ],
                "checked_fields": report.checked_fields,
            }
            if args.json:
                _write_json(None, result)
            else:
                print(f"Bundle consistency: {'PASS' if report.is_consistent else 'FAIL'}")
                if report.issues:
                    for issue in report.issues:
                        print(f"  [{issue.severity.upper()}] {issue.field}: {issue.message}")
                else:
                    print("  No issues found.")
            return EXIT_OK if report.is_consistent else EXIT_INCOMPLETE

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
        return _run_audit_anchor_command(args)

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
    # Lazy import for enterprise features
    ep = _import_enterprise()

    state_path = Path(args.state_path) if getattr(args, "state_path", None) else None
    key_path = Path(args.key_path) if getattr(args, "key_path", None) else None

    floor = ep.PolicyRevisionFloor(
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
        schema_errors = ep.validate_enterprise_policy(policy_data)
        if schema_errors:
            print("error: policy schema validation failed:", file=sys.stderr)
            for err in schema_errors:
                print(f"  - {err}", file=sys.stderr)
            return EXIT_INCOMPLETE

        # Compute digest (single implementation: ep.compute_policy_digest)
        computed_digest = ep.compute_policy_digest(
            ep.EnterprisePolicy(
                revision=int(policy_data["revision"]),
                digest="",
                settings=dict(policy_data.get("settings", {})),
                rules=[dict(r) for r in policy_data.get("rules", [])],
            )
        )

        # Check digest if provided
        if "digest" in policy_data and policy_data["digest"] != computed_digest:
            print(
                f"error: digest mismatch: stored {policy_data['digest'][:16]}... "
                f"computed {computed_digest[:16]}...",
                file=sys.stderr,
            )
            return EXIT_ERROR

        policy = ep.EnterprisePolicy(
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

            # Compute digest (single implementation: ep.compute_policy_digest)
            computed_digest = ep.compute_policy_digest(
                ep.EnterprisePolicy(
                    revision=int(policy_data["revision"]),
                    digest="",
                    settings=dict(policy_data.get("settings", {})),
                    rules=[dict(r) for r in policy_data.get("rules", [])],
                )
            )

            policy = ep.EnterprisePolicy(
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
        schema_errors = ep.validate_enterprise_policy(policy_data)
        if schema_errors:
            print("error: policy schema validation failed:", file=sys.stderr)
            for err in schema_errors:
                print(f"  - {err}", file=sys.stderr)
            return EXIT_INCOMPLETE

        # Compute digest (single implementation: ep.compute_policy_digest)
        computed_digest = ep.compute_policy_digest(
            ep.EnterprisePolicy(
                revision=int(policy_data["revision"]),
                digest="",
                settings=dict(policy_data.get("settings", {})),
                rules=[dict(r) for r in policy_data.get("rules", [])],
            )
        )

        if "digest" in policy_data and policy_data["digest"] != computed_digest:
            print(
                f"error: digest mismatch: stored {policy_data['digest'][:16]}... "
                f"computed {computed_digest[:16]}...",
                file=sys.stderr,
            )
            return EXIT_ERROR

        policy = ep.EnterprisePolicy(
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
        print("EMERGENCY STOP: ACTIVE" if active else "Emergency stop: not active")
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
        print("Emergency stop deactivated." if removed else "No sentinel file was present.")
        return EXIT_OK

    return EXIT_ERROR


def main() -> int:
    """Main entry point for the CLI (single argparse implementation)."""
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
