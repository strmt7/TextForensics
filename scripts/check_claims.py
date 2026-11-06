#!/usr/bin/env python3
"""
check_claims.py — Machine-verifiable claims validation for CI (U7).

Validates claims from docs/CLAIMS.yaml against the codebase, tests, and
artifacts, and enforces the claim-to-evidence linkage (U7):
  (a) every claim carries evidence_record_id + run_artifact_sha256;
  (b) every referenced run artifact is re-hashed; mismatch = fail;
  (c) claim numbers (``values`` map) are compared against the cited
      record's ``results`` (with optional per-claim ``tolerance``), and
      every scalar value must appear in the claim statement;
  (d) a ``verified`` claim whose evidence record is more than 90 days
      old, or whose detector version changed since the run, fails as
      ``stale``;
  (e) a run artifact without a ``drops`` manifest is ``incomplete``
      and its claims fail;
  (f) the gate writes docs/evidence/report-card.md, which leads with
      the worst-slice human false-positive rate and lists failed
      claims. The card is deterministic (no timestamps, no repo HEAD),
      so CI can diff it and hand-edited numbers fail.

Tool invocations always go through the current interpreter
(sys.executable): there is no guarantee a bare ``python`` binary exists
on the machine running CI, and console scripts may not be on PATH.

Usage:
    python scripts/check_claims.py [--root PATH]
        [--report-card PATH | --no-report-card]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import date
from pathlib import Path
from typing import Any

import jsonschema
import yaml

REPO_ROOT = Path(__file__).parent.parent

STALENESS_DAYS = 90

# Console-script entry points mapped to their importable module, so the
# gate runs them via the current interpreter instead of relying on PATH.
_TOOL_MODULES = {
    "python": None,  # replaced by sys.executable itself
    "pytest": "pytest",
    "ruff": "ruff",
    "bandit": "bandit",
    "pip-audit": "pip_audit",
}


def _claims_file(root: Path) -> Path:
    return root / "docs" / "CLAIMS.yaml"


def _registry_file(root: Path) -> Path:
    return root / "docs" / "evidence" / "registry.json"


def _schemas_dir(root: Path) -> Path:
    return root / "src" / "textforensics" / "schemas"


def _detectors_file(root: Path) -> Path:
    return root / "src" / "textforensics" / "detectors.py"


def _report_card_file(root: Path) -> Path:
    return root / "docs" / "evidence" / "report-card.md"


def _resolve_command(cmd: list[str]) -> list[str]:
    """Rewrite a command to run through the current interpreter.

    ``["ruff", "check", "src/"]`` becomes
    ``[sys.executable, "-m", "ruff", "check", "src/"]``. Unknown tools
    are passed through unchanged (and will fail loudly if missing).
    """
    if not cmd:
        return cmd
    head = cmd[0]
    if head == "python":
        return [sys.executable, *cmd[1:]]
    module = _TOOL_MODULES.get(head)
    if module is not None:
        return [sys.executable, "-m", module, *cmd[1:]]
    return cmd


def _split_chain(command: str) -> list[list[str]]:
    """Split a ``cmd1 && cmd2`` chain into its parts."""
    return [part.split() for part in command.split("&&") if part.strip()]


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_schema(root: Path, name: str) -> dict[str, Any]:
    return json.loads((_schemas_dir(root) / name).read_text(encoding="utf-8"))


def _schema_errors(schema: dict[str, Any], instance: Any) -> list[str]:
    validator = jsonschema.Draft202012Validator(schema)
    return [
        f"{'.'.join(str(p) for p in e.path)}: {e.message}" for e in validator.iter_errors(instance)
    ]


def load_claims(root: Path) -> list[dict[str, Any]]:
    text = _claims_file(root).read_text(encoding="utf-8")
    _check_no_duplicate_keys(text, _claims_file(root))
    data = yaml.safe_load(text)
    return data.get("claims", [])


def _check_no_duplicate_keys(text: str, path: Path) -> None:
    """Fail fast on duplicate YAML mapping keys (last-wins is silent)."""
    node = yaml.compose(text)
    duplicates: list[str] = []

    def walk(mapping_node: Any, path_str: str = "") -> None:
        if not hasattr(mapping_node, "value"):
            return
        if mapping_node.tag == "tag:yaml.org,2002:map":
            seen: set[str] = set()
            for key_node, value_node in mapping_node.value:
                key = key_node.value
                child_path = f"{path_str}.{key}" if path_str else str(key)
                if key in seen:
                    duplicates.append(child_path)
                seen.add(key)
                walk(value_node, child_path)
        elif mapping_node.tag == "tag:yaml.org,2002:seq":
            for item in mapping_node.value:
                walk(item, path_str)

    walk(node)
    if duplicates:
        raise ValueError(f"Duplicate YAML keys in {path}: {duplicates}")


def load_registry(root: Path) -> list[dict[str, Any]]:
    """Load and schema-validate the evidence registry."""
    path = _registry_file(root)
    if not path.exists():
        raise FileNotFoundError(
            f"Evidence registry not found: {path} "
            "(U7: every claim must cite a record in docs/evidence/registry.json)"
        )
    registry = json.loads(path.read_text(encoding="utf-8"))
    errors = _schema_errors(_load_schema(root, "evidence-registry.schema.json"), registry)
    if errors:
        raise ValueError(f"Evidence registry fails its schema: {errors}")
    return registry.get("records", [])


def verify_registry_records(
    root: Path, records: list[dict[str, Any]]
) -> tuple[dict[str, dict[str, Any]], list[tuple[str, str]]]:
    """Re-hash every registry artifact and validate it against its schema.

    Returns (records_by_id, failures). A failure here fails the gate
    even if no claim cites the record: the registry itself must be
    truthful.
    """
    artifact_schema = _load_schema(root, "run-artifact.schema.json")
    records_by_id: dict[str, dict[str, Any]] = {}
    failures: list[tuple[str, str]] = []
    for record in records:
        record_id = record["evidence_record_id"]
        artifact_path = root / record["run_artifact"]
        if not artifact_path.exists():
            failures.append((record_id, f"run artifact not found: {record['run_artifact']}"))
            continue
        actual = _sha256_file(artifact_path)
        if actual != record["run_artifact_sha256"]:
            failures.append(
                (
                    record_id,
                    "run artifact hash mismatch (U7 (b)): "
                    f"registry says {record['run_artifact_sha256'][:12]}..., "
                    f"file hashes to {actual[:12]}... — the artifact was modified "
                    "after the record was written",
                )
            )
            continue
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        errors = _schema_errors(artifact_schema, artifact)
        if errors:
            drops_missing = any("drops" in e for e in errors)
            verdict = (
                "incomplete: run artifact has no drops manifest (U7 (e))"
                if drops_missing
                else "schema"
            )
            failures.append((record_id, f"run artifact fails its schema ({verdict}): {errors}"))
            continue
        records_by_id[record_id] = {"record": record, "artifact": artifact, "path": artifact_path}
    return records_by_id, failures


def current_detector_version(root: Path) -> str | None:
    """Read the builtin detector version from detectors.py (no import)."""
    text = _detectors_file(root).read_text(encoding="utf-8")
    match = re.search(r'detector_version\s*=\s*"([^"]+)"', text)
    return match.group(1) if match else None


def _resolve_dotted(results: dict[str, Any], metric: str) -> tuple[bool, Any]:
    """Resolve a dotted metric path (e.g. ``packages.cryptography``)."""
    node: Any = results
    for part in metric.split("."):
        if not isinstance(node, dict) or part not in node:
            return False, None
        node = node[part]
    return True, node


def _values_match(expected: Any, actual: Any, tolerance: float) -> bool:
    if isinstance(expected, bool) or isinstance(actual, bool):
        return expected is actual
    if isinstance(expected, (int, float)) and isinstance(actual, (int, float)):
        return abs(expected - actual) <= tolerance
    return expected == actual


def _value_in_statement(value: Any, statement: str) -> bool:
    """A scalar claim number must appear in the claim statement.

    Integers/floats match as standalone numbers (never as part of a
    longer number such as 3.11); 0 also matches the word "zero".
    Strings match verbatim. Lists and dicts are exempt: they are
    compared against the record, not quoted in prose.
    """
    if isinstance(value, (bool, list, dict)):
        return True
    if isinstance(value, (int, float)):
        pattern = rf"(?<![\d.]){re.escape(str(value))}(?![\d.])"
        if re.search(pattern, statement):
            return True
        return bool(value == 0 and re.search(r"\bzero\b", statement, flags=re.IGNORECASE))
    return str(value) in statement


def check_evidence_linkage(
    claim: dict[str, Any],
    records_by_id: dict[str, dict[str, Any]],
    root: Path,
    today: date,
    detector_version: str | None,
) -> tuple[bool, str, str]:
    """Enforce the U7 claim-to-evidence linkage for one claim.

    Returns (ok, message, verdict) where verdict is one of
    "pass", "fail", "stale", "incomplete".
    """
    claim_id = claim.get("id", "unknown")
    record_id = claim.get("evidence_record_id")
    claim_sha = claim.get("run_artifact_sha256")
    if not record_id or not claim_sha:
        return (
            False,
            f"Claim {claim_id}: missing evidence_record_id or run_artifact_sha256 (U7 (a))",
            "fail",
        )
    entry = records_by_id.get(record_id)
    if entry is None:
        return (
            False,
            f"Claim {claim_id}: evidence record {record_id} is not in the registry",
            "fail",
        )
    record = entry["record"]
    artifact = entry["artifact"]
    if record["run_artifact_sha256"] != claim_sha:
        return (
            False,
            f"Claim {claim_id}: run_artifact_sha256 does not match the registry "
            f"(claim {claim_sha[:12]}... vs registry {record['run_artifact_sha256'][:12]}...)",
            "fail",
        )
    actual = _sha256_file(entry["path"])
    if actual != claim_sha:
        return (
            False,
            f"Claim {claim_id}: run artifact hash mismatch (U7 (b)) — the artifact "
            f"was modified after the record was written (file {actual[:12]}... vs "
            f"claim {claim_sha[:12]}...)",
            "fail",
        )
    if "drops" not in artifact:
        return (
            False,
            f"Claim {claim_id}: incomplete — run artifact has no drops manifest (U7 (e))",
            "incomplete",
        )
    run_date = date.fromisoformat(artifact["run_date"])
    age_days = (today - run_date).days
    if claim.get("status") == "verified" and age_days > STALENESS_DAYS:
        return (
            False,
            f"Claim {claim_id}: stale — evidence record is {age_days} days old "
            f"(> {STALENESS_DAYS} days) (U7 (d))",
            "stale",
        )
    artifact_version = artifact.get("detector_version")
    if (
        claim.get("status") == "verified"
        and artifact_version is not None
        and detector_version is not None
        and artifact_version != detector_version
    ):
        return (
            False,
            f"Claim {claim_id}: stale — detector version changed since the run "
            f"({artifact_version} -> {detector_version}) (U7 (d))",
            "stale",
        )
    last_verified = claim.get("last_verified")
    if last_verified and last_verified != artifact["run_date"]:
        return (
            False,
            f"Claim {claim_id}: last_verified {last_verified} does not match "
            f"evidence run date {artifact['run_date']}",
            "fail",
        )
    tolerance = float(claim.get("tolerance", 0))
    for metric, expected in (claim.get("values") or {}).items():
        found, actual_value = _resolve_dotted(artifact.get("results", {}), metric)
        if not found:
            return (
                False,
                f"Claim {claim_id}: metric {metric!r} is not in the evidence "
                f"record's results (U7 (c))",
                "fail",
            )
        if not _values_match(expected, actual_value, tolerance):
            return (
                False,
                f"Claim {claim_id}: value mismatch (U7 (c)) — {metric}: claim says "
                f"{expected!r}, evidence record says {actual_value!r}",
                "fail",
            )
        if not _value_in_statement(expected, claim.get("statement", "")):
            return (
                False,
                f"Claim {claim_id}: value {expected!r} ({metric}) does not appear "
                "in the claim statement (U7 (c))",
                "fail",
            )
    return True, "evidence linkage OK", "pass"


def run_command(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    cmd = _resolve_command(cmd)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd or REPO_ROOT)
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"
    return result.returncode, result.stdout, result.stderr


def run_chain(command: str, cwd: Path | None = None) -> tuple[int, str, str]:
    """Run a ``&&``-chained command; stop at the first failing part."""
    out, err = "", ""
    for part in _split_chain(command):
        code, out, err = run_command(part, cwd=cwd)
        if code != 0:
            return code, out, err
    return 0, out, err


def check_test_evidence(evidence_path: str, root: Path) -> tuple[bool, str]:
    """Check if a test file/path exists and tests pass."""
    if evidence_path.startswith("tests/"):
        # Handle both "tests/file.py" and "tests/file.py::Class::method" formats
        parts = evidence_path.split("::", 1)
        test_file = root / parts[0]
        if not test_file.exists():
            return False, f"Test file not found: {test_file}"
        # Run the specific test
        cmd = [sys.executable, "-m", "pytest", evidence_path, "-q", "-p", "no:cacheprovider"]
        code, stdout, stderr = run_command(cmd, cwd=root)
        if code != 0:
            return False, f"Test failed: {stdout}\n{stderr}"
        return True, "Test passed"
    return False, f"Unknown test path format: {evidence_path}"


def check_benchmark_artifact(evidence_path: str, root: Path) -> tuple[bool, str]:
    """Check if a benchmark artifact exists and is more than a placeholder."""
    path = root / evidence_path
    if not path.exists():
        return False, f"Benchmark artifact not found: {path}"
    if path.is_dir():
        entries = [p for p in path.iterdir() if p.name != "README.md"]
        if not entries:
            return False, (
                f"Benchmark artifact directory holds only a placeholder README: {path} "
                "(no loader or run artifact)"
            )
    return True, "Artifact exists"


def check_code_audit(evidence_path: str, root: Path) -> tuple[bool, str]:
    """Check if a code path exists."""
    path = root / evidence_path
    if not path.exists():
        return False, f"Code path not found: {path}"
    return True, "Code path exists"


def check_doc(evidence_path: str, root: Path) -> tuple[bool, str]:
    """Check if a doc/file exists and contains expected content."""
    path = root / evidence_path
    if not path.exists():
        return False, f"Document not found: {path}"
    return True, "Document exists"


def check_external_audit(evidence_path: str, root: Path) -> tuple[bool, str]:
    """Run an external audit command."""
    code, stdout, stderr = run_chain(evidence_path, cwd=root)
    if code != 0:
        return False, f"Command failed (exit {code}): {stderr or stdout}"
    return True, "Audit passed"


def check_command(evidence_path: str, root: Path) -> tuple[bool, str]:
    """Run a shell command and check it succeeds.

    A non-zero exit is a failure — including for bandit/pip-audit, whose
    exit codes report findings. Claims that cite those tools must use a
    command whose exit code already encodes the claim (e.g. bandit
    ``-lll`` reports only high-severity findings).
    """
    code, stdout, stderr = run_chain(evidence_path, cwd=root)
    if code == 0:
        return True, "Command succeeded"
    detail = (stderr or stdout).strip().splitlines()
    tail = "\n".join(detail[-20:])
    return False, f"Command failed (exit {code}): {tail}"


def verify_claim(
    claim: dict[str, Any],
    records_by_id: dict[str, dict[str, Any]],
    root: Path,
    today: date,
    detector_version: str | None,
) -> tuple[bool, str, str]:
    """Verify a single claim: evidence linkage first, then its evidence.

    Returns (ok, message, verdict) with verdict in
    "pass" / "fail" / "stale" / "incomplete".
    """
    claim_id = claim.get("id", "unknown")
    evidence_type = claim.get("evidence_type", "")
    evidence_path = claim.get("evidence_path", "")
    status = claim.get("status", "unverified")

    if status in ("unverified", "false", "stale"):
        return False, f"Claim {claim_id}: status is '{status}' - requires verification", "fail"

    ok, msg, verdict = check_evidence_linkage(claim, records_by_id, root, today, detector_version)
    if not ok:
        return False, msg, verdict

    try:
        if evidence_type == "test":
            ok, msg = check_test_evidence(evidence_path, root)
        elif evidence_type == "benchmark_artifact":
            ok, msg = check_benchmark_artifact(evidence_path, root)
        elif evidence_type == "code_audit":
            ok, msg = check_code_audit(evidence_path, root)
        elif evidence_type == "doc":
            ok, msg = check_doc(evidence_path, root)
        elif evidence_type == "external_audit":
            ok, msg = check_external_audit(evidence_path, root)
        elif evidence_type == "command":
            ok, msg = check_command(evidence_path, root)
        else:
            return False, f"Unknown evidence type: {evidence_path}", "fail"
    except Exception as e:
        return False, f"Verification error: {e}", "fail"
    return ok, msg, "pass" if ok else "fail"


def worst_slice_fpr(
    records_by_id: dict[str, dict[str, Any]],
) -> tuple[float | None, str | None]:
    """Find the worst-slice human false-positive rate in the registry.

    Looks for ``worst_slice_human_fpr`` in any record's results (or
    ``human_fpr.worst_slice``). Returns (value, record_id) or (None, None)
    when no human-FPR evidence is recorded — the honest answer until
    U1/dataset runs produce real measurements.
    """
    worst: float | None = None
    worst_record: str | None = None
    for record_id, entry in records_by_id.items():
        results = entry["artifact"].get("results", {})
        value = results.get("worst_slice_human_fpr")
        if value is None and isinstance(results.get("human_fpr"), dict):
            value = results["human_fpr"].get("worst_slice")
        if isinstance(value, (int, float)) and (worst is None or value > worst):
            worst = float(value)
            worst_record = record_id
    return worst, worst_record


def write_report_card(
    root: Path,
    claim_results: list[tuple[str, str, str, bool, str, str]],
    records_by_id: dict[str, dict[str, Any]],
    registry_failures: list[tuple[str, str]],
    card_path: Path | None = None,
) -> Path:
    """Write the deterministic evidence report card (U7 (f)).

    claim_results entries are (claim_id, status, record_id, ok, verdict,
    message). The card carries no timestamps and no repo HEAD: its content
    is fully determined by the claims, the registry, and the verdicts, so
    CI can diff it and hand-edits fail.
    """
    fpr, fpr_record = worst_slice_fpr(records_by_id)
    lines = [
        "# TextForensics evidence report card",
        "",
        "Generated by `scripts/check_claims.py` (U7 claim-to-evidence gate). "
        "Do not hand-edit: the gate regenerates this file and CI diffs it.",
        "",
        "## Worst-slice human false-positive rate",
        "",
    ]
    if fpr is None:
        lines += [
            "**unknown** — no human-FPR evidence is recorded in the registry yet "
            "(Phase 5 release gate). No FPR is claimed anywhere in this repository.",
            "",
        ]
    else:
        lines += [
            f"**{fpr}** (worst slice; evidence record `{fpr_record}`)",
            "",
        ]
    failed = [r for r in claim_results if not r[3]]
    lines += [
        "## Claims",
        "",
        f"{len(claim_results) - len(failed)} passed, {len(failed)} failed "
        f"of {len(claim_results)} claims.",
        "",
    ]
    if failed:
        lines += ["### Failed claims", ""]
        for claim_id, _status, record_id, _ok, verdict, message in failed:
            lines.append(f"- **{claim_id}** (`{verdict}`; evidence `{record_id}`): {message}")
        lines.append("")
    lines += [
        "### All claims",
        "",
        "| claim | status | evidence record | verdict |",
        "| --- | --- | --- | --- |",
    ]
    for claim_id, status, record_id, _ok, verdict, _message in claim_results:
        lines.append(f"| {claim_id} | {status} | {record_id} | {verdict} |")
    lines.append("")
    if registry_failures:
        lines += ["## Registry failures", ""]
        for record_id, message in registry_failures:
            lines.append(f"- **{record_id}**: {message}")
        lines.append("")
    lines += [
        "## Evidence records",
        "",
        "| record | kind | run date | detector version | badge | artifact sha256 |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for record_id in sorted(records_by_id):
        entry = records_by_id[record_id]
        artifact = entry["artifact"]
        sha = entry["record"]["run_artifact_sha256"]
        version = artifact.get("detector_version", "—")
        lines.append(
            f"| {record_id} | {artifact.get('kind', '—')} | {artifact.get('run_date', '—')} "
            f"| {version} | {artifact.get('badge', '—')} | `{sha[:12]}...` |"
        )
    lines.append("")
    path = card_path or _report_card_file(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate docs/CLAIMS.yaml (U7 claim-to-evidence gate)."
    )
    parser.add_argument(
        "--root", type=Path, default=REPO_ROOT, help="repo root (default: this repo)"
    )
    parser.add_argument(
        "--report-card",
        type=Path,
        default=None,
        help="report card path (default: docs/evidence/report-card.md)",
    )
    parser.add_argument(
        "--no-report-card", action="store_true", help="do not write the report card"
    )
    args = parser.parse_args(argv)
    root = args.root

    print(f"Loading claims from {_claims_file(root)}")
    try:
        claims = load_claims(root)
    except (FileNotFoundError, ValueError) as e:
        print(f"CI FAILED: {e}")
        return 1
    print(f"Found {len(claims)} claims\n")

    try:
        records = load_registry(root)
    except (FileNotFoundError, ValueError) as e:
        print(f"CI FAILED: {e}")
        return 1
    records_by_id, registry_failures = verify_registry_records(root, records)
    if registry_failures:
        print("Registry failures:")
        for record_id, msg in registry_failures:
            print(f"  - {record_id}: {msg}")
        print()

    today = date.today()
    detector_version = current_detector_version(root)
    print(f"Evidence registry: {len(records)} records, {len(records_by_id)} valid")
    print(f"Builtin detector version: {detector_version}\n")

    claim_results: list[tuple[str, str, str, bool, str, str]] = []
    for claim in claims:
        claim_id = claim.get("id", "unknown")
        print(f"Verifying {claim_id}... ", end="", flush=True)
        ok, msg, verdict = verify_claim(claim, records_by_id, root, today, detector_version)
        print("PASS" if ok else f"FAIL - {msg}")
        claim_results.append(
            (
                claim_id,
                claim.get("status", ""),
                claim.get("evidence_record_id", "—"),
                ok,
                verdict,
                msg,
            )
        )

    if args.report_card is not None:
        write_report_card(root, claim_results, records_by_id, registry_failures, args.report_card)
    elif not args.no_report_card:
        write_report_card(root, claim_results, records_by_id, registry_failures)

    failed = [r for r in claim_results if not r[3]]
    print(f"\n{'=' * 60}")
    print(f"Results: {len(claim_results) - len(failed)} passed, {len(failed)} failed")
    if registry_failures:
        print(f"Registry failures: {len(registry_failures)}")

    if failed or registry_failures:
        if failed:
            print("\nFailed claims:")
            for claim_id, _status, _record, _ok, _verdict, msg in failed:
                print(f"  - {claim_id}: {msg}")
        print("\nCI FAILED: One or more claims could not be verified.")
        return 1

    print("\nAll claims verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
