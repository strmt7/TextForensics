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


# ---------------------------------------------------------------------------
# ENG-16 / byte policy (docs/verification/byte-policy.md): doc evidence
# binds to persisted bytes (UTF-8, LF) and an explicit as-of source SHA.
# ---------------------------------------------------------------------------

DOC_STATES = ("implemented", "tested", "historical", "blocked")

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")

# Release bar for a worst-slice human-FPR claim, as recorded in
# EV-20261110-dataset-opai-bench (fpr_bar): a supported slice needs at
# least 100 human rows and a Wilson 95% upper bound at or below 0.05.
FPR_BAR_N_HUMAN_MINIMUM = 100
FPR_BAR_WILSON_UPPER_CEILING = 0.05


def _git_output(root: Path, *args: str) -> tuple[int, str]:
    """Run git in root; (returncode, stdout). 127 when git is unavailable."""
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return 127, ""
    return result.returncode, result.stdout.strip()


def _git_commit_exists(root: Path, sha: str) -> bool:
    code, _ = _git_output(root, "cat-file", "-e", f"{sha}^{{commit}}")
    return code == 0


def _git_doc_unchanged_since(root: Path, as_of: str, rel_path: str) -> bool | None:
    """True if rel_path is unchanged between as_of and HEAD.

    Returns None when git cannot answer (missing git, bad ref): the
    caller must fail closed, not assume "unchanged".
    """
    code, _ = _git_output(root, "diff", "--quiet", as_of, "HEAD", "--", rel_path)
    if code == 0:
        return True
    if code == 1:
        return False
    return None


def _crlf_hint(path: Path) -> str:
    try:
        if b"\r\n" in path.read_bytes():
            return (
                " (bytes contain CRLF line endings — see "
                "docs/verification/byte-policy.md; do not rehash to "
                "host-specific bytes)"
            )
    except OSError:
        pass
    return ""


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
                    "after the record was written"
                    f"{_crlf_hint(artifact_path)}",
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


def check_doc(
    evidence_path: str, root: Path, claim: dict[str, Any] | None = None
) -> tuple[bool, str]:
    """Check a ``doc`` evidence assertion (ENG-16).

    File existence is NOT evidence. The claim must carry:
    - ``doc_sha256``: SHA-256 of the cited document's persisted bytes
      (UTF-8, LF — see docs/verification/byte-policy.md). A recorded
      digest that does not match the current bytes FAILS.
    - ``doc_as_of_sha``: the full commit SHA whose tree the digest was
      computed from. It must resolve in this repo.
    - ``doc_state``: ``implemented`` | ``tested`` | ``historical`` |
      ``blocked``. ``implemented``/``tested`` assert a property of the
      current tree, so the cited document must be unchanged since the
      as-of SHA; ``historical`` is a dated record (bytes still pinned
      by the digest); ``blocked`` can never pass.
    - ``executable_property`` (bool): when true, the claim asserts an
      executable property and ``executable_check`` (a command) must be
      present and exit 0. A saved ``cited_content_present=true``-style
      note is not execution evidence.
    """
    if claim is None:
        return (
            False,
            "doc evidence requires the claim's doc_sha256 / doc_as_of_sha / "
            "doc_state fields (ENG-16: existence is not evidence)",
        )
    rel = Path(evidence_path)
    if rel.is_absolute() or ".." in rel.parts:
        return False, f"doc evidence path escapes the repo: {evidence_path}"
    path = root / evidence_path
    if not path.exists():
        return False, f"Document not found: {path}"
    doc_sha = claim.get("doc_sha256")
    if not doc_sha or not _SHA256_RE.match(str(doc_sha)):
        return (
            False,
            f"doc evidence for {evidence_path} has no recorded doc_sha256 "
            "(ENG-16: bind the assertion to the document's current content digest)",
        )
    actual = _sha256_file(path)
    if actual != doc_sha:
        return (
            False,
            f"doc evidence digest mismatch for {evidence_path}: recorded "
            f"{str(doc_sha)[:12]}..., current bytes hash to {actual[:12]}..."
            f"{_crlf_hint(path)} (ENG-16)",
        )
    as_of = claim.get("doc_as_of_sha")
    if not as_of or not _SHA1_RE.match(str(as_of)):
        return (
            False,
            f"doc evidence for {evidence_path} has no valid doc_as_of_sha "
            "(ENG-16: record the source SHA the digest was computed from)",
        )
    if not _git_commit_exists(root, str(as_of)):
        return (
            False,
            f"doc evidence as-of SHA {as_of} does not resolve in this repo (ENG-16)",
        )
    state = claim.get("doc_state")
    if state not in DOC_STATES:
        return (
            False,
            f"doc evidence for {evidence_path} has doc_state {state!r}; "
            f"expected one of {', '.join(DOC_STATES)} (ENG-16)",
        )
    if state == "blocked":
        return (
            False,
            f"doc evidence for {evidence_path} is blocked: the asserted "
            "property is not established (ENG-16)",
        )
    if state in ("implemented", "tested"):
        unchanged = _git_doc_unchanged_since(root, str(as_of), evidence_path)
        if unchanged is None:
            return (
                False,
                f"doc evidence for {evidence_path}: cannot verify the document "
                f"is unchanged since as-of {str(as_of)[:12]}... (git unavailable "
                "or error) (ENG-16)",
            )
        if not unchanged:
            return (
                False,
                f"doc evidence for {evidence_path} changed since as-of "
                f"{str(as_of)[:12]}... — re-verify and re-record the digest / "
                "as-of SHA (ENG-16)",
            )
    if claim.get("executable_property"):
        check = claim.get("executable_check")
        if not check:
            return (
                False,
                f"doc evidence for {evidence_path} asserts an executable "
                "property but carries no executable_check (ENG-16: a saved "
                "content note is not execution evidence)",
            )
        code, stdout, stderr = run_chain(str(check), cwd=root)
        if code != 0:
            detail = (stderr or stdout).strip().splitlines()
            tail = "\n".join(detail[-10:])
            return (
                False,
                f"doc evidence executable_check failed (exit {code}) for {evidence_path}: {tail}",
            )
    return True, "Document digest and as-of SHA verified"


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
            ok, msg = check_doc(evidence_path, root, claim)
        elif evidence_type == "external_audit":
            ok, msg = check_external_audit(evidence_path, root)
        elif evidence_type == "command":
            ok, msg = check_command(evidence_path, root)
        else:
            return False, f"Unknown evidence type: {evidence_path}", "fail"
    except Exception as e:
        return False, f"Verification error: {e}", "fail"
    return ok, msg, "pass" if ok else "fail"


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _worst_document_slice(artifact: dict[str, Any]) -> dict[str, Any] | None:
    """The document slice with the largest per-slice Wilson FPR upper bound.

    Segment slices are a different unit (sentences, not documents) and
    are never candidates for a document-level worst slice.
    """
    results = artifact.get("results", {})
    slices = results.get("slices")
    if not isinstance(slices, list):
        return None
    docs = [s for s in slices if isinstance(s, dict) and s.get("slice_kind") == "document"]
    if not docs:
        return None

    def upper(s: dict[str, Any]) -> float:
        wilson = s.get("fpr_native_wilson")
        if isinstance(wilson, dict) and _is_number(wilson.get("ci_upper")):
            return float(wilson["ci_upper"])
        return -1.0

    return max(docs, key=upper)


def _slice_blockers(slice_entry: dict[str, Any]) -> list[str]:
    assessment = slice_entry.get("assessment")
    if isinstance(assessment, dict):
        blockers = assessment.get("blockers")
        if isinstance(blockers, list):
            return [str(b) for b in blockers]
    return []


def human_fpr_summary(
    records_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Schema-aware human-FPR aggregation over the registry (ENG-16).

    Wilson-upper-bound field names, enumerated from the run-artifact
    schema (``results`` is a free-form object) and the committed
    measurement runs, plus the validation-registry schema
    (``evidence-record.schema.json`` ``$defs.metric_estimate``:
    ``records[].metrics[].fpr_native.ci_upper`` with ``value``/``n``/
    ``method`` — mirrored in the run artifacts' per-slice values below):

    - ``results.worst_slice_wilson_ci_upper`` — worst-slice Wilson 95%
      upper bound (EV-20261110-human-fpr).
    - ``results.worst_document_slice_wilson_ci_upper`` — same, document
      slices only (EV-20261110-human-fpr).
    - ``results.slices[].fpr_native_wilson.ci_upper`` — per-slice Wilson
      95% upper bound, with ``n_human`` and ``assessment`` (``can_support_fpr_claim``,
      ``blockers``) on the same slice entry.
    - ``results.human_fpr_native.wilson_95_ci_upper`` — a SINGLE slice's
      Wilson 95% upper bound (EV-20261110-dataset-opai-bench); present
      evidence, never a worst-slice lead.
    - ``results.pooled_documents_only.ci_upper`` and
      ``results.pooled_all_slices_including_segments.ci_upper`` — pooled
      values. Pooling hides slice heterogeneity (and the segment pool
      mixes units); pooled values are NEVER a worst-slice statistic.
    - Legacy point-rate keys (unchanged behaviour):
      ``results.worst_slice_human_fpr`` and
      ``results.human_fpr.worst_slice``.

    A worst-slice Wilson upper bound qualifies as the lead only when
    the worst document slice behind it meets the release bar
    (n_human >= 100, Wilson upper <= 0.05, assessment says the slice
    can support an FPR claim). Anything else is present-but-unqualified
    evidence: the lead stays ``unknown`` with an accurate reason, and
    is NEVER filled from a best slice, a single slice, or a pooled
    value.
    """
    entries: list[dict[str, Any]] = []
    best_point: tuple[float, str] | None = None
    best_wilson: tuple[float, str] | None = None

    def consider(kind: str, value: float, record_id: str) -> None:
        nonlocal best_point, best_wilson
        target = best_point if kind == "point_rate" else best_wilson
        if target is None or value > target[0]:
            if kind == "point_rate":
                best_point = (value, record_id)
            else:
                best_wilson = (value, record_id)

    for record_id, entry in records_by_id.items():
        artifact = entry["artifact"]
        results = artifact.get("results", {})
        if not isinstance(results, dict):
            continue

        # Legacy point-rate keys: a worst-slice point rate, when present.
        point_value = results.get("worst_slice_human_fpr")
        if point_value is None and isinstance(results.get("human_fpr"), dict):
            point_value = results["human_fpr"].get("worst_slice")
        if _is_number(point_value):
            entries.append(
                {
                    "record_id": record_id,
                    "field": "results.worst_slice_human_fpr",
                    "value": float(point_value),
                    "kind": "worst_slice_point_rate",
                    "n": None,
                    "qualified": True,
                    "reason": "worst-slice point rate",
                }
            )
            consider("point_rate", float(point_value), record_id)

        # Worst-slice Wilson upper bounds (top-level aggregation fields).
        worst_slice = _worst_document_slice(artifact)
        for field in (
            "worst_slice_wilson_ci_upper",
            "worst_document_slice_wilson_ci_upper",
        ):
            value = results.get(field)
            if not _is_number(value):
                continue
            if worst_slice is None:
                qualified = False
                reason = (
                    "no per-slice detail in the record to establish that "
                    "the worst slice meets the bar (n>=100, Wilson upper "
                    "<=0.05, slice can support an FPR claim)"
                )
            else:
                wilson = worst_slice.get("fpr_native_wilson") or {}
                n_human = worst_slice.get("n_human")
                assessment = worst_slice.get("assessment") or {}
                can_support = assessment.get("can_support_fpr_claim") is True
                blockers = _slice_blockers(worst_slice)
                dataset = worst_slice.get("dataset", worst_slice.get("record_id", "?"))
                if (
                    isinstance(n_human, int)
                    and n_human >= FPR_BAR_N_HUMAN_MINIMUM
                    and float(value) <= FPR_BAR_WILSON_UPPER_CEILING
                    and can_support
                ):
                    qualified = True
                    reason = f"worst document slice {dataset} (n_human={n_human}) meets the bar"
                else:
                    qualified = False
                    detail = (
                        "; ".join(blockers)
                        if blockers
                        else (
                            f"worst document slice {dataset} (n_human={n_human}) "
                            "does not meet the bar"
                        )
                    )
                    reason = f"present but unqualified: {detail}"
            entries.append(
                {
                    "record_id": record_id,
                    "field": f"results.{field}",
                    "value": float(value),
                    "kind": "worst_slice_wilson_upper",
                    "n": worst_slice.get("n_human") if worst_slice else None,
                    "qualified": qualified,
                    "reason": reason,
                }
            )
            if qualified:
                consider("wilson_upper", float(value), record_id)

        # Single-slice Wilson upper bound: present evidence, never a lead.
        human_fpr = results.get("human_fpr_native")
        if isinstance(human_fpr, dict) and _is_number(human_fpr.get("wilson_95_ci_upper")):
            entries.append(
                {
                    "record_id": record_id,
                    "field": "results.human_fpr_native.wilson_95_ci_upper",
                    "value": float(human_fpr["wilson_95_ci_upper"]),
                    "kind": "single_slice_wilson_upper",
                    "n": human_fpr.get("n_human"),
                    "qualified": False,
                    "reason": (
                        "single-slice value (one dataset slice, "
                        f"n_human={human_fpr.get('n_human')}); not a "
                        "worst-slice aggregation, so it cannot fill the lead"
                    ),
                }
            )

        # Per-slice detail only when the record carries no top-level
        # worst-slice field: report the worst document slice itself.
        has_worst_field = any(
            _is_number(results.get(f))
            for f in (
                "worst_slice_wilson_ci_upper",
                "worst_document_slice_wilson_ci_upper",
            )
        )
        if not has_worst_field and worst_slice is not None:
            wilson = worst_slice.get("fpr_native_wilson") or {}
            if _is_number(wilson.get("ci_upper")):
                blockers = _slice_blockers(worst_slice)
                entries.append(
                    {
                        "record_id": record_id,
                        "field": "results.slices[].fpr_native_wilson.ci_upper (worst document slice)",
                        "value": float(wilson["ci_upper"]),
                        "kind": "per_slice_wilson_upper",
                        "n": worst_slice.get("n_human"),
                        "qualified": False,
                        "reason": (
                            "per-slice value; this record has no worst-slice "
                            "aggregation field" + (f": {'; '.join(blockers)}" if blockers else "")
                        ),
                    }
                )

        # Pooled values: recorded for completeness, never a lead.
        for field in (
            "pooled_documents_only",
            "pooled_all_slices_including_segments",
        ):
            pooled = results.get(field)
            if isinstance(pooled, dict) and _is_number(pooled.get("ci_upper")):
                entries.append(
                    {
                        "record_id": record_id,
                        "field": f"results.{field}.ci_upper",
                        "value": float(pooled["ci_upper"]),
                        "kind": "pooled_wilson_upper",
                        "n": pooled.get("n"),
                        "qualified": False,
                        "reason": (
                            "pooled value: pooling hides slice heterogeneity "
                            "(and the segment pool mixes units) and is never "
                            "a worst-slice statistic"
                        ),
                    }
                )

    # A worst-slice point rate is the direct statistic and leads when
    # present; a qualified Wilson upper bound leads only when no point
    # rate exists. The two are never mixed into one max.
    if best_point is not None:
        lead_kind, (lead_value, lead_record) = "point_rate", best_point
    elif best_wilson is not None:
        lead_kind, (lead_value, lead_record) = "wilson_upper", best_wilson
    else:
        lead_kind, lead_value, lead_record = None, None, None

    if lead_value is not None:
        reason = ""
    elif not entries:
        reason = (
            "no human-FPR evidence is recorded in the registry yet "
            "(Phase 5 release gate). No FPR is claimed anywhere in this repository."
        )
    else:
        parts = []
        for e in entries:
            if e["kind"] == "worst_slice_wilson_upper":
                parts.append(
                    f"worst-slice Wilson 95% upper bound {e['value']} in "
                    f"`{e['record_id']}` ({e['field']}) — {e['reason']}"
                )
            elif e["kind"] == "single_slice_wilson_upper":
                parts.append(
                    f"single-slice Wilson 95% upper bound {e['value']} in "
                    f"`{e['record_id']}` — {e['reason']}"
                )
            elif e["kind"] == "per_slice_wilson_upper":
                parts.append(
                    f"per-slice Wilson 95% upper bound {e['value']} in "
                    f"`{e['record_id']}` — {e['reason']}"
                )
            elif e["kind"] == "pooled_wilson_upper":
                parts.append(
                    f"pooled Wilson 95% upper bound {e['value']} in "
                    f"`{e['record_id']}` ({e['field']}) — {e['reason']}"
                )
        reason = (
            "human-FPR evidence is present in the registry but unqualified "
            "for a worst-slice lead: " + "; ".join(parts)
        )

    return {
        "lead_kind": lead_kind,
        "lead_value": lead_value,
        "lead_record": lead_record,
        "entries": entries,
        "reason": reason,
    }


def worst_slice_fpr(
    records_by_id: dict[str, dict[str, Any]],
) -> tuple[float | None, str | None]:
    """Worst-slice human false-positive rate for the report-card lead.

    Returns (value, record_id) or (None, None) when no qualified
    worst-slice evidence exists. A qualified worst-slice Wilson 95%
    upper bound is returned as the value; the caller labels it as an
    upper bound (see human_fpr_summary), never as a point rate.
    """
    summary = human_fpr_summary(records_by_id)
    return summary["lead_value"], summary["lead_record"]


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
    summary = human_fpr_summary(records_by_id)
    lines = [
        "# TextForensics evidence report card",
        "",
        "Generated by `scripts/check_claims.py` (U7 claim-to-evidence gate). "
        "Do not hand-edit: the gate regenerates this file and CI diffs it.",
        "",
        "## Worst-slice human false-positive rate",
        "",
    ]
    if summary["lead_value"] is None:
        lines += [
            f"**unknown** — {summary['reason']}",
            "",
        ]
        if summary["entries"]:
            lines += [
                "### Human-FPR evidence present in the registry (unqualified)",
                "",
                "The following Wilson-upper-bound / FPR evidence exists in "
                "registry run artifacts. None of it qualifies as a "
                "worst-slice lead (see the reason above); it is listed here "
                "so the card does not claim no evidence exists.",
                "",
            ]
            for e in summary["entries"]:
                lines.append(
                    f"- `{e['record_id']}`: `{e['field']}` = {e['value']} "
                    f"({e['kind']}; {e['reason']})"
                )
            lines.append("")
    else:
        label = (
            "worst slice; Wilson 95% upper bound"
            if summary["lead_kind"] == "wilson_upper"
            else "worst slice"
        )
        lines += [
            f"**{summary['lead_value']}** ({label}; evidence record `{summary['lead_record']}`)",
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
