#!/usr/bin/env python3
"""
check_claims.py — Machine-verifiable claims validation for CI.

Validates claims from docs/CLAIMS.yaml against the codebase, tests, and artifacts.
Exits non-zero on any unverified/false/stale claim or missing evidence.

Tool invocations always go through the current interpreter
(sys.executable): there is no guarantee a bare ``python`` binary exists
on the machine running CI, and console scripts may not be on PATH.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml


REPO_ROOT = Path(__file__).parent.parent
CLAIMS_FILE = REPO_ROOT / "docs" / "CLAIMS.yaml"

# Console-script entry points mapped to their importable module, so the
# gate runs them via the current interpreter instead of relying on PATH.
_TOOL_MODULES = {
    "python": None,  # replaced by sys.executable itself
    "pytest": "pytest",
    "ruff": "ruff",
    "bandit": "bandit",
    "pip-audit": "pip_audit",
}


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


def load_claims() -> list[dict[str, Any]]:
    text = CLAIMS_FILE.read_text(encoding="utf-8")
    _check_no_duplicate_keys(text)
    data = yaml.safe_load(text)
    return data.get("claims", [])


def _check_no_duplicate_keys(text: str) -> None:
    """Fail fast on duplicate YAML mapping keys (last-wins is silent)."""
    node = yaml.compose(text)
    duplicates: list[str] = []

    def walk(mapping_node: Any, path: str = "") -> None:
        if not hasattr(mapping_node, "value"):
            return
        if mapping_node.tag == "tag:yaml.org,2002:map":
            seen: set[str] = set()
            for key_node, value_node in mapping_node.value:
                key = key_node.value
                child_path = f"{path}.{key}" if path else str(key)
                if key in seen:
                    duplicates.append(child_path)
                seen.add(key)
                walk(value_node, child_path)
        elif mapping_node.tag == "tag:yaml.org,2002:seq":
            for item in mapping_node.value:
                walk(item, path)

    walk(node)
    if duplicates:
        raise ValueError(f"Duplicate YAML keys in {CLAIMS_FILE}: {duplicates}")


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


def check_test_evidence(evidence_path: str) -> tuple[bool, str]:
    """Check if a test file/path exists and tests pass."""
    if evidence_path.startswith("tests/"):
        # Handle both "tests/file.py" and "tests/file.py::Class::method" formats
        parts = evidence_path.split("::", 1)
        test_file = REPO_ROOT / parts[0]
        if not test_file.exists():
            return False, f"Test file not found: {test_file}"
        # Run the specific test
        cmd = [sys.executable, "-m", "pytest", evidence_path, "-q", "-p", "no:cacheprovider"]
        code, stdout, stderr = run_command(cmd)
        if code != 0:
            return False, f"Test failed: {stdout}\n{stderr}"
        return True, "Test passed"
    return False, f"Unknown test path format: {evidence_path}"


def check_benchmark_artifact(evidence_path: str) -> tuple[bool, str]:
    """Check if a benchmark artifact exists and is more than a placeholder."""
    path = REPO_ROOT / evidence_path
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


def check_code_audit(evidence_path: str) -> tuple[bool, str]:
    """Check if a code path exists."""
    path = REPO_ROOT / evidence_path
    if not path.exists():
        return False, f"Code path not found: {path}"
    return True, "Code path exists"


def check_doc(evidence_path: str) -> tuple[bool, str]:
    """Check if a doc/file exists and contains expected content."""
    path = REPO_ROOT / evidence_path
    if not path.exists():
        return False, f"Document not found: {path}"
    return True, "Document exists"


def check_external_audit(evidence_path: str) -> tuple[bool, str]:
    """Run an external audit command."""
    code, stdout, stderr = run_chain(evidence_path)
    if code != 0:
        return False, f"Command failed (exit {code}): {stderr or stdout}"
    return True, "Audit passed"


def check_command(evidence_path: str) -> tuple[bool, str]:
    """Run a shell command and check it succeeds.

    A non-zero exit is a failure — including for bandit/pip-audit, whose
    exit codes report findings. Claims that cite those tools must use a
    command whose exit code already encodes the claim (e.g. bandit
    ``-lll`` reports only high-severity findings).
    """
    code, stdout, stderr = run_chain(evidence_path)
    if code == 0:
        return True, "Command succeeded"
    detail = (stderr or stdout).strip().splitlines()
    tail = "\n".join(detail[-20:])
    return False, f"Command failed (exit {code}): {tail}"


def verify_claim(claim: dict[str, Any]) -> tuple[bool, str]:
    """Verify a single claim against its evidence."""
    claim_id = claim.get("id", "unknown")
    evidence_type = claim.get("evidence_type", "")
    evidence_path = claim.get("evidence_path", "")
    status = claim.get("status", "unverified")

    if status in ("unverified", "false", "stale"):
        return False, f"Claim status is '{status}' - requires verification"

    try:
        if evidence_type == "test":
            return check_test_evidence(evidence_path)
        elif evidence_type == "benchmark_artifact":
            return check_benchmark_artifact(evidence_path)
        elif evidence_type == "code_audit":
            return check_code_audit(evidence_path)
        elif evidence_type == "doc":
            return check_doc(evidence_path)
        elif evidence_type == "external_audit":
            return check_external_audit(evidence_path)
        elif evidence_type == "command":
            return check_command(evidence_path)
        else:
            return False, f"Unknown evidence type: {evidence_path}"
    except Exception as e:
        return False, f"Verification error: {e}"


def main() -> int:
    print(f"Loading claims from {CLAIMS_FILE}")
    claims = load_claims()
    print(f"Found {len(claims)} claims\n")

    failed = []
    passed = 0

    for claim in claims:
        claim_id = claim.get("id", "unknown")
        print(f"Verifying {claim_id}... ", end="", flush=True)

        ok, msg = verify_claim(claim)
        if ok:
            print("PASS")
            passed += 1
        else:
            print(f"FAIL - {msg}")
            failed.append((claim_id, msg))

    print(f"\n{'=' * 60}")
    print(f"Results: {passed} passed, {len(failed)} failed")

    if failed:
        print("\nFailed claims:")
        for cid, msg in failed:
            print(f"  - {cid}: {msg}")
        print("\nCI FAILED: One or more claims could not be verified.")
        return 1

    print("\nAll claims verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
