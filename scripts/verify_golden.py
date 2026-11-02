#!/usr/bin/env python3
"""Verify golden case files match their expected deterministic outputs.

This script is used in CI to enforce byte-deterministic outputs for case file generation.
It compares generated case files with golden files and exits with appropriate codes:
- EXIT_OK (0): All golden files match
- EXIT_ERROR (3): One or more golden files differ

Usage:
    python scripts/verify_golden.py [path/to/golden/dir]
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

# Import exit codes from the package
from textforensics.constants import EXIT_ERROR, EXIT_OK
from textforensics.casefile import seal_case_file
from textforensics.report import build_forensic_bundle


# Test configuration
GOLDEN_TEST_TEXT = (
    "I tested this text to verify the golden case file generation. "
    "It contains enough words for detection in some detectors."
)


def compute_case_hash(case: dict[str, Any]) -> str:
    """Compute SHA256 hash of a case file in canonical form.

    Excludes the case_sha256 field from the hash computation.
    """
    case_copy = {k: v for k, v in case.items() if k != "case_sha256"}
    canonical = json.dumps(
        case_copy,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def generate_case_file() -> dict[str, Any]:
    """Generate a deterministic case file for golden comparison."""
    bundle = build_forensic_bundle(
        GOLDEN_TEST_TEXT,
        ledger_path=None,
    )
    bundle_dict = bundle.to_dict()

    # Strip runtime_ms for deterministic output
    for r in bundle_dict.get("detector_results", []):
        r.pop("runtime_ms", None)
    for f in bundle_dict.get("detector_failures", []):
        f.pop("runtime_ms", None)

    return seal_case_file(
        bundle_dict,
        deterministic=True,
        fixed_timestamp="1970-01-01T00:00:00+00:00",
    )


def verify_golden_file(golden_path: Path) -> tuple[bool, str]:
    """Verify a golden file matches the expected deterministic output.

    Returns:
        Tuple of (is_valid, message)
    """
    if not golden_path.exists():
        return False, f"Golden file not found: {golden_path}"

    try:
        with open(golden_path, encoding="utf-8") as f:
            golden_content = f.read()
        golden_data = json.loads(golden_content)
    except (OSError, json.JSONDecodeError) as e:
        return False, f"Failed to read golden file {golden_path}: {e}"

    # Generate the expected case file
    generated = generate_case_file()

    # Compare hashes
    golden_hash = compute_case_hash(golden_data)
    generated_hash = compute_case_hash(generated)

    if golden_hash == generated_hash:
        return True, f"PASS: {golden_path.name} matches expected output"

    return False, (
        f"MISMATCH: {golden_path.name}\n"
        f"  Expected SHA256: {golden_hash}\n"
        f"  Generated SHA256: {generated_hash}\n"
        f"  The golden file needs to be regenerated."
    )


def main() -> int:
    """Run golden verification and return exit code."""
    # Determine the golden directory
    if len(sys.argv) > 1:
        golden_dir = Path(sys.argv[1])
    else:
        golden_dir = Path(__file__).resolve().parent.parent / "tests" / "golden"

    if not golden_dir.exists():
        print(f"ERROR: Golden directory not found: {golden_dir}", file=sys.stderr)
        return EXIT_ERROR

    # Find and verify all golden case files
    golden_files = list(golden_dir.glob("*.json"))

    if not golden_files:
        print(f"WARNING: No golden files found in {golden_dir}", file=sys.stderr)
        return EXIT_OK  # No files to verify is not an error

    all_passed = True
    for golden_path in sorted(golden_files):
        passed, message = verify_golden_file(golden_path)
        print(message)
        if not passed:
            all_passed = False

    if all_passed:
        print(f"\nAll {len(golden_files)} golden file(s) verified successfully.")
        return EXIT_OK
    else:
        print("\nGolden file verification failed. Regenerate with: python scripts/generate_golden.py",
              file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())