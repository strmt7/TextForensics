#!/usr/bin/env python3
"""Generate golden case files for deterministic testing.

Usage:
    python scripts/generate_golden.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from textforensics.casefile import seal_case_file, verify_case_file
from textforensics.report import build_forensic_bundle


GOLDEN_TEST_TEXT = (
    "I tested this text to verify the golden case file generation. "
    "It contains enough words for detection in some detectors."
)

GOLDEN_DIR = Path(__file__).resolve().parent.parent / "tests" / "golden"
GOLDEN_FILE = GOLDEN_DIR / "case-file-valid.json"


def main() -> int:
    """Generate the golden case file."""
    # Ensure the golden directory exists
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)

    # Build the forensic bundle
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

    # Seal the case file
    case = seal_case_file(
        bundle_dict,
        deterministic=True,
        fixed_timestamp="1970-01-01T00:00:00+00:00",
    )

    # Write the golden file
    with open(GOLDEN_FILE, "w", encoding="utf-8") as f:
        json.dump(case, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write("\n")

    # Verify the written file
    with open(GOLDEN_FILE, encoding="utf-8") as f:
        payload = json.load(f)

    result = verify_case_file(payload)
    if result["valid"]:
        print(f"Generated golden file: {GOLDEN_FILE}")
        print(f"Case SHA256: {payload['case_sha256']}")
        return 0
    else:
        print(f"ERROR: Generated file failed verification: {result['errors']}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())