#!/usr/bin/env python3
"""Standalone CI script: verify generated bundles against golden files.

Compares bundle archives generated from case files with golden bundles
stored in a golden directory.  Exits with:

- EXIT_OK (0): All golden bundles match.
- EXIT_ERROR (3): One or more bundles differ.

Usage:
    python scripts/verify_bundle.py [path/to/golden/dir]
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from textforensics.bundle import pack_bundle, verify_bundle
from textforensics.casefile import seal_case_file
from textforensics.constants import EXIT_ERROR, EXIT_OK
from textforensics.report import build_forensic_bundle

# ---------------------------------------------------------------------------
# Test configuration
# ---------------------------------------------------------------------------

GOLDEN_TEST_TEXT = (
    "I tested this text to verify the golden bundle generation. "
    "It contains enough words for detection in some detectors."
)

GOLDEN_BUNDLE_NAME = "case-bundle-valid.tar.gz"
GOLDEN_MANIFEST_NAME = "case-bundle-valid.tar.gz.manifest.json"


def _generate_case_file() -> dict:
    """Generate a deterministic case file for golden comparison."""
    bundle = build_forensic_bundle(GOLDEN_TEST_TEXT, ledger_path=None)
    bundle_dict = bundle.to_dict()

    for r in bundle_dict.get("detector_results", []):
        r.pop("runtime_ms", None)
    for f in bundle_dict.get("detector_failures", []):
        f.pop("runtime_ms", None)

    return seal_case_file(
        bundle_dict,
        deterministic=True,
        fixed_timestamp="1970-01-01T00:00:00+00:00",
    )


def _generate_bundle() -> tuple[str, str]:
    """Generate a bundle from the golden test case file.

    Returns (bundle_digest, per_file_digests).
    """
    case = _generate_case_file()

    with tempfile.TemporaryDirectory() as tmp:
        case_path = Path(tmp) / "case.json"
        case_path.write_text(
            json.dumps(case, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        bundle_path = Path(tmp) / GOLDEN_BUNDLE_NAME
        manifest = pack_bundle(case_path, bundle_path)
        return manifest.bundle_digest, manifest.per_file_digests


def _golden_bundle_digest(golden_dir: Path) -> str | None:
    """Read the expected bundle digest from the golden manifest file."""
    manifest_path = golden_dir / GOLDEN_MANIFEST_NAME
    if not manifest_path.exists():
        return None
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    return data.get("bundle_digest")


def _golden_per_file_digests(golden_dir: Path) -> dict[str, str] | None:
    """Read the expected per-file digests from the golden manifest file."""
    manifest_path = golden_dir / GOLDEN_MANIFEST_NAME
    if not manifest_path.exists():
        return None
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    return data.get("per_file_digests")


def verify_golden_bundle(golden_dir: Path) -> tuple[bool, str]:
    """Verify a golden bundle matches the expected deterministic output.

    Returns:
        Tuple of (is_valid, message)
    """
    golden_bundle = golden_dir / GOLDEN_BUNDLE_NAME
    if not golden_bundle.exists():
        return False, f"Golden bundle not found: {golden_bundle}"

    try:
        expected_digest = _golden_bundle_digest(golden_dir)
        expected_per_file = _golden_per_file_digests(golden_dir)

        if expected_digest is None:
            return False, f"Golden manifest not found: {golden_dir / GOLDEN_MANIFEST_NAME}"

        # Generate the expected bundle
        generated_digest, generated_per_file = _generate_bundle()

        # Compare digests
        if generated_digest != expected_digest:
            return False, (
                f"MISMATCH: {GOLDEN_BUNDLE_NAME}\n"
                f"  Expected bundle digest: {expected_digest}\n"
                f"  Generated bundle digest: {generated_digest}\n"
                f"  The golden bundle needs to be regenerated."
            )

        # Compare per-file digests
        for fname, expected in expected_per_file.items():
            actual = generated_per_file.get(fname)
            if actual != expected:
                return False, (
                    f"MISMATCH: per-file digest for {fname}\n"
                    f"  Expected: {expected}\n"
                    f"  Generated: {actual}\n"
                    f"  The golden bundle needs to be regenerated."
                )

        # Verify the golden bundle itself
        result = verify_bundle(golden_bundle, expected_digest=generated_digest)
        if not result.valid:
            return False, f"Golden bundle fails integrity check: {result.errors}"

        return True, f"PASS: {GOLDEN_BUNDLE_NAME} matches expected output"

    except Exception as exc:
        return False, f"ERROR: Failed to verify golden bundle: {exc}"


def main() -> int:
    """Run golden bundle verification and return exit code."""
    if len(sys.argv) > 1:
        golden_dir = Path(sys.argv[1])
    else:
        golden_dir = Path(__file__).resolve().parent.parent / "tests" / "golden"

    if not golden_dir.exists():
        print(f"ERROR: Golden directory not found: {golden_dir}", file=sys.stderr)
        return EXIT_ERROR

    passed, message = verify_golden_bundle(golden_dir)
    print(message)

    if passed:
        print("\nGolden bundle verified successfully.")
        return EXIT_OK
    else:
        print("\nGolden bundle verification failed. "
              "Regenerate with: python scripts/generate_golden.py",
              file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
