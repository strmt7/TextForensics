#!/usr/bin/env python3
"""Validate that the package version in pyproject.toml follows semver.

This script is used by the semver.yml GitHub Actions workflow to validate
that version numbers follow semantic versioning conventions.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


def main() -> int:
    """Check that the version in pyproject.toml follows semver format."""
    pyproject_path = Path("pyproject.toml")

    if not pyproject_path.exists():
        print("ERROR: pyproject.toml not found")
        return 1

    content = pyproject_path.read_text(encoding="utf-8")

    # Match version = "..." pattern
    match = re.search(r'version\s*=\s*"([^"]+)"', content)
    if not match:
        print("ERROR: version field not found in pyproject.toml")
        return 1

    version = match.group(1)
    print(f"Current version: {version}")

    # Validate semver: MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]
    # Following Semantic Versioning 2.0.0 specification
    if re.match(r"^\d+\.\d+\.\d+(?:-[a-zA-Z0-9]+)?(?:\+[a-zA-Z0-9]+)?$", version):
        print("Version format is valid semver")
        return 0

    print("ERROR: version does not follow semver format")
    print("Expected: MAJOR.MINOR.PATCH (e.g., 1.0.0)")
    print("Can include pre-release: MAJOR.MINOR.PATCH-rc.1")
    print("Can include build: MAJOR.MINOR.PATCH+build.123")
    return 1


if __name__ == "__main__":
    sys.exit(main())