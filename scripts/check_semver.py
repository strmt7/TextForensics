#!/usr/bin/env python3
"""Validate that the package version in pyproject.toml follows semver."""
from __future__ import annotations

import re
import sys
from pathlib import Path


def main() -> int:
    content = Path("pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'version = "([^"]+)"', content)
    if not match:
        print("ERROR: version field not found in pyproject.toml")
        return 1
    version = match.group(1)
    print(f"Current version: {version}")
    if re.match(r"^\d+\.\d+\.\d+(?:-[a-zA-Z0-9]+)?(?:\+[a-zA-Z0-9]+)?$", version):
        print("Version format is valid semver")
        return 0
    print("ERROR: version does not follow semver format")
    return 1


if __name__ == "__main__":
    sys.exit(main())