#!/usr/bin/env python3
"""
Validate pyproject.toml dependencies are sorted alphabetically within each group.

This ensures consistent ordering and makes diffs cleaner.
"""

import re
import sys
from pathlib import Path

try:
    import tomllib
except ImportError:
    import tomli as tomllib


def check_sorted(items: list[str], group_name: str) -> list[str]:
    """Check if a list of dependencies is sorted alphabetically (case-insensitive)."""
    issues = []
    # Extract package name from dependency spec (e.g., "pytest>=8,<9" -> "pytest")
    package_names = []
    for item in items:
        # Split on common version specifiers
        name = re.split(r"[<>!=~\[ ]", item)[0].strip()
        if name:
            package_names.append(name.lower())

    sorted_names = sorted(package_names)
    if package_names != sorted_names:
        issues.append(
            f"Dependencies in [{group_name}] are not sorted alphabetically:\n"
            f"  Current: {package_names}\n"
            f"  Expected: {sorted_names}"
        )
    return issues


def main() -> int:
    """Main entry point."""
    pyproject_path = Path(__file__).parent.parent / "pyproject.toml"

    if not pyproject_path.exists():
        print("pyproject.toml not found")
        return 1

    with pyproject_path.open("rb") as f:
        data = tomllib.load(f)

    all_issues = []

    # Check project.dependencies (main dependencies)
    if "project" in data and "dependencies" in data["project"]:
        deps = data["project"]["dependencies"]
        if isinstance(deps, list):
            all_issues.extend(check_sorted(deps, "project.dependencies"))

    # Check project.optional-dependencies
    if "project" in data and "optional-dependencies" in data["project"]:
        opt_deps = data["project"]["optional-dependencies"]
        if isinstance(opt_deps, dict):
            for group_name, deps in opt_deps.items():
                if isinstance(deps, list):
                    all_issues.extend(
                        check_sorted(deps, f"project.optional-dependencies.{group_name}")
                    )

    if all_issues:
        print("pyproject.toml dependency ordering validation failed:")
        print("=" * 60)
        for issue in all_issues:
            print(issue)
        return 1

    print("pyproject.toml dependencies are correctly sorted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
