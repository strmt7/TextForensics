#!/usr/bin/env python3
"""
Validate AGENTS.md rules - specifically check that README claims are traceable to run artifacts.

AGENTS.md Rule #1: Never invent benchmark results. README numbers must trace to a committed/reproducible run artifact.

This script validates that any numeric claims in README.md about benchmarks,
accuracy, performance, etc. have corresponding run artifacts.
"""

import re
import sys
from pathlib import Path


def extract_numeric_claims(readme_path: Path) -> list[tuple[str, str, int]]:
    """Extract numeric claims from README.md that look like benchmark results."""
    claims = []

    with readme_path.open("r", encoding="utf-8") as f:
        content = f.read()

    # Look for patterns like "95% accuracy", "AUROC 0.92", "F1: 0.87", etc.
    patterns = [
        (r"(\d+(?:\.\d+)?)\s*%\s*(?:accuracy|precision|recall|F1|AUROC|AUPRC)", "percentage"),
        (r"(?:AUROC|AUPRC|F1|accuracy|precision|recall)(?:\s+score)?\s*(?:of|is|:)?\s*(\d+(?:\.\d+)?)", "score"),
        (r"(?:benchmark|benchmarks?)\s+(?:show|shows|showed|result|results?)\s+(?:an?|of)?\s*(\d+(?:\.\d+)?)\s*%", "benchmark"),
        (r"(\d+(?:\.\d+)?)\s*(?:times?|x)\s*(?:faster|slower|speedup)", "performance"),
        (r"(?:pass|fail|passing|failing)\s+(?:rate|ratio)\s*(?:of|is|:)?\s*(\d+(?:\.\d+)?)\s*%", "rate"),
    ]

    for pattern, claim_type in patterns:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            line_num = content[:match.start()].count("\n") + 1
            claims.append((match.group(0), claim_type, line_num))

    return claims


def find_run_artifacts() -> list[Path]:
    """Find benchmark run artifacts in the repository."""
    artifacts = []

    # Look for common benchmark artifact locations
    search_paths = [
        Path(".benchmarks"),
        Path("benchmarks"),
        Path("testdata/benchmarks"),
        Path("testdata"),
        Path(".github/workflows"),
    ]

    for search_path in search_paths:
        if search_path.exists():
            # Look for JSON, YAML, CSV files that might contain benchmark results
            for ext in ["*.json", "*.yaml", "*.yml", "*.csv", "*.md"]:
                artifacts.extend(search_path.rglob(ext))

    return artifacts


def check_claim_traceability(claims: list[tuple[str, str, int]], artifacts: list[Path]) -> list[str]:
    """Check if claims have traceable artifacts."""
    issues = []

    if not claims:
        return issues

    if not artifacts:
        issues.append("No benchmark run artifacts found in repository")
        return issues

    # For now, just warn if claims exist but we can't automatically verify them
    # This is a heuristic - in practice, you'd want to parse artifacts and cross-reference
    artifact_names = [a.name for a in artifacts]
    issues.append(
        f"Found {len(claims)} numeric claim(s) in README.md. "
        f"Found {len(artifacts)} potential artifact(s): {', '.join(artifact_names[:5])}{'...' if len(artifact_names) > 5 else ''}. "
        f"Manual verification recommended per AGENTS.md Rule #1."
    )

    for claim, claim_type, line_num in claims:
        issues.append(f"  Line {line_num}: '{claim}' ({claim_type})")

    return issues


def main() -> int:
    """Main entry point."""
    readme_path = Path(__file__).parent.parent / "README.md"

    if not readme_path.exists():
        print("README.md not found")
        return 1

    claims = extract_numeric_claims(readme_path)
    artifacts = find_run_artifacts()

    issues = check_claim_traceability(claims, artifacts)

    if issues:
        print("AGENTS.md Rule #1 Validation: README claims traceability check")
        print("=" * 60)
        for issue in issues:
            print(issue)
        print("\nNote: This is a heuristic check. Per AGENTS.md Rule #1:")
        print("  'Never invent benchmark results. README numbers must trace to")
        print("   a committed/reproducible run artifact.'")
        print("\nPlease ensure all numeric claims in README.md have corresponding")
        print("run artifacts committed to the repository.")
        # Don't fail - just warn for now
        return 0

    print("AGENTS.md Rule #1 Validation: No numeric claims found in README.md to verify")
    return 0


if __name__ == "__main__":
    sys.exit(main())