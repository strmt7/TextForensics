#!/usr/bin/env python3
"""
Fuzz target for JSON parsing in api.py, casefile.py, benchmark.py
"""

import json
import sys

import atheris


def TestOneInput(data: bytes) -> None:
    """Fuzz JSON parsing across multiple modules."""
    try:
        # Try to parse as JSON
        parsed = json.loads(data.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return

    if not isinstance(parsed, dict):
        return

    # Test api.py JSON handling (TextRequest, CompareRequest)
    try:
        from textforensics.api import CompareRequest, TextRequest

        if "text" in parsed:
            TextRequest(text=str(parsed.get("text", "")))
        if "before" in parsed and "after" in parsed:
            CompareRequest(before=str(parsed.get("before", "")), after=str(parsed.get("after", "")))
    except Exception:
        pass  # Validation errors are expected for fuzzing

    # Test casefile.py JSON handling
    try:
        from textforensics.casefile import seal_case_file, verify_case_file

        verify_case_file(parsed)

        # Also test seal_case_file with a minimal forensic bundle
        if parsed.get("schema") == "textforensics.forensic-bundle/v1":
            seal_case_file(parsed)
    except Exception:
        pass

    # Test benchmark.py JSONL line parsing
    try:
        # Create a temporary file with this JSON line
        import tempfile

        from textforensics.benchmark import _load_scores
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps(parsed) + "\n")
            temp_path = f.name
        try:
            _load_scores(temp_path, strict=False)
        finally:
            import os
            os.unlink(temp_path)
    except Exception:
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
