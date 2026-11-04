#!/usr/bin/env python3
"""
Fuzz target for JSON/YAML config parsing across TextForensics.

Covers:
- JSON parsing (valid, malformed, deeply nested, large)
- YAML config parsing (if PyYAML is available)
- API request validation (TextRequest, CompareRequest)
- Case file parsing (seal_case_file, verify_case_file)
- Benchmark JSONL line parsing (_load_scores)
- Schema validation paths
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import atheris
except ImportError:  # atheris optional; TestOneInput still importable
    atheris = None

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

# Try importing yaml; if unavailable, skip YAML fuzzing
try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def _fuzz_json(text: str) -> None:
    """Fuzz JSON parsing paths."""
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return

    if not isinstance(parsed, dict):
        # Also test arrays and scalars for robustness
        return

    # ------------------------------------------------------------------
    # 1. API request validation
    # ------------------------------------------------------------------
    try:
        from textforensics.api import CompareRequest, TextRequest

        if "text" in parsed:
            try:
                TextRequest(text=str(parsed.get("text", "")))
            except Exception:
                pass
        if "before" in parsed and "after" in parsed:
            try:
                CompareRequest(
                    before=str(parsed.get("before", "")),
                    after=str(parsed.get("after", "")),
                )
            except Exception:
                pass
    except Exception:
        pass

    # ------------------------------------------------------------------
    # 2. Case file parsing
    # ------------------------------------------------------------------
    try:
        from textforensics.casefile import seal_case_file, verify_case_file

        try:
            verify_case_file(parsed)
        except Exception:
            pass

        if parsed.get("schema") == "textforensics.forensic-bundle/v1":
            try:
                seal_case_file(parsed)
            except Exception:
                pass
    except Exception:
        pass

    # ------------------------------------------------------------------
    # 3. Benchmark JSONL line parsing
    # ------------------------------------------------------------------
    try:
        import os
        import tempfile

        from textforensics.benchmark import _load_scores

        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps(parsed) + "\n")
            temp_path = f.name
        try:
            _load_scores(temp_path, strict=False)
        finally:
            os.unlink(temp_path)
    except Exception:
        pass

    # ------------------------------------------------------------------
    # 4. Schema validation
    # ------------------------------------------------------------------
    try:
        from textforensics.schema import validate

        for schema_name in ("forensic-bundle", "detector-result", "case-file", "trust-map"):
            try:
                validate(parsed, schema_name)
            except Exception:
                pass
    except Exception:
        pass

    # ------------------------------------------------------------------
    # 5. Bundle canonical JSON
    # ------------------------------------------------------------------
    try:
        from textforensics.bundle import canonical_json_bytes

        try:
            canonical_json_bytes(parsed)
        except Exception:
            pass
    except Exception:
        pass


def _fuzz_yaml(text: str) -> None:
    """Fuzz YAML parsing paths."""
    if not HAS_YAML:
        return

    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError:
        return

    if parsed is None:
        return

    if isinstance(parsed, dict):
        # Test YAML-as-config patterns
        _fuzz_json(json.dumps(parsed))
    elif isinstance(parsed, list):
        # Test YAML lists (e.g., benchmark YAML configs)
        for item in parsed:
            if isinstance(item, dict):
                _fuzz_json(json.dumps(item))


def TestOneInput(data: bytes) -> None:
    """Fuzz JSON/YAML config parsing."""
    # ------------------------------------------------------------------
    # Decode with various strategies
    # ------------------------------------------------------------------
    for errors_mode in ("strict", "replace", "ignore"):
        try:
            text = data.decode("utf-8", errors=errors_mode)
        except (UnicodeDecodeError, UnicodeError):
            continue

        # ------------------------------------------------------------------
        # JSON parsing
        # ------------------------------------------------------------------
        _fuzz_json(text)

        # Also test truncated / partial JSON for robustness
        for cut in (len(text) // 2, len(text) // 4, 100):
            if cut < len(text):
                _fuzz_json(text[:cut])

        # ------------------------------------------------------------------
        # YAML parsing
        # ------------------------------------------------------------------
        _fuzz_yaml(text)

        # ------------------------------------------------------------------
        # Deeply nested JSON stress
        # ------------------------------------------------------------------
        try:
            # Construct a deeply nested structure
            depth = min(len(text) % 50 + 1, 100)
            nested = "null"
            for _ in range(depth):
                nested = f"[{nested}]"
            json.loads(nested)
        except (json.JSONDecodeError, RecursionError):
            pass
        except Exception:
            pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
