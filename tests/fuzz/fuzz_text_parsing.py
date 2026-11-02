#!/usr/bin/env python3
"""
Fuzz target for text input parsing across TextForensics.

Covers:
- UTF-8 decoding edge cases (valid, invalid, replacement)
- Null bytes and control characters
- Very long text inputs
- Whitespace-only and empty inputs
- Text validation in config.py and engine.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import atheris

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))


def TestOneInput(data: bytes) -> None:
    """Fuzz text input parsing and validation."""
    # ------------------------------------------------------------------
    # 1. UTF-8 decoding with various error handlers
    # ------------------------------------------------------------------
    for errors_mode in ("strict", "replace", "surrogateescape", "ignore"):
        try:
            text = data.decode("utf-8", errors=errors_mode)
        except (UnicodeDecodeError, UnicodeError):
            continue

        # ------------------------------------------------------------------
        # 2. config.py: validate_text_input
        # ------------------------------------------------------------------
        try:
            from textforensics.config import validate_text_input

            for max_bytes in (1, 64, 256, 1024, 10_000, 2_000_000):
                try:
                    validate_text_input(text, max_input_bytes=max_bytes)
                except (ValueError, TypeError):
                    pass  # Expected validation failures
        except Exception:
            pass

        # ------------------------------------------------------------------
        # 3. config.py: read_text_file (write to temp file, then read)
        # ------------------------------------------------------------------
        try:
            import os
            import tempfile

            from textforensics.config import read_text_file

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, encoding="utf-8"
            ) as f:
                f.write(text)
                temp_path = f.name
            try:
                read_text_file(temp_path, max_input_bytes=2_000_000)
            finally:
                os.unlink(temp_path)
        except Exception:
            pass

        # ------------------------------------------------------------------
        # 4. engine.py: analyze_text
        # ------------------------------------------------------------------
        try:
            from textforensics.engine import analyze_text

            try:
                result = analyze_text(text)
                # Verify result invariants
                assert hasattr(result, "score")
                assert hasattr(result, "verdict")
            except ValueError:
                pass  # Empty text or other validation error
        except Exception:
            pass

        # ------------------------------------------------------------------
        # 5. engine.py: _verdict with edge-case scores
        # ------------------------------------------------------------------
        try:
            from textforensics.engine import _verdict

            for score in (0.0, 0.32, 0.33, 0.5, 0.67, 0.68, 1.0):
                for rel in (0.0, 0.27, 0.28, 0.5, 1.0):
                    try:
                        v = _verdict(score, rel)
                        assert v in (
                            "insufficient_evidence",
                            "machine_like_patterns",
                            "human_like_patterns",
                            "indeterminate",
                        )
                    except ValueError:
                        pass
        except Exception:
            pass

        # ------------------------------------------------------------------
        # 6. detectors.py: BuiltinHeuristicDetector.detect
        # ------------------------------------------------------------------
        try:
            from textforensics.detectors import BuiltinHeuristicDetector, execute_detector

            detector = BuiltinHeuristicDetector()
            result, failure = execute_detector(detector, text)
            if result is not None:
                result.validate(detector=detector)
        except Exception:
            pass

        # ------------------------------------------------------------------
        # 7. config.py: Settings.from_env with host derived from text
        # ------------------------------------------------------------------
        try:
            import os

            from textforensics.config import Settings

            os.environ["TEXTFORENSICS_HOST"] = text[:255]
            try:
                Settings.from_env()
            finally:
                del os.environ["TEXTFORENSICS_HOST"]
        except Exception:
            pass

        # ------------------------------------------------------------------
        # 8. config.py: is_loopback_host / is_unspecified_host / ensure_bind_allowed
        # ------------------------------------------------------------------
        try:
            from textforensics.config import (
                ensure_bind_allowed,
                is_loopback_host,
                is_unspecified_host,
            )

            host = text.strip()
            if host:
                is_loopback_host(host)
                is_unspecified_host(host)
                try:
                    ensure_bind_allowed(host, allow_remote=False)
                except ValueError:
                    pass
        except Exception:
            pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()