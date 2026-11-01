#!/usr/bin/env python3
"""
Fuzz target for text input validation in config.py and cli.py
"""

import sys
import atheris


def TestOneInput(data: bytes) -> None:
    """Fuzz text input validation functions."""
    try:
        text = data.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        return

    # Test validate_text_input from config.py
    try:
        from textforensics.config import validate_text_input, Settings, read_text_file

        # With various max_input_bytes settings
        for max_bytes in [64, 256, 1024, 2_000_000]:
            try:
                validate_text_input(text, max_input_bytes=max_bytes)
            except (ValueError, TypeError):
                pass  # Expected validation failures
    except Exception:
        pass

    # Test read_text_file from config.py
    try:
        from textforensics.config import read_text_file
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write(text)
            temp_path = f.name
        try:
            read_text_file(temp_path, max_input_bytes=2_000_000)
        finally:
            import os
            os.unlink(temp_path)
    except Exception:
        pass

    # Test Settings.from_env with various env values
    try:
        import os
        os.environ["TEXTFORENSICS_HOST"] = text[:255]
        try:
            Settings.from_env()
        finally:
            del os.environ["TEXTFORENSICS_HOST"]
    except Exception:
        pass

    # Test is_loopback_host and is_unspecified_host with fuzzer input
    try:
        from textforensics.config import is_loopback_host, is_unspecified_host, ensure_bind_allowed

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


def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()