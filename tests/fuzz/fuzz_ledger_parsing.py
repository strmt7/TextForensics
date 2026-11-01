#!/usr/bin/env python3
"""
Fuzz target for ledger parsing in provenance.py
"""

import json
import sys
import tempfile
from pathlib import Path

import atheris


def TestOneInput(data: bytes) -> None:
    """Fuzz ledger parsing and validation."""
    try:
        text = data.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        return

    # Test verify_ledger with fuzzed input
    try:
        from textforensics.provenance import _verify_ledger_unlocked, verify_ledger

        with tempfile.TemporaryDirectory() as tmpdir:
            ledger_path = Path(tmpdir) / "test_ledger.jsonl"

            # Write fuzzed input to ledger
            ledger_path.write_text(text, encoding="utf-8")

            try:
                verify_ledger(ledger_path)
                # Result always returned, no exception expected
            except Exception:
                pass
    except Exception:
        pass

    # Test _verify_ledger_unlocked with individual JSON lines
    try:
        from textforensics.provenance import (
            _canonical_record_payload,
            _verify_ledger_unlocked,
            sha256_bytes,
        )

        lines = text.strip().split("\n") if text.strip() else []

        for line in lines:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not isinstance(record, dict):
                continue

            try:
                # Test canonical payload computation
                payload_bytes = _canonical_record_payload(record)

                # Test hash computation
                sha256_bytes(payload_bytes)
            except Exception:
                pass

        # Write test ledger and verify
        with tempfile.TemporaryDirectory() as tmpdir:
            ledger_path = Path(tmpdir) / "test_ledger.jsonl"

            # Write the lines
            with ledger_path.open("w", encoding="utf-8") as f:
                for line in lines:
                    f.write(line + "\n")

            try:
                _verify_ledger_unlocked(ledger_path)
            except Exception:
                pass
    except Exception:
        pass

    # Test snapshot_file with fuzzed inputs
    try:
        from textforensics.provenance import snapshot_file

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            file_path = tmpdir / "test.txt"
            ledger_path = tmpdir / "test_ledger.jsonl"

            # Write fuzzed content to file
            file_path.write_bytes(data)

            try:
                snapshot_file(file_path, ledger_path)
            except Exception:
                pass
    except Exception:
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
