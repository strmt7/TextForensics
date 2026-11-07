"""Pytest configuration for TextForensics tests."""

import sys
from pathlib import Path

# Add src to path for imports
src_path = Path(__file__).parent.parent / "src"
if src_path.exists() and str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

# Add the tests directory itself so test modules can share helpers
# (e.g. _token_fixture) without reaching into each other.
tests_path = Path(__file__).parent
if str(tests_path) not in sys.path:
    sys.path.insert(0, str(tests_path))
