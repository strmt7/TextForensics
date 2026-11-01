from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from textforensics.config import (
    Settings,
    _env_int,
    is_unspecified_host,
    read_text_file,
    validate_text_input,
)


class EnvIntEdgeCaseTests(unittest.TestCase):
    """Tests for _env_int error branches (lines 34-35)."""

    def test_env_int_rejects_non_integer(self):
        """Test that _env_int raises ValueError for non-integer values."""
        with patch.dict(os.environ, {"TEXTFORENSICS_X": "not-a-number"}, clear=True):
            with self.assertRaises(ValueError) as ctx:
                _env_int("X", 1, minimum=1, maximum=100)
            self.assertIn("must be an integer", str(ctx.exception))


class UnspecifiedHostTests(unittest.TestCase):
    """Tests for is_unspecified_host edge cases (lines 59-65)."""

    def test_asterisk_is_unspecified(self):
        """Test that '*' is detected as an unspecified host (wildcard bind)."""
        self.assertTrue(is_unspecified_host("*"))

    def test_invalid_ip_returns_false(self):
        """Test that invalid IP addresses return False for is_unspecified_host."""
        # These should not raise, but return False
        self.assertFalse(is_unspecified_host("not-an-ip"))
        self.assertFalse(is_unspecified_host("256.256.256.256"))
        self.assertFalse(is_unspecified_host("999.999.999.999"))

    def test_ipv6_unspecified_detected(self):
        """Test IPv6 unspecified address :: is detected."""
        self.assertTrue(is_unspecified_host("::"))
        self.assertTrue(is_unspecified_host("0::0"))


class ValidateTextInputEdgeCases(unittest.TestCase):
    """Tests for validate_text_input edge cases."""

    def test_rejects_non_string_input(self):
        """Test that validate_text_input rejects non-string inputs."""
        with self.assertRaises(ValueError):
            validate_text_input(123, max_input_bytes=100)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            validate_text_input(None, max_input_bytes=100)  # type: ignore[arg-type]

    def test_rejects_whitespace_only(self):
        """Test that whitespace-only strings are rejected."""
        with self.assertRaises(ValueError):
            validate_text_input("   \t\n  ", max_input_bytes=100)


class ReadTextFileEdgeCases(unittest.TestCase):
    """Tests for read_text_file edge cases."""

    def test_missing_file_raises_error(self):
        """Test that reading a non-existent file raises an error."""
        with self.assertRaises((FileNotFoundError, ValueError, OSError)):
            read_text_file("/nonexistent/path/to/file.txt", max_input_bytes=1000)


class SettingsEnvTests(unittest.TestCase):
    """Tests for Settings.from_env edge cases."""

    def test_invalid_log_level_rejected(self):
        """Test that invalid log level raises ValueError."""
        with patch.dict(os.environ, {"TEXTFORENSICS_LOG_LEVEL": "TRACE"}, clear=True):
            with self.assertRaises(ValueError) as ctx:
                Settings.from_env()
            self.assertIn("LOG_LEVEL", str(ctx.exception))

    def test_env_int_invalid_value(self):
        """Test that _env_int with non-integer value raises ValueError."""
        with patch.dict(os.environ, {"TEXTFORENSICS_PORT": "abc"}, clear=True):
            with self.assertRaises(ValueError) as ctx:
                Settings.from_env()
            self.assertIn("must be an integer", str(ctx.exception))

    def test_env_int_out_of_range(self):
        """Test that _env_int with out-of-range value raises ValueError."""
        with patch.dict(os.environ, {"TEXTFORENSICS_PORT": "0"}, clear=True), \
             self.assertRaises(ValueError):
            Settings.from_env()
        with patch.dict(os.environ, {"TEXTFORENSICS_PORT": "70000"}, clear=True), \
             self.assertRaises(ValueError):
            Settings.from_env()


if __name__ == "__main__":
    unittest.main()
