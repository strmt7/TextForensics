from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from textforensics.config import (
    Settings,
    _env_bool,
    _env_int,
    ensure_bind_allowed,
    is_loopback_host,
    read_text_file,
    validate_text_input,
)


class EnvParsingTests(unittest.TestCase):
    def test_env_bool_truthy_values(self):
        for raw in ("1", "true", "yes", "on", "TRUE", "Yes"):
            with patch.dict(os.environ, {"TEXTFORENSICS_X": raw}, clear=True):
                self.assertTrue(_env_bool("X", False), raw)

    def test_env_bool_falsy_values(self):
        for raw in ("0", "false", "no", "off", "FALSE"):
            with patch.dict(os.environ, {"TEXTFORENSICS_X": raw}, clear=True):
                self.assertFalse(_env_bool("X", True), raw)

    def test_env_bool_invalid_fails_fast(self):
        with patch.dict(os.environ, {"TEXTFORENSICS_X": "maybe"}, clear=True):
            with self.assertRaises(ValueError):
                _env_bool("X", False)

    def test_env_bool_default_when_unset(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertTrue(_env_bool("X", True))
            self.assertFalse(_env_bool("X", False))

    def test_env_int_within_bounds(self):
        with patch.dict(os.environ, {"TEXTFORENSICS_X": "5000"}, clear=True):
            self.assertEqual(_env_int("X", 1, minimum=1, maximum=10000), 5000)

    def test_env_int_default_when_unset(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(_env_int("X", 42, minimum=1, maximum=100), 42)

    def test_env_int_out_of_bounds_fails(self):
        with patch.dict(os.environ, {"TEXTFORENSICS_X": "0"}, clear=True):
            with self.assertRaises(ValueError):
                _env_int("X", 1, minimum=1, maximum=100)


class SettingsTests(unittest.TestCase):
    def test_defaults_are_loopback_and_private(self):
        with patch.dict(os.environ, {}, clear=True):
            settings = Settings.from_env()
        self.assertEqual(settings.host, "127.0.0.1")
        self.assertEqual(settings.port, 8765)
        self.assertEqual(settings.max_input_bytes, 2_000_000)
        self.assertFalse(settings.allow_remote)
        self.assertFalse(settings.access_log)
        self.assertEqual(settings.log_level, "INFO")

    def test_environment_overrides(self):
        env = {
            "TEXTFORENSICS_HOST": "0.0.0.0",
            "TEXTFORENSICS_PORT": "9001",
            "TEXTFORENSICS_MAX_INPUT_BYTES": "4096",
            "TEXTFORENSICS_ALLOW_REMOTE": "true",
            "TEXTFORENSICS_ACCESS_LOG": "yes",
            "TEXTFORENSICS_LOG_LEVEL": "debug",
        }
        with patch.dict(os.environ, env, clear=True):
            settings = Settings.from_env()
        self.assertEqual(settings.host, "0.0.0.0")
        self.assertEqual(settings.port, 9001)
        self.assertEqual(settings.max_input_bytes, 4096)
        self.assertTrue(settings.allow_remote)
        self.assertTrue(settings.access_log)
        self.assertEqual(settings.log_level, "DEBUG")

    def test_invalid_environment_fails_fast(self):
        with patch.dict(os.environ, {"TEXTFORENSICS_PORT": "70000"}, clear=True):
            with self.assertRaises(ValueError):
                Settings.from_env()

    def test_invalid_log_level_fails_fast(self):
        with patch.dict(os.environ, {"TEXTFORENSICS_LOG_LEVEL": "trace"}, clear=True):
            with self.assertRaises(ValueError):
                Settings.from_env()

    def test_settings_is_frozen(self):
        settings = Settings()
        with self.assertRaises(Exception):
            settings.host = "0.0.0.0"


class LoopbackTests(unittest.TestCase):
    def test_loopback_detection(self):
        self.assertTrue(is_loopback_host("127.0.0.1"))
        self.assertTrue(is_loopback_host("::1"))
        self.assertTrue(is_loopback_host("localhost"))
        self.assertTrue(is_loopback_host("ip6-localhost"))
        self.assertTrue(is_loopback_host("[::1]"))
        self.assertFalse(is_loopback_host("0.0.0.0"))
        self.assertFalse(is_loopback_host("192.168.1.5"))
        self.assertFalse(is_loopback_host("example.com"))

    def test_remote_bind_requires_opt_in(self):
        with self.assertRaises(ValueError):
            ensure_bind_allowed("0.0.0.0", allow_remote=False)
        ensure_bind_allowed("0.0.0.0", allow_remote=True)
        ensure_bind_allowed("127.0.0.1", allow_remote=False)


class InputValidationTests(unittest.TestCase):
    def test_rejects_empty(self):
        with self.assertRaises(ValueError):
            validate_text_input("", max_input_bytes=100)
        with self.assertRaises(ValueError):
            validate_text_input("   ", max_input_bytes=100)
        with self.assertRaises(ValueError):
            validate_text_input(None, max_input_bytes=100)  # type: ignore[arg-type]

    def test_rejects_oversized(self):
        with self.assertRaises(ValueError):
            validate_text_input("x" * 200, max_input_bytes=100)

    def test_size_uses_utf8_bytes(self):
        validate_text_input("é", max_input_bytes=2)
        with self.assertRaises(ValueError):
            validate_text_input("é", max_input_bytes=1)

    def test_returns_text_unchanged(self):
        text = "hello world"
        self.assertEqual(validate_text_input(text, max_input_bytes=100), text)


class ReadTextFileTests(unittest.TestCase):
    def test_file_limit_checked_before_reading(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "large.txt"
            path.write_bytes(b"x" * 100)
            with self.assertRaises(ValueError):
                read_text_file(path, max_input_bytes=64)

    def test_reads_utf8_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "small.txt"
            path.write_text("héllo", encoding="utf-8")
            self.assertEqual(read_text_file(path, max_input_bytes=64), "héllo")

    def test_rejects_nonexistent_file(self):
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises((ValueError, OSError)):
            read_text_file(Path(tmp) / "missing.txt", max_input_bytes=64)


if __name__ == "__main__":
    unittest.main()
