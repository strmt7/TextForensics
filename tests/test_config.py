import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from textforensics.config import (
    Settings,
    ensure_bind_allowed,
    is_loopback_host,
    read_text_file,
    validate_text_input,
)


class ConfigTests(unittest.TestCase):
    def test_defaults_are_loopback_and_private(self):
        with patch.dict(os.environ, {}, clear=True):
            settings = Settings.from_env()
        self.assertEqual(settings.host, "127.0.0.1")
        self.assertFalse(settings.allow_remote)
        self.assertFalse(settings.access_log)

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
        with patch.dict(
            os.environ,
            {"TEXTFORENSICS_PORT": "70000"},
            clear=True,
        ):
            with self.assertRaises(ValueError):
                Settings.from_env()

    def test_loopback_detection(self):
        self.assertTrue(is_loopback_host("127.0.0.1"))
        self.assertTrue(is_loopback_host("::1"))
        self.assertTrue(is_loopback_host("localhost"))
        self.assertFalse(is_loopback_host("0.0.0.0"))
        self.assertFalse(is_loopback_host("192.168.1.5"))

    def test_remote_bind_requires_opt_in(self):
        with self.assertRaises(ValueError):
            ensure_bind_allowed("0.0.0.0", allow_remote=False)
        ensure_bind_allowed("0.0.0.0", allow_remote=True)

    def test_file_limit_is_checked_before_reading(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "large.txt"
            path.write_bytes(b"x" * 100)
            with self.assertRaises(ValueError):
                read_text_file(path, max_input_bytes=64)

    def test_input_limit_uses_utf8_bytes(self):
        validate_text_input("é", max_input_bytes=2)
        with self.assertRaises(ValueError):
            validate_text_input("é", max_input_bytes=1)


if __name__ == "__main__":
    unittest.main()
