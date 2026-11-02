"""Tests for the emergency stop sentinel (rejection-rejector pattern)."""

from __future__ import annotations

import asyncio
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from textforensics.constants import EXIT_ERROR
from textforensics.emergency_stop import (
    ENV_VAR,
    EmergencyStopError,
    EmergencyStopSentinel,
    assert_not_stopped,
    check_emergency_stop,
)

HAS_MCP = importlib.util.find_spec("mcp") is not None

TEXT = (
    "I ran this test yesterday. The first result looked odd, so I "
    "changed one cable, repeated it, and wrote down the second result."
)


class CheckEmergencyStopTests(unittest.TestCase):
    """Tests for the module-level check_emergency_stop function."""

    def test_returns_false_when_env_var_unset(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(ENV_VAR, None)
            self.assertFalse(check_emergency_stop())

    def test_returns_false_when_env_var_empty(self):
        with mock.patch.dict(os.environ, {ENV_VAR: ""}):
            self.assertFalse(check_emergency_stop())

    def test_returns_false_when_sentinel_file_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sentinel"
            with mock.patch.dict(os.environ, {ENV_VAR: str(path)}):
                self.assertFalse(check_emergency_stop())

    def test_returns_true_when_sentinel_file_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sentinel"
            path.write_text("stop", encoding="utf-8")
            with mock.patch.dict(os.environ, {ENV_VAR: str(path)}):
                self.assertTrue(check_emergency_stop())

    def test_returns_true_on_malformed_path(self):
        # Fail-closed: a null-byte path is malformed -> STOP.
        self.assertTrue(check_emergency_stop("bad\x00path"))

    def test_returns_true_on_null_byte_path(self):
        self.assertTrue(check_emergency_stop("bad\x00path"))

    def test_explicit_path_overrides_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            active = Path(tmp) / "active"
            inactive = Path(tmp) / "inactive"
            active.write_text("stop", encoding="utf-8")
            with mock.patch.dict(os.environ, {ENV_VAR: str(inactive)}):
                self.assertTrue(check_emergency_stop(str(active)))

    def test_explicit_path_ignored_when_env_unset(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sentinel"
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop(ENV_VAR, None)
                self.assertFalse(check_emergency_stop(str(path)))


class EmergencyStopSentinelTests(unittest.TestCase):
    """Tests for the EmergencyStopSentinel class."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "sentinel"

    def _sentinel(self) -> EmergencyStopSentinel:
        s = EmergencyStopSentinel()
        s.configure(str(self.path))
        return s

    def test_configure_then_inactive(self):
        s = self._sentinel()
        self.assertFalse(s.is_active())

    def test_activate_creates_file_and_is_active(self):
        s = self._sentinel()
        returned = s.activate()
        self.assertEqual(returned, self.path)
        self.assertTrue(self.path.exists())
        self.assertTrue(s.is_active())

    def test_deactivate_removes_file(self):
        s = self._sentinel()
        s.activate()
        removed = s.deactivate()
        self.assertTrue(removed)
        self.assertFalse(self.path.exists())
        self.assertFalse(s.is_active())

    def test_deactivate_when_absent_returns_false(self):
        s = self._sentinel()
        self.assertFalse(s.deactivate())

    def test_assert_not_stopped_raises_when_active(self):
        s = self._sentinel()
        s.activate()
        with self.assertRaises(EmergencyStopError):
            s.assert_not_stopped()

    def test_assert_not_stopped_passes_when_inactive(self):
        s = self._sentinel()
        s.assert_not_stopped()  # must not raise

    def test_activate_without_configuration_raises(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(ENV_VAR, None)
            s = EmergencyStopSentinel()
            with self.assertRaises(ValueError):
                s.activate()

    def test_deactivate_without_configuration_raises(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(ENV_VAR, None)
            s = EmergencyStopSentinel()
            with self.assertRaises(ValueError):
                s.deactivate()

    def test_env_var_configuration(self):
        with mock.patch.dict(os.environ, {ENV_VAR: str(self.path)}):
            s = EmergencyStopSentinel()
            self.assertFalse(s.is_active())
            s.activate()
            self.assertTrue(s.is_active())

    def test_malformed_configured_path_is_active_fail_closed(self):
        s = EmergencyStopSentinel()
        s.configure("")  # empty path is malformed
        self.assertTrue(s.is_active())
        with self.assertRaises(EmergencyStopError):
            s.assert_not_stopped()

    def test_creates_parent_dirs_on_activate(self):
        nested = Path(self.tmp.name) / "a" / "b" / "sentinel"
        s = EmergencyStopSentinel()
        s.configure(str(nested))
        s.activate()
        self.assertTrue(nested.exists())


class EngineIntegrationTests(unittest.TestCase):
    """Emergency stop gates the analysis engine."""

    def test_engine_blocked_when_active(self):
        from textforensics.engine import analyze_text

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sentinel"
            with mock.patch.dict(os.environ, {ENV_VAR: str(path)}):
                Path(path).write_text("stop", encoding="utf-8")
                with self.assertRaises(EmergencyStopError):
                    analyze_text(TEXT)

    def test_engine_allowed_when_inactive(self):
        from textforensics.engine import analyze_text

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sentinel"
            with mock.patch.dict(os.environ, {ENV_VAR: str(path)}):
                result = analyze_text(TEXT)
                self.assertIsNotNone(result)


class ApiIntegrationTests(unittest.TestCase):
    """Emergency stop gates API endpoints at dispatch entry and per action."""

    @classmethod
    def setUpClass(cls):
        try:
            from textforensics.api import create_app

            cls.app = create_app()
        except RuntimeError:
            raise unittest.SkipTest("fastapi not installed")
        from fastapi.testclient import TestClient

        cls.client = TestClient(cls.app, raise_server_exceptions=False)

    def test_api_blocked_at_dispatch_when_active(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sentinel"
            with mock.patch.dict(os.environ, {ENV_VAR: str(path)}):
                path.write_text("stop", encoding="utf-8")
                response = self.client.post(
                    "/v1/analyze",
                    json={"text": TEXT},
                )
                self.assertEqual(response.status_code, 503)
                self.assertIn("Emergency stop", response.json()["detail"])

    def test_api_allowed_when_inactive(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sentinel"
            with mock.patch.dict(os.environ, {ENV_VAR: str(path)}):
                response = self.client.post(
                    "/v1/analyze",
                    json={"text": TEXT},
                )
                self.assertEqual(response.status_code, 200)


@unittest.skipUnless(HAS_MCP, "MCP development dependencies are not installed")
class McpServerIntegrationTests(unittest.TestCase):
    """Emergency stop gates MCP tool calls."""

    @classmethod
    def setUpClass(cls):
        from textforensics.mcp_server import _server

        cls.server = _server()

    def _call(self, name, **kwargs):
        async def _run():
            return await self.server.call_tool(name, kwargs)

        return asyncio.run(_run())

    def test_mcp_tool_blocked_when_active(self):
        from mcp.server.mcpserver.exceptions import UnexpectedToolError

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sentinel"
            path.write_text("stop", encoding="utf-8")
            with mock.patch.dict(os.environ, {ENV_VAR: str(path)}):
                with self.assertRaises(UnexpectedToolError):
                    self._call("analyze_ai_text", text=TEXT)

    def test_mcp_tool_allowed_when_inactive(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sentinel"
            with mock.patch.dict(os.environ, {ENV_VAR: str(path)}):
                # Should not raise EmergencyStopError.
                try:
                    self._call("analyze_ai_text", text=TEXT)
                except EmergencyStopError:
                    self.fail("EmergencyStopError raised while stop inactive")


class ModuleLevelGuardTests(unittest.TestCase):
    """Tests for module-level assert_not_stopped and get_sentinel."""

    def test_module_guard_raises_when_active(self):
        from textforensics.emergency_stop import get_sentinel

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sentinel"
            with mock.patch.dict(os.environ, {ENV_VAR: str(path)}):
                path.write_text("stop", encoding="utf-8")
                with self.assertRaises(EmergencyStopError):
                    assert_not_stopped()

    def test_module_guard_passes_when_inactive(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(ENV_VAR, None)
            assert_not_stopped()  # must not raise

    def test_get_sentinel_is_singleton(self):
        from textforensics.emergency_stop import get_sentinel

        self.assertIs(get_sentinel(), get_sentinel())


class CliEmergencyCommandTests(unittest.TestCase):
    """In-process CLI tests for the emergency subcommands."""

    def _run_main(self, argv, env_overrides=None):
        import io
        import sys as _sys

        from textforensics.cli import main

        old_argv = _sys.argv
        old_stdin = _sys.stdin
        old_stdout = _sys.stdout
        old_stderr = _sys.stderr
        old_env = {}
        if env_overrides:
            for key, value in env_overrides.items():
                old_env[key] = os.environ.get(key)
                os.environ[key] = value
        try:
            _sys.argv = ["textforensics", *argv]
            _sys.stdin = io.StringIO("")
            _sys.stdout = io.StringIO()
            _sys.stderr = io.StringIO()
            code = main()
            return code, _sys.stdout.getvalue(), _sys.stderr.getvalue()
        except SystemExit as e:
            return e.code, _sys.stdout.getvalue(), _sys.stderr.getvalue()
        finally:
            _sys.argv = old_argv
            _sys.stdin = old_stdin
            _sys.stdout = old_stdout
            _sys.stderr = old_stderr
            for key, value in old_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_status_not_configured(self):
        code, out, err = self._run_main(["emergency", "status"])
        self.assertEqual(code, 0)
        self.assertIn("active", out.lower())

    def test_status_with_configured_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sentinel"
            code, out, err = self._run_main(
                ["emergency", "status", "--path", str(path)]
            )
            self.assertEqual(code, 0)
            self.assertIn("not active", out)

    def test_activate_then_status_shows_active(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sentinel"
            code, out, err = self._run_main(
                ["emergency", "activate", "--path", str(path)]
            )
            self.assertEqual(code, 0)
            self.assertTrue(path.exists())

            code, out, err = self._run_main(
                ["emergency", "status", "--path", str(path)]
            )
            self.assertEqual(code, 0)
            self.assertIn("ACTIVE", out)

    def test_deactivate_removes_sentinel(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sentinel"
            path.write_text("stop", encoding="utf-8")
            code, out, err = self._run_main(
                ["emergency", "deactivate", "--path", str(path)]
            )
            self.assertEqual(code, 0)
            self.assertFalse(path.exists())

    def test_activate_without_configuration_fails(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(ENV_VAR, None)
            code, out, err = self._run_main(["emergency", "activate"])
            self.assertEqual(code, EXIT_ERROR)
            self.assertIn("error", err.lower())

    def test_scan_blocked_by_sentinel(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sentinel"
            path.write_text("stop", encoding="utf-8")
            code, out, err = self._run_main(
                ["scan", "--json"],
                env_overrides={ENV_VAR: str(path)},
            )
            self.assertEqual(code, EXIT_ERROR)
            self.assertIn("emergency stop", err.lower())


if __name__ == "__main__":
    unittest.main()