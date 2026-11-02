"""Tests for the Typer-based CLI."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path

from textforensics.constants import EXIT_OK, EXIT_INCOMPLETE


TEXT = (
    "I ran this test yesterday. The first result looked odd, so I "
    "changed one cable, repeated it, and wrote down the second result."
)


class TyperCliTests(unittest.TestCase):
    """Tests for Typer CLI help commands."""

    @classmethod
    def setUpClass(cls):
        """Import typer_cli module once."""
        import textforensics.typer_cli as typer_cli_module
        cls.typer_module = typer_cli_module

    def _run_app(self, argv: list[str], stdin: str | None = None) -> tuple[int, str, str]:
        """Run the Typer app with given argv and stdin, return (exit_code, stdout, stderr)."""
        old_argv = sys.argv
        old_stdin = sys.stdin
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        try:
            sys.argv = ["textforensics-typer", *argv]
            if stdin is not None:
                sys.stdin = StringIO(stdin)
            sys.stdout = StringIO()
            sys.stderr = StringIO()
            self.typer_module.app()
            return 0, sys.stdout.getvalue(), sys.stderr.getvalue()
        except SystemExit as e:
            return e.code, sys.stdout.getvalue(), sys.stderr.getvalue()
        except Exception as e:
            return 1, sys.stdout.getvalue(), f"{type(e).__name__}: {e}"
        finally:
            sys.argv = old_argv
            sys.stdin = old_stdin
            sys.stdout = old_stdout
            sys.stderr = old_stderr


class HelpTests(TyperCliTests):
    """Tests for help output on all commands."""

    def test_version(self):
        code, out, err = self._run_app(["--version"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("textforensics", out.lower())

    def test_scan_help(self):
        code, out, err = self._run_app(["scan", "--help"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("scan", out.lower())

    def test_report_help(self):
        code, out, err = self._run_app(["report", "--help"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("report", out.lower())

    def test_case_help(self):
        code, out, err = self._run_app(["case", "--help"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("case", out.lower())

    def test_bundle_help(self):
        code, out, err = self._run_app(["bundle", "--help"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("bundle", out.lower())

    def test_drift_help(self):
        code, out, err = self._run_app(["drift", "--help"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("drift", out.lower())

    def test_capability_help(self):
        code, out, err = self._run_app(["capability", "--help"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("capability", out.lower())

    def test_verify_help(self):
        code, out, err = self._run_app(["verify", "--help"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("verify", out.lower())

    def test_localize_help(self):
        code, out, err = self._run_app(["localize", "--help"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("localize", out.lower())

    def test_benchmark_help(self):
        code, out, err = self._run_app(["benchmark", "--help"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("benchmark", out.lower())

    def test_schema_help(self):
        code, out, err = self._run_app(["schema", "--help"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("schema", out.lower())

    def test_detectors_help(self):
        code, out, err = self._run_app(["detectors", "--help"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("detectors", out.lower())

    def test_compare_help(self):
        code, out, err = self._run_app(["compare", "--help"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("compare", out.lower())

    def test_snapshot_help(self):
        code, out, err = self._run_app(["snapshot", "--help"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("snapshot", out.lower())

    def test_verify_ledger_help(self):
        code, out, err = self._run_app(["verify-ledger", "--help"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("verify-ledger", out.lower())

    def test_audit_help(self):
        code, out, err = self._run_app(["audit", "--help"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("audit", out.lower())

    def test_web_help(self):
        code, out, err = self._run_app(["web", "--help"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("web", out.lower())

    def test_serve_help(self):
        code, out, err = self._run_app(["serve", "--help"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("serve", out.lower())

    def test_calibrate_help(self):
        code, out, err = self._run_app(["calibrate", "--help"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("calibrate", out.lower())

    def test_fingerprint_help(self):
        code, out, err = self._run_app(["fingerprint", "--help"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("fingerprint", out.lower())

    def test_check_help(self):
        code, out, err = self._run_app(["check", "--help"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("check", out.lower())

    def test_select_threshold_help(self):
        code, out, err = self._run_app(["select-threshold", "--help"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("select-threshold", out.lower())

    def test_schema_list_help(self):
        code, out, err = self._run_app(["schema", "list", "--help"])
        self.assertEqual(code, EXIT_OK)

    def test_schema_show_help(self):
        code, out, err = self._run_app(["schema", "show", "test", "--help"])
        self.assertEqual(code, EXIT_OK)

    def test_schema_validate_help(self):
        code, out, err = self._run_app(["schema", "validate", "--help"])
        self.assertEqual(code, EXIT_OK)

    def test_bundle_pack_help(self):
        code, out, err = self._run_app(["bundle", "pack", "--help"])
        self.assertEqual(code, EXIT_OK)

    def test_bundle_verify_help(self):
        code, out, err = self._run_app(["bundle", "verify", "--help"])
        self.assertEqual(code, EXIT_OK)

    def test_bundle_list_help(self):
        code, out, err = self._run_app(["bundle", "list", "--help"])
        self.assertEqual(code, EXIT_OK)

    def test_case_export_help(self):
        code, out, err = self._run_app(["case", "export", "--help"])
        self.assertEqual(code, EXIT_OK)

    def test_case_verify_help(self):
        code, out, err = self._run_app(["case", "verify", "test.json", "--help"])
        self.assertIn("case", out.lower())

    def test_localize_diff_help(self):
        code, out, err = self._run_app(["localize", "diff", "--help"])
        self.assertEqual(code, EXIT_OK)

    def test_localize_anomalies_help(self):
        code, out, err = self._run_app(["localize", "anomalies", "--help"])
        self.assertEqual(code, EXIT_OK)

    def test_localize_segments_help(self):
        code, out, err = self._run_app(["localize", "segments", "--help"])
        self.assertEqual(code, EXIT_OK)

    def test_verify_case_help(self):
        code, out, err = self._run_app(["verify", "case", "test.json", "--help"])
        self.assertIn("verify", out.lower())

    def test_verify_all_help(self):
        code, out, err = self._run_app(["verify", "all", "--help"])
        self.assertEqual(code, EXIT_OK)


class FunctionalTests(TyperCliTests):
    """Tests for functional behavior of the Typer CLI."""

    def test_scan_json_from_stdin(self):
        code, out, err = self._run_app(["scan", "analyze", "--json"], stdin=TEXT)
        self.assertEqual(code, EXIT_OK, err)
        payload = json.loads(out)
        self.assertIn("diagnostic_reliability", payload)
        self.assertIn("confidence_semantics", payload)

    def test_scan_json_from_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.txt"
            source.write_text(TEXT, encoding="utf-8")
            code, out, err = self._run_app(["scan", "analyze", "--json", "--file", str(source)])
            self.assertEqual(code, EXIT_OK, err)
            payload = json.loads(out)
            self.assertIn("diagnostic_reliability", payload)

    def test_report_json_from_stdin(self):
        code, out, err = self._run_app(["report"], stdin=TEXT)
        self.assertEqual(code, EXIT_OK, err)
        payload = json.loads(out)
        self.assertIn("trust_map", payload)
        self.assertFalse(payload["input"]["raw_text_included"])

    def test_audit_json_from_stdin(self):
        code, out, err = self._run_app(["audit"], stdin=TEXT)
        self.assertEqual(code, EXIT_OK, err)
        payload = json.loads(out)
        self.assertIsInstance(payload, list)

    def test_compare_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            before = Path(tmp) / "before.txt"
            after = Path(tmp) / "after.txt"
            before.write_text(TEXT, encoding="utf-8")
            after.write_text(TEXT + " extra.", encoding="utf-8")
            code, out, err = self._run_app(["compare", str(before), str(after)])
            self.assertEqual(code, EXIT_OK, err)
            self.assertIn("similarity", out)

    def test_detectors_list(self):
        code, out, err = self._run_app(["detectors"])
        self.assertEqual(code, EXIT_OK, err)
        payload = json.loads(out)
        self.assertIn("detectors", payload)
        self.assertTrue(payload["detectors"])

    def test_case_export_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.txt"
            case = Path(tmp) / "case.json"
            source.write_text(TEXT, encoding="utf-8")

            export = self._run_app(["case", "export", "--file", str(source), "--output", str(case)])
            self.assertEqual(export[0], EXIT_OK, export[2] or export[1])
            self.assertTrue(case.exists())
            case_text = case.read_text(encoding="utf-8")
            self.assertNotIn(TEXT, case_text)

            verify = self._run_app(["case", "verify", str(case)])
            # Case verify should succeed
            payload = json.loads(verify[1])
            self.assertTrue(payload.get("valid", False))

    def test_bundle_pack_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.txt"
            case_path = Path(tmp) / "case.json"
            bundle_path = Path(tmp) / "bundle.tar.gz"
            source.write_text(TEXT, encoding="utf-8")
            # Create a case file first
            self._run_app(["case", "export", "--file", str(source), "--output", str(case_path)])
            # Pack the bundle
            code, out, err = self._run_app(["bundle", "pack", str(case_path), str(bundle_path)])
            self.assertEqual(code, EXIT_OK, err or out)

    def test_fingerprint_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            dataset = Path(tmp) / "test.jsonl"
            dataset.write_text(
                json.dumps({"label": "human", "text": "human text"})
                + "\n"
                + json.dumps({"label": "ai", "text": "ai text"})
                + "\n",
                encoding="utf-8",
            )
            code, out, err = self._run_app(
                ["fingerprint", str(dataset), "TestDataset", "--version", "1.0.0", "--split", "test"]
            )
            self.assertEqual(code, EXIT_OK, err)
            payload = json.loads(out)
            self.assertEqual(payload["name"], "TestDataset")
            self.assertEqual(payload["schema"], "textforensics.dataset-fingerprint/v1")

    def test_check_command_disjoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            cal = Path(tmp) / "cal.jsonl"
            eval = Path(tmp) / "eval.jsonl"
            cal.write_text(json.dumps({"label": "human", "text": "calibration human"}) + "\n", encoding="utf-8")
            eval.write_text(json.dumps({"label": "human", "text": "evaluation human"}) + "\n", encoding="utf-8")

            code, out, err = self._run_app(["check", str(cal), str(eval)])
            self.assertEqual(code, EXIT_OK, err)
            payload = json.loads(out)
            self.assertTrue(payload["disjoint"])

    def test_localize_segments(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.txt"
            source.write_text(TEXT * 4, encoding="utf-8")
            code, out, err = self._run_app(["localize", "segments", str(source), "--sentences", "4"])
            self.assertEqual(code, EXIT_OK, err)
            payload = json.loads(out)
            self.assertIsInstance(payload, list)
            if payload:
                self.assertIn("index", payload[0])
                self.assertIn("score", payload[0])

    def test_verify_all_requires_artifacts(self):
        code, out, err = self._run_app(["verify", "all"])
        # Should fail with EXIT_ERROR (3) when no artifacts provided
        self.assertEqual(code, 3)


class DelegationTests(unittest.TestCase):
    """Tests for argparse to Typer delegation."""

    def test_typer_flag_delegates_to_typer_cli(self):
        """Test that --typer flag delegates to Typer CLI."""
        import subprocess
        import sys
        result = subprocess.run(
            [sys.executable, "-m", "textforensics.cli", "--typer", "--help"],
            capture_output=True,
            text=True,
        )
        # Should show Typer-style output, not argparse
        self.assertEqual(result.returncode, EXIT_OK)
        self.assertIn("textforensics", result.stdout.lower())


if __name__ == "__main__":
    unittest.main()