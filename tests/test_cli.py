import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from textforensics.constants import (
    EXIT_DOWNGRADED,
    EXIT_ERROR,
    EXIT_INCOMPLETE,
    EXIT_OK,
)

TEXT = (
    "I ran this test yesterday. The first result looked odd, so I "
    "changed one cable, repeated it, and wrote down the second result."
)


class CliTests(unittest.TestCase):
    def run_cli(self, *args, input_text=None):
        return subprocess.run(
            [sys.executable, "-m", "textforensics.cli", *args],
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_version(self):
        result = self.run_cli("--version")
        self.assertEqual(result.returncode, EXIT_OK)
        self.assertIn("textforensics", result.stdout.lower())

    def test_scan_json_from_stdin(self):
        result = self.run_cli("scan", "--json", input_text=TEXT)
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)
        payload = json.loads(result.stdout)
        self.assertIn("diagnostic_reliability", payload)
        self.assertIn("confidence_semantics", payload)

    def test_case_export_verify_and_tamper(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.txt"
            case = Path(tmp) / "case.json"
            source.write_text(TEXT, encoding="utf-8")

            exported = self.run_cli(
                "case",
                "export",
                "--file",
                str(source),
                "--output",
                str(case),
            )
            self.assertEqual(exported.returncode, EXIT_OK, exported.stderr)
            self.assertTrue(case.exists())
            self.assertNotIn(TEXT, case.read_text(encoding="utf-8"))

            verified = self.run_cli("case", "verify", str(case))
            self.assertEqual(verified.returncode, EXIT_OK, verified.stderr)
            self.assertTrue(json.loads(verified.stdout)["valid"])

            payload = json.loads(case.read_text(encoding="utf-8"))
            payload["forensic_bundle"]["content_sha256"] = "0" * 64
            case.write_text(json.dumps(payload), encoding="utf-8")

            tampered = self.run_cli("case", "verify", str(case))
            # Tampered case: MPL exit 1 (seal failed), not 2 (incomplete).
            self.assertEqual(tampered.returncode, EXIT_DOWNGRADED)
            self.assertFalse(json.loads(tampered.stdout)["valid"])

    def test_remote_bind_guard_surfaces_clean_error(self):
        result = self.run_cli(
            "web",
            "--host",
            "0.0.0.0",
            "--no-browser",
        )
        self.assertEqual(result.returncode, EXIT_ERROR)
        self.assertIn("Refusing to bind", result.stderr)

    def test_verify_command_with_case_file(self):
        """The verify command should verify a case file through N-version replay."""
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.txt"
            case = Path(tmp) / "case.json"
            source.write_text(TEXT, encoding="utf-8")

            # Export a case file
            export = self.run_cli(
                "case",
                "export",
                "--file",
                str(source),
                "--output",
                str(case),
            )
            self.assertEqual(export.returncode, EXIT_OK, export.stderr)

            # Verify it with the new verify command
            result = self.run_cli("verify", str(case))
            self.assertEqual(result.returncode, EXIT_OK, result.stderr)
            payload = json.loads(result.stdout)
            self.assertTrue(payload.get("overall_valid", False))

    def test_verify_command_with_tampered_case_file(self):
        """Tampered case file should fail verification."""
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.txt"
            case = Path(tmp) / "case.json"
            source.write_text(TEXT, encoding="utf-8")

            # Export a case file
            export = self.run_cli(
                "case",
                "export",
                "--file",
                str(source),
                "--output",
                str(case),
            )
            self.assertEqual(export.returncode, EXIT_OK)

            # Tamper with it
            payload = json.loads(case.read_text(encoding="utf-8"))
            payload["forensic_bundle"]["trust_map"]["overall"] = "strong"
            case.write_text(json.dumps(payload), encoding="utf-8")

            # Verify should fail
            result = self.run_cli("verify", str(case))
            self.assertEqual(result.returncode, EXIT_INCOMPLETE)
            self.assertFalse(json.loads(result.stdout).get("overall_valid", True))

    def test_verify_all_flag_requires_artifacts(self):
        """verify --all without artifacts should return error."""
        result = self.run_cli("verify", "--all")
        self.assertEqual(result.returncode, EXIT_ERROR)
        self.assertIn("No artifacts provided", result.stdout)

    def test_exit_codes_match_constants(self):
        """Exit codes should match the defined constants."""
        self.assertEqual(EXIT_OK, 0)
        self.assertEqual(EXIT_DOWNGRADED, 1)
        self.assertEqual(EXIT_INCOMPLETE, 2)
        self.assertEqual(EXIT_ERROR, 3)

    def test_build_info_outputs_json(self):
        """build-info should output valid JSON with required fields."""
        result = self.run_cli("build-info")
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)
        payload = json.loads(result.stdout)
        # Required fields
        self.assertIn("source_commit", payload)
        self.assertIn("source_commit_verified", payload)
        self.assertIn("python_version", payload)
        self.assertIn("dependencies_sha256", payload)
        self.assertIn("api_version", payload)
        self.assertIn("api_spec_sha256", payload)
        self.assertIn("detector_adapter_api_sha256", payload)
        self.assertIn("calibration_format_version", payload)
        self.assertIn("benchmark_format_version", payload)
        self.assertIn("contract_info", payload)
        # source_commit should be a non-empty string
        self.assertIsInstance(payload["source_commit"], str)
        self.assertGreater(len(payload["source_commit"]), 0)

    def test_build_info_verify_returns_valid(self):
        """build-info --verify should return a verification report."""
        result = self.run_cli("build-info", "--verify")
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)
        payload = json.loads(result.stdout)
        self.assertIn("valid", payload)
        self.assertIn("checks", payload)
        self.assertIn("errors", payload)
        self.assertIsInstance(payload["valid"], bool)
        self.assertIsInstance(payload["checks"], list)
        self.assertIsInstance(payload["errors"], list)


if __name__ == "__main__":
    unittest.main()
