import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


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
        self.assertEqual(result.returncode, 0)
        self.assertIn("textforensics", result.stdout.lower())

    def test_scan_json_from_stdin(self):
        result = self.run_cli("scan", "--json", input_text=TEXT)
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertIn("diagnostic_reliability", payload)
        self.assertIn("confidence_semantics", payload)

    def test_detectors_lists_optional_model_without_enabling_it(self):
        result = self.run_cli("detectors", "--health")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        ids = {
            row["detector_id"]
            for row in payload["optional_detectors"]
        }
        self.assertIn("desklib/ai-text-detector-v1.01", ids)

    def test_unknown_report_detector_fails_cleanly(self):
        result = self.run_cli(
            "report",
            "--detector",
            "does/not-exist",
            input_text=TEXT,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("Unknown detector_id", result.stderr)

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
            self.assertEqual(exported.returncode, 0, exported.stderr)
            self.assertTrue(case.exists())
            self.assertNotIn(TEXT, case.read_text(encoding="utf-8"))

            verified = self.run_cli("case", "verify", str(case))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertTrue(json.loads(verified.stdout)["valid"])

            payload = json.loads(case.read_text(encoding="utf-8"))
            payload["forensic_bundle"]["content_sha256"] = "0" * 64
            case.write_text(json.dumps(payload), encoding="utf-8")

            tampered = self.run_cli("case", "verify", str(case))
            self.assertEqual(tampered.returncode, 1)
            self.assertFalse(json.loads(tampered.stdout)["valid"])

    def test_remote_bind_guard_surfaces_clean_error(self):
        result = self.run_cli(
            "web",
            "--host",
            "0.0.0.0",
            "--no-browser",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("Refusing to bind", result.stderr)


if __name__ == "__main__":
    unittest.main()
