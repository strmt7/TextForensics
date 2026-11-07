"""Tests for the U4 ``tf mixed-origin`` CLI command."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from textforensics.constants import EXIT_DOWNGRADED, EXIT_ERROR

TEXT = (
    "I ran this test yesterday. The first result looked odd, so I "
    "changed one cable, repeated it, and wrote down the second result. "
    "The device behaved differently after the change, which suggests the "
    "cable was the cause of the earlier fault in the first place."
)

CANARY = "CANARY-2d7c5-PEACOCK-GRANITE-9914"

# Plain human prose (original filler, six sentences of 25-31 words
# each) used for the covered-regime path: every segment scores
# human-consistent, so the report verdicts "human" when the regime
# is covered by the segment record.
LIBRARY_TEXT = (
    "The old library on Mill Street opens its reading room at nine in the morning, "
    "and the morning light falls across the long wooden tables where students spread "
    "out their notes. The librarian keeps a small brass bell on the desk, and she "
    "rings it once when the clock strikes twelve to mark the lunch hour. In the "
    "afternoon the room grows quieter, and the only sounds are pages turning and the "
    "occasional cough from the far corner near the window. The collection holds mostly "
    "local history, with shelves of parish records, maps of the old railway lines, and "
    "bound volumes of the town newspaper going back a hundred years. Visitors who want "
    "a particular volume fill in a slip at the desk, and the librarian fetches it from "
    "the stack room behind the counter. On rainy days the reading room fills early, and "
    "the regulars take their usual seats by the tall windows that look out over the "
    "market square."
)


class MixedOriginCliTests(unittest.TestCase):
    def run_cli(self, *args, input_text=None):
        return subprocess.run(
            [sys.executable, "-m", "textforensics.cli", *args],
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_json_report_withheld_without_regime(self):
        # No --language/--domain and no segment record yet: condition
        # (iv) withholds the verdict; exit code 1 (downgraded).
        result = self.run_cli("mixed-origin", "--text", TEXT, "--json")
        self.assertEqual(result.returncode, EXIT_DOWNGRADED, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["schema"], "textforensics.mixed-origin-report/v1")
        self.assertEqual(payload["verdict"], "withheld")
        self.assertTrue(any("no_validation_slice" in r for r in payload["withheld_reasons"]))
        self.assertNotIn(TEXT, result.stdout)

    def test_json_report_human_with_covered_regime(self):
        # The segment record (commit 5) covers en + news, so a plain
        # human text in that regime is verdicted "human", exit 0.
        result = self.run_cli(
            "mixed-origin",
            "--text",
            LIBRARY_TEXT,
            "--json",
            "--language",
            "en",
            "--domain",
            "news",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["verdict"], "human")
        self.assertEqual(payload["withheld_reasons"], [])
        self.assertEqual(payload["collaboration_type"], "HH")
        self.assertTrue(payload["regime"]["validation_slice_covered"])
        self.assertTrue(all(s["evidence"] == "human-consistent" for s in payload["segments"]))
        self.assertNotIn("Mill Street", result.stdout)

    def test_json_report_withheld_with_uncovered_domain(self):
        # A declared regime outside the segment record's domains
        # ("legal" is not in abstracts/essays/news/reports) is
        # uncovered: condition (iv) withholds the verdict.
        result = self.run_cli(
            "mixed-origin",
            "--text",
            LIBRARY_TEXT,
            "--json",
            "--language",
            "en",
            "--domain",
            "legal",
        )
        self.assertEqual(result.returncode, EXIT_DOWNGRADED, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["verdict"], "withheld")
        self.assertTrue(any("no_validation_slice" in r for r in payload["withheld_reasons"]))
        self.assertFalse(payload["regime"]["validation_slice_covered"])

    def test_pretty_output_has_no_raw_text(self):
        text = (
            "The committee filed the "
            f"{CANARY} reference with the minutes for the record. "
            "Members asked several questions about the budget and the "
            "timeline before the chair closed the session for the day. "
            "The proposal required further discussion before any vote."
        )
        result = self.run_cli("mixed-origin", "--text", text)
        self.assertEqual(result.returncode, EXIT_DOWNGRADED, result.stderr)
        self.assertNotIn(CANARY, result.stdout)
        self.assertNotIn("committee filed", result.stdout)
        self.assertIn("Verdict", result.stdout)
        self.assertIn("withheld", result.stdout)
        self.assertIn("Limitations", result.stdout)

    def test_out_writes_report_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.json"
            result = self.run_cli("mixed-origin", "--text", TEXT, "--out", str(out))
            self.assertEqual(result.returncode, EXIT_DOWNGRADED, result.stderr)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["verdict"], "withheld")
            self.assertNotIn(TEXT, out.read_text(encoding="utf-8"))

    def test_explicit_missing_registry_is_an_error(self):
        result = self.run_cli(
            "mixed-origin", "--text", TEXT, "--json", "--registry", "/nonexistent/registry.json"
        )
        self.assertEqual(result.returncode, EXIT_ERROR, result.stderr)

    def test_no_adversarial_flag(self):
        result = self.run_cli("mixed-origin", "--text", TEXT, "--json", "--no-adversarial")
        self.assertEqual(result.returncode, EXIT_DOWNGRADED, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["operation_hypothesis"]["operation"], "unknown")

    def test_stdin_input(self):
        result = self.run_cli("mixed-origin", "--json", input_text=TEXT)
        self.assertEqual(result.returncode, EXIT_DOWNGRADED, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["verdict"], "withheld")


if __name__ == "__main__":
    unittest.main()
