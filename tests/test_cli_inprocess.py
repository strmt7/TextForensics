from __future__ import annotations

import argparse
import json
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path

from textforensics.cli import build_parser, main

TEXT = (
    "I ran this test yesterday. The first result looked odd, so I "
    "changed one cable, repeated it, and wrote down the second result."
)

FORMULAIC = (
    "Furthermore, it is important to note that this robust solution "
    "seamlessly unlocks the potential."
)

class CliInProcessTests(unittest.TestCase):
    """In-process CLI tests for line coverage (not subprocess)."""

    def _run_main(self, argv: list[str], stdin: str | None = None) -> tuple[int, str, str]:
        """Run main() with given argv and stdin, return (exit_code, stdout, stderr)."""
        old_argv = sys.argv
        old_stdin = sys.stdin
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        try:
            sys.argv = ["textforensics", *argv]
            if stdin is not None:
                sys.stdin = StringIO(stdin)
            sys.stdout = StringIO()
            sys.stderr = StringIO()
            exit_code = main()
            return exit_code, sys.stdout.getvalue(), sys.stderr.getvalue()
        except SystemExit as e:
            return e.code, sys.stdout.getvalue(), sys.stderr.getvalue()
        finally:
            sys.argv = old_argv
            sys.stdin = old_stdin
            sys.stdout = old_stdout
            sys.stderr = old_stderr

    def test_version(self):
        code, out, err = self._run_main(["--version"])
        self.assertEqual(code, 0)
        self.assertIn("textforensics", out.lower())

    def test_scan_json_from_stdin(self):
        code, out, err = self._run_main(["scan", "--json"], stdin=TEXT)
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertIn("diagnostic_reliability", payload)
        self.assertIn("confidence_semantics", payload)

    def test_scan_json_from_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.txt"
            source.write_text(TEXT, encoding="utf-8")
            code, out, err = self._run_main(["scan", "--json", "--file", str(source)])
            self.assertEqual(code, 0, err)
            payload = json.loads(out)
            self.assertIn("diagnostic_reliability", payload)

    def test_audit_json_from_stdin(self):
        # audit outputs JSON by default (no --json flag)
        code, out, err = self._run_main(["audit"], stdin=FORMULAIC)
        self.assertEqual(code, 0, err)
        issues = json.loads(out)
        self.assertTrue(any("stock_phrasing" in i["issue"] for i in issues))

    def test_localize_json(self):
        # localize outputs JSON by default
        code, out, err = self._run_main(["localize", "--sentences", "2"], stdin=TEXT * 2)
        self.assertEqual(code, 0, err)
        segments = json.loads(out)
        self.assertGreaterEqual(len(segments), 1)

    def test_compare_output(self):
        # compare outputs human-readable text (no --json flag)
        with tempfile.TemporaryDirectory() as tmp:
            before = Path(tmp) / "before.txt"
            after = Path(tmp) / "after.txt"
            before.write_text(TEXT, encoding="utf-8")
            after.write_text(TEXT + " extra.", encoding="utf-8")
            code, out, err = self._run_main(["compare", str(before), str(after)])
            self.assertEqual(code, 0, err)
            self.assertIn("similarity", out)
            self.assertIn("score_delta", out)
            self.assertIn("before_verdict", out)
            self.assertIn("after_verdict", out)

    def test_compare_output(self):
        # compare outputs human-readable text (no --json flag)
        with tempfile.TemporaryDirectory() as tmp:
            before = Path(tmp) / "before.txt"
            after = Path(tmp) / "after.txt"
            before.write_text(TEXT, encoding="utf-8")
            after.write_text(TEXT + " extra.", encoding="utf-8")
            code, out, err = self._run_main(["compare", str(before), str(after)])
            self.assertEqual(code, 0, err)
            self.assertIn("similarity", out)
            self.assertIn("score_delta", out)
            self.assertIn("before_verdict", out)
            self.assertIn("after_verdict", out)

    def test_snapshot_verify_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            source = Path(tmp) / "draft.txt"
            source.write_text("first draft", encoding="utf-8")
            code, out, err = self._run_main(["snapshot", str(source), "--ledger", str(ledger)])
            self.assertEqual(code, 0, err)
            code, out, err = self._run_main(["verify-ledger", str(ledger)])
            self.assertEqual(code, 0, err)

    def test_case_export_verify_and_tamper(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.txt"
            case = Path(tmp) / "case.json"
            source.write_text(TEXT, encoding="utf-8")

            code, out, err = self._run_main([
                "case", "export",
                "--file", str(source),
                "--output", str(case),
            ])
            self.assertEqual(code, 0, err)
            self.assertTrue(case.exists())
            self.assertNotIn(TEXT, case.read_text(encoding="utf-8"))

            code, out, err = self._run_main(["case", "verify", str(case)])
            self.assertEqual(code, 0, err)
            self.assertTrue(json.loads(out)["valid"])

            payload = json.loads(case.read_text(encoding="utf-8"))
            payload["forensic_bundle"]["content_sha256"] = "0" * 64
            case.write_text(json.dumps(payload), encoding="utf-8")

            code, out, err = self._run_main(["case", "verify", str(case)])
            self.assertEqual(code, 1, err)
            self.assertFalse(json.loads(out)["valid"])

    def test_calibrate_benchmark_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            cal = Path(tmp) / "cal.jsonl"
            evalf = Path(tmp) / "eval.jsonl"
            # Use different content for calibration and evaluation to avoid dataset fingerprint collision
            cal_human = "I tested the device this morning and it worked."
            cal_ai = "Furthermore, this robust solution seamlessly unlocks potential."
            eval_human = "I tested the device this afternoon and it failed."
            eval_ai = "Moreover, this approach is fundamentally flawed and fails."
            for p, h, a in [(cal, cal_human, cal_ai), (evalf, eval_human, eval_ai)]:
                p.write_text(
                    json.dumps({"label": "human", "text": h}) + "\n" +
                    json.dumps({"label": "ai", "text": a}) + "\n",
                    encoding="utf-8"
                )
            cal_out = Path(tmp) / "cal.json"
            code, out, err = self._run_main(["calibrate", str(cal), "--target-fpr", "0.0", "--output", str(cal_out)])
            self.assertEqual(code, 0, err)
            cal_artifact = json.loads(cal_out.read_text(encoding="utf-8"))
            self.assertIn("recommended_threshold", cal_artifact)

            # Use evalf (different file with different content) for evaluation
            code, out, err = self._run_main(["benchmark", str(evalf), "--calibration", str(cal_out)])
            self.assertEqual(code, 0, err)
            self.assertEqual(json.loads(out)["mode"], "held_out_evaluation")

    def test_benchmark_same_dataset_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            path.write_text(
                json.dumps({"label": "human", "text": "hi"}) + "\n" +
                json.dumps({"label": "ai", "text": "ai text"}) + "\n",
                encoding="utf-8"
            )
            cal_out = Path(tmp) / "cal.json"
            self._run_main(["calibrate", str(path), "--target-fpr", "0.0", "--output", str(cal_out)])
            code, out, err = self._run_main(["benchmark", str(path), "--calibration", str(cal_out)])
            self.assertEqual(code, 2, err)
            self.assertIn("matches the calibration dataset", err)

    def test_detectors_list(self):
        code, out, err = self._run_main(["detectors"])
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertIn("detectors", payload)
        self.assertTrue(payload["detectors"])

    def test_detectors_health(self):
        code, out, err = self._run_main(["detectors", "--health"])
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertIn("plugin_health", payload)
        self.assertTrue(payload["plugin_health"])

    def test_report_json(self):
        # report outputs JSON by default
        code, out, err = self._run_main(["report"], stdin=TEXT)
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertIn("trust_map", payload)
        self.assertFalse(payload["input"]["raw_text_included"])

    def test_web_remote_bind_guard(self):
        code, out, err = self._run_main(["web", "--host", "0.0.0.0", "--no-browser"])
        self.assertEqual(code, 2, err)
        self.assertIn("Refusing to bind", err)

    def test_remote_bind_guard_serve(self):
        code, out, err = self._run_main(["serve", "--host", "0.0.0.0"])
        self.assertEqual(code, 2, err)
        self.assertIn("Refusing to bind", err)

    def test_invalid_command(self):
        code, out, err = self._run_main(["notacommand"])
        self.assertEqual(code, 2)

    def test_scan_short_text_warning(self):
        # Short text triggers warning but still exits 0
        code, out, err = self._run_main(["scan", "--json"], stdin="hi")
        self.assertEqual(code, 0, err)


class CliParserTests(unittest.TestCase):
    def test_parser_has_all_subcommands(self):
        parser = build_parser()
        subparsers_actions = [
            a for a in parser._actions
            if isinstance(a, argparse._SubParsersAction)
        ]
        self.assertTrue(subparsers_actions)
        subcommands = set()
        for sp in subparsers_actions:
            subcommands.update(sp.choices.keys())
        expected = {
            "scan", "audit", "localize", "compare", "snapshot",
            "verify-ledger", "calibrate", "benchmark", "detectors",
            "report", "case", "web", "serve",
        }
        self.assertTrue(expected.issubset(subcommands))


if __name__ == "__main__":
    unittest.main()