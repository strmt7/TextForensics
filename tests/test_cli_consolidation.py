"""Tests for the Phase 2 wave (b) CLI consolidation.

Covers the commands ported from the deleted Typer CLI into ``cli.py``
(``capability policy``, ``bundle check``), the ``--text`` input flag on
``scan``/``audit``/``report``/``case export``, and ``bundle.read_bundle``
(the reader the Typer ``bundle check`` used to import but never existed).
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path

from textforensics.bundle import pack_bundle, read_bundle
from textforensics.casefile import write_case_file
from textforensics.cli import build_parser, main
from textforensics.constants import EXIT_ERROR, EXIT_INCOMPLETE, EXIT_OK
from textforensics.policy import (
    CapabilityClaim,
    CapabilityLedger,
    EvidenceLabel,
    EvidenceRef,
    EvidenceTier,
)
from textforensics.report import build_forensic_bundle

FORMULAIC = (
    "Furthermore, it is important to note that this robust solution "
    "seamlessly unlocks the potential of modern technology for every user."
)
PLAIN = (
    "I ran this test yesterday. The first result looked odd, so I "
    "changed one cable, repeated it, and wrote down the second result."
)
DETECTOR = "test/detector"


def _write_ledger(
    tmp: Path,
    claims: list[tuple[str, EvidenceTier] | tuple[str, EvidenceTier, EvidenceLabel]],
) -> Path:
    """Build a capability ledger JSON file with the given claims.

    Each claim is ``(capability, tier)`` or ``(capability, tier, label)``;
    the evidence label defaults to ``CALCULATED``. A ``VALIDATED`` claim
    needs an ``EXECUTED`` evidence reference to be effective (W2, S04),
    so a genuinely passing ledger must label it so explicitly.
    """
    ledger = CapabilityLedger()
    for entry in claims:
        capability, tier = entry[0], entry[1]
        label = entry[2] if len(entry) > 2 else EvidenceLabel.CALCULATED
        ledger.register(
            CapabilityClaim(
                detector_id=DETECTOR,
                capability=capability,
                tier=tier,
                evidence=[
                    EvidenceRef(
                        label=label,
                        tier=tier,
                        artifact="test",
                    )
                ],
            )
        )
    path = tmp / "capability_ledger.json"
    path.write_text(json.dumps(ledger.to_dict(), indent=2), encoding="utf-8")
    return path


class _RunMainMixin:
    """Run main() in-process, capturing stdout/stderr and the exit code."""

    def _run_main(self, argv: list[str], stdin: str | None = None) -> tuple[int, str, str]:
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
        except SystemExit as exc:
            return exc.code, sys.stdout.getvalue(), sys.stderr.getvalue()
        finally:
            sys.argv = old_argv
            sys.stdin = old_stdin
            sys.stdout = old_stdout
            sys.stderr = old_stderr


class TestCapabilityPolicyCLI(_RunMainMixin, unittest.TestCase):
    """`capability policy`, ported from the former Typer CLI."""

    def test_policy_empty_ledger_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger_path = _write_ledger(Path(tmp), [])
            code, out, _err = self._run_main(
                ["capability", "policy", DETECTOR, "--ledger", str(ledger_path)]
            )
            self.assertEqual(code, EXIT_INCOMPLETE)
            self.assertIn("Policy evaluation: production for test/detector", out)
            self.assertIn("[PROD-LANGUAGE-COVERAGE]", out)
            self.assertIn("MISSING: language_coverage (required: validated+)", out)

    def test_policy_json_mode_does_not_crash(self):
        """Regression test: the Typer version raised NameError in --json mode
        (all_passed was only assigned in the non-JSON branch) and always
        exited EXIT_ERROR. The ported command must return the JSON list
        and EXIT_INCOMPLETE for a failing ledger."""
        with tempfile.TemporaryDirectory() as tmp:
            ledger_path = _write_ledger(Path(tmp), [])
            code, out, _err = self._run_main(
                ["capability", "policy", DETECTOR, "--ledger", str(ledger_path), "--json"]
            )
            self.assertEqual(code, EXIT_INCOMPLETE)
            results = json.loads(out)
            self.assertEqual(len(results), 3)
            self.assertEqual(
                [r["rule_id"] for r in results],
                [
                    "prod-language-coverage",
                    "prod-length-robustness",
                    "prod-domain-accuracy",
                ],
            )
            self.assertTrue(all(r["passed"] is False for r in results))

    def test_policy_passing_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger_path = _write_ledger(
                Path(tmp),
                [
                    # A VALIDATED claim needs an EXECUTED evidence reference
                    # to be effective (W2, S04); CALCULATED alone no longer
                    # authorizes it.
                    ("language_coverage", EvidenceTier.VALIDATED, EvidenceLabel.EXECUTED),
                    ("length_robustness", EvidenceTier.TOOL_BACKED),
                    ("domain_accuracy", EvidenceTier.TOOL_BACKED),
                ],
            )
            code, out, _err = self._run_main(
                ["capability", "policy", DETECTOR, "--ledger", str(ledger_path)]
            )
            self.assertEqual(code, EXIT_OK)
            self.assertIn("[PASS]", out)
            self.assertNotIn("MISSING:", out)

    def test_policy_validated_without_executed_evidence_fails(self):
        """W2, S04: a VALIDATED claim with only CALCULATED evidence is
        ineffective, so the ledger cannot pass the production policy."""
        with tempfile.TemporaryDirectory() as tmp:
            ledger_path = _write_ledger(
                Path(tmp),
                [
                    ("language_coverage", EvidenceTier.VALIDATED),
                    ("length_robustness", EvidenceTier.TOOL_BACKED),
                    ("domain_accuracy", EvidenceTier.TOOL_BACKED),
                ],
            )
            code, out, _err = self._run_main(
                ["capability", "policy", DETECTOR, "--ledger", str(ledger_path)]
            )
            self.assertEqual(code, EXIT_INCOMPLETE)
            self.assertIn("MISSING: language_coverage", out)

    def test_policy_minimum_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger_path = _write_ledger(
                Path(tmp),
                [
                    ("language_coverage", EvidenceTier.READABLE),
                    ("length_robustness", EvidenceTier.READABLE),
                ],
            )
            code, _out, _err = self._run_main(
                [
                    "capability",
                    "policy",
                    DETECTOR,
                    "--ledger",
                    str(ledger_path),
                    "--policy",
                    "minimum",
                ]
            )
            self.assertEqual(code, EXIT_OK)

    def test_policy_unknown_choice_rejected_by_parser(self):
        parser = build_parser()
        with self.assertRaises(SystemExit) as ctx:
            parser.parse_args(["capability", "policy", DETECTOR, "--policy", "bogus"])
        self.assertEqual(ctx.exception.code, 2)


class TestBundleCheckCLI(_RunMainMixin, unittest.TestCase):
    """`bundle check`, ported from the former Typer CLI."""

    def _bundle_json(self, tmp: Path) -> Path:
        bundle = build_forensic_bundle(FORMULAIC, deterministic=True)
        path = tmp / "bundle.json"
        path.write_text(json.dumps(bundle.to_dict(), indent=2), encoding="utf-8")
        return path

    def test_check_bundle_json_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle_path = self._bundle_json(Path(tmp))
            code, out, _err = self._run_main(["bundle", "check", str(bundle_path)])
            self.assertEqual(code, EXIT_OK)
            self.assertIn("Bundle consistency: PASS", out)

    def test_check_case_file_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bundle = build_forensic_bundle(FORMULAIC, deterministic=True)
            case_path = tmp_path / "case.json"
            write_case_file(case_path, bundle.to_dict(), deterministic=True)
            code, out, _err = self._run_main(["bundle", "check", str(case_path)])
            self.assertEqual(code, EXIT_OK)
            self.assertIn("Bundle consistency: PASS", out)

    def test_check_archive_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bundle = build_forensic_bundle(FORMULAIC, deterministic=True)
            case_path = tmp_path / "case.json"
            write_case_file(case_path, bundle.to_dict(), deterministic=True)
            archive_path = tmp_path / "bundle.tar.gz"
            pack_bundle(case_path, archive_path)
            code, out, _err = self._run_main(["bundle", "check", str(archive_path)])
            self.assertEqual(code, EXIT_OK)
            self.assertIn("Bundle consistency: PASS", out)

    def test_check_json_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle_path = self._bundle_json(Path(tmp))
            code, out, _err = self._run_main(["bundle", "check", str(bundle_path), "--json"])
            self.assertEqual(code, EXIT_OK)
            result = json.loads(out)
            self.assertTrue(result["is_consistent"])
            self.assertIn("checked_fields", result)
            self.assertIn("trust_map.overall", result["checked_fields"])

    def test_check_missing_schema_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad_path = Path(tmp) / "bad.json"
            bad_path.write_text(json.dumps({"consensus": {"verdict": "ai_like"}}), encoding="utf-8")
            code, out, _err = self._run_main(["bundle", "check", str(bad_path)])
            self.assertEqual(code, EXIT_INCOMPLETE)
            self.assertIn("Bundle consistency: FAIL", out)
            self.assertIn("schema", out)

    def test_check_missing_file_errors(self):
        code, _out, err = self._run_main(["bundle", "check", "/nonexistent/bundle.json"])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("error:", err)


class TestTextFlagCLI(_RunMainMixin, unittest.TestCase):
    """The --text/-t input flag, ported from the former Typer CLI."""

    def test_scan_text_matches_file_input(self):
        from textforensics.engine import analyze_text

        expected = analyze_text(FORMULAIC)
        code, out, _err = self._run_main(["scan", "--text", FORMULAIC, "--json"])
        self.assertEqual(code, EXIT_OK)
        data = json.loads(out)
        self.assertEqual(data["score"], expected.score)
        self.assertEqual(data["verdict"], expected.verdict)

    def test_scan_file_takes_precedence_over_text(self):
        """--file wins over --text, matching the former Typer precedence."""
        from textforensics.engine import analyze_text

        with tempfile.TemporaryDirectory() as tmp:
            file_path = Path(tmp) / "input.txt"
            file_path.write_text(PLAIN, encoding="utf-8")
            code, out, _err = self._run_main(
                ["scan", "--file", str(file_path), "--text", FORMULAIC, "--json"]
            )
            self.assertEqual(code, EXIT_OK)
            data = json.loads(out)
            self.assertEqual(data["score"], analyze_text(PLAIN).score)

    def test_report_text(self):
        code, out, _err = self._run_main(["report", "--text", FORMULAIC, "--deterministic"])
        self.assertEqual(code, EXIT_OK)
        data = json.loads(out)
        self.assertIn("schema", data)
        self.assertIn("trust_map", data)

    def test_case_export_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_path = Path(tmp) / "case.json"
            code, out, _err = self._run_main(
                [
                    "case",
                    "export",
                    "--text",
                    FORMULAIC,
                    "--deterministic",
                    "--output",
                    str(case_path),
                ]
            )
            self.assertEqual(code, EXIT_OK)
            self.assertTrue(case_path.exists())
            payload = json.loads(case_path.read_text(encoding="utf-8"))
            self.assertIn("forensic_bundle", payload)

    def test_audit_text(self):
        code, out, _err = self._run_main(["audit", "--text", FORMULAIC])
        self.assertEqual(code, EXIT_OK)
        data = json.loads(out)
        self.assertIsInstance(data, list)

    def test_scan_empty_text_errors(self):
        code, _out, err = self._run_main(["scan", "--text", ""])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("error:", err)


class TestReadBundle(unittest.TestCase):
    """bundle.read_bundle: the reader the Typer `bundle check` imported
    from .bundle but never existed, so the command crashed on every call."""

    def _sealed_case(self, tmp: Path) -> tuple[Path, dict]:
        bundle = build_forensic_bundle(FORMULAIC, deterministic=True)
        case_path = tmp / "case.json"
        write_case_file(case_path, bundle.to_dict(), deterministic=True)
        return case_path, bundle.to_dict()

    def test_read_bundle_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = build_forensic_bundle(FORMULAIC, deterministic=True).to_dict()
            path = Path(tmp) / "bundle.json"
            path.write_text(json.dumps(bundle), encoding="utf-8")
            self.assertEqual(read_bundle(path)["schema"], bundle["schema"])

    def test_read_case_file_unwraps_forensic_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_path, bundle = self._sealed_case(Path(tmp))
            result = read_bundle(case_path)
            self.assertEqual(result["schema"], bundle["schema"])
            self.assertIn("trust_map", result)

    def test_read_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case_path, bundle = self._sealed_case(tmp_path)
            archive_path = tmp_path / "bundle.tar.gz"
            pack_bundle(case_path, archive_path)
            result = read_bundle(archive_path)
            self.assertEqual(result["schema"], bundle["schema"])

    def test_read_zip_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case_path, bundle = self._sealed_case(tmp_path)
            archive_path = tmp_path / "bundle.zip"
            pack_bundle(case_path, archive_path)
            result = read_bundle(archive_path)
            self.assertEqual(result["schema"], bundle["schema"])

    def test_read_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            read_bundle("/nonexistent/bundle.json")

    def test_read_non_bundle_json_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "other.json"
            path.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
            with self.assertRaises(ValueError):
                read_bundle(path)

    def test_read_malformed_json_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(json.JSONDecodeError):
                read_bundle(path)


if __name__ == "__main__":
    unittest.main()
