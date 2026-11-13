"""W3 worker F4 kill tests for ``textforensics.verify``.

Audit W3 re-proof (py-JSON fix): the two new ``RecursionError`` handlers
in ``_load_case_file_payload`` and ``verify_case_file_path`` had no kill
tests. Both handlers are defensive — the loader's explicit 100-level
depth cap (``MAX_JSON_DEPTH``) rejects hostile nesting before the
downstream helpers run, so a real ``RecursionError`` is not reachable
through the public path on this Python — and the handlers are exercised
here by simulating the failure they guard against (the same mock
precedent as the W3 datasets depth tests, which simulate the Python
3.14+ json behaviour with a fake decoder). Every test below kills at
least one canonical re-proof survivor; the mapping is recorded in
hidden_files/audit-w3-worker-f4.md §5.
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import textforensics.verify as verify_mod
from textforensics.verify import verify_case_file_path


class TestAuditW3WorkerF4Verify(unittest.TestCase):
    def test_recursion_error_in_loader_reports_array_as_not_object(self):
        # Kills AddNot [559,11] in _load_case_file_payload: the mutant
        # negates the startswith("[") check, so a deeply nested array
        # that raises RecursionError is reported as "invalid JSON"
        # instead of "case file must be a JSON object" — and a deeply
        # nested object is reported as "must be a JSON object" instead
        # of "invalid JSON".
        with tempfile.TemporaryDirectory() as tmp:
            array_path = Path(tmp) / "array.json"
            array_path.write_text("[" * 1100 + "]" * 1100, encoding="utf-8")
            object_path = Path(tmp) / "object.json"
            object_path.write_text('{"a": ' + "[" * 1100 + "]" * 1100 + "}", encoding="utf-8")
            with mock.patch.object(
                verify_mod.json,
                "loads",
                side_effect=RecursionError("maximum recursion depth exceeded"),
            ):
                array_report = verify_case_file_path(array_path)
                self.assertFalse(array_report.overall_valid)
                self.assertFalse(array_report.case_file["valid"])
                self.assertEqual(
                    array_report.case_file["errors"],
                    ["case file must be a JSON object"],
                )
                object_report = verify_case_file_path(object_path)
                self.assertFalse(object_report.overall_valid)
                self.assertFalse(object_report.case_file["valid"])
                self.assertEqual(
                    object_report.case_file["errors"],
                    ["invalid JSON: maximum recursion depth exceeded"],
                )

    def test_recursion_error_in_verify_all_is_structured_invalid(self):
        # Kills ExceptionReplacer [922,11] (the mutant's except clause
        # does not catch RecursionError, so it propagates instead of
        # becoming a structured invalid) and the four
        # ReplaceFalseWithTrue mutants in the handler's report:
        # [929,25] (case_file["valid"]), [931,33] ("seal_verified"),
        # [932,38] ("trust_map_verified"), [935,26] ("overall_valid").
        # Each mutant flips exactly one of these fields to True.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "case.json"
            path.write_text("{}", encoding="utf-8")
            with mock.patch.object(
                verify_mod,
                "verify_all",
                side_effect=RecursionError("maximum recursion depth exceeded"),
            ):
                report = verify_case_file_path(path)
        self.assertFalse(report.overall_valid)
        self.assertIs(report.overall_valid, False)
        self.assertFalse(report.case_file["valid"])
        self.assertIs(report.case_file["valid"], False)
        self.assertIs(report.case_file["seal_verified"], False)
        self.assertIs(report.case_file["trust_map_verified"], False)
        self.assertEqual(report.case_file["dimensions"], {})
        self.assertEqual(
            report.case_file["errors"],
            ["invalid JSON: maximum recursion depth exceeded"],
        )


if __name__ == "__main__":
    unittest.main()
