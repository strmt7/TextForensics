"""W3 worker F4 kill tests for ``textforensics.datasets``.

Audit W3 re-proof (py-JSON fix): the 100-level nesting bound in
``iter_detectrl_x_rows`` and its two helpers were never in mutation
scope before, so their mutants had no kill tests. These tests pin the
exact behaviour each survivor changes: exact error messages (the
pre-existing tests assert only the exception type), the literal 100
depth bound, the literal 16 MiB default object cap, the exact-size
object boundary, and the ``_fill`` buffer-guard threshold (which is
``max_object_bytes + chunk_size``, so chunk-size mutants are observable
through it). Every test below kills at least one phase-1 survivor;
the mapping is recorded in hidden_files/audit-w3-worker-f4.md §5.
"""

import json
import re
import tempfile
import unittest
from pathlib import Path

from textforensics.datasets import (
    DatasetFetchError,
    _check_raw_json_nesting_depth,
    _json_value_depth,
    iter_detectrl_x_rows,
)


def _exact(message: str) -> str:
    """An assertRaisesRegex pattern matching one exact message."""
    return re.escape(message)


class TestAuditW3WorkerF4DetectRLX(unittest.TestCase):
    def _write(self, tmp, name, blob):
        path = Path(tmp) / name
        path.write_bytes(blob if isinstance(blob, bytes) else blob.encode("utf-8"))
        return path

    def test_exact_array_error_for_bare_object_and_empty_file(self):
        # Kills NotEq_Lt [2325,17] (bare object: '{' > '[' so the mutant
        # proceeds and reports "row 0 is not a JSON object" instead) and
        # NotEq_Gt [2325,17] (empty file: '' > '[' is False, so the mutant
        # proceeds and reports "truncated" instead).
        with tempfile.TemporaryDirectory() as tmp:
            bare = self._write(tmp, "bare.json", json.dumps({"a": 1}))
            with self.assertRaisesRegex(
                DatasetFetchError,
                _exact(
                    "detectrl_x: expected a JSON array file (first non-whitespace "
                    "character is '{', not '[')"
                ),
            ):
                list(iter_detectrl_x_rows(bare))
            empty = self._write(tmp, "empty.json", b"")
            with self.assertRaisesRegex(
                DatasetFetchError,
                _exact(
                    "detectrl_x: expected a JSON array file (first non-whitespace "
                    "character is '', not '[')"
                ),
            ):
                list(iter_detectrl_x_rows(empty))

    def test_truncated_after_comma_reports_truncation(self):
        # Kills AddNot [2335,15]: the mutant never fires the guard and
        # reports "row 1 is not a JSON object" instead of truncation.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "trunc.json", '[{"a": 1},')
            with self.assertRaisesRegex(
                DatasetFetchError,
                _exact("detectrl_x: file ended before the JSON array closed (truncated?)"),
            ):
                list(iter_detectrl_x_rows(path))

    def test_truncated_mid_object_reports_not_parseable(self):
        # Kills ReplaceAndWithOr [2335,19] and Delete_Not [2335,23]: both
        # mutants fire the loop-top guard on (eof, non-empty buf) — the
        # state reached after the decode handler's final fill — and report
        # "truncated" instead of "row 1 is not parseable JSON".
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "mid.json", '[{"a": 1}, {"a": 2')
            with self.assertRaisesRegex(
                DatasetFetchError,
                _exact("detectrl_x: row 1 is not parseable JSON"),
            ):
                list(iter_detectrl_x_rows(path))

    def test_repeated_comma_reports_unexpected_comma(self):
        # Kills Eq_LtE [2339,20]: the mutant takes the ']' branch for ','
        # and reports "trailing comma" instead of "unexpected comma".
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "rep.json", '[{"a": 1},,{"a": 2}]')
            with self.assertRaisesRegex(
                DatasetFetchError,
                _exact("detectrl_x: unexpected comma in JSON array"),
            ):
                list(iter_detectrl_x_rows(path))

    def test_empty_array_with_single_trailing_character_rejected(self):
        # Kills NumberReplacer [2343,26] (buf[2:] in the loop-top ']'
        # branch): the mutant skips both ']' and the trailing character,
        # so the file looks clean and yields [] instead of raising.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "trail.json", b"[]x")
            with self.assertRaisesRegex(
                DatasetFetchError,
                _exact("detectrl_x: trailing data after the closing JSON array"),
            ):
                list(iter_detectrl_x_rows(path))

    def test_string_element_reports_not_an_object(self):
        # Kills Eq_Lt [2346,20] and Eq_LtE [2346,20] (the mutants take the
        # comma branch for '"' and report "unexpected comma") and
        # NotEq_Lt [2353,20] (the mutant decodes the string and reports
        # "row 0 is str, expected object").
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "bad.json", b'["not an object"]')
            with self.assertRaisesRegex(
                DatasetFetchError,
                _exact("detectrl_x: row 0 is not a JSON object (found '\"')"),
            ):
                list(iter_detectrl_x_rows(path))

    def test_close_brace_at_element_position_reports_not_an_object(self):
        # Kills NotEq_Gt [2353,20]: the mutant proceeds to raw_decode and
        # reports "row 0 is not parseable JSON" instead.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "brace.json", b"[}]")
            with self.assertRaisesRegex(
                DatasetFetchError,
                _exact("detectrl_x: row 0 is not a JSON object (found '}')"),
            ):
                list(iter_detectrl_x_rows(path))

    def test_truncated_after_row_reports_truncation(self):
        # Kills AddNot [2396,15] and Delete_Not [2396,23]: both mutants
        # skip the post-row guard and report "expected ',' or ']'" instead.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "norow.json", b'[{"a": 1}')
            with self.assertRaisesRegex(
                DatasetFetchError,
                _exact("detectrl_x: file ended before the JSON array closed (truncated?)"),
            ):
                list(iter_detectrl_x_rows(path))

    def test_missing_comma_after_row_reports_exact_row(self):
        # Kills all 13 message mutants at [2409,71]/[2409,73]: the row
        # number in the message is index - 1, so three missing-comma
        # positions are needed — after row 0 kills 10 (Mod/RShift/BitXor
        # agree with the original there), after row 1 kills Mod and
        # BitXor, after row 2 kills RShift. Also kills Eq_GtE [2403,22]
        # (the mutant treats '{' as ']' and reports "trailing data").
        cases = [
            ('[{"a": 1} {"b": 2}]', 0),
            ('[{"a": 1}, {"b": 2} {"c": 3}]', 1),
            ('[{"a": 1}, {"b": 2}, {"c": 3} {"d": 4}]', 2),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            for blob, row in cases:
                path = self._write(tmp, f"miss{row}.json", blob)
                with (
                    self.subTest(after_row=row),
                    self.assertRaisesRegex(
                        DatasetFetchError,
                        _exact(
                            f"detectrl_x: expected ',' or ']' after row {row}, "
                            "found '{' (missing comma?)"
                        ),
                    ),
                ):
                    list(iter_detectrl_x_rows(path))

    def test_string_after_row_reports_missing_comma(self):
        # Kills Eq_LtE [2400,20] (the mutant consumes '"' as a comma and
        # reports "row 1 is not a JSON object") and Eq_LtE [2403,22]
        # (the mutant treats '"' as ']' and reports "trailing data").
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "str.json", b'[{"a": 1} "x"]')
            with self.assertRaisesRegex(
                DatasetFetchError,
                _exact(
                    "detectrl_x: expected ',' or ']' after row 0, "
                    "found '\"' (missing comma?)"
                ),
            ):
                list(iter_detectrl_x_rows(path))

    def test_object_after_close_with_single_trailing_character_rejected(self):
        # Kills NumberReplacer [2404,26] (buf[2:] in the post-row ']'
        # branch): the mutant skips both ']' and the trailing character.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "trail.json", b'[{"a": 1}]x')
            with self.assertRaisesRegex(
                DatasetFetchError,
                _exact("detectrl_x: trailing data after the closing JSON array"),
            ):
                list(iter_detectrl_x_rows(path))

    def test_depth_boundary_100_accepted_101_rejected(self):
        # Kills module-level NumberReplacer [2160,32] occ 164 (100 -> 101:
        # the 101-deep row would be accepted) and occ 165 (100 -> 99: the
        # 100-deep row would be rejected), and Gt_GtE [2378,38] (the
        # decoded-value backstop with >= rejects the exactly-100 row).
        # The bound is the literal 100, not the constant read back.
        row_100 = '{"a": ' + "[" * 99 + "1" + "]" * 99 + "}"
        row_101 = '{"a": ' + "[" * 100 + "1" + "]" * 100 + "}"
        with tempfile.TemporaryDirectory() as tmp:
            ok = self._write(tmp, "ok.json", "[" + row_100 + "]")
            self.assertEqual(len(list(iter_detectrl_x_rows(ok))), 1)
            deep = self._write(tmp, "deep.json", "[" + row_101 + "]")
            with self.assertRaisesRegex(
                DatasetFetchError,
                _exact("detectrl_x: row 0 exceeds the nesting-depth budget"),
            ):
                list(iter_detectrl_x_rows(deep))

    # NOTE (ordering): unittest runs TestCase methods ALPHABETICALLY,
    # not in file order — so this test's NAME is what puts it first
    # (test_chunk_... < test_close_... < test_default_...). It must run
    # before the 16 MiB cap test: under a tiny-chunk mutant (21/20/1-byte
    # chunks) the 16 MiB test is pathologically slow (hundreds of
    # thousands of single-chunk fills, each rescanning the growing
    # buffer — the first re-prove runs hung 30+ min on LShift_Add
    # [2275,19] before being killed), while this test kills those
    # mutants in seconds — the guard fires after a few fills because
    # the threshold is max_object_bytes + chunk_size with the small
    # explicit cap (100). The re-prove runs the file with -x, so the
    # guard failure stops the run before the heavy test. Do NOT rename
    # this test to something sorting after test_default_... .
    def test_chunk_size_guard_threshold(self):
        # Kills all 10 chunk-size mutants at [2275,17]/[2275,19]/
        # [2275,22]. _fill raises when len(buf) exceeds max_object_bytes
        # + chunk_size, so the chunk size is observable through the
        # guard threshold with a small explicit cap (100): the two 2 MiB
        # chunks miss the guard on a 1.1 MB malformed object (the
        # original raises "exceeds"), the 512 KiB chunk trips it on a
        # 600 KB malformed object (the original reports "not parseable"),
        # and the tiny/negative chunks trip it on a 200-byte malformed
        # object (the original reports "not parseable").
        with tempfile.TemporaryDirectory() as tmp:
            big = self._write(tmp, "big.json", b'[{"a": "' + b"x" * 1099992)
            with self.assertRaisesRegex(
                DatasetFetchError,
                _exact("detectrl_x: single object exceeds the 100-byte object budget"),
            ):
                list(iter_detectrl_x_rows(big, max_object_bytes=100))
            mid = self._write(tmp, "mid.json", b'[{"a": "' + b"x" * 599992)
            with self.assertRaisesRegex(
                DatasetFetchError,
                _exact("detectrl_x: row 0 is not parseable JSON"),
            ):
                list(iter_detectrl_x_rows(mid, max_object_bytes=100))
            small = self._write(tmp, "small.json", b'[{"a": "' + b"x" * 192)
            with self.assertRaisesRegex(
                DatasetFetchError,
                _exact("detectrl_x: row 0 is not parseable JSON"),
            ):
                list(iter_detectrl_x_rows(small, max_object_bytes=100))

    def test_default_object_cap_boundary_16mib(self):
        # Kills all 18 default-cap mutants at [2236,70]/[2236,73]/
        # [2236,75]/[2236,80]/[2236,82]: the 10 smaller caps reject the
        # exactly-16 MiB object the original accepts, and the 8 bigger
        # caps accept the 16 MiB + 1 object the original rejects. Uses
        # the DEFAULT cap (no max_object_bytes argument).
        cap = 16 * 1024 * 1024
        with tempfile.TemporaryDirectory() as tmp:
            exact = '{"a": "' + "x" * (cap - 9) + '"}'
            self.assertEqual(len(exact), cap)
            path = self._write(tmp, "exact.json", "[" + exact + "]")
            self.assertEqual(len(list(iter_detectrl_x_rows(path))), 1)
            over = '{"a": "' + "x" * (cap - 8) + '"}'
            self.assertEqual(len(over), cap + 1)
            path = self._write(tmp, "over.json", "[" + over + "]")
            with self.assertRaisesRegex(
                DatasetFetchError,
                _exact(f"detectrl_x: row 0 exceeds the {cap}-byte object budget"),
            ):
                list(iter_detectrl_x_rows(path))

    def test_exact_object_size_accepted_with_small_cap(self):
        # Kills Gt_GtE [2382,19]: an object of exactly max_object_bytes
        # is accepted by the original (end > cap is strict) and rejected
        # by the mutant (>=).
        obj = '{"a": "' + "x" * 91 + '"}'
        self.assertEqual(len(obj), 100)
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "exact.json", "[" + obj + "]")
            self.assertEqual(
                len(list(iter_detectrl_x_rows(path, max_object_bytes=100))), 1
            )

    def test_raw_depth_check_rejects_violation_after_first_close(self):
        # Kills Eq_GtE [2209,21]: the mutant returns at the first closer
        # whose depth stays >= 0 (the ']' after [1]) and never scans the
        # deep nesting in the later "b" value.
        with self.assertRaises(DatasetFetchError):
            _check_raw_json_nesting_depth(
                '{"a": [1], "b": [[[[1]]]]}', max_depth=2, row_index=0
            )

    def test_json_value_depth_uses_deepest_sibling(self):
        # Kills Gt_NotEq and Gt_IsNot [2228,21]: both mutants lower
        # max_seen when the shallow {"b": 1} subtree is popped after the
        # deep [[[1]]] subtree, returning 2 instead of 4.
        self.assertEqual(_json_value_depth({"a": {"b": 1}, "c": [[[1]]]}), 4)


if __name__ == "__main__":
    unittest.main()
