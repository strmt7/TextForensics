"""W3 Worker F3 kill tests for the verify module (audit-w3-f).

Covers the 51 killable runtime/module-level survivors of the 152
verify survivors (70 annotation + 7 annotation timeouts + 5
domain-equivalent + 4 unobservable-value entries are baseline
entries, see audit-w3-worker-f.md §6). Each test targets a specific
mutant; the re-proof (audit-w3-f3-reprove-verify.py) hand-applies
each mutant with cosmic-ray mutate_code and runs the owning test
class.

Depth semantics (verified against verify.py): the root is depth 1;
a chain of k nested dicts has max depth k+1, so a 99-deep chain has
max depth 100 (original False) and a 100-deep chain has max depth
101 (original True). The boundary pair kills nearly everything in
_json_depth_exceeded.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from textforensics.casefile import seal_case_file
from textforensics.report import build_forensic_bundle
from textforensics.verify import (
    _json_depth_exceeded,
    _load_case_file_payload,
    verify_case_file,
    verify_case_file_combined,
    verify_case_file_path,
    verify_case_file_path_combined,
)

TEXT = (
    "I tested the device twice yesterday and wrote down what changed. "
    "The second run was warmer, so I plan to repeat it before drawing conclusions."
)

MAX_CASE_FILE_BYTES = 32 * 1024 * 1024


def _chain(depth: int) -> dict:
    """A chain of `depth` nested dicts (max depth depth + 1)."""
    value: dict = {}
    for _ in range(depth):
        value = {"a": value}
    return value


def _list_chain(depth: int) -> list:
    """A chain of `depth` nested lists (max depth depth + 1)."""
    value: list = []
    for _ in range(depth):
        value = [value]
    return value


def _valid_case() -> dict:
    bundle = build_forensic_bundle(TEXT).to_dict()
    return seal_case_file(bundle)


def _padded_json_file(tmp: Path, size: int) -> Path:
    """A JSON dict file of exactly `size` bytes."""
    path = tmp / f"case-{size}.json"
    # {"pad":"<N x's>"} is N + 10 bytes (compact separators).
    path.write_text(
        json.dumps({"pad": "x" * (size - 10)}, separators=(",", ":")),
        encoding="utf-8",
    )
    assert path.stat().st_size == size, path.stat().st_size
    return path


class TestJsonDepthExceededKill(unittest.TestCase):
    """_json_depth_exceeded: 21 Add-family + 3 Gt + 2 AddNot +
    ReplaceTrueWithFalse [77,19] + 5 NumberReplacer (+ timeout
    Add_Pow [79,39] occ 0 and NumberReplacer [73,21] occ 8)."""

    def test_99_deep_is_not_exceeded(self):
        # Max depth exactly 100. Kills: Gt_Eq/Gt_GtE/Gt_Is [76,17]
        # (all flip at exactly 100; for `is`, depth 100 is the cached
        # small int); NumberReplacer [73,21] occ 9 (stack init 1->2);
        # NumberReplacer [79,41]/[81,41] occ 11/13 (+1->+2);
        # Add_LShift [79,39]/[81,39] (depth doubles per level).
        self.assertIs(_json_depth_exceeded(_chain(99)), False)

    def test_100_deep_is_exceeded(self):
        # Max depth 101. Kills: the `+`->`-`/`*`/`/`/`//`/`%`/`**`/
        # `|`/`&`/`^` family at [79,39]/[81,39] (children stay at or
        # below the parent depth); Add_Pow [79,39] occ 0 and
        # [81,39] occ 1 (`** 1` is the identity); AddNot [74,10]
        # (`while not stack:` never runs); ReplaceTrueWithFalse
        # [77,19]; NumberReplacer [73,21] occ 8 (stack init 1->0);
        # NumberReplacer [79,41]/[81,41] occ 10/12 (+1->+0).
        self.assertIs(_json_depth_exceeded(_chain(100)), True)

    def test_50_deep_is_not_exceeded(self):
        # Max depth 51. Kills the +1->+2 NumberReplacers
        # ([79,41]/[81,41] occ 11/13: mutant max depth 102).
        self.assertIs(_json_depth_exceeded(_chain(50)), False)

    def test_60_deep_is_not_exceeded(self):
        # Max depth 61. Kills Add_LShift [81,39] (depth doubles per
        # level, so a 60-deep chain already exceeds the cap).
        self.assertIs(_json_depth_exceeded(_chain(60)), False)

    def test_list_payload_does_not_raise(self):
        # AddNot [78,11]: the mutant negates `isinstance(current,
        # dict)`, so it calls `.values()` on the list and raises
        # AttributeError. The original returns False.
        self.assertIs(_json_depth_exceeded({"a": [1, 2]}), False)

    def test_99_deep_list_is_not_exceeded(self):
        # List branch [81,39]/[81,41]: a 99-deep nested list has
        # max depth 100. Kills the Add-family at [81,39] (the
        # `+`->`-`/`*`/`/`/`//`/`%`/`**`/`|`/`&`/`^` mutants change
        # the child depth) and NumberReplacer [81,41] occ 13
        # (+1->+2, max depth 102).
        self.assertIs(_json_depth_exceeded(_list_chain(99)), False)

    def test_100_deep_list_is_exceeded(self):
        # List branch [81,39]/[81,41]: a 100-deep nested list has
        # max depth 101. Kills Add_Pow [81,39] occ 1 (`** 1` is the
        # identity) and NumberReplacer [81,41] occ 12 (+1->+0, max
        # depth 100).
        self.assertIs(_json_depth_exceeded(_list_chain(100)), True)


class TestVerifyCaseFileKill(unittest.TestCase):
    """ReplaceFalseWithTrue [233,21]/[235,29]/[236,34] (the
    depth-exceeded early return in verify_case_file)."""

    def test_non_dict_payload_is_invalid(self):
        result = verify_case_file([1, 2, 3])
        self.assertIs(result["valid"], False)
        self.assertIs(result["seal_verified"], False)
        self.assertIs(result["trust_map_verified"], False)

    def test_deep_payload_is_invalid(self):
        # [233,21]/[235,29]/[236,34]: a 100-deep payload hits the
        # depth-exceeded return (not the non-dict return). The
        # mutants flip its "valid"/"seal_verified"/
        # "trust_map_verified" False values to True.
        result = verify_case_file(_chain(100))
        self.assertIs(result["valid"], False)
        self.assertEqual(result["errors"], ["case file exceeds the JSON depth limit"])
        self.assertIs(result["seal_verified"], False)
        self.assertIs(result["trust_map_verified"], False)


class TestCombinedKill(unittest.TestCase):
    """AddNot [475,47]/[476,57] (LIST payload fallback dict);
    ReplaceFalseWithTrue [481,44]/[481,76] (mocked nversion)."""

    def test_list_payload_returns_dict(self):
        # AddNot [475,47]/[476,57]: the fallback dict is built only
        # when the primary (casefile) verification RAISES. A plain
        # list payload does not raise there, so the primary is mocked
        # to raise ValueError; the fallback dict is then built with
        # `payload.get(...) if isinstance(payload, dict) else None`.
        # The AddNot mutant calls `.get` on the list and the
        # AttributeError escapes.
        with mock.patch(
            "textforensics.casefile.verify_case_file",
            side_effect=ValueError("boom"),
        ):
            result = verify_case_file_combined([1, 2, 3])
        self.assertIsInstance(result, dict)
        self.assertIs(result["valid"], False)

    def test_mocked_primary_without_valid_is_invalid(self):
        # ReplaceFalseWithTrue [481,76] (the primary .get("valid",
        # False) default): the nversion is real (valid True for a
        # valid case) and the primary is mocked to return a dict
        # WITHOUT "valid". The combined result is False; the mutant
        # (default True) returns True.
        case = _valid_case()
        mocked_primary = {
            "errors": [],
            "seal_verified": True,
            "trust_map_verified": True,
            "dimensions": {},
            "schema": case.get("schema"),
            "case_sha256": case.get("case_sha256"),
            "note": None,
        }
        with mock.patch(
            "textforensics.casefile.verify_case_file",
            return_value=mocked_primary,
        ):
            result = verify_case_file_combined(case)
        self.assertIs(result["valid"], False)

    def test_mocked_nversion_without_valid_is_invalid(self):
        # No real path leaves "valid" out of the nversion dict, so
        # the .get("valid", False) defaults are killable only via a
        # mock: with a valid primary and an nversion without "valid",
        # the combined result is False; the mutant (default True)
        # returns True.
        case = _valid_case()
        mocked = {
            "errors": [],
            "seal_verified": True,
            "trust_map_verified": True,
            "dimensions": {},
        }
        with mock.patch(
            "textforensics.verify.verify_case_file", return_value=mocked
        ):
            result = verify_case_file_combined(case)
        self.assertIs(result["valid"], False)


class TestLoadPayloadKill(unittest.TestCase):
    """AddNot [550,7] (100-deep payload); ExceptionReplacer
    [544,11] (OSError in _load_case_file_payload)."""

    def test_deep_payload_is_depth_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "deep.json"
            path.write_text(json.dumps(_chain(100)), encoding="utf-8")
            _, error = _load_case_file_payload(path)
        # The mutant short-circuits the depth check to False and
        # returns the payload.
        self.assertEqual(error, "case file exceeds the JSON depth limit")

    def test_missing_file_is_read_error(self):
        _, error = _load_case_file_payload(Path("/tmp/does-not-exist-tf-w3.json"))
        self.assertTrue(error.startswith("cannot read case file"), error)

    def test_directory_is_read_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, error = _load_case_file_payload(Path(tmp))
        self.assertTrue(error.startswith("cannot read case file"), error)


class TestPathCombinedKill(unittest.TestCase):
    """ReplaceFalseWithTrue [509,25]/[510,30] (the _invalid template
    in verify_case_file_path_combined)."""

    def test_missing_file_is_invalid(self):
        result = verify_case_file_path_combined(Path("/tmp/does-not-exist-tf-w3.json"))
        self.assertIs(result["seal_verified"], False)
        self.assertIs(result["trust_map_verified"], False)


class TestVerifyCaseFilePathKill(unittest.TestCase):
    """ReplaceFalseWithTrue [889,33]/[890,38]/[898,25]/[900,33]/
    [901,38]/[904,26] (the two early-return VerificationReports in
    verify_case_file_path)."""

    def test_missing_file_report_is_invalid(self):
        # Load-error path: kills [889,33] (seal_verified) and
        # [890,38] (trust_map_verified); the "valid"/"overall_valid"
        # literals there were already killed by the existing tests.
        report = verify_case_file_path(Path("/tmp/does-not-exist-tf-w3.json"))
        self.assertIs(report.case_file["seal_verified"], False)
        self.assertIs(report.case_file["trust_map_verified"], False)
        self.assertIs(report.overall_valid, False)

    def test_non_dict_file_report_is_invalid(self):
        # Non-dict JSON path: kills [898,25] (valid), [900,33]
        # (seal_verified), [901,38] (trust_map_verified) and
        # [904,26] (overall_valid).
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "list.json"
            path.write_text("[1, 2]", encoding="utf-8")
            report = verify_case_file_path(path)
        self.assertIs(report.case_file["valid"], False)
        self.assertIs(report.case_file["seal_verified"], False)
        self.assertIs(report.case_file["trust_map_verified"], False)
        self.assertIs(report.overall_valid, False)


class TestModuleLevelKill(unittest.TestCase):
    """Module-level MAX_CASE_FILE_BYTES (8 Mul-family +
    NumberReplacer [66,22]/[66,27]/[66,34]) and MAX_JSON_DEPTH
    (NumberReplacer [67,17] occ 6/7, killed by the depth tests)."""

    def test_two_mib_file_reads(self):
        # Every `*`->`+`/`-`/`%`/`|`/`^` mutant at [66,25]/[66,32]
        # shrinks the cap to at most 65,536 bytes (or 0/negative), so
        # a 2 MiB file returns the cap error under the mutant.
        with tempfile.TemporaryDirectory() as tmp:
            path = _padded_json_file(Path(tmp), 2 * 1024 * 1024)
            _, error = _load_case_file_payload(path)
        self.assertIsNone(error)

    def test_exact_cap_file_reads(self):
        # A file of exactly MAX_CASE_FILE_BYTES bytes is read by the
        # original (`>` is strict). Kills: NumberReplacer [66,22]
        # occ 1 (32->31, limit 32,505,856), [66,27] occ 2 and [66,34]
        # occ 4 (1024->1023, limit 33,521,664), and the Gt_GtE
        # [541,33] timeout mutant (`>`->`>=` returns the cap error
        # at exactly the cap).
        with tempfile.TemporaryDirectory() as tmp:
            path = _padded_json_file(Path(tmp), MAX_CASE_FILE_BYTES)
            _, error = _load_case_file_payload(path)
        self.assertIsNone(error)

    def test_one_over_cap_file_is_capped(self):
        # One byte over the cap is rejected by the original. Kills:
        # NumberReplacer [66,22] occ 1 (32->33, limit 34,603,008),
        # [66,27] occ 3 and [66,34] occ 5 (1024->1025, limit
        # 33,587,200) — the mutant reads the file instead.
        with tempfile.TemporaryDirectory() as tmp:
            path = _padded_json_file(Path(tmp), MAX_CASE_FILE_BYTES + 1)
            _, error = _load_case_file_payload(path)
        self.assertTrue(error.startswith("case file exceeds the"), error)
