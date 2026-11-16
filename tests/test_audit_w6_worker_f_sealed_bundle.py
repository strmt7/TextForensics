"""Worker F (W6) — kill tests for the sealed_bundle.py phase-1 survivors.

Each test pins exact behaviour at a mutated position: the
distinguishing inputs are chosen so the replacement operator
changes the observable result (or raises).

- test_nested_bundle_parent_dirs_are_created kills
  ReplaceTrueWithFalse occ 5 ([579, 43]):
  `record_target.parent.mkdir(parents=True, ...)` -> parents=False.
  A seal-record path several levels under nonexistent parents
  succeeds originally and raises FileNotFoundError under the mutant.
  (The bundle_target mkdir on line 575 is a different, unmutated
  call — the test must pass a seal_record_path to reach the
  mutated one.)
- test_seal_record_uses_two_space_indent kills NumberReplacer occ 68
  ([586, 44]): `indent=2` -> `indent=3` in the seal-record dumps.
  The seal-record file bytes must carry exactly two-space
  indentation. (The 2 -> 1 twin, occ 69, is killed by the same
  assertions.)
- test_seal_record_keys_are_sorted kills ReplaceTrueWithFalse occ 7
  ([586, 57]): `sort_keys=True` -> False. The seal record is built
  in insertion order (schema, manifest, manifest_sha256, ...) which
  is NOT sorted, so the mutant reorders the file bytes; the test
  pins the sorted top-level key order.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from textforensics.casefile import seal_case_file
from textforensics.report import build_forensic_bundle
from textforensics.sealed_bundle import write_sealed_bundle

TEXT = (
    "The committee met on Tuesday to review the quarterly figures and "
    "discuss the outlook for the coming year. The chair opened the meeting "
    "with a summary of the previous session, and the members agreed to "
    "focus on three items: revenue, staffing, and the maintenance budget. "
    "Revenue grew modestly in the first quarter, driven by new contracts "
    "in the northern region. Staffing remains tight, and the hiring plan "
    "was approved with minor changes. The maintenance budget was reduced "
    "after a review of the supplier quotes. The meeting ended with a plan "
    "to reconvene in four weeks to review progress on each item."
)


def sealed_case():
    bundle = build_forensic_bundle(TEXT).to_dict()
    return seal_case_file(bundle, deterministic=True, fixed_timestamp="1970-01-01T00:00:00+00:00")


class TestSealedBundleW6Killers(unittest.TestCase):
    def test_nested_bundle_parent_dirs_are_created(self):
        with tempfile.TemporaryDirectory() as td:
            case = sealed_case()
            target = Path(td) / "a" / "b" / "c" / "bundle.zip"
            record_path = Path(td) / "x" / "y" / "z" / "seal-record.json"
            self.assertFalse(target.parent.exists())
            self.assertFalse(record_path.parent.exists())
            write_sealed_bundle(case, target, record_path)
            self.assertTrue(target.is_file())
            self.assertTrue(record_path.is_file())

    def test_seal_record_uses_two_space_indent(self):
        with tempfile.TemporaryDirectory() as td:
            case = sealed_case()
            target = Path(td) / "bundle.zip"
            record_path = Path(td) / "seal-record.json"
            write_sealed_bundle(case, target, record_path)
            data = record_path.read_bytes()
            self.assertIn(b'\n  "archive_sha256"', data)
            self.assertNotIn(b'\n   "archive_sha256"', data)
            self.assertNotIn(b'\n "archive_sha256"', data)

    def test_seal_record_keys_are_sorted(self):
        with tempfile.TemporaryDirectory() as td:
            case = sealed_case()
            target = Path(td) / "bundle.zip"
            record_path = Path(td) / "seal-record.json"
            write_sealed_bundle(case, target, record_path)
            data = record_path.read_bytes()
            # Top-level key order only (byte search would catch nested
            # keys — the manifest's own "signature"/"schema" fields —
            # so parse with an order-preserving hook instead).
            pairs = json.loads(data, object_pairs_hook=list)
            keys = [k for k, _ in pairs]
            self.assertEqual(keys, sorted(keys))


if __name__ == "__main__":
    unittest.main()
