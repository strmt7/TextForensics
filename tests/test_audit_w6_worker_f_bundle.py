"""Worker F (W6) — kill tests for the bundle.py phase-1 survivors.

Each test pins exact behaviour at a mutated position: the
distinguishing inputs are chosen so the replacement operator
changes the observable result (or raises).

- test_nan_json_falls_back_to_raw_hash kills ExceptionReplacer occ 1
  ([252, 42]): `except (json.JSONDecodeError, ValueError)` ->
  `except (json.JSONDecodeError, CosmicRayTestingException)`. A .json
  file that parses but holds NaN makes _canonical_json_bytes raise
  ValueError (allow_nan=False); the original falls back to the raw
  hash, the mutant lets the ValueError escape pack_bundle.
- test_manifest_uses_two_space_indent kills NumberReplacer occ 50
  (indent 2 -> 3) and occ 51 (indent 2 -> 1) at [279, 47]: the
  manifest bytes must carry exactly two-space indentation.
- test_manifest_keeps_non_ascii_filename_raw kills
  ReplaceFalseWithTrue occ 3 ([279, 63]): ensure_ascii False ->
  True. A non-ASCII bundle filename must appear raw (UTF-8) in the
  manifest bytes, not as a \\uXXXX escape.

The ExceptionReplacer occ 0 mutant ([252, 20], json.JSONDecodeError)
is INCOMPETENT: cosmic-ray's operator crashes on the dotted name
(AttributeError: 'PythonNode' object has no attribute 'value'), so
no mutant exists to kill; it stays out of the baseline.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from textforensics.bundle import _sha256, pack_bundle


def _make_case_file(tmp_dir: Path) -> Path:
    """Create a minimal valid case file JSON for testing."""
    case = {
        "schema": "textforensics.case-file/v1",
        "tool": {"name": "TextForensics", "version": "0.2.0"},
        "forensic_bundle": {
            "schema": "textforensics.forensic-bundle/v1",
            "content_sha256": "a" * 64,
            "input": {"raw_text_included": False},
            "detector_results": [],
            "detector_failures": [],
            "trust_map": {"overall": "partial", "dimensions": []},
        },
        "raw_text_included": False,
        "case_sha256": "b" * 64,
    }
    path = tmp_dir / "case.json"
    path.write_text(json.dumps(case, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


class TestBundleW6Killers(unittest.TestCase):
    def test_nan_json_falls_back_to_raw_hash(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            case_dir = tmp / "case_files"
            case_dir.mkdir()
            # Parses as JSON (Python's json accepts NaN by default) but
            # _canonical_json_bytes rejects it (allow_nan=False), so the
            # original falls back to the raw-bytes hash.
            raw = b'{"x": NaN}\n'
            (case_dir / "data.json").write_bytes(raw)
            output = tmp / "b.tar.gz"
            manifest = pack_bundle(case_dir, output)
            self.assertEqual(manifest.per_file_digests["data.json"], _sha256(raw))

    def test_manifest_uses_two_space_indent(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            case = _make_case_file(tmp)
            output = tmp / "b.tar.gz"
            pack_bundle(case, output)
            data = (tmp / "b.tar.gz.manifest.json").read_bytes()
            self.assertIn(b'\n  "schema"', data)
            self.assertNotIn(b'\n   "schema"', data)
            self.assertNotIn(b'\n "schema"', data)

    def test_manifest_keeps_non_ascii_filename_raw(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            case = _make_case_file(tmp)
            output = tmp / "b\xfcndle.tar.gz"
            pack_bundle(case, output)
            data = (tmp / "b\xfcndle.tar.gz.manifest.json").read_bytes()
            self.assertIn("b\xfcndle".encode(), data)
            self.assertNotIn(b"\\u00fc", data)


if __name__ == "__main__":
    unittest.main()
