"""Worker F (W6) — kill tests for the datasets.py phase-1 survivors.

- test_mage_source_id_is_16_hex kills NumberReplacer occ 112 and
  occ 113 ([1570, 59]): ``canonical_text_sha256(text)[:16]`` -> [:15]
  / [:17]. The source_id must be exactly "mage:" + the first 16 hex
  digits of the canonical text hash.
- test_write_sample_cache_accepts_runtime_built_plain_filename kills
  ReplaceComparisonOperator_NotEq_IsNot occ 6 ([2084, 36]):
  ``filename != Path(filename).name`` -> ``filename is not
  Path(filename).name``. The filename is passed as a ``str``
  subclass: pathlib's ``Path(...).name`` always returns a plain
  ``str``, so it can never be identical to the subclass instance,
  and the mutant rejects a valid plain filename with ValueError
  while the original (value comparison) accepts it. (A plain
  ``str`` built with ``"".join`` does NOT reliably kill it:
  ``Path(x).name is x`` for a single-component name depends on
  CPython string-identity internals and flip-flops between
  execution contexts — verified 2026-11-16: the join-built
  filename killed the mutant in a stdin probe but survived under
  pytest in the re-prove. The subclass construction is
  deterministic in every context.)

NOTE: the four other _map_mage survivors (Sub_RShift / Sub_BitXor
on ``1 - int(native)``, NotEq_Lt on ``native != 1``, NotEq_Gt on
``native != 0``) are NOT killable: the guard at line 1554 restricts
native to {0, 1} before any of them is reached, and on {0, 1} the
mutated expressions coincide with the originals. They are
classified domain-equivalent in
audit-w6-f-equiv-reasons-datasets.json.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from textforensics.datasets import (
    NormalizedRow,
    get_spec,
    map_row,
    read_sample_cache,
    write_sample_cache,
)
from textforensics.ledger import canonical_text_sha256


def _row(text, label=0):
    return NormalizedRow(
        text=text,
        label=label,
        dataset="mage",
        config="default",
        split="train",
        source_id="r0",
        regime="raw",
        meta={},
    )


class TestDatasetsW6Killers(unittest.TestCase):
    def test_mage_source_id_is_16_hex(self):
        (row,) = map_row(
            "mage",
            {"text": "m", "label": 0, "src": "cmv_machine_gpt4"},
            "default",
            "train",
        )
        expected = "mage:" + canonical_text_sha256("m")[:16]
        self.assertEqual(row.source_id, expected)
        self.assertEqual(len(row.source_id), len("mage:") + 16)

    def test_write_sample_cache_accepts_runtime_built_plain_filename(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)

            # A str subclass: Path(...).name always returns a plain
            # str, so it can never be identical to this instance.
            # The mutant (identity comparison) rejects it; the
            # original (value comparison) accepts it.
            class PlainName(str):
                pass

            filename = PlainName("other.jsonl")
            path, _manifest = write_sample_cache(
                get_spec("beemo"),
                "default",
                "train",
                [_row("hello world this is a test")],
                cache_dir=root,
                filename=filename,
            )
            self.assertTrue(path.is_file())
            self.assertEqual(path.name, "other.jsonl")

    def test_read_sample_cache_accepts_runtime_built_plain_filename(self):
        # Parent decision on the W4 baseline twin (occ 7): the
        # read_sample_cache NotEq_IsNot entry carried the same wrong
        # justification as the write_sample_cache occ 6 entry (dropped
        # in the W6 refresh) — `Path(x).name is x` is not
        # identity-stable. This test kills it the same way: a str
        # subclass filename is never identical to the plain str
        # returned by Path(...).name, so the mutant (identity
        # comparison) rejects a valid plain filename with ValueError
        # while the original (value comparison) accepts it.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)

            class PlainName(str):
                pass

            filename = PlainName("other.jsonl")
            write_sample_cache(
                get_spec("beemo"),
                "default",
                "train",
                [_row("hello world this is a test")],
                cache_dir=root,
                filename=filename,
            )
            rows = read_sample_cache(
                get_spec("beemo"),
                "default",
                "train",
                cache_dir=root,
                filename=filename,
            )
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0].text, "hello world this is a test")


if __name__ == "__main__":
    unittest.main()
