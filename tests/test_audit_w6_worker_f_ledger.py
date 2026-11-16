"""Worker F (W6) — kill tests for the ledger.py phase-1 survivors.

Each test pins exact behaviour at a mutated position: the
distinguishing inputs are chosen so the replacement operator
changes the observable result (or raises).

- test_save_ledger_creates_nested_parent_dirs kills
  ReplaceTrueWithFalse occ 24 ([1004, 32]):
  `output.parent.mkdir(parents=True, ...)` -> parents=False.
- test_save_graph_creates_nested_parent_dirs kills
  ReplaceTrueWithFalse occ 34 ([1519, 32]):
  `target.parent.mkdir(parents=True, ...)` -> parents=False.
- test_save_to_file_creates_nested_parent_dirs kills
  ReplaceTrueWithFalse occ 38 ([2027, 34]):
  `path.parent.mkdir(parents=True, ...)` -> parents=False.
- test_save_graph_keeps_non_ascii_metadata_raw kills
  ReplaceFalseWithTrue occ 22 ([1522, 59]):
  `ensure_ascii=False` -> True. Node metadata is dumped raw, so a
  non-ASCII metadata value must appear as UTF-8, not ``\\uXXXX``.
- test_save_graph_uses_two_space_indent kills NumberReplacer occ 90
  and occ 91 ([1522, 43]): `indent=2` -> 3 / 1.
- test_save_to_file_uses_two_space_indent kills NumberReplacer
  occ 118 and occ 119 ([2030, 47]): `indent=2` -> 3 / 1.

NOTE: the `ensure_ascii=False` in ``CalibrationChain.save_to_file``
([2030, 63], occ 29) is NOT killable: ``to_dict`` returns only
64-hex digests and an int, and ``append`` rejects anything that is
not a 64-character hex digest, so the flag can never change the
bytes. It is classified runtime-equivalent (unobservable-value)
in audit-w6-f-equiv-reasons-ledger.json.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from textforensics.ledger import (
    CalibrationChain,
    DecisionLedger,
    ProvenanceGraph,
    save_graph,
    save_ledger,
)

TEXT = "The committee met on Tuesday to review the quarterly figures."


def _ledger_records():
    ledger = DecisionLedger()
    ledger.record(
        TEXT,
        SimpleNamespace(
            detector_id="d",
            detector_version="1",
            verdict="ai",
            score=0.5,
            runtime_ms=1.0,
        ),
    )
    return list(ledger._records)


class TestLedgerW6Killers(unittest.TestCase):
    def test_save_ledger_creates_nested_parent_dirs(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "a" / "b" / "c" / "ledger.jsonl"
            self.assertFalse(target.parent.exists())
            save_ledger(_ledger_records(), target)
            self.assertTrue(target.is_file())

    def test_save_graph_creates_nested_parent_dirs(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "a" / "b" / "c" / "graph.json"
            self.assertFalse(target.parent.exists())
            save_graph(ProvenanceGraph(), target)
            self.assertTrue(target.is_file())

    def test_save_to_file_creates_nested_parent_dirs(self):
        with tempfile.TemporaryDirectory() as td:
            chain = CalibrationChain()
            chain.append("a" * 64)
            target = Path(td) / "a" / "b" / "c" / "chain.json"
            self.assertFalse(target.parent.exists())
            chain.save_to_file(target)
            self.assertTrue(target.is_file())

    def test_save_graph_keeps_non_ascii_metadata_raw(self):
        with tempfile.TemporaryDirectory() as td:
            graph = ProvenanceGraph()
            graph.add_node(
                "evidence",
                "content",
                "op",
                metadata={"note": "bündle"},
            )
            target = Path(td) / "graph.json"
            save_graph(graph, target)
            data = target.read_bytes()
            self.assertIn("bündle".encode(), data)
            self.assertNotIn(b"\\u00fc", data)

    def test_save_graph_uses_two_space_indent(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "graph.json"
            save_graph(ProvenanceGraph(), target)
            data = target.read_bytes()
            self.assertIn(b'\n  "nodes"', data)
            self.assertNotIn(b'\n   "nodes"', data)
            self.assertNotIn(b'\n "nodes"', data)

    def test_save_to_file_uses_two_space_indent(self):
        with tempfile.TemporaryDirectory() as td:
            chain = CalibrationChain()
            chain.append("a" * 64)
            target = Path(td) / "chain.json"
            chain.save_to_file(target)
            data = target.read_bytes()
            self.assertIn(b'\n  "chain"', data)
            self.assertNotIn(b'\n   "chain"', data)
            self.assertNotIn(b'\n "chain"', data)


if __name__ == "__main__":
    unittest.main()
