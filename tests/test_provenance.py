from __future__ import annotations

import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from textforensics.provenance import (
    _canonical_record_payload,
    _verify_ledger_unlocked,
    sha256_bytes,
    snapshot_file,
    verify_ledger,
)


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


class HashingTests(unittest.TestCase):
    def test_sha256_bytes_is_stable(self):
        self.assertEqual(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        self.assertEqual(len(sha256_bytes(b"x")), 64)

    def test_canonical_payload_is_sorted(self):
        payload = _canonical_record_payload({"b": 1, "a": 2})
        self.assertEqual(payload, b'{"a":2,"b":1}')


class LedgerChainTests(unittest.TestCase):
    def test_empty_ledger_is_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            result = verify_ledger(ledger)
            self.assertFalse(result["valid"])
            self.assertIn("ledger_not_found", result["errors"])

    def test_chain_links_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "draft.txt"
            ledger = Path(tmp) / "ledger.jsonl"
            _write(file, "first")
            snapshot_file(file, ledger)
            _write(file, "second")
            snapshot_file(file, ledger)
            result = verify_ledger(ledger)
            self.assertTrue(result["valid"], result["errors"])
            self.assertEqual(result["records"], 2)

    def test_tamper_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "draft.txt"
            ledger = Path(tmp) / "ledger.jsonl"
            _write(file, "first")
            snapshot_file(file, ledger)
            _write(file, "second")
            snapshot_file(file, ledger)

            lines = ledger.read_text(encoding="utf-8").splitlines()
            tampered = lines[0].replace('"file_size": 5', '"file_size": 6')
            ledger.write_text(tampered + "\n" + lines[1] + "\n", encoding="utf-8")
            self.assertFalse(verify_ledger(ledger)["valid"])
            with self.assertRaises(ValueError):
                snapshot_file(file, ledger)

    def test_append_refuses_invalid_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "draft.txt"
            ledger = Path(tmp) / "ledger.jsonl"
            _write(file, "first")
            snapshot_file(file, ledger)
            ledger.write_text("not json\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                snapshot_file(file, ledger)

    def test_invalid_json_lines_are_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            ledger.write_text("not json\n", encoding="utf-8")
            result = verify_ledger(ledger)
            self.assertFalse(result["valid"])
            self.assertTrue(any("invalid_json" in e for e in result["errors"]))

    def test_record_not_object_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            ledger.write_text('["not", "an", "object"]\n', encoding="utf-8")
            result = verify_ledger(ledger)
            self.assertFalse(result["valid"])
            self.assertTrue(any("record_not_object" in e for e in result["errors"]))

    def test_record_hash_mismatch_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "draft.txt"
            ledger = Path(tmp) / "ledger.jsonl"
            _write(file, "first")
            record = snapshot_file(file, ledger)
            tampered = dict(record)
            tampered["file_size"] = 999
            tampered.pop("record_sha256", None)
            ledger.write_text(
                json.dumps(tampered, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            result = verify_ledger(ledger)
            self.assertFalse(result["valid"])
            self.assertTrue(any("record_hash_mismatch" in e for e in result["errors"]))

    def test_chain_mismatch_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "draft.txt"
            ledger = Path(tmp) / "ledger.jsonl"
            _write(file, "first")
            first = snapshot_file(file, ledger)
            _write(file, "second")
            second = snapshot_file(file, ledger)
            # Rewrite the second record with a foreign previous hash.
            broken = dict(second)
            broken["previous_record_sha256"] = "0" * 64
            broken.pop("record_sha256", None)
            ledger.write_text(
                json.dumps(first, sort_keys=True) + "\n"
                + json.dumps(broken, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            result = verify_ledger(ledger)
            self.assertFalse(result["valid"])
            self.assertTrue(any("chain_mismatch" in e for e in result["errors"]))

    def test_concurrent_writers_keep_one_valid_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "draft.txt"
            ledger = Path(tmp) / "ledger.jsonl"
            _write(file, "concurrent snapshot source")

            with ThreadPoolExecutor(max_workers=4) as pool:
                records = list(
                    pool.map(lambda _: snapshot_file(file, ledger), range(8))
                )

            verified = verify_ledger(ledger)
            self.assertTrue(verified["valid"], verified["errors"])
            self.assertEqual(verified["records"], 8)
            self.assertEqual(len(records), 8)
            self.assertTrue(Path(str(ledger) + ".lock").exists())

    def test_ledger_warning_about_local_clock(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "draft.txt"
            ledger = Path(tmp) / "ledger.jsonl"
            _write(file, "first")
            snapshot_file(file, ledger)
            self.assertIn("not an independent trusted timestamp", verify_ledger(ledger)["warning"].lower())

    def test_snapshot_record_has_required_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "draft.txt"
            ledger = Path(tmp) / "ledger.jsonl"
            _write(file, "first")
            record = snapshot_file(file, ledger)
            self.assertEqual(record["schema"], "textforensics-ledger/v1")
            self.assertEqual(record["file_name"], "draft.txt")
            self.assertEqual(record["file_size"], 5)
            self.assertEqual(len(record["file_sha256"]), 64)
            self.assertIsNone(record["previous_record_sha256"])
            self.assertEqual(len(record["record_sha256"]), 64)

    def test_second_record_links_to_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "draft.txt"
            ledger = Path(tmp) / "ledger.jsonl"
            _write(file, "first")
            first = snapshot_file(file, ledger)
            _write(file, "second")
            second = snapshot_file(file, ledger)
            self.assertEqual(second["previous_record_sha256"], first["record_sha256"])

    def test_unlocked_verification_helper(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            self.assertFalse(_verify_ledger_unlocked(ledger)["valid"])


if __name__ == "__main__":
    unittest.main()
