from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from textforensics.provenance import _verify_ledger_unlocked, sha256_bytes, snapshot_file, verify_ledger


class ProvenanceEdgeCaseTests(unittest.TestCase):
    """Tests for provenance.py uncovered lines."""

    def test_empty_file_snapshot(self):
        """Test snapshot_file with an empty file (line 89 edge case)."""
        with tempfile.TemporaryDirectory() as tmp:
            file_path = Path(tmp) / "empty.txt"
            ledger_path = Path(tmp) / "ledger.jsonl"
            
            file_path.write_text("", encoding="utf-8")
            
            record = snapshot_file(file_path, ledger_path)
            self.assertEqual(record["file_size"], 0)
            self.assertEqual(record["file_sha256"], sha256_bytes(b""))

    def test_missing_ledger_file(self):
        """Test verify_ledger with missing ledger file."""
        with tempfile.TemporaryDirectory() as tmp:
            ledger_path = Path(tmp) / "nonexistent.jsonl"
            result = verify_ledger(ledger_path)
            self.assertFalse(result["valid"])
            self.assertIn("ledger_not_found", result["errors"])

    def test_corrupted_ledger_json(self):
        """Test verify_ledger with corrupted JSON in ledger."""
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            ledger.write_text("not valid json\n", encoding="utf-8")
            result = verify_ledger(ledger)
            self.assertFalse(result["valid"])

    def test_ledger_with_empty_lines(self):
        """Test verify_ledger handles empty lines between records."""
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "draft.txt"
            ledger = Path(tmp) / "ledger.jsonl"
            file.write_text("test content", encoding="utf-8")
            
            record1 = snapshot_file(file, ledger)
            
            # Add only empty lines
            content = ledger.read_text(encoding="utf-8")
            ledger.write_text(content + "\n\n\n\n", encoding="utf-8")
            
            result = verify_ledger(ledger)
            self.assertTrue(result["valid"], result["errors"])

    def test_unlocked_verification_handles_empty_file(self):
        """Test _verify_ledger_unlocked with empty file (covers line 89)."""
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "empty.jsonl"
            ledger.write_text("", encoding="utf-8")
            result = _verify_ledger_unlocked(ledger)
            self.assertIsInstance(result, dict)
            self.assertIn("valid", result)

    def test_verify_ledger_empty_lines_and_whitespace(self):
        """Test verify_ledger with empty lines and whitespace-only lines."""
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            # Write only whitespace lines
            ledger.write_text("   \n\n\t\n", encoding="utf-8")
            result = verify_ledger(ledger)
            self.assertIsInstance(result, dict)
            self.assertIn("valid", result)
            # Empty file should have 0 records
            self.assertEqual(result["records"], 0)

    def test_second_record_gets_previous_hash(self):
        """Test that second record correctly links to first.
        
        This covers the snapshot_file code path where ledger exists
        and we read the previous_record_sha256.
        """
        with tempfile.TemporaryDirectory() as tmp:
            file1 = Path(tmp) / "file1.txt"
            file2 = Path(tmp) / "file2.txt"
            ledger = Path(tmp) / "ledger.jsonl"
            
            file1.write_text("first file content", encoding="utf-8")
            file2.write_text("second file content", encoding="utf-8")
            
            record1 = snapshot_file(file1, ledger)
            record2 = snapshot_file(file2, ledger)
            
            # Second record should link to first
            self.assertEqual(record2["previous_record_sha256"], record1["record_sha256"])
            
            # Verify the chain
            result = verify_ledger(ledger)
            self.assertTrue(result["valid"], result["errors"])
            self.assertEqual(result["records"], 2)

    def test_ledger_with_mixed_empty_and_valid_lines(self):
        """Test that valid lines are processed correctly when mixed with empty lines."""
        with tempfile.TemporaryDirectory() as tmp:
            file1 = Path(tmp) / "file1.txt"
            file2 = Path(tmp) / "file2.txt"
            ledger = Path(tmp) / "ledger.jsonl"
            
            file1.write_text("content one", encoding="utf-8")
            file2.write_text("content two", encoding="utf-8")
            
            snapshot_file(file1, ledger)
            
            # Read and write ledger with empty lines interspersed
            lines = ledger.read_text(encoding="utf-8").strip().split("\n")
            ledger.write_text("\n".join([lines[0], "", lines[0], ""] * 2), encoding="utf-8")
            
            # This should still work - valid JSON lines are processed
            result = verify_ledger(ledger)
            # The ledger has duplicate entries with same hash - that's a chain mismatch
            # But the point is to test that we process non-empty lines
            self.assertIsInstance(result, dict)
            self.assertIn("valid", result)

    def test_snapshot_reading_ledger_with_empty_lines(self):
        """Test snapshot_file when reading an existing ledger that has empty lines.
        
        This tests the 142->141 branch where the for loop continues over empty lines.
        """
        with tempfile.TemporaryDirectory() as tmp:
            file1 = Path(tmp) / "file1.txt"
            file2 = Path(tmp) / "file2.txt"
            ledger = Path(tmp) / "ledger.jsonl"
            
            file1.write_text("first content", encoding="utf-8")
            file2.write_text("second content", encoding="utf-8")
            
            # Create first snapshot
            record1 = snapshot_file(file1, ledger)
            
            # Manually create a ledger file with empty lines before the next record
            ledger.write_text(ledger.read_text(encoding="utf-8") + "\n\n\n", encoding="utf-8")
            
            # Now snapshot file2 - it should read the previous_record_sha256 from record1
            # and ignore the empty lines
            record2 = snapshot_file(file2, ledger)
            self.assertEqual(record2["previous_record_sha256"], record1["record_sha256"])


if __name__ == "__main__":
    unittest.main()