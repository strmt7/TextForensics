"""Tests for benchmark fingerprinting and contamination prevention."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from textforensics.benchmark_fingerprint import (
    DatasetFingerprint,
    check_disjointness,
    fingerprint_dataset,
    load_fingerprint,
    save_fingerprint,
    validate_disjointness,
    verify_fingerprint,
)

HUMAN_SAMPLE = "I ran this test yesterday. The first result looked odd, " \
               "so I changed one cable, repeated it, and wrote down the result."
AI_SAMPLE = "Furthermore, this robust solution seamlessly unlocks the potential."


def write_test_dataset(
    path: Path,
    human_samples: list[str] | None = None,
    ai_samples: list[str] | None = None,
) -> None:
    """Write a test JSONL dataset."""
    human_samples = human_samples or [HUMAN_SAMPLE]
    ai_samples = ai_samples or [AI_SAMPLE]
    rows = [{"label": "human", "text": h} for h in human_samples]
    rows += [{"label": "ai", "text": a} for a in ai_samples]
    path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )


class DatasetFingerprintTests(unittest.TestCase):
    """Tests for DatasetFingerprint class."""

    def test_fingerprint_creation(self):
        """Test basic fingerprint creation."""
        fp = DatasetFingerprint(
            name="TestDataset",
            version="1.0.0",
            split="test",
            sample_count=10,
            dataset_hash="abc123",
        )
        self.assertEqual(fp.name, "TestDataset")
        self.assertEqual(fp.version, "1.0.0")
        self.assertEqual(fp.split, "test")
        self.assertEqual(fp.sample_count, 10)
        self.assertEqual(fp.dataset_hash, "abc123")

    def test_fingerprint_is_immutable(self):
        """Test that fingerprint dataclass is frozen."""
        fp = DatasetFingerprint(
            name="Test",
            version="1.0",
            split="test",
        )
        with self.assertRaises(AttributeError):
            fp.name = "changed"  # type: ignore

    def test_fingerprint_to_dict(self):
        """Test serialization to dictionary."""
        fp = DatasetFingerprint(
            name="TestDataset",
            version="1.0.0",
            split="test",
            sample_count=5,
        )
        d = fp.to_dict()
        self.assertEqual(d["name"], "TestDataset")
        self.assertEqual(d["schema"], "textforensics.dataset-fingerprint/v1")
        self.assertIn("created_at", d)

    def test_fingerprint_from_dict(self):
        """Test deserialization from dictionary."""
        data = {
            "name": "TestDataset",
            "version": "2.0.0",
            "split": "evaluation",
            "filters": {"language": "en"},
            "sample_count": 100,
            "content_hashes": ["hash1", "hash2"],
            "dataset_hash": "abcd1234",
            "created_at": "2024-01-01T00:00:00Z",
        }
        fp = DatasetFingerprint.from_dict(data)
        self.assertEqual(fp.name, "TestDataset")
        self.assertEqual(fp.filters, {"language": "en"})
        self.assertEqual(len(fp.content_hashes), 2)

    def test_fingerprint_missing_required_field(self):
        """Test that deserialization fails without required fields."""
        data = {"name": "Test"}  # Missing version, split, dataset_hash
        with self.assertRaises(ValueError):
            DatasetFingerprint.from_dict(data)


class FingerprintDatasetTests(unittest.TestCase):
    """Tests for fingerprint_dataset function."""

    def test_create_fingerprint(self):
        """Test creating a fingerprint from a dataset."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.jsonl"
            write_test_dataset(path)

            fp = fingerprint_dataset(
                path,
                name="TestDataset",
                version="1.0.0",
                split="test",
            )

            self.assertEqual(fp.name, "TestDataset")
            self.assertEqual(fp.version, "1.0.0")
            self.assertEqual(fp.split, "test")
            self.assertEqual(fp.sample_count, 2)  # 1 human + 1 AI sample
            self.assertEqual(len(fp.content_hashes), 2)
            self.assertEqual(len(fp.dataset_hash), 64)

    def test_fingerprint_with_filters(self):
        """Test fingerprint with applied filters."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.jsonl"
            write_test_dataset(path)

            fp = fingerprint_dataset(
                path,
                name="TestDataset",
                version="1.0.0",
                split="test",
                filters={"max_length": 1000, "language": "en"},
            )

            self.assertEqual(fp.filters, {"max_length": 1000, "language": "en"})

    def test_fingerprint_nonexistent_file(self):
        """Test that fingerprint fails on nonexistent file."""
        with self.assertRaises(FileNotFoundError):
            fingerprint_dataset("/nonexistent/file.jsonl", name="Test")

    def test_fingerprint_stable(self):
        """Test that fingerprint is stable across calls."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.jsonl"
            write_test_dataset(path)

            fp1 = fingerprint_dataset(path, name="Test", version="1.0")
            fp2 = fingerprint_dataset(path, name="Test", version="1.0")

            self.assertEqual(fp1.dataset_hash, fp2.dataset_hash)
            self.assertEqual(fp1.content_hashes, fp2.content_hashes)


class VerifyFingerprintTests(unittest.TestCase):
    """Tests for verify_fingerprint function."""

    def test_verify_valid_fingerprint(self):
        """Test verification of a valid fingerprint."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.jsonl"
            write_test_dataset(path)

            fp = fingerprint_dataset(path, name="Test", version="1.0")
            result = verify_fingerprint(path, fp)

            self.assertTrue(result["valid"])
            self.assertEqual(result["errors"], [])

    def test_verify_modified_dataset(self):
        """Test that modified dataset fails verification."""
        with tempfile.TemporaryDirectory() as tmp:
            # Create original file
            original_path = Path(tmp) / "original.jsonl"
            write_test_dataset(original_path)

            # Create fingerprint from original
            fp = fingerprint_dataset(
                original_path,
                name="Test",
                version="1.0",
            )

            # Now modify the same file
            modified_content = json.dumps({"label": "human", "text": "completely different content"})
            original_path.write_text(modified_content + "\n", encoding="utf-8")

            result = verify_fingerprint(original_path, fp)

            self.assertFalse(result["valid"])
            self.assertIn("hash mismatch", result["errors"][0].lower())

    def test_verify_nonexistent_file(self):
        """Test verification of nonexistent file."""
        fp = DatasetFingerprint(
            name="Test",
            version="1.0",
            split="test",
            dataset_hash="abc123",
        )

        result = verify_fingerprint("/nonexistent/file.jsonl", fp)

        self.assertFalse(result["valid"])
        self.assertIn("not found", result["errors"][0].lower())

    def test_verify_sample_count_mismatch(self):
        """Test detection of sample count mismatch."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.jsonl"
            write_test_dataset(path, human_samples=[HUMAN_SAMPLE, HUMAN_SAMPLE])
            # Original has 2 human samples, fingerprint expects 1

            fp = DatasetFingerprint(
                name="Test",
                version="1.0",
                split="test",
                sample_count=1,
                dataset_hash="dummy",  # Wrong hash too
            )

            result = verify_fingerprint(path, fp)

            self.assertFalse(result["valid"])


class CheckDisjointnessTests(unittest.TestCase):
    """Tests for check_disjointness function."""

    def test_disjoint_datasets(self):
        """Test that disjoint datasets are correctly identified."""
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "calibration.jsonl"
            eval_path = Path(tmp) / "evaluation.jsonl"

            write_test_dataset(
                cal_path,
                human_samples=["I tested device A"],
                ai_samples=["AI text A"],
            )
            write_test_dataset(
                eval_path,
                human_samples=["I tested device B"],
                ai_samples=["AI text B"],
            )

            cal_fp = fingerprint_dataset(cal_path, name="Test", version="1.0", split="calibration")
            eval_fp = fingerprint_dataset(eval_path, name="Test", version="1.0", split="evaluation")

            result = check_disjointness(cal_path, cal_fp, eval_path, eval_fp)

            self.assertTrue(result["disjoint"])
            self.assertEqual(result["shared_samples"], 0)

    def test_overlapping_datasets(self):
        """Test detection of overlapping samples."""
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "calibration.jsonl"
            eval_path = Path(tmp) / "evaluation.jsonl"

            # Same samples in both
            sample = "I tested device one and it failed"
            write_test_dataset(cal_path, human_samples=[sample])
            write_test_dataset(eval_path, human_samples=[sample])

            cal_fp = fingerprint_dataset(cal_path, name="Test", version="1.0", split="calibration")
            eval_fp = fingerprint_dataset(eval_path, name="Test", version="1.0", split="evaluation")

            result = check_disjointness(cal_path, cal_fp, eval_path, eval_fp)

            self.assertFalse(result["disjoint"])
            self.assertGreater(result["shared_samples"], 0)

    def test_validate_disjointness_raises_on_overlap(self):
        """Test that validate_disjointness raises ValueError on overlap."""
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "calibration.jsonl"
            eval_path = Path(tmp) / "evaluation.jsonl"

            sample = "I tested device one and it failed"
            write_test_dataset(cal_path, human_samples=[sample])
            write_test_dataset(eval_path, human_samples=[sample])

            cal_fp = fingerprint_dataset(cal_path, name="Test", version="1.0", split="calibration")
            eval_fp = fingerprint_dataset(eval_path, name="Test", version="1.0", split="evaluation")

            with self.assertRaises(ValueError) as ctx:
                validate_disjointness(cal_path, cal_fp, eval_path, eval_fp)

            self.assertIn("contamination", str(ctx.exception).lower())


class FingerprintSerializationTests(unittest.TestCase):
    """Tests for fingerprint save/load operations."""

    def test_save_and_load_fingerprint(self):
        """Test saving and loading a fingerprint."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.jsonl"
            write_test_dataset(path)

            original_fp = fingerprint_dataset(path, name="Test", version="1.0")

            save_path = Path(tmp) / "fingerprint.json"
            load_path = save_fingerprint(original_fp, save_path)

            self.assertEqual(load_path, save_path)
            self.assertTrue(save_path.exists())

            loaded_fp = load_fingerprint(save_path)

            self.assertEqual(original_fp.name, loaded_fp.name)
            self.assertEqual(original_fp.version, loaded_fp.version)
            self.assertEqual(original_fp.dataset_hash, loaded_fp.dataset_hash)
            self.assertEqual(original_fp.content_hashes, loaded_fp.content_hashes)


class ContaminationDetectionTests(unittest.TestCase):
    """Tests for contamination detection scenarios."""

    def test_identical_files_detected_as_contaminated(self):
        """Test that identical files are flagged as contaminated."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "shared.jsonl"
            write_test_dataset(path)

            fp = fingerprint_dataset(path, name="Test", version="1.0")

            # Same file for both
            result = check_disjointness(path, fp, path, fp)

            self.assertFalse(result["disjoint"])

    def test_filters_in_fingerprint(self):
        """Test that filters are included in fingerprint."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.jsonl"
            write_test_dataset(path)

            filters = {"language": "en", "min_length": 50, "domains": ["news", "blogs"]}
            fp = fingerprint_dataset(
                path,
                name="TestDataset",
                version="1.0.0",
                split="test",
                filters=filters,
            )

            self.assertEqual(fp.filters, filters)


if __name__ == "__main__":
    unittest.main()
