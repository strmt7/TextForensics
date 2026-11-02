from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from textforensics.bundle import (
    BUNDLE_SCHEMA,
    BundleManifest,
    BundleVerificationResult,
    _canonical_json_bytes,
    _sha256,
    list_bundle,
    pack_bundle,
    verify_bundle,
)


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


def _make_multi_file_dir(tmp_dir: Path) -> Path:
    """Create a directory with multiple files for multi-file bundle testing."""
    subdir = tmp_dir / "case_files"
    subdir.mkdir()

    # Case file
    case = {
        "schema": "textforensics.case-file/v1",
        "tool": {"name": "TextForensics", "version": "0.2.0"},
        "forensic_bundle": {
            "schema": "textforensics.forensic-bundle/v1",
            "content_sha256": "c" * 64,
            "input": {"raw_text_included": False},
            "detector_results": [{"detector_id": "test", "score": 0.5}],
            "detector_failures": [],
            "trust_map": {"overall": "partial", "dimensions": []},
        },
        "raw_text_included": False,
        "case_sha256": "d" * 64,
    }
    (subdir / "case.json").write_text(
        json.dumps(case, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    # Metadata file
    meta = {"version": "1.0", "notes": "test case bundle"}
    (subdir / "metadata.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    # Non-JSON file
    (subdir / "readme.txt").write_text("Test case bundle\n", encoding="utf-8")

    return subdir


class CanonicalizationTests(unittest.TestCase):
    def test_canonical_json_bytes_is_stable(self):
        a = _canonical_json_bytes({"b": 1, "a": 2})
        b = _canonical_json_bytes({"a": 2, "b": 1})
        self.assertEqual(a, b)
        self.assertTrue(a.startswith(b'{"a":'))

    def test_sha256_hex_length(self):
        digest = _sha256(b"hello")
        self.assertEqual(len(digest), 64)


class ManifestDataclassTests(unittest.TestCase):
    def test_manifest_roundtrip(self):
        m = BundleManifest(
            schema=BUNDLE_SCHEMA,
            bundle_filename="test.tar.gz",
            format="tar.gz",
            per_file_digests={"case.json": "abc123"},
            bundle_digest="def456",
        )
        data = m.to_dict()
        m2 = BundleManifest.from_dict(data)
        self.assertEqual(m.bundle_filename, m2.bundle_filename)
        self.assertEqual(m.per_file_digests, m2.per_file_digests)
        self.assertEqual(m.bundle_digest, m2.bundle_digest)

    def test_manifest_canonical_json(self):
        m = BundleManifest(
            bundle_filename="test.zip",
            format="zip",
            per_file_digests={"a.json": "111"},
            bundle_digest="222",
        )
        result = m.to_canonical_json()
        self.assertIsInstance(result, bytes)
        # Should be compact JSON
        self.assertNotIn(b": ", result)
        self.assertNotIn(b", ", result)


class SingleFileBundleTests(unittest.TestCase):
    """Tests for packing a single case file."""

    def test_pack_and_verify_tar_gz(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = _make_case_file(Path(tmp))
            output = Path(tmp) / "bundle.tar.gz"

            manifest = pack_bundle(case, output)
            self.assertTrue(output.exists())
            self.assertTrue((output.parent / "bundle.tar.gz.manifest.json").exists())

            self.assertEqual(manifest.format, "tar.gz")
            self.assertEqual(manifest.bundle_filename, "bundle.tar.gz")
            self.assertIn("case.json", manifest.per_file_digests)
            self.assertEqual(len(manifest.bundle_digest), 64)

            result = verify_bundle(output)
            self.assertTrue(result.valid)
            self.assertEqual(result.per_file_status["case.json"], "ok")
            self.assertTrue(result.bundle_digest_match)

    def test_pack_and_verify_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = _make_case_file(Path(tmp))
            output = Path(tmp) / "bundle.zip"

            manifest = pack_bundle(case, output)
            self.assertTrue(output.exists())

            self.assertEqual(manifest.format, "zip")
            self.assertEqual(manifest.bundle_filename, "bundle.zip")
            self.assertIn("case.json", manifest.per_file_digests)

            result = verify_bundle(output)
            self.assertTrue(result.valid)
            self.assertEqual(result.per_file_status["case.json"], "ok")

    def test_pack_unsupported_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = _make_case_file(Path(tmp))
            output = Path(tmp) / "bundle.bz2"

            with self.assertRaises(ValueError):
                pack_bundle(case, output)

    def test_pack_nonexistent_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "bundle.tar.gz"
            with self.assertRaises(FileNotFoundError):
                pack_bundle(Path(tmp) / "no_such_file.json", output)


class MultiFileBundleTests(unittest.TestCase):
    """Tests for packing directories with multiple files."""

    def test_pack_and_verify_multi_file_tar_gz(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = _make_multi_file_dir(Path(tmp))
            output = Path(tmp) / "multi.tar.gz"

            manifest = pack_bundle(case_dir, output)
            self.assertEqual(manifest.format, "tar.gz")
            self.assertIn("case.json", manifest.per_file_digests)
            self.assertIn("metadata.json", manifest.per_file_digests)
            self.assertIn("readme.txt", manifest.per_file_digests)

            result = verify_bundle(output)
            self.assertTrue(result.valid)
            for f, status in result.per_file_status.items():
                self.assertEqual(status, "ok", f"File {f} should be ok")

    def test_pack_and_verify_multi_file_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = _make_multi_file_dir(Path(tmp))
            output = Path(tmp) / "multi.zip"

            pack_bundle(case_dir, output)
            result = verify_bundle(output)
            self.assertTrue(result.valid)
            self.assertEqual(len(result.per_file_status), 3)


class TamperingTests(unittest.TestCase):
    """Tests for detecting tampered bundles."""

    def test_detect_tampered_archive_tar_gz(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = _make_case_file(Path(tmp))
            output = Path(tmp) / "bundle.tar.gz"

            pack_bundle(case, output)

            # Tamper: flip a byte in the archive
            data = bytearray(output.read_bytes())
            # Flip a byte near the middle
            mid = len(data) // 2
            data[mid] ^= 0xFF
            output.write_bytes(bytes(data))

            result = verify_bundle(output)
            self.assertFalse(result.valid)
            self.assertFalse(result.bundle_digest_match)

    def test_detect_tampered_file_in_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = _make_case_file(Path(tmp))
            output = Path(tmp) / "bundle.zip"

            pack_bundle(case, output)

            # Read original zip contents
            import zipfile

            with zipfile.ZipFile(output, "r") as zf:
                entries = {n: zf.read(n) for n in zf.namelist()}

            # Tamper case.json content
            entries["case.json"] = entries["case.json"][:-2] + b"XX"

            # Re-create zip with tampered content
            with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for n in entries:
                    zf.writestr(n, entries[n])

            result = verify_bundle(output)
            self.assertFalse(result.valid)
            self.assertEqual(result.per_file_status.get("case.json"), "tampered")


class DigestVerificationTests(unittest.TestCase):
    """Tests for expected-digest verification."""

    def test_expected_digest_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = _make_case_file(Path(tmp))
            output = Path(tmp) / "bundle.tar.gz"

            manifest = pack_bundle(case, output)
            result = verify_bundle(output, expected_digest=manifest.bundle_digest)
            self.assertTrue(result.valid)

    def test_expected_digest_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = _make_case_file(Path(tmp))
            output = Path(tmp) / "bundle.tar.gz"

            pack_bundle(case, output)
            wrong = "0" * 64
            result = verify_bundle(output, expected_digest=wrong)
            self.assertFalse(result.valid)


class MissingManifestTests(unittest.TestCase):
    def test_no_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "orphan.tar.gz"
            fake.write_bytes(b"fake")
            result = verify_bundle(fake)
            self.assertFalse(result.valid)
            self.assertTrue(any("manifest" in e.lower() for e in result.errors))

    def test_no_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = verify_bundle(Path(tmp) / "no_such.tar.gz")
            self.assertFalse(result.valid)


class ListBundleTests(unittest.TestCase):
    def test_list_tar_gz(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = _make_case_file(Path(tmp))
            output = Path(tmp) / "bundle.tar.gz"
            pack_bundle(case, output)

            entries = list_bundle(output)
            names = [e["name"] for e in entries]
            self.assertIn("case.json", names)

    def test_list_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = _make_multi_file_dir(Path(tmp))
            output = Path(tmp) / "bundle.zip"
            pack_bundle(case_dir, output)

            entries = list_bundle(output)
            names = [e["name"] for e in entries]
            self.assertIn("case.json", names)
            self.assertIn("metadata.json", names)
            self.assertIn("readme.txt", names)

    def test_list_nonexistent(self):
        with self.assertRaises(FileNotFoundError):
            list_bundle("/nonexistent/bundle.tar.gz")


class ResultDataclassTests(unittest.TestCase):
    def test_result_to_dict(self):
        result = BundleVerificationResult(
            valid=True,
            per_file_status={"case.json": "ok"},
            bundle_digest_match=True,
        )
        d = result.to_dict()
        self.assertTrue(d["valid"])
        self.assertEqual(d["per_file_status"]["case.json"], "ok")


class BundleDeterminismTests(unittest.TestCase):
    """Ensure packing the same files yields the same archive digest."""

    def test_tar_gz_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = _make_case_file(Path(tmp))
            m1 = pack_bundle(case, Path(tmp) / "b1.tar.gz")
            m2 = pack_bundle(case, Path(tmp) / "b2.tar.gz")
            self.assertEqual(m1.bundle_digest, m2.bundle_digest)

    def test_zip_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = _make_case_file(Path(tmp))
            m1 = pack_bundle(case, Path(tmp) / "b1.zip")
            m2 = pack_bundle(case, Path(tmp) / "b2.zip")
            self.assertEqual(m1.bundle_digest, m2.bundle_digest)


class ManifestSchemaTests(unittest.TestCase):
    """Tests for manifest structure validation."""

    def test_manifest_has_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = _make_case_file(Path(tmp))
            m = pack_bundle(case, Path(tmp) / "b.tar.gz")
            self.assertEqual(m.schema, BUNDLE_SCHEMA)

    def test_manifest_file_is_valid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = _make_case_file(Path(tmp))
            output = Path(tmp) / "b.tar.gz"
            pack_bundle(case, output)
            manifest_path = output.with_name("b.tar.gz.manifest.json")
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertIn("per_file_digests", data)
            self.assertIn("bundle_digest", data)
            self.assertIn("format", data)

    def test_manifest_per_file_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = _make_multi_file_dir(Path(tmp))
            m = pack_bundle(case_dir, Path(tmp) / "b.zip")
            self.assertEqual(len(m.per_file_digests), 3)


if __name__ == "__main__":
    unittest.main()
