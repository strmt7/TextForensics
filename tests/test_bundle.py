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


class DecompressionCapTests(unittest.TestCase):
    """A crafted archive must never exhaust memory (zip/tar bomb)."""

    BOMB_BYTES = 11 * 1024 * 1024  # just over the 10 MiB per-file cap

    def _write_manifest(self, tmp: Path, archive: Path, fmt: str, digest: str) -> None:
        from datetime import datetime

        from textforensics.bundle import BundleManifest

        manifest = BundleManifest(
            schema=BUNDLE_SCHEMA,
            created_at=datetime.now().isoformat(),
            bundle_filename=archive.name,
            format=fmt,
            per_file_digests={"bomb.bin": digest},
            bundle_digest=_sha256(archive.read_bytes()),
        )
        manifest_path = archive.with_name(archive.name + ".manifest.json")
        manifest_path.write_text(
            json.dumps(manifest.to_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    def test_zip_bomb_rejected_by_verify(self):
        import zipfile

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            content = b"\x00" * self.BOMB_BYTES  # compresses to ~10 KB
            archive = tmp_path / "bundle.zip"
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("bomb.bin", content)
            self._write_manifest(tmp_path, archive, "zip", _sha256(content))

            result = verify_bundle(archive)
            self.assertFalse(result.valid)
            self.assertTrue(any("exceeds" in e for e in result.errors))

    def test_zip_bomb_rejected_by_list(self):
        import zipfile

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            archive = tmp_path / "bundle.zip"
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("bomb.bin", b"\x00" * self.BOMB_BYTES)
            with self.assertRaises(ValueError):
                list_bundle(archive)

    def test_tar_gz_bomb_rejected_by_verify(self):
        import io
        import tarfile

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            content = b"\x00" * self.BOMB_BYTES
            archive = tmp_path / "bundle.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                info = tarfile.TarInfo(name="bomb.bin")
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
            self._write_manifest(tmp_path, archive, "tar.gz", _sha256(content))

            result = verify_bundle(archive)
            self.assertFalse(result.valid)
            self.assertTrue(any("exceeds" in e for e in result.errors))


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


class LegacyEmptyManifestTests(unittest.TestCase):
    """C18: the legacy bundle verifier must validate the manifest
    contract first and open/validate the container regardless of
    file-map emptiness.  A legitimately empty bundle is NOT a
    supported artifact (the packer refuses to create one), so an
    empty per-file map is malformed — and arbitrary bytes are never
    a bundle, even with a matching self-declared digest."""

    def _write(self, tmp: Path, name: str, archive_bytes: bytes, manifest: dict) -> Path:
        archive = tmp / name
        archive.write_bytes(archive_bytes)
        (tmp / (name + ".manifest.json")).write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        return archive

    def _manifest(self, archive: Path, *, fmt="zip", schema=BUNDLE_SCHEMA,
                  per_file=None, digest=None, bundle_digest=None):
        return {
            "schema": schema,
            "created_at": "2026-01-01T00:00:00+00:00",
            "bundle_filename": archive.name,
            "format": fmt,
            "per_file_digests": {} if per_file is None else per_file,
            "bundle_digest": _sha256(archive.read_bytes()) if bundle_digest is None else bundle_digest,
        }

    def test_non_archive_with_empty_manifest_rejected(self):
        # The audit repro: plain non-ZIP bytes, matching self-declared
        # digest, wrong manifest schema, unsupported format, empty map.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            raw = b"this is not a zip archive at all, just plain bytes"
            archive = tmp_path / "b.zip"
            manifest = self._manifest(
                archive, fmt="unsupported-format", schema="wrong-schema",
                per_file={}, bundle_digest=_sha256(raw),
            )
            archive.write_bytes(raw)
            (tmp_path / "b.zip.manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            result = verify_bundle(archive)
            self.assertFalse(result.valid, result.errors)
            self.assertTrue(result.errors)

    def test_empty_file_map_rejected_for_real_archive(self):
        import zipfile

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            archive = tmp_path / "b.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("case.json", b"{}")
            manifest = self._manifest(archive, per_file={})
            (tmp_path / "b.zip.manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            result = verify_bundle(archive)
            self.assertFalse(result.valid, result.errors)

    def test_wrong_manifest_schema_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = _make_case_file(Path(tmp))
            output = Path(tmp) / "b.zip"
            pack_bundle(case, output)
            manifest_path = Path(tmp) / "b.zip.manifest.json"
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            data["schema"] = "wrong-schema"
            manifest_path.write_text(json.dumps(data), encoding="utf-8")
            result = verify_bundle(output)
            self.assertFalse(result.valid, result.errors)

    def test_unsupported_format_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = _make_case_file(Path(tmp))
            output = Path(tmp) / "b.zip"
            pack_bundle(case, output)
            manifest_path = Path(tmp) / "b.zip.manifest.json"
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            data["format"] = "rar"
            manifest_path.write_text(json.dumps(data), encoding="utf-8")
            result = verify_bundle(output)
            self.assertFalse(result.valid, result.errors)

    def test_wrong_shaped_manifest_rejected(self):
        for bad in (None, "x", [1], 42, {"schema": BUNDLE_SCHEMA}):
            with self.subTest(manifest=bad):
                with tempfile.TemporaryDirectory() as tmp:
                    tmp_path = Path(tmp)
                    archive = tmp_path / "b.zip"
                    import zipfile

                    with zipfile.ZipFile(archive, "w") as zf:
                        zf.writestr("case.json", b"{}")
                    (tmp_path / "b.zip.manifest.json").write_text(
                        json.dumps(bad), encoding="utf-8"
                    )
                    result = verify_bundle(archive)
                    self.assertFalse(result.valid, result.errors)

    def test_non_dict_file_map_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = _make_case_file(Path(tmp))
            output = Path(tmp) / "b.zip"
            pack_bundle(case, output)
            manifest_path = Path(tmp) / "b.zip.manifest.json"
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            data["per_file_digests"] = ["case.json"]
            manifest_path.write_text(json.dumps(data), encoding="utf-8")
            result = verify_bundle(output)
            self.assertFalse(result.valid, result.errors)

    def test_extra_member_rejected(self):
        import zipfile

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = _make_case_file(tmp_path)
            output = tmp_path / "b.zip"
            pack_bundle(case, output)
            # Add an unlisted member without touching the manifest.
            with zipfile.ZipFile(output, "a") as zf:
                zf.writestr("extra.txt", b"unlisted")
            manifest_path = tmp_path / "b.zip.manifest.json"
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            data["bundle_digest"] = _sha256(output.read_bytes())
            manifest_path.write_text(json.dumps(data), encoding="utf-8")
            result = verify_bundle(output)
            self.assertFalse(result.valid, result.errors)

    def test_duplicate_member_rejected(self):
        import zipfile

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = _make_case_file(tmp_path)
            output = tmp_path / "b.zip"
            pack_bundle(case, output)
            with zipfile.ZipFile(output) as zf:
                original = zf.read("case.json")
            # A duplicate with IDENTICAL content: every per-file digest
            # still matches, so only duplicate-member rejection can
            # catch it.
            import warnings

            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)  # deliberate duplicate
                with zipfile.ZipFile(output, "a") as zf:
                    zf.writestr("case.json", original)
            manifest_path = tmp_path / "b.zip.manifest.json"
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            data["bundle_digest"] = _sha256(output.read_bytes())
            manifest_path.write_text(json.dumps(data), encoding="utf-8")
            result = verify_bundle(output)
            self.assertFalse(result.valid, result.errors)

    def test_missing_member_rejected(self):
        import zipfile

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = _make_case_file(tmp_path)
            output = tmp_path / "b.zip"
            manifest = pack_bundle(case, output)
            # Rebuild the archive without case.json; manifest unchanged
            # except the archive digest.
            with zipfile.ZipFile(output, "w") as zf:
                zf.writestr("other.txt", b"x")
            manifest_path = tmp_path / "b.zip.manifest.json"
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            data["bundle_digest"] = _sha256(output.read_bytes())
            manifest_path.write_text(json.dumps(data), encoding="utf-8")
            result = verify_bundle(output)
            self.assertFalse(result.valid, result.errors)

    def test_non_archive_bytes_with_valid_manifest_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            raw = b"not an archive"
            archive = tmp_path / "b.zip"
            manifest = self._manifest(archive, per_file={}, bundle_digest=_sha256(raw))
            archive.write_bytes(raw)
            (tmp_path / "b.zip.manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            result = verify_bundle(archive)
            self.assertFalse(result.valid, result.errors)

    def test_malformed_manifest_json_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            archive = tmp_path / "b.zip"
            import zipfile

            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("case.json", b"{}")
            (tmp_path / "b.zip.manifest.json").write_text("{not json", encoding="utf-8")
            result = verify_bundle(archive)
            self.assertFalse(result.valid, result.errors)


if __name__ == "__main__":
    unittest.main()
