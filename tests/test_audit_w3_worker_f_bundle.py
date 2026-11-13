"""W3 Worker F (recovery F3) — kill tests for the bundle proof survivors.

Every test names the mutant(s) it kills (position + operator + occurrence
from the audit-w3-f2-proof-bundle run). The 51 annotation survivors need
no test (postponed-evaluation `|` entries, §6); the 11 domain-equivalent
runtime survivors are recorded in §6 with source-verified reasons.
Re-proved mutant by mutant with cosmic-ray mutate_code in the scratch
worktree (audit-w3-f3-reprove-bundle.py).
"""

import io
import json
import tarfile
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

from textforensics.bundle import (
    BUNDLE_SCHEMA,
    MAX_BUNDLE_COMPRESSED_BYTES,
    MAX_BUNDLE_FILE_BYTES,
    MAX_MANIFEST_BYTES,
    _list_archive_members,
    _sha256,
    _validate_manifest_contract,
    verify_bundle,
)

ZERO_10M = b"\x00" * MAX_BUNDLE_FILE_BYTES


def _manifest(archive, *, fmt="zip", per_file, archive_bytes=None, bundle_digest=None, **overrides):
    if bundle_digest is None:
        assert archive_bytes is not None, "pass archive_bytes or bundle_digest"
        bundle_digest = _sha256(archive_bytes)
    data = {
        "schema": BUNDLE_SCHEMA,
        "created_at": "2026-01-01T00:00:00+00:00",
        "bundle_filename": archive.name,
        "format": fmt,
        "per_file_digests": per_file,
        "bundle_digest": bundle_digest,
    }
    data.update(overrides)
    return data


def _write(tmp, name, archive_bytes, manifest):
    archive = tmp / name
    archive.write_bytes(archive_bytes)
    (tmp / (name + ".manifest.json")).write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return archive


def _zip_bytes(files):
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)  # deliberate duplicates
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, data in files:
                zf.writestr(name, data)
    return buf.getvalue()


def _tar_bytes(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in files:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class HexDigestTests(unittest.TestCase):
    """ReplaceComparisonOperator_Eq_GtE / Eq_LtE [281,46] occ 2
    (`len(value) == 64` in _is_hex_digest)."""

    def test_digest_63_and_65_chars_rejected(self):
        for length in (63, 65):
            with self.subTest(length=length):
                manifest = {
                    "schema": BUNDLE_SCHEMA,
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "bundle_filename": "b.zip",
                    "format": "zip",
                    "per_file_digests": {"a.bin": "a" * length},
                    "bundle_digest": "b" * 64,
                }
                _, errors = _validate_manifest_contract(manifest)
                self.assertIn(
                    "Manifest digest for 'a.bin' is not a 64-character hex digest",
                    errors,
                )


class ManifestContractTests(unittest.TestCase):
    """ReplaceComparisonOperator_NotEq_Gt [301,35] occ 0 (schema) and
    ReplaceOrWithAnd [305,65] / [309,60] / [318,41] occ 1/2/3 (the
    `not isinstance(...) or not ...` guards)."""

    def _base(self, **overrides):
        data = {
            "schema": BUNDLE_SCHEMA,
            "created_at": "2026-01-01T00:00:00+00:00",
            "bundle_filename": "b.zip",
            "format": "zip",
            "per_file_digests": {"a.bin": "a" * 64},
            "bundle_digest": "b" * 64,
        }
        data.update(overrides)
        return data

    def test_schema_lexicographically_less_rejected(self):
        # "a" < BUNDLE_SCHEMA ("textforensics.bundle-manifest/v1"): the
        # original != rejects it; the > mutant accepts it.
        _, errors = _validate_manifest_contract(self._base(schema="a"))
        self.assertIn(f"Manifest schema is not {BUNDLE_SCHEMA}: 'a'", errors)

    def test_bundle_filename_non_string_rejected(self):
        # Exactly one disjunct true: not a str, but truthy — the `and`
        # mutant accepts it.
        _, errors = _validate_manifest_contract(self._base(bundle_filename=123))
        self.assertIn("Manifest bundle_filename is missing or not a string", errors)

    def test_created_at_non_string_rejected(self):
        _, errors = _validate_manifest_contract(self._base(created_at=123))
        self.assertIn("Manifest created_at is missing or not a string", errors)

    def test_per_file_name_non_string_rejected(self):
        # A JSON manifest cannot carry an int key, so call the contract
        # directly with the dict.
        _, errors = _validate_manifest_contract(self._base(per_file_digests={123: "a" * 64}))
        self.assertIn(
            "Manifest per_file_digests has a non-string or empty file name",
            errors,
        )


class ListArchiveMembersTests(unittest.TestCase):
    """ReplaceComparisonOperator_Eq_LtE [345,15] / [348,17] (fmt ==),
    ExceptionReplacer [353,50] / [353,60] / [353,69] (EOFError /
    OSError / ValueError), ZeroIterationForLoop [358,16] / [366,16],
    ReplaceBinaryOperator_Add_* [372,65] occ 3 (the duplicates message)."""

    def test_format_just_below_tar_gz_unsupported(self):
        # "tar.ga" <= "tar.gz" but != "tar.gz": the <= mutant tries to
        # open it as tar.gz instead of returning "Unsupported format".
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "b.tar.gz"
            archive.write_bytes(_tar_bytes([("a.bin", b"x")]))
            members, error = _list_archive_members(archive, "tar.ga")
            self.assertIsNone(members)
            self.assertEqual(error, "Unsupported format: tar.ga")

    def test_format_just_below_zip_unsupported(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "b.zip"
            archive.write_bytes(_zip_bytes([("a.bin", b"x")]))
            members, error = _list_archive_members(archive, "y")
            self.assertIsNone(members)
            self.assertEqual(error, "Unsupported format: y")

    def test_format_above_zip_unsupported(self):
        # "zz" > "zip": the >= mutant on `fmt == "zip"` takes the zip
        # branch and tries to open the tar.gz file as a zip (BadZipFile
        # -> "not a readable zip archive") instead of returning
        # "Unsupported format". Kills ReplaceComparisonOperator_Eq_GtE
        # [348,17] occ 4 (a timeout-kill re-proved as a survivor).
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "b.tar.gz"
            archive.write_bytes(_tar_bytes([("a.bin", b"x")]))
            members, error = _list_archive_members(archive, "zz")
            self.assertIsNone(members)
            self.assertEqual(error, "Unsupported format: zz")

    def test_truncated_gzip_is_eof_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = _tar_bytes([("a.bin", b"hello")])
            archive = Path(tmp) / "t.tar.gz"
            archive.write_bytes(raw[: len(raw) // 2])
            members, error = _list_archive_members(archive, "tar.gz")
            self.assertIsNone(members)
            self.assertTrue(
                error.startswith("Bundle is not a readable tar.gz archive: "),
                error,
            )

    def test_directory_is_os_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            members, error = _list_archive_members(Path(tmp), "tar.gz")
            self.assertIsNone(members)
            self.assertTrue(
                error.startswith("Bundle is not a readable tar.gz archive: "),
                error,
            )

    def test_invalid_utf8_zip_filename_is_value_error(self):
        # A zip member name with invalid UTF-8 bytes and the UTF-8 flag
        # set raises UnicodeDecodeError (a ValueError subclass) inside
        # infolist(); the ValueError handler must convert it to an
        # error, not let it propagate.
        with tempfile.TemporaryDirectory() as tmp:
            raw = bytearray(_zip_bytes([("x.bin", b"hello")]))
            lh = raw.find(b"PK\x03\x04")
            raw[lh + 7] |= 0x08  # UTF-8 flag bit
            raw[lh + 30] = 0xFF  # invalid UTF-8 lead byte
            cd = raw.find(b"PK\x01\x02")
            raw[cd + 9] |= 0x08
            raw[cd + 46] = 0xFF
            archive = Path(tmp) / "u.zip"
            archive.write_bytes(bytes(raw))
            members, error = _list_archive_members(archive, "zip")
            self.assertIsNone(members)
            self.assertTrue(
                error.startswith("Bundle is not a readable zip archive: "),
                error,
            )

    def test_duplicate_members_exact_message(self):
        # Exact message (two duplicates): kills the ZeroIterationForLoop
        # [358,16] occ 5 on the duplicates loop (skipped loop -> no
        # duplicates error). (The Add_* mutants on THIS line's "+" were
        # already killed by the existing tests; the surviving Add_*
        # family lives on the collisions line [372,65], killed by the
        # collision test below.)
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            archive_bytes = _zip_bytes(
                [("a.bin", b"1"), ("b.bin", b"2"), ("a.bin", b"1"), ("b.bin", b"2")]
            )
            manifest = _manifest(
                tmp_path / "b.zip",
                per_file={"a.bin": _sha256(b"1"), "b.bin": _sha256(b"2")},
                archive_bytes=archive_bytes,
            )
            archive = _write(tmp_path, "b.zip", archive_bytes, manifest)
            result = verify_bundle(archive)
            self.assertFalse(result.valid)
            self.assertEqual(
                result.errors,
                ["Duplicate member names in archive: a.bin, b.bin"],
            )

    def test_case_insensitive_collision_exact_message(self):
        # Exact message: kills the ZeroIterationForLoop [366,16] occ 6
        # on the collisions loop AND the ReplaceBinaryOperator_Add_*
        # family [372,65] occ 3 (x11) on this line's "+" (every Add_*
        # mutant raises TypeError instead of producing the message).
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            archive_bytes = _zip_bytes([("A.bin", b"1"), ("a.bin", b"2")])
            manifest = _manifest(
                tmp_path / "b.zip",
                per_file={"A.bin": _sha256(b"1"), "a.bin": _sha256(b"2")},
                archive_bytes=archive_bytes,
            )
            archive = _write(tmp_path, "b.zip", archive_bytes, manifest)
            result = verify_bundle(archive)
            self.assertFalse(result.valid)
            self.assertEqual(
                result.errors,
                ["Member names collide case-insensitively: a.bin"],
            )


class MemberSetTests(unittest.TestCase):
    """ReplaceBinaryOperator_Sub_BitXor [477,54] occ 1 (extra/missing
    set difference), ZeroIterationForLoop [477,16] occ 8 (extra loop)
    and [480,22] occ 9 (size loop)."""

    def test_extra_member_status_and_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            archive_bytes = _zip_bytes([("a.bin", b"1"), ("extra.bin", b"2")])
            manifest = _manifest(
                tmp_path / "b.zip",
                per_file={"a.bin": _sha256(b"1")},
                archive_bytes=archive_bytes,
            )
            archive = _write(tmp_path, "b.zip", archive_bytes, manifest)
            result = verify_bundle(archive)
            self.assertFalse(result.valid)
            self.assertEqual(result.per_file_status.get("extra.bin"), "extra")
            self.assertIn(
                "Archive contains extra.bin, which the manifest does not list",
                result.errors,
            )

    def test_missing_member_exact_errors(self):
        # Exact errors list: the ^ mutant would add a spurious
        # "Archive contains missing.bin ..." error for the missing file.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            archive_bytes = _zip_bytes([("a.bin", b"1")])
            manifest = _manifest(
                tmp_path / "b.zip",
                per_file={
                    "a.bin": _sha256(b"1"),
                    "missing.bin": "c" * 64,
                },
                archive_bytes=archive_bytes,
            )
            archive = _write(tmp_path, "b.zip", archive_bytes, manifest)
            result = verify_bundle(archive)
            self.assertFalse(result.valid)
            self.assertEqual(result.per_file_status.get("missing.bin"), "missing")
            self.assertEqual(result.errors, ["File not found in archive: missing.bin"])

    def test_extra_member_over_cap_is_error_not_extra(self):
        # An extra member that is ALSO over the per-file cap: the size
        # loop (step 3) overwrites its "extra" status with "error".
        # The ZeroIteration mutant on the size loop leaves it "extra".
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            archive_bytes = _zip_bytes(
                [("a.bin", b"1"), ("extra.bin", b"\x00" * (MAX_BUNDLE_FILE_BYTES + 1))]
            )
            manifest = _manifest(
                tmp_path / "b.zip",
                per_file={"a.bin": _sha256(b"1")},
                archive_bytes=archive_bytes,
            )
            archive = _write(tmp_path, "b.zip", archive_bytes, manifest)
            result = verify_bundle(archive)
            self.assertFalse(result.valid)
            self.assertEqual(result.per_file_status.get("extra.bin"), "error")


class SizeCapTests(unittest.TestCase):
    """ReplaceComparisonOperator_Gt_Eq / Gt_GtE / Gt_Is on the size-cap
    checks [403,34] / [417,32] / [481,16] / [484,40] / [496,35] /
    [511,38] / [525,34], NumberReplacer [488,25] occ 54/55
    (total_decompressed = 0 -> 1/-1), ReplaceContinueWithBreak [491,12]
    occ 0, ReplaceBreakWithContinue [528,16] occ 0."""

    def _sparse(self, tmp, name, size):
        path = tmp / name
        with open(path, "wb") as f:
            f.truncate(size)
        return path

    def test_bundle_exactly_at_compressed_cap_passes_cap_check(self):
        # Exactly MAX: the original > does not trigger; the == / >=
        # mutants return the cap error instead of proceeding.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            archive = self._sparse(tmp_path, "b.zip", MAX_BUNDLE_COMPRESSED_BYTES)
            (tmp_path / "b.zip.manifest.json").write_text("{not json", encoding="utf-8")
            result = verify_bundle(archive)
            self.assertNotIn("Bundle exceeds the", " ".join(result.errors))
            self.assertIn("Failed to parse manifest", " ".join(result.errors))

    def test_bundle_over_compressed_cap_rejected(self):
        # Over MAX: the original > triggers; the `is` mutant (large
        # ints are never identical objects) does not.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            archive = self._sparse(tmp_path, "b.zip", MAX_BUNDLE_COMPRESSED_BYTES + 1)
            result = verify_bundle(archive)
            self.assertFalse(result.valid)
            self.assertTrue(
                any("Bundle exceeds the" in e for e in result.errors),
                result.errors,
            )

    def test_manifest_exactly_at_cap_passes_cap_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            archive = tmp_path / "b.zip"
            archive.write_bytes(_zip_bytes([("a.bin", b"1")]))
            manifest_path = tmp_path / "b.zip.manifest.json"
            with open(manifest_path, "wb") as f:
                f.truncate(MAX_MANIFEST_BYTES)
            result = verify_bundle(archive)
            self.assertNotIn("Manifest exceeds the", " ".join(result.errors))
            self.assertIn("Failed to parse manifest", " ".join(result.errors))

    def test_manifest_over_cap_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            archive = tmp_path / "b.zip"
            archive.write_bytes(_zip_bytes([("a.bin", b"1")]))
            manifest_path = tmp_path / "b.zip.manifest.json"
            with open(manifest_path, "wb") as f:
                f.truncate(MAX_MANIFEST_BYTES + 1)
            result = verify_bundle(archive)
            self.assertFalse(result.valid)
            self.assertTrue(
                any("Manifest exceeds the" in e for e in result.errors),
                result.errors,
            )

    def _exact_cap_member(self, fmt):
        # One member of exactly MAX_BUNDLE_FILE_BYTES: the original >
        # does not trigger anywhere (step 3, tar/zip extraction
        # checks); the == / >= mutants flag it.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            name = "a.bin"
            files = [(name, ZERO_10M)]
            archive_bytes = _tar_bytes(files) if fmt == "tar.gz" else _zip_bytes(files)
            archive_name = "b.tar.gz" if fmt == "tar.gz" else "b.zip"
            manifest = _manifest(
                tmp_path / archive_name,
                fmt=fmt,
                per_file={name: _sha256(ZERO_10M)},
                archive_bytes=archive_bytes,
            )
            archive = _write(tmp_path, archive_name, archive_bytes, manifest)
            result = verify_bundle(archive)
            self.assertTrue(result.valid, result.errors)
            self.assertEqual(result.per_file_status.get(name), "ok")
            self.assertNotIn("per-file cap", " ".join(result.errors))

    def test_member_exactly_at_per_file_cap_tar_gz(self):
        self._exact_cap_member("tar.gz")

    def test_member_exactly_at_per_file_cap_zip(self):
        self._exact_cap_member("zip")

    def _total_bundle(self, sizes, fmt="zip"):
        """Build a bundle whose members have the given sizes (bytes of
        zeros) and return (tmp_path, archive, result)."""
        tmp = tempfile.TemporaryDirectory()
        tmp_path = Path(tmp.name)
        files = [(f"m{i:02d}.bin", b"\x00" * size) for i, size in enumerate(sizes)]
        archive_bytes = _zip_bytes(files)
        per_file = {
            name: _sha256(b"\x00" * size)
            for name, size in ((f"m{i:02d}.bin", size) for i, size in enumerate(sizes))
        }
        manifest = _manifest(
            tmp_path / "b.zip",
            fmt=fmt,
            per_file=per_file,
            archive_bytes=archive_bytes,
        )
        archive = _write(tmp_path, "b.zip", archive_bytes, manifest)
        return tmp, archive, verify_bundle(archive)

    def test_total_exactly_at_cap_valid(self):
        # 10 x 10MB = exactly MAX: no total-cap error anywhere (step 3
        # == / >= mutants, extraction == / >= mutants, and the +1
        # total_decompressed mutant all trigger on exact equality).
        tmp, archive, result = self._total_bundle([MAX_BUNDLE_FILE_BYTES] * 10)
        try:
            self.assertTrue(result.valid, result.errors)
            self.assertNotIn("total cap", " ".join(result.errors))
        finally:
            tmp.cleanup()

    def test_total_one_byte_over_cap_rejected(self):
        # 10 x 10MB + 1 byte: the original rejects; the -1
        # total_decompressed mutant and the `is` mutant on the
        # extraction total check do not.
        tmp, archive, result = self._total_bundle([MAX_BUNDLE_FILE_BYTES] * 10 + [1])
        try:
            self.assertFalse(result.valid)
            self.assertTrue(any("total cap" in e for e in result.errors), result.errors)
        finally:
            tmp.cleanup()

    def test_total_over_cap_with_all_members_preflagged(self):
        # 11 x (10MB + 1): every member is pre-flagged "error" in step
        # 3, so the extraction loop skips them all and its total check
        # never fires — the step-3 total error is the ONLY total-cap
        # signal, so the `is` mutant on it is observable.
        tmp, archive, result = self._total_bundle([MAX_BUNDLE_FILE_BYTES + 1] * 11)
        try:
            self.assertFalse(result.valid)
            self.assertTrue(any("total cap" in e for e in result.errors), result.errors)
        finally:
            tmp.cleanup()

    def test_over_cap_member_first_then_valid_member_verified(self):
        # The step-4 `continue` for already-flagged members: the
        # `break` mutant stops the loop at the over-cap member and the
        # valid member is never verified.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            files = [
                ("aaa.bin", b"\x00" * (MAX_BUNDLE_FILE_BYTES + 1)),
                ("zzz.bin", b"valid"),
            ]
            archive_bytes = _zip_bytes(files)
            manifest = _manifest(
                tmp_path / "b.zip",
                per_file={
                    "aaa.bin": _sha256(b"\x00" * (MAX_BUNDLE_FILE_BYTES + 1)),
                    "zzz.bin": _sha256(b"valid"),
                },
                archive_bytes=archive_bytes,
            )
            archive = _write(tmp_path, "b.zip", archive_bytes, manifest)
            result = verify_bundle(archive)
            self.assertFalse(result.valid)
            self.assertEqual(result.per_file_status.get("aaa.bin"), "error")
            self.assertEqual(result.per_file_status.get("zzz.bin"), "ok")

    def test_break_after_total_cap_skips_remaining_members(self):
        # 12 x 10MB: the total exceeds MAX after the 11th member, so
        # the loop breaks and m11 is never processed. The `continue`
        # mutant processes it (status "ok").
        tmp, archive, result = self._total_bundle([MAX_BUNDLE_FILE_BYTES] * 12)
        try:
            self.assertFalse(result.valid)
            self.assertTrue(any("total cap" in e for e in result.errors), result.errors)
            self.assertNotIn("m11.bin", result.per_file_status)
        finally:
            tmp.cleanup()

    def test_total_one_over_cap_with_following_member(self):
        # NumberReplacer [488,25] occ 55 (total_decompressed = 0 ->
        # -1): 10 x 10MB + 1 byte + 1 byte. After the 11th member the
        # original total is MAX+1 (error + break, so m11 is never
        # processed); the -1 mutant's total is exactly MAX (no error,
        # no break, so m11 is processed and gets status "ok"). The
        # plain 11-member test cannot kill it: the 11th member is
        # last, so there is no following member to observe, and the
        # step-3 total error fires in both cases.
        tmp, archive, result = self._total_bundle([MAX_BUNDLE_FILE_BYTES] * 10 + [1, 1])
        try:
            self.assertFalse(result.valid)
            self.assertTrue(any("total cap" in e for e in result.errors), result.errors)
            self.assertNotIn("m11.bin", result.per_file_status)
        finally:
            tmp.cleanup()


class DigestTests(unittest.TestCase):
    """ReplaceComparisonOperator_Eq_GtE [445,33] occ 5 (bundle_digest),
    ReplaceComparisonOperator_NotEq_Gt [452,53] occ 1 (expected),
    ReplaceComparisonOperator_Eq_LtE [540,27] occ 8 (file digest),
    ReplaceComparisonOperator_Eq_LtE [508,21] occ 7 (fmt == "zip" in
    step 4), ReplaceOrWithAnd [468,44] / [558,40] occ 4/5
    (expected_digest or ""), ExceptionReplacer [550,15] occ 15
    (catch-all Exception in step 4), ZeroIterationForLoop [477,16]
    occ 8 (missing-members loop)."""

    def test_bad_crc_member_is_error_not_raise(self):
        # A zip member whose stored data is corrupted fails the CRC
        # check on read (BadZipFile, an Exception subclass): the
        # catch-all handler must convert it to status "error", not
        # let it propagate out of verify_bundle.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            content = b"hello world, this is the member content"
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
                zf.writestr("a.bin", content)
            raw = bytearray(buf.getvalue())
            at = raw.find(content)
            assert at > 0, "member content not found in the archive bytes"
            raw[at] ^= 0xFF  # corrupt one stored byte -> CRC mismatch
            archive_bytes = bytes(raw)
            manifest = _manifest(
                tmp_path / "b.zip",
                per_file={"a.bin": _sha256(content)},
                archive_bytes=archive_bytes,
            )
            archive = _write(tmp_path, "b.zip", archive_bytes, manifest)
            result = verify_bundle(archive)
            self.assertFalse(result.valid)
            self.assertEqual(result.per_file_status.get("a.bin"), "error")
            self.assertTrue(
                any("Error verifying a.bin" in e for e in result.errors),
                result.errors,
            )

    def test_missing_loop_error_ordering(self):
        # ZeroIterationForLoop [477,16] occ 8 (the missing-members
        # loop): its effect is duplicated by step 4's KeyError
        # handler, EXCEPT for error ordering. With a tampered member
        # sorting BEFORE a missing member, the original appends the
        # missing error in step 3 (before any step-4 error); the
        # mutant appends it during step 4 (after the tampered error).
        # Assert the exact errors list, in order.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            content = b"tampered-content"
            archive_bytes = _zip_bytes([("aaa.bin", content)])
            manifest = _manifest(
                tmp_path / "b.zip",
                per_file={
                    "aaa.bin": "d" * 64,
                    "zzz.bin": "c" * 64,
                },
                archive_bytes=archive_bytes,
            )
            archive = _write(tmp_path, "b.zip", archive_bytes, manifest)
            result = verify_bundle(archive)
            self.assertFalse(result.valid)
            self.assertEqual(result.per_file_status.get("aaa.bin"), "tampered")
            self.assertEqual(result.per_file_status.get("zzz.bin"), "missing")
            self.assertEqual(
                result.errors,
                [
                    "File not found in archive: zzz.bin",
                    "File digest mismatch for aaa.bin: expected "
                    + "d" * 64
                    + ", got "
                    + _sha256(content),
                ],
            )

    def _valid_bundle(self, tmp_path, fmt="zip"):
        files = [("a.bin", b"content")]
        archive_bytes = _tar_bytes(files) if fmt == "tar.gz" else _zip_bytes(files)
        archive_name = "b.tar.gz" if fmt == "tar.gz" else "b.zip"
        manifest = _manifest(
            tmp_path / archive_name,
            fmt=fmt,
            per_file={"a.bin": _sha256(b"content")},
            archive_bytes=archive_bytes,
        )
        archive = _write(tmp_path, archive_name, archive_bytes, manifest)
        return archive

    def test_bundle_digest_smaller_than_actual_mismatch(self):
        # bundle_digest "0"*64 is the smallest 64-hex string, so the
        # actual digest is always >= it but != it: the original ==
        # reports a mismatch; the >= mutant reports a match.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            archive = self._valid_bundle(tmp_path)
            manifest_path = tmp_path / "b.zip.manifest.json"
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            data["bundle_digest"] = "0" * 64
            manifest_path.write_text(json.dumps(data), encoding="utf-8")
            result = verify_bundle(archive)
            self.assertFalse(result.valid)
            self.assertFalse(result.bundle_digest_match)
            self.assertTrue(
                any("Archive digest mismatch" in e for e in result.errors),
                result.errors,
            )

    def test_expected_digest_greater_than_actual_mismatch(self):
        # expected "f"*64 is the largest 64-hex string, so the actual
        # digest is always < it but != it: the original != reports a
        # mismatch; the > mutant does not.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            archive = self._valid_bundle(tmp_path)
            actual = _sha256(archive.read_bytes())
            self.assertLess(actual, "f" * 64)
            result = verify_bundle(archive, expected_digest="f" * 64)
            self.assertFalse(result.valid)
            self.assertTrue(
                any("Digest does not match expected" in e for e in result.errors),
                result.errors,
            )

    def test_file_digest_smaller_than_expected_is_tampered(self):
        # expected "f"*64: the actual digest is always <= it but !=
        # it — the original == reports tampered; the <= mutant reports ok.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            archive = self._valid_bundle(tmp_path)
            manifest_path = tmp_path / "b.zip.manifest.json"
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            data["per_file_digests"]["a.bin"] = "f" * 64
            manifest_path.write_text(json.dumps(data), encoding="utf-8")
            result = verify_bundle(archive)
            self.assertFalse(result.valid)
            self.assertEqual(result.per_file_status.get("a.bin"), "tampered")

    def test_tar_gz_bundle_verifies_per_file_ok(self):
        # Step 4 fmt == "zip": for a tar.gz bundle the original takes
        # the tar branch; the <= mutant takes the zip branch (KeyError
        # -> "missing"). Assert the member verifies ok.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            archive = self._valid_bundle(tmp_path, fmt="tar.gz")
            result = verify_bundle(archive)
            self.assertTrue(result.valid, result.errors)
            self.assertEqual(result.per_file_status.get("a.bin"), "ok")

    def test_expected_digest_echoed_on_valid_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            archive = self._valid_bundle(tmp_path)
            actual = _sha256(archive.read_bytes())
            result = verify_bundle(archive, expected_digest=actual)
            self.assertTrue(result.valid, result.errors)
            self.assertEqual(result.expected_digest, actual)

    def test_expected_digest_echoed_on_member_error(self):
        # The member_error early return echoes expected_digest too.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            archive_bytes = _zip_bytes([("a.bin", b"1"), ("a.bin", b"1")])
            manifest = _manifest(
                tmp_path / "b.zip",
                per_file={"a.bin": _sha256(b"1")},
                archive_bytes=archive_bytes,
            )
            archive = _write(tmp_path, "b.zip", archive_bytes, manifest)
            actual = _sha256(archive.read_bytes())
            result = verify_bundle(archive, expected_digest=actual)
            self.assertFalse(result.valid)
            self.assertEqual(result.expected_digest, actual)


if __name__ == "__main__":
    unittest.main()
