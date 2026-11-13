"""W3 Worker F3 kill tests for the sealed_bundle module (audit-w3-f).

Covers the killable runtime survivors of the 211 sealed_bundle
survivors (121 annotation + the domain-equivalent / unobservable
entries are baseline entries, see audit-w3-worker-f.md §6). Each
test targets a specific mutant; the re-proof
(audit-w3-f3-reprove-sealed_bundle.py) hand-applies each mutant
with cosmic-ray mutate_code and runs the owning test class.

CORRECTIONS to the F2 classify-notes (verified against the source):
- [536,35] Eq_Lt/Eq_LtE are DOMAIN-EQUIVALENT, not killable: in
  the seal_failed replay branch report["exit_code"] is the
  standalone exit_code, which is only ever 1 or 2 there, so
  `== 0`, `< 0` and `<= 0` are all False. (F2's "exit_code must
  be exactly 0 vs 1/2" kill plan cannot distinguish them.)
- [414,42] NotEq_Gt is DOMAIN-EQUIVALENT: the standalone exit
  code is only ever 0/1/2 (verified by grepping every
  `report["exit_code"] =` assignment in _standalone_verify.py),
  and `!= 0` coincides with `> 0` on that set. (F2's FLAG,
  confirmed.)
- [240,30] NotEq_IsNot is DOMAIN-EQUIVALENT: both sides are
  booleans, and `is not` coincides with `!=` on the True/False
  singletons.
- [480,32] ReplaceAndWithOr is DOMAIN-EQUIVALENT (in context):
  at the comparison block, manifest is not None implies
  seal_record is not None (the re-read that sets manifest runs
  only when seal_record is a dict), and seal_record None implies
  manifest None (the re-read is skipped) — the two are never
  exactly-one-None, so `and` coincides with `or`. (F2's
  "manifest None + seal_record set" case is unreachable: the
  standalone verifier's checks are a superset of the re-read's,
  so any bundle failing the re-read already failed standalone
  and the cross-check is unavailable.)
- [463,42] Gt_Is and [468,33] Gt_Is are UNOBSERVABLE: the
  standalone verifier rejects >1024 entries and over-cap
  entries before the cross-check runs, so the cross-check's
  `is` mutants (which need an over-cap input to reach) are
  never exercised. The Eq/GtE mutants at the same positions
  ARE killable with exactly-at-cap fixtures.
- [537,38] NumberReplacer occ 56/57 (the `2` in the
  `report["exit_code"] = 2` assignment) are UNOBSERVABLE: the
  assignment only runs when exit_code == 0 in the seal_failed
  branch, which never happens (exit_code is 1 or 2 there) — a
  dead assignment.
- The `!=` -> `<` / `>` kill inputs follow the corrected rule
  (same systematic error as casefile/sealing): for `x != K` ->
  `<`, the distinguishing input has x > K; for `->`, x < K.
"""

import hashlib
import io
import unittest
import zipfile
from unittest import mock

from textforensics.casefile import seal_case_file
from textforensics.detectors import DetectorPrediction
from textforensics.dsse import sign_envelope
from textforensics.report import build_forensic_bundle
from textforensics.sealed_bundle import (
    COMMENT_PREFIX,
    MAX_ENTRIES,
    MAX_ENTRY_BYTES,
    MAX_SEALED_RESULTS_BYTES,
    MAX_TOTAL_BYTES,
    PAYLOAD_TYPE,
    SealedBundleError,
    _pack_zip,
    _read_capped,
    _sha256,
    _standalone_verifier_bytes,
    build_manifest,
    canonical_json_bytes,
    pack_sealed_bundle,
    verify_sealed_bundle,
)
from textforensics.sealing import public_key_from_seed

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
SEED = bytes(range(32))
SIGNER = {"identity": "strmt7", "role": "sealer"}
PUBLICATION = {
    "channel": "test-channel",
    "reference": "test-ref-1",
    "published_at_utc": "2026-11-13T00:00:00+00:00",
}


def sealed_case(*, publication=None, determinism=None, determinism_reasons=None):
    bundle = build_forensic_bundle(TEXT).to_dict()
    kwargs = {"deterministic": True, "fixed_timestamp": "1970-01-01T00:00:00+00:00"}
    if publication is not None:
        kwargs["digest_publication"] = publication
    if determinism is not None:
        kwargs["determinism"] = determinism
    if determinism_reasons is not None:
        kwargs["determinism_reasons"] = determinism_reasons
    return seal_case_file(bundle, **kwargs)


def _pack(case=None, **kwargs):
    return pack_sealed_bundle(case if case is not None else sealed_case(), **kwargs)


def _verify(archive, record=None, **kwargs):
    return verify_sealed_bundle(archive, seal_record=record, **kwargs)


def _verify_signed(archive, record):
    """Verify a bundle built by _pack_with_extra_files (signed)."""
    return verify_sealed_bundle(archive, seal_record=record, public_key=public_key_from_seed(SEED))


def _seal_record_errors(result):
    sr = result.get("seal_record") or {}
    return sr.get("errors", [])


def _case_of_size(target_bytes: int) -> dict:
    """A sealed case whose canonical JSON is exactly `target_bytes`.

    The bundle is padded with a "padding" field before sealing (an
    extra bundle field is tolerated by the verifiers — verified
    empirically); the padding length is adjusted once by measurement
    (the size is linear in the padding length).
    """
    bundle = build_forensic_bundle(TEXT).to_dict()
    bundle["padding"] = ""
    case = seal_case_file(bundle, deterministic=True, fixed_timestamp="1970-01-01T00:00:00+00:00")
    base = len(canonical_json_bytes(case))
    bundle["padding"] = "x" * (target_bytes - base)
    case = seal_case_file(bundle, deterministic=True, fixed_timestamp="1970-01-01T00:00:00+00:00")
    assert len(canonical_json_bytes(case)) == target_bytes, len(canonical_json_bytes(case))
    return case


def _zip_with_member(name: str, data: bytes) -> tuple[zipfile.ZipFile, object]:
    """A one-member STORED zip (in-memory) for direct _read_capped tests."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        info = zipfile.ZipInfo(filename=name, date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_STORED
        info.create_system = 0
        info.external_attr = 0o644 << 16
        zf.writestr(info, data)
    buf.seek(0)
    zf = zipfile.ZipFile(buf)
    return zf, zf.infolist()[0]


def _pack_with_extra_files(case, extra: dict[str, bytes]):
    """Pack a SIGNED bundle whose files are case.json + verify.py +
    the given extra entries (each listed in the manifest). Used for
    the exactly-at-cap fixtures (1024 entries, 64 MiB entry, 256 MiB
    total). The manifest is built and signed exactly as
    pack_sealed_bundle does it."""
    case_bytes = canonical_json_bytes(case)
    files: dict[str, bytes] = {
        "case.json": case_bytes,
        "verify.py": _standalone_verifier_bytes(),
    }
    files.update(extra)
    unsigned_manifest = build_manifest(case, files, signer=None)
    unsigned_bytes = canonical_json_bytes(unsigned_manifest)
    signature = sign_envelope(PAYLOAD_TYPE, unsigned_bytes, SEED)
    manifest = build_manifest(case, files, signature=signature, signer=None)
    manifest_bytes = canonical_json_bytes(manifest)
    files["manifest.json"] = manifest_bytes
    comment = COMMENT_PREFIX + _sha256(manifest_bytes)
    archive = _pack_zip(files, comment)
    seal_record = {
        "schema": "textforensics.sealed-bundle-seal-record/v1",
        "manifest": manifest,
        "manifest_sha256": _sha256(manifest_bytes),
        "bundle_sha256": None,  # recomputed below via the same helper
        "archive_sha256": _sha256(archive),
        "signature": signature,
        "timestamp": None,
        "digest_publication": None,
    }
    # _bundle_digest is the module's own helper; import it lazily to
    # keep the top-level import list short.
    from textforensics.sealed_bundle import _bundle_digest

    seal_record["bundle_sha256"] = _bundle_digest(files, manifest)
    return archive, seal_record


class _StubDetector:
    """A detector returning a deliberately different score, so a
    non_deterministic declaration produces a replay warning."""

    detector_id = "textforensics/builtin-heuristic"
    detector_version = "0.1.0"
    detector_family = "stylometric-heuristic"
    execution = "local"

    def detect(self, text):
        return DetectorPrediction(
            schema="textforensics.detector-result/v2",
            detector_id=self.detector_id,
            detector_version="0.1.0",
            detector_family="stylometric-heuristic",
            execution="local",
            score=0.99,
            score_semantics="higher_means_more_machine_like; uncalibrated pattern score",
            verdict="ai_like",
            threshold=None,
        )


class TestReadCappedKill(unittest.TestCase):
    """_read_capped: Add-family [352,43] (6 killable) + NumberReplacer
    [352,45] 1->0 + Gt_Eq/Gt_GtE/Gt_Is [353,17]."""

    def test_over_cap_entry_errors(self):
        # Kills: Add_Sub/Mul/Div/FloorDiv/Pow/RShift [352,43] (each
        # reads at most MAX bytes, so no error is raised) +
        # NumberReplacer [352,45] 1->0 (reads MAX) + Gt_Is [353,17]
        # (the mutant `is` is always False for the large int, so it
        # returns the data instead of raising).
        zf, info = _zip_with_member("case.json", b"x" * (MAX_ENTRY_BYTES + 1))
        with zf, self.assertRaises(SealedBundleError):
            _read_capped(zf, info)

    def test_exact_cap_entry_reads(self):
        # Kills Gt_Eq/Gt_GtE [353,17]: the original reads an entry
        # of exactly MAX_ENTRY_BYTES (not >), the mutants raise.
        zf, info = _zip_with_member("case.json", b"x" * MAX_ENTRY_BYTES)
        with zf:
            data = _read_capped(zf, info)
        self.assertEqual(len(data), MAX_ENTRY_BYTES)


class TestPackKill(unittest.TestCase):
    """NotEq_Lt/Gt [240,30]; Gt_Eq/Gt_GtE/Gt_Is [248,23];
    Is_IsNot [323,19] + AddNot [323,7]/[325,11]."""

    def test_signer_only_raises(self):
        # [240,30] NotEq_Lt: seed None, signer given -> (True !=
        # False) is True (raise) but (True < False) is False
        # (mutant proceeds and packs).
        with self.assertRaisesRegex(
            SealedBundleError, "signing_seed and signer must be given together"
        ):
            _pack(signing_seed=None, signer=SIGNER)

    def test_seed_only_raises(self):
        # [240,30] NotEq_Gt: seed given, signer None -> (False !=
        # True) is True but (False > True) is False.
        with self.assertRaisesRegex(
            SealedBundleError, "signing_seed and signer must be given together"
        ):
            _pack(signing_seed=SEED, signer=None)

    def test_exact_32mib_case_packs(self):
        # [248,23] Gt_Eq/Gt_GtE: a case of exactly
        # MAX_SEALED_RESULTS_BYTES bytes is not over the cap; the
        # mutants (`==`/`>=`) refuse it.
        case = _case_of_size(MAX_SEALED_RESULTS_BYTES)
        archive, _ = pack_sealed_bundle(case)
        self.assertTrue(len(archive) > 0)

    def test_over_32mib_case_refused(self):
        # [248,23] Gt_Is: a case one byte over the cap is refused by
        # the original; the mutant `is` is always False for the large
        # int, so it packs it.
        case = _case_of_size(MAX_SEALED_RESULTS_BYTES + 1)
        with self.assertRaisesRegex(
            SealedBundleError, "case.json exceeds the 32 MiB sealed-results cap"
        ):
            pack_sealed_bundle(case)

    def test_seal_publication_used_when_none_given(self):
        # [323,19] Is_IsNot + AddNot [323,7] + AddNot [325,11]: with
        # digest_publication=None and a seal carrying a publication,
        # the seal record must carry the seal's publication. The
        # Is_IsNot mutant (`is not None` -> False when publication
        # is None) skips the lookup; the AddNot mutants skip it too.
        case = sealed_case(publication=PUBLICATION)
        _, record = pack_sealed_bundle(case)
        self.assertEqual(record["digest_publication"], PUBLICATION)

    def test_explicit_publication_is_used(self):
        # Same mutants, other direction: with an explicit
        # publication, the seal lookup must NOT overwrite it. (The
        # case's seal has no publication here, so the mutant lookup
        # would set it to None.)
        _, record = _pack(digest_publication=PUBLICATION)
        self.assertEqual(record["digest_publication"], PUBLICATION)


class TestPackSignerKill(unittest.TestCase):
    """ReplaceOrWithAnd [243,37]/[243,67] (signer guard) and
    [291,60] (seed-length guard) in pack_sealed_bundle."""

    def test_signer_without_identity_raises(self):
        # [243,37] OrWithAnd (first `or`): a dict signer without
        # identity makes ONLY the second side (not identity) True.
        # The mutant `and` is False and proceeds to KeyError on
        # signer["identity"].
        with self.assertRaisesRegex(SealedBundleError, "signer needs identity and role"):
            _pack(signing_seed=SEED, signer={"role": "sealer"})

    def test_signer_without_role_raises(self):
        # [243,67] OrWithAnd (second `or`): a dict signer with
        # identity but no role makes ONLY the third side (not role)
        # True. The mutant `and` is False and proceeds to KeyError
        # on signer["role"].
        with self.assertRaisesRegex(SealedBundleError, "signer needs identity and role"):
            _pack(signing_seed=SEED, signer={"identity": "strmt7"})

    def test_non_dict_signer_raises(self):
        # [243,37] OrWithAnd, other side: a non-dict signer makes
        # ONLY the first side (not a Mapping) True. The mutant `and`
        # evaluates signer.get and raises AttributeError.
        with self.assertRaisesRegex(SealedBundleError, "signer needs identity and role"):
            _pack(signing_seed=SEED, signer="not-a-dict")

    def test_short_seed_raises(self):
        # [291,60] OrWithAnd: a 31-byte seed is the right type but
        # the wrong length (side 1 False, side 2 True). The mutant
        # `and` is False and proceeds into public_key_from_seed,
        # which rejects the short seed.
        with self.assertRaisesRegex(SealedBundleError, "signing_seed must be 32 bytes"):
            _pack(signing_seed=b"x" * 31, signer=SIGNER)

    def test_long_seed_raises(self):
        # [291,81] NotEq_Lt: a 33-byte seed makes `len != 32` True
        # (original raises) but `len < 32` False (mutant proceeds
        # into public_key_from_seed, which rejects the long seed).
        with self.assertRaisesRegex(SealedBundleError, "signing_seed must be 32 bytes"):
            _pack(signing_seed=b"x" * 33, signer=SIGNER)

    def test_non_bytes_seed_raises(self):
        # [291,60] OrWithAnd, other side: a 32-char str seed is the
        # wrong type but the right length (side 1 True, side 2
        # False). The mutant `and` is False and proceeds.
        with self.assertRaisesRegex(SealedBundleError, "signing_seed must be 32 bytes"):
            _pack(signing_seed="x" * 32, signer=SIGNER)


class TestVerifyKill(unittest.TestCase):
    """Seal-record cross-check: NotEq_Lt/Gt/Is/IsNot [457,62]/
    [461,46]/[489,58]/[493,56]/[509,50]; Gt_Eq/Gt_GtE [463,42]/
    [468,33]; Gt_GtE [455,34]; NumberReplacer [459,28];
    AddNot [518,15]; ZeroIterationForLoop [460,32]/[514,25]."""

    def test_valid_record_passes(self):
        # Kills NotEq_IsNot [457,62]/[461,46]: the seal record's
        # manifest and digests are distinct-but-equal objects (the
        # bundle's copies are JSON-round-tripped), so the mutant
        # `is not` is True and reports spurious errors. Also kills
        # ZeroIterationForLoop [460,32] (the `for info in infos`
        # loop populates `files`; skipping it breaks _bundle_digest).
        archive, record = _pack()
        result = _verify(archive, record)
        self.assertEqual(_seal_record_errors(result), [])
        self.assertEqual(result["exit_code"], 0)

    def test_tampered_manifest_detected(self):
        # Kills NotEq_Lt/Gt/Is [457,62]: any tampered manifest makes
        # the original `!=` True; the Lt/Gt mutants raise TypeError
        # on the dict comparison (caught as a different error), and
        # the Is mutant is False for a distinct object.
        archive, record = _pack()
        record["manifest"] = dict(record["manifest"])
        record["manifest"]["files"] = []
        result = _verify(archive, record)
        self.assertIn(
            "seal_record.manifest does not match the bundle manifest",
            _seal_record_errors(result),
        )

    def test_manifest_sha_greater_detected(self):
        # [461,46] NotEq_Lt: recorded "f"*64 is greater than the
        # computed hash, so `!=` is True but `<` is False.
        archive, record = _pack()
        record["manifest_sha256"] = "f" * 64
        result = _verify(archive, record)
        self.assertIn("seal_record.manifest_sha256 mismatch", _seal_record_errors(result))

    def test_manifest_sha_lesser_detected(self):
        # [461,46] NotEq_Gt: recorded "0"*64 is less than the
        # computed hash, so `!=` is True but `>` is False.
        archive, record = _pack()
        record["manifest_sha256"] = "0" * 64
        result = _verify(archive, record)
        self.assertIn("seal_record.manifest_sha256 mismatch", _seal_record_errors(result))

    def test_tampered_manifest_sha_detected(self):
        # [461,46] NotEq_Is: a tampered (distinct-object) digest
        # makes the original `!=` True but the mutant `is` False.
        archive, record = _pack()
        record["manifest_sha256"] = "a" * 64
        result = _verify(archive, record)
        self.assertIn("seal_record.manifest_sha256 mismatch", _seal_record_errors(result))

    def test_archive_sha_greater_detected(self):
        # [489,58] NotEq_Lt.
        archive, record = _pack()
        record["archive_sha256"] = "f" * 64
        result = _verify(archive, record)
        self.assertIn("seal_record.archive_sha256 mismatch", _seal_record_errors(result))

    def test_archive_sha_lesser_detected(self):
        # [489,58] NotEq_Gt.
        archive, record = _pack()
        record["archive_sha256"] = "0" * 64
        result = _verify(archive, record)
        self.assertIn("seal_record.archive_sha256 mismatch", _seal_record_errors(result))

    def test_tampered_archive_sha_detected(self):
        # [489,58] NotEq_Is.
        archive, record = _pack()
        record["archive_sha256"] = "a" * 64
        result = _verify(archive, record)
        self.assertIn("seal_record.archive_sha256 mismatch", _seal_record_errors(result))

    def test_bundle_sha_greater_detected(self):
        # [493,56] NotEq_Lt.
        archive, record = _pack()
        record["bundle_sha256"] = "f" * 64
        result = _verify(archive, record)
        self.assertIn("seal_record.bundle_sha256 mismatch", _seal_record_errors(result))

    def test_bundle_sha_lesser_detected(self):
        # [493,56] NotEq_Gt.
        archive, record = _pack()
        record["bundle_sha256"] = "0" * 64
        result = _verify(archive, record)
        self.assertIn("seal_record.bundle_sha256 mismatch", _seal_record_errors(result))

    def test_tampered_bundle_sha_detected(self):
        # [493,56] NotEq_Is.
        archive, record = _pack()
        record["bundle_sha256"] = "a" * 64
        result = _verify(archive, record)
        self.assertIn("seal_record.bundle_sha256 mismatch", _seal_record_errors(result))

    def _token_bundle(self):
        from _token_fixture import build_token_for_digest

        case = sealed_case()
        case_bytes = canonical_json_bytes(case)
        token = build_token_for_digest(hashlib.sha256(case_bytes).digest())
        archive, record = pack_sealed_bundle(case, timestamp_token=token)
        return archive, record

    def test_token_sha_greater_detected(self):
        # [509,50] NotEq_Lt.
        archive, record = self._token_bundle()
        record["timestamp"]["token_sha256"] = "f" * 64
        result = _verify(archive, record)
        self.assertIn(
            "seal_record timestamp token digest mismatch",
            _seal_record_errors(result),
        )

    def test_token_sha_lesser_detected(self):
        # [509,50] NotEq_Gt.
        archive, record = self._token_bundle()
        record["timestamp"]["token_sha256"] = "0" * 64
        result = _verify(archive, record)
        self.assertIn(
            "seal_record timestamp token digest mismatch",
            _seal_record_errors(result),
        )

    def test_tampered_token_sha_detected(self):
        # [509,50] NotEq_Is.
        archive, record = self._token_bundle()
        record["timestamp"]["token_sha256"] = "a" * 64
        result = _verify(archive, record)
        self.assertIn(
            "seal_record timestamp token digest mismatch",
            _seal_record_errors(result),
        )

    def test_1024_entry_bundle_passes(self):
        # [463,42] Gt_Eq/Gt_GtE: exactly MAX_ENTRIES entries is not
        # over the cap; the mutants (`==`/`>=`) raise
        # SealedBundleError in the cross-check re-read.
        case = sealed_case()
        extra = {f"extra-{i:04d}.bin": b"" for i in range(MAX_ENTRIES - 3)}
        archive, record = _pack_with_extra_files(case, extra)
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            self.assertEqual(len(zf.infolist()), MAX_ENTRIES)
        result = _verify_signed(archive, record)
        self.assertEqual(_seal_record_errors(result), [])

    def test_exact_cap_entry_in_bundle_passes(self):
        # [468,33] Gt_Eq/Gt_GtE: an entry of exactly
        # MAX_ENTRY_BYTES is not over the cap; the mutants raise.
        case = sealed_case()
        extra = {"extra.bin": b"x" * MAX_ENTRY_BYTES}
        archive, record = _pack_with_extra_files(case, extra)
        result = _verify_signed(archive, record)
        self.assertEqual(_seal_record_errors(result), [])

    def test_exact_total_bundle_passes(self):
        # [455,34] Gt_GtE + NumberReplacer [459,28] occ 50/51
        # (`total = 0` -> 1/-1): a bundle whose total is exactly
        # MAX_TOTAL_BYTES is not over the cap. The last extra entry
        # is sized so the total (including manifest.json) is exact.
        case = sealed_case()
        case_bytes = canonical_json_bytes(case)
        verify_bytes = _standalone_verifier_bytes()
        # Three 64 MiB entries + case + verify.py; the last entry
        # absorbs the remainder (manifest size is stable: digests
        # are fixed-length hex and sizes stay 8 digits).
        base_extra = 3 * MAX_ENTRY_BYTES
        probe_extra = {
            "extra-0.bin": b"x" * MAX_ENTRY_BYTES,
            "extra-1.bin": b"x" * MAX_ENTRY_BYTES,
            "extra-2.bin": b"x" * MAX_ENTRY_BYTES,
            "extra-3.bin": b"x" * 1024,
        }
        probe_archive, probe_record = _pack_with_extra_files(case, probe_extra)
        with zipfile.ZipFile(io.BytesIO(probe_archive)) as zf:
            manifest_size = zf.getinfo("manifest.json").file_size
        remainder = (
            MAX_TOTAL_BYTES - len(case_bytes) - len(verify_bytes) - manifest_size - base_extra
        )
        self.assertGreater(remainder, 0)
        # The manifest grows when extra-3.bin's size gains digits
        # (1024 -> ~60M is +4 bytes), so the first build uses
        # remainder - 1024 (safely under the cap), measures the
        # actual total, and the second build adjusts up by the exact
        # shortfall. The size field stays 8 digits across the
        # few-byte adjustment, so the second build is exact.
        extra = {
            "extra-0.bin": b"x" * MAX_ENTRY_BYTES,
            "extra-1.bin": b"x" * MAX_ENTRY_BYTES,
            "extra-2.bin": b"x" * MAX_ENTRY_BYTES,
            "extra-3.bin": b"x" * (remainder - 1024),
        }
        archive, record = _pack_with_extra_files(case, extra)
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            actual = sum(info.file_size for info in zf.infolist())
        extra["extra-3.bin"] = b"x" * (remainder - 1024 + (MAX_TOTAL_BYTES - actual))
        archive, record = _pack_with_extra_files(case, extra)
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            total = sum(info.file_size for info in zf.infolist())
        self.assertEqual(total, MAX_TOTAL_BYTES)
        result = _verify_signed(archive, record)
        self.assertEqual(_seal_record_errors(result), [])

    def test_record_errors_reported_as_fail_checks(self):
        # AddNot [518,15] + ZeroIterationForLoop [514,25]: with a
        # tampered record, each error must appear as a "fail" check.
        # The AddNot mutant appends a "pass" check instead; the
        # ZeroIteration mutant appends no checks at all.
        archive, record = _pack()
        record["manifest_sha256"] = "a" * 64
        result = _verify(archive, record)
        checks = result["seal_record"]["checks"]
        self.assertTrue(checks)
        self.assertTrue(all(c["status"] == "fail" for c in checks))

    def test_valid_record_reports_pass_check(self):
        # AddNot [518,15], other direction: with no errors, a
        # single "pass" check must be present.
        archive, record = _pack()
        result = _verify(archive, record)
        checks = result["seal_record"]["checks"]
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0]["status"], "pass")


class TestReplayKill(unittest.TestCase):
    """Exit-code mutants [545,38]/[560,40]/[561,38] and the
    replay-gate IsNot_Is [530,37]; ExceptionReplacer [543,40]/
    [543,50]/[543,59]/[543,71] (replay read errors). The
    SealedBundleError except clauses [478,19]/[547,19] and the
    NumberReplacer [549,38] occ 60/61 in the dead handler are
    UNOBSERVABLE (SealedBundleError subclasses ValueError, so the
    preceding except tuple catches it first) — see §6."""

    def _warning_case(self):
        return sealed_case(
            determinism={"textforensics/builtin-heuristic": "non_deterministic"},
            determinism_reasons={"textforensics/builtin-heuristic": "sampled"},
        )

    def test_replay_with_warnings_exit_2(self):
        # [560,37] Eq_NotEq/Eq_Lt/Eq_Gt + [560,40] NumberReplacer
        # occ 64/65 (`0` -> 1/-1) + [561,38] NumberReplacer occ
        # 66/67 (`2` -> 1/3): a valid replay with warnings must
        # report exit_code 2. (The Eq_LtE mutant at [560,37] is
        # equivalent: `<= 0` coincides with `== 0` on {0,1,2}.)
        archive, _ = _pack(self._warning_case())
        result = verify_sealed_bundle(archive, text=TEXT, detectors=[_StubDetector()])
        self.assertEqual(result["exit_code"], 2)
        self.assertTrue(result["replay"]["warnings"])

    def test_record_error_keeps_exit_1_with_warnings(self):
        # [560,37] Eq_GtE: a tampered seal record is a record error
        # (exit_code 1) while seal_failed stays False (the standalone
        # verifier passed), so the replay still runs. With a valid
        # replay that has warnings, the original `elif exit_code == 0
        # and warnings` is False (exit_code 1) and the exit code stays
        # 1; the mutant `>= 0` is always True and wrongly sets it to 2.
        # (CORRECTION 2026-11-13: Eq_GtE is KILLABLE, not equivalent —
        # `>= 0` differs from `== 0` exactly when exit_code is 1.)
        archive, record = _pack(self._warning_case())
        record["manifest_sha256"] = "a" * 64
        result = _verify(archive, record, text=TEXT, detectors=[_StubDetector()])
        self.assertIn("seal_record.manifest_sha256 mismatch", _seal_record_errors(result))
        self.assertTrue(result["replay"]["warnings"])
        self.assertEqual(result["exit_code"], 1)

    def test_verify_with_neither_replay_not_requested(self):
        # [530,37] IsNot_Is: with neither text nor detectors, no
        # replay runs. The mutant (`text is None or detectors is
        # None`) is True and runs the replay.
        archive, _ = _pack()
        result = verify_sealed_bundle(archive)
        self.assertEqual(result["replay"]["status"], "not_requested")

    def test_verify_with_text_and_detectors_replays(self):
        # [530,37] IsNot_Is, other direction: with text AND
        # detectors, the replay runs. The mutant is False and skips
        # it.
        archive, _ = _pack()
        result = verify_sealed_bundle(archive, text=TEXT, detectors=[_StubDetector()])
        # A ran replay returns the replay_case_file dict (with
        # "checks"); the mutant returns the "not_requested" dict.
        self.assertIn("checks", result["replay"])

    def _replay_read_error(self, exc):
        archive, _ = _pack()
        with mock.patch("textforensics.sealed_bundle._read_capped", side_effect=exc):
            return verify_sealed_bundle(archive, text=TEXT)

    def test_key_error_in_replay_is_unavailable(self):
        # ExceptionReplacer [543,40] (KeyError in the replay read).
        result = self._replay_read_error(KeyError("case.json"))
        self.assertEqual(result["replay"]["status"], "unavailable")
        self.assertEqual(result["exit_code"], 1)

    def test_os_error_in_replay_is_unavailable(self):
        # ExceptionReplacer [543,50] (OSError in the replay read) +
        # NumberReplacer [545,38] occ 58/59 (the `1` in the first
        # handler's `report["exit_code"] = 1`).
        result = self._replay_read_error(OSError("cannot read"))
        self.assertEqual(result["replay"]["status"], "unavailable")
        self.assertEqual(result["exit_code"], 1)

    def test_value_error_in_replay_is_unavailable(self):
        # ExceptionReplacer [543,59] (ValueError in the replay read).
        result = self._replay_read_error(ValueError("bad json"))
        self.assertEqual(result["replay"]["status"], "unavailable")
        self.assertEqual(result["exit_code"], 1)

    def test_recursion_error_in_replay_is_unavailable(self):
        # ExceptionReplacer [543,71] (RecursionError in the replay read).
        result = self._replay_read_error(RecursionError("too deep"))
        self.assertEqual(result["replay"]["status"], "unavailable")
        self.assertEqual(result["exit_code"], 1)


class TestSealRecordCompareKill(unittest.TestCase):
    """ExceptionReplacer [511,24]/[511,34]/[511,45] (KeyError /
    TypeError / AttributeError in the seal-record comparison block).
    The comparison block's exceptions are reachable only via a mock:
    _bundle_digest is called with the manifest's file list, and a
    raised KeyError/TypeError/AttributeError there must be reported
    as "seal-record cross-check failed", not propagate."""

    def _compare_error(self, exc):
        archive, record = _pack()
        with mock.patch("textforensics.sealed_bundle._bundle_digest", side_effect=exc):
            return _verify(archive, record)

    def test_key_error_in_compare_is_reported(self):
        result = self._compare_error(KeyError("missing"))
        self.assertTrue(
            any("seal-record cross-check failed" in e for e in _seal_record_errors(result))
        )

    def test_type_error_in_compare_is_reported(self):
        result = self._compare_error(TypeError("bad type"))
        self.assertTrue(
            any("seal-record cross-check failed" in e for e in _seal_record_errors(result))
        )

    def test_attribute_error_in_compare_is_reported(self):
        result = self._compare_error(AttributeError("no attr"))
        self.assertTrue(
            any("seal-record cross-check failed" in e for e in _seal_record_errors(result))
        )
