"""Tests for the sealed bundle packer/verifier (Phase 3 U2, brief §(b)).

Covers MPL determinism (identical bytes for identical input),
seal-record digests, T2 signatures, T3 timestamp tokens, the
seal_failed replay gate, and the refusal paths (invalid case,
non-v3 case, bad token).
"""

import hashlib
import io
import json
import unittest
import zipfile

from textforensics.casefile import replay_case_file, seal_case_file
from textforensics.report import build_forensic_bundle
from textforensics.schema import load_schema
from textforensics.sealed_bundle import (
    COMMENT_PREFIX,
    SealedBundleError,
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


def sealed_case():
    bundle = build_forensic_bundle(TEXT).to_dict()
    return seal_case_file(bundle, deterministic=True, fixed_timestamp="1970-01-01T00:00:00+00:00")


def read_zip(data):
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return {name: zf.read(name) for name in zf.namelist()}, zf.comment.decode("ascii")


class PackTests(unittest.TestCase):
    def test_pack_is_deterministic(self):
        case = sealed_case()
        first, _ = pack_sealed_bundle(case)
        second, _ = pack_sealed_bundle(case)
        self.assertEqual(first, second)
        self.assertEqual(hashlib.sha256(first).hexdigest(), hashlib.sha256(second).hexdigest())

    def test_pack_structure_is_mpl_normalised(self):
        case = sealed_case()
        archive, record = pack_sealed_bundle(case)
        contents, comment = read_zip(archive)
        self.assertEqual(sorted(contents), ["case.json", "manifest.json", "verify.py"])
        self.assertTrue(comment.startswith(COMMENT_PREFIX))
        self.assertEqual(
            comment[len(COMMENT_PREFIX) :],
            hashlib.sha256(contents["manifest.json"]).hexdigest(),
        )
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            for info in zf.infolist():
                self.assertEqual(info.compress_type, zipfile.ZIP_STORED)
                self.assertEqual(info.date_time, (1980, 1, 1, 0, 0, 0))
                self.assertEqual(info.create_system, 0)
                self.assertEqual(info.external_attr, 0o644 << 16)
                self.assertEqual(info.extra, b"")
                self.assertEqual(info.comment, b"")

    def test_manifest_matches_schema(self):
        import jsonschema

        case = sealed_case()
        _, record = pack_sealed_bundle(case)
        jsonschema.validate(record["manifest"], load_schema("sealed-bundle-manifest"))

    def test_seal_record_digests(self):
        case = sealed_case()
        archive, record = pack_sealed_bundle(case)
        contents, _ = read_zip(archive)
        self.assertEqual(
            record["manifest_sha256"],
            hashlib.sha256(contents["manifest.json"]).hexdigest(),
        )
        self.assertEqual(record["archive_sha256"], hashlib.sha256(archive).hexdigest())
        listed = b"".join(contents[item["path"]] for item in record["manifest"]["files"])
        self.assertEqual(record["bundle_sha256"], hashlib.sha256(listed).hexdigest())
        self.assertEqual(record["manifest"]["context"]["case_id"], case["case_sha256"])
        self.assertEqual(
            record["manifest"]["context"]["input_sha256"],
            case["input"]["content_sha256"],
        )
        self.assertIsNone(record["signature"])
        self.assertIsNone(record["timestamp"])
        self.assertIsNone(record["digest_publication"])

    def test_pack_refuses_non_v3_case(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        v2 = seal_case_file(bundle, version="v2")
        with self.assertRaises(SealedBundleError):
            pack_sealed_bundle(v2)

    def test_pack_refuses_invalid_case(self):
        case = sealed_case()
        case["limitations"]["plain_language"]["human_fpr"] = "forged"
        with self.assertRaises(SealedBundleError):
            pack_sealed_bundle(case)

    def test_pack_refuses_seed_without_signer(self):
        with self.assertRaises(SealedBundleError):
            pack_sealed_bundle(sealed_case(), signing_seed=SEED)


class SignaturePackTests(unittest.TestCase):
    def test_signed_bundle_verifies(self):
        case = sealed_case()
        archive, record = pack_sealed_bundle(case, signing_seed=SEED, signer=SIGNER)
        self.assertIsNotNone(record["signature"])
        self.assertEqual(record["manifest"]["context"]["signer"]["identity"], "strmt7")
        result = verify_sealed_bundle(archive, public_key=public_key_from_seed(SEED))
        self.assertEqual(result["exit_code"], 0, json.dumps(result, indent=2))
        self.assertEqual(result["standalone"]["signature"], "verified")
        self.assertEqual(result["standalone"]["exit_code"], 0)

    def test_signed_bundle_without_key_is_incomplete(self):
        case = sealed_case()
        archive, _ = pack_sealed_bundle(case, signing_seed=SEED, signer=SIGNER)
        result = verify_sealed_bundle(archive)
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(result["standalone"]["signature"], "unavailable")

    def test_seal_record_cross_check_passes(self):
        case = sealed_case()
        archive, record = pack_sealed_bundle(case, signing_seed=SEED, signer=SIGNER)
        result = verify_sealed_bundle(
            archive,
            public_key=public_key_from_seed(SEED),
            seal_record=record,
        )
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["seal_record"]["errors"], [])

    def test_seal_record_tamper_is_detected(self):
        case = sealed_case()
        archive, record = pack_sealed_bundle(case)
        record["archive_sha256"] = "0" * 64
        result = verify_sealed_bundle(archive, seal_record=record)
        self.assertEqual(result["exit_code"], 1)
        self.assertTrue(result["seal_record"]["errors"])

    def test_malformed_seal_record_is_an_error_not_a_crash(self):
        case = sealed_case()
        archive, _ = pack_sealed_bundle(case)
        result = verify_sealed_bundle(archive, seal_record=["not", "a", "dict"])
        self.assertEqual(result["exit_code"], 1)
        self.assertIn("seal_record must be a JSON object", result["seal_record"]["errors"])

    def test_manifest_listing_missing_file_is_an_error_not_a_crash(self):
        case = sealed_case()
        archive, record = pack_sealed_bundle(case)
        # Rebuild the zip without case.json; the manifest still lists it.
        contents, _ = read_zip(archive)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
            for name in ("manifest.json", "verify.py"):
                info = zipfile.ZipInfo(filename=name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_STORED
                info.create_system = 0
                info.external_attr = 0o644 << 16
                zf.writestr(info, contents[name])
            zf.comment = (
                COMMENT_PREFIX + hashlib.sha256(contents["manifest.json"]).hexdigest()
            ).encode("ascii")
        result = verify_sealed_bundle(buf.getvalue(), seal_record=record)
        self.assertEqual(result["exit_code"], 1)
        self.assertTrue(result["seal_record"]["errors"])


class TimestampPackTests(unittest.TestCase):
    def test_token_pack_and_verify(self):
        from _token_fixture import build_token_for_digest

        case = sealed_case()
        case_bytes = canonical_json_bytes(case)
        token = build_token_for_digest(hashlib.sha256(case_bytes).digest())
        archive, record = pack_sealed_bundle(
            case, timestamp_token=token, tsa_url="https://freetsa.org/tsr"
        )
        self.assertIsNotNone(record["timestamp"])
        self.assertEqual(record["timestamp"]["qualified"], "unknown")
        self.assertEqual(record["timestamp"]["tsa_url"], "https://freetsa.org/tsr")
        self.assertEqual(record["timestamp"]["token_sha256"], hashlib.sha256(token).hexdigest())
        contents, _ = read_zip(archive)
        self.assertIn("timestamp-token.der", contents)
        result = verify_sealed_bundle(archive, seal_record=record)
        self.assertEqual(result["exit_code"], 0, json.dumps(result, indent=2))
        self.assertEqual(result["standalone"]["timestamp"]["gen_time"], "20261107120000Z")

    def test_token_with_wrong_imprint_is_refused(self):
        from _token_fixture import build_token_for_digest

        token = build_token_for_digest(hashlib.sha256(b"other").digest())
        with self.assertRaises(SealedBundleError):
            pack_sealed_bundle(sealed_case(), timestamp_token=token)


class ReplayGateTests(unittest.TestCase):
    def test_replay_runs_when_seal_passes(self):
        case = sealed_case()
        archive, _ = pack_sealed_bundle(case)
        result = verify_sealed_bundle(archive, text=TEXT)
        self.assertEqual(result["exit_code"], 0, json.dumps(result, indent=2))
        self.assertTrue(result["replay"]["valid"])
        self.assertEqual(result["replay"]["checks"]["text"]["status"], "matched")

    def test_replay_aborts_on_text_mismatch(self):
        case = sealed_case()
        archive, _ = pack_sealed_bundle(case)
        result = verify_sealed_bundle(archive, text="different text entirely")
        self.assertEqual(result["exit_code"], 1)
        self.assertIn("text_hash_mismatch", result["replay"]["errors"])

    def test_replay_unavailable_when_seal_fails(self):
        case = sealed_case()
        archive, record = pack_sealed_bundle(case)
        # Corrupt the bundle bytes after packing: the seal fails.
        raw = bytearray(archive)
        raw[100] ^= 0xFF
        result = verify_sealed_bundle(bytes(raw), text=TEXT)
        self.assertEqual(result["exit_code"], 1)
        self.assertEqual(result["replay"]["status"], "unavailable")
        self.assertEqual(result["replay"]["reason"], "seal_failed")

    def test_replay_unavailable_when_seal_incomplete(self):
        # A signed bundle verified without a key: the standalone check
        # is incomplete (exit 2), so replay must not run at all.
        case = sealed_case()
        archive, _ = pack_sealed_bundle(case, signing_seed=SEED, signer=SIGNER)
        result = verify_sealed_bundle(archive, text=TEXT)
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(result["replay"]["status"], "unavailable")
        self.assertEqual(result["replay"]["reason"], "seal_failed")

    def test_replay_matches_package_replay(self):
        case = sealed_case()
        archive, _ = pack_sealed_bundle(case)
        result = verify_sealed_bundle(archive, text=TEXT)
        direct = replay_case_file(case, text=TEXT)
        self.assertEqual(result["replay"]["valid"], direct["valid"])
        self.assertEqual(result["replay"]["errors"], direct["errors"])


if __name__ == "__main__":
    unittest.main()
