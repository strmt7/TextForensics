"""Tests for the standalone bundle verifier (Phase 3 U2, brief §(e)).

The verifier lives in ``src/textforensics/_standalone_verify.py`` and
must run with the standard library only, without the package
installed.  Bundles here are built by a minimal MPL packer in this
file (an independent implementation of the normalisation), which also
cross-checks the real packer in ``sealed_bundle.py``.
"""

import hashlib
import importlib.util
import io
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from _token_fixture import build_token_for_digest

from textforensics.casefile import seal_case_file, verify_case_file
from textforensics.report import build_forensic_bundle

REPO_ROOT = Path(__file__).resolve().parent.parent
STANDALONE_PATH = REPO_ROOT / "src" / "textforensics" / "_standalone_verify.py"

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


def load_standalone():
    spec = importlib.util.spec_from_file_location("standalone_verify", STANDALONE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def canonical_json(payload):
    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def make_manifest(files, *, signature=None, case_id=None):
    """Build the MPL manifest for *files* (name -> bytes)."""
    manifest = {
        "schema": "textforensics.sealed-bundle-manifest/v1",
        "context": {
            "tool_version": "0.1.0",
            "case_id": case_id,
            "input_sha256": None,
            "registry_sha256": None,
            "signature": signature,
            "timestamp_token_sha256": None,
            "appeal_checklist_digest": None,
        },
        "files": [
            {
                "path": name,
                "role": {
                    "case.json": "case-file",
                    "manifest.json": "manifest",
                    "verify.py": "verifier",
                    "timestamp-token.der": "timestamp-token",
                }.get(name, "other"),
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
            for name, data in sorted(files.items())
            if name != "manifest.json"
        ],
    }
    return manifest


def pack_bundle(entries, *, comment_override=None, deflate=None, sort=True):
    """Pack *entries* (name -> bytes) with MPL normalisation."""
    names = sorted(entries) if sort else list(entries)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        for name in names:
            info = zipfile.ZipInfo(filename=name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = (
                zipfile.ZIP_DEFLATED if deflate and name in deflate else zipfile.ZIP_STORED
            )
            info.create_system = 0
            info.external_attr = 0o644 << 16
            zf.writestr(info, entries[name])
    data = buf.getvalue()
    manifest_bytes = entries.get("manifest.json", b"")
    comment = comment_override
    if comment is None:
        comment = "mpl-bundle-sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    # Rewrite the archive comment (zipfile does not expose it on write).
    return _set_archive_comment(data, comment.encode("ascii"))


def _set_archive_comment(data, comment):
    offset = data.rfind(b"PK\x05\x06")
    assert offset >= 0
    head = data[: offset + 20]
    tail = data[offset + 22 :]
    return head + struct.pack("<H", len(comment)) + comment + tail


def build_case_bytes():
    bundle = build_forensic_bundle(TEXT).to_dict()
    case = seal_case_file(bundle, deterministic=True, fixed_timestamp="1970-01-01T00:00:00+00:00")
    assert verify_case_file(case)["valid"]
    return canonical_json(case), case


def build_bundle(*, signature=None, token_der=None, case_bytes=None, case=None):
    """Build a valid sealed bundle; returns (bundle_bytes, manifest, case)."""
    if case_bytes is None:
        case_bytes, case = build_case_bytes()
    else:
        assert case is not None
    verifier_bytes = STANDALONE_PATH.read_bytes()
    entries = {"case.json": case_bytes, "verify.py": verifier_bytes}
    if token_der is not None:
        entries["timestamp-token.der"] = token_der
    manifest = make_manifest(entries, signature=signature, case_id=case["case_sha256"])
    manifest_bytes = canonical_json(manifest)
    entries["manifest.json"] = manifest_bytes
    return pack_bundle(entries), manifest, case


class StandaloneSelfContainedTests(unittest.TestCase):
    def test_no_package_imports(self):
        source = STANDALONE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("import textforensics", source)
        self.assertNotIn("from textforensics", source)
        self.assertNotIn("from .", source)

    def test_runs_without_the_package_installed(self):
        bundle, _, _ = build_bundle()
        tmp = Path(tempfile.mkdtemp(prefix="standalone-verify-"))
        try:
            verifier_copy = tmp / "verify.py"
            shutil.copyfile(STANDALONE_PATH, verifier_copy)
            bundle_path = tmp / "bundle.zip"
            bundle_path.write_bytes(bundle)
            env = dict(os.environ)
            env.pop("PYTHONPATH", None)
            result = subprocess.run(
                [sys.executable, str(verifier_copy), str(bundle_path)],
                capture_output=True,
                text=True,
                cwd=str(tmp),
                env=env,
                timeout=120,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            # stdout is the JSON report followed by the scope statement line.
            lines = result.stdout.strip().splitlines()
            scope_statement = lines[-1]
            report = json.loads("\n".join(lines[:-1]))
            self.assertEqual(report["tool"], "textforensics-standalone-verify")
            self.assertIn("integrity since sealing only", scope_statement)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class StandaloneEd25519Tests(unittest.TestCase):
    def test_rfc8032_test_vector(self):
        mod = load_standalone()
        # RFC 8032 section 7.1, TEST 1 (empty message).
        public_key = bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        )
        signature = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        self.assertTrue(mod._ed25519_verify(public_key, b"", signature))
        self.assertFalse(mod._ed25519_verify(public_key, b"x", signature))

    def test_agrees_with_package_implementation(self):
        from textforensics.ed25519 import public_key_from_seed, sign, verify

        mod = load_standalone()
        for seed in (bytes(range(32)), bytes([7]) * 32, os.urandom(32)):
            public_key = public_key_from_seed(seed)
            message = os.urandom(64)
            signature = sign(seed, message)
            self.assertTrue(mod._ed25519_verify(public_key, message, signature))
            self.assertTrue(verify(public_key, message, signature))
            # Flip a bit inside S (byte 40): replacing the last byte
            # with zero is a no-op whenever S's top byte is already
            # zero, which made this assertion flaky.
            tampered = signature[:40] + bytes([signature[40] ^ 0x01]) + signature[41:]
            self.assertFalse(mod._ed25519_verify(public_key, message, tampered))


class StandaloneBundleTests(unittest.TestCase):
    def setUp(self):
        self.mod = load_standalone()

    def _check_status(self, report, check_id):
        for check in report["checks"]:
            if check["id"] == check_id:
                return check["status"]
        self.fail(f"check {check_id} not present")

    def test_valid_bundle_verifies(self):
        bundle, _, _ = build_bundle()
        report = self.mod.verify_bundle_bytes(bundle)
        self.assertEqual(report["exit_code"], 0, json.dumps(report, indent=2))
        self.assertEqual(self._check_status(report, "seal_manifest_digest"), "pass")
        self.assertEqual(self._check_status(report, "seal_case_hash"), "pass")
        self.assertEqual(self._check_status(report, "seal_custody"), "pass")
        self.assertEqual(self._check_status(report, "seal_checklist"), "pass")
        self.assertEqual(report["signature"], "absent")
        self.assertEqual(report["replay"]["status"], "unavailable")
        self.assertIn("integrity since sealing only", report["scope_statement"])
        self.assertIn("origin: unauthenticated", report["scope_statement"])
        self.assertEqual(len(report["honest_limits"]), 2)

    def test_tampered_case_fails(self):
        case_bytes, case = build_case_bytes()
        tampered = json.loads(case_bytes.decode("utf-8"))
        tampered["limitations"]["plain_language"]["human_fpr"] = "forged"
        bundle, _, _ = build_bundle(case_bytes=canonical_json(tampered), case=case)
        report = self.mod.verify_bundle_bytes(bundle)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._check_status(report, "seal_case_hash"), "fail")
        # The manifest still matches (it was rebuilt over the tampered
        # case), so only the case hash fails.
        self.assertEqual(self._check_status(report, "seal_manifest_digests"), "pass")

    def test_wrong_manifest_digest_fails(self):
        case_bytes, case = build_case_bytes()
        verifier_bytes = STANDALONE_PATH.read_bytes()
        entries = {"case.json": case_bytes, "verify.py": verifier_bytes}
        manifest = make_manifest(entries, case_id=case["case_sha256"])
        # The ZIP CRCs stay valid; only the manifest's recorded digest
        # is wrong — the seal check must catch it.
        manifest["files"][0]["sha256"] = "0" * 64
        entries["manifest.json"] = canonical_json(manifest)
        bundle = pack_bundle(entries)
        report = self.mod.verify_bundle_bytes(bundle)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._check_status(report, "seal_manifest_digests"), "fail")

    def test_corrupt_zip_entry_fails_on_read(self):
        bundle, _, _ = build_bundle()
        raw = bytearray(bundle)
        pos = raw.find(b"forensic_bundle")
        raw[pos] ^= 0xFF
        report = self.mod.verify_bundle_bytes(bytes(raw))
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._check_status(report, "container_read"), "fail")

    def test_wrong_comment_digest_fails(self):
        case_bytes, case = build_case_bytes()
        verifier_bytes = STANDALONE_PATH.read_bytes()
        entries = {"case.json": case_bytes, "verify.py": verifier_bytes}
        manifest = make_manifest(entries, case_id=case["case_sha256"])
        entries["manifest.json"] = canonical_json(manifest)
        bundle = pack_bundle(entries, comment_override="mpl-bundle-sha256:" + "0" * 64)
        report = self.mod.verify_bundle_bytes(bundle)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._check_status(report, "seal_manifest_digest"), "fail")

    def test_deflated_entry_fails(self):
        case_bytes, case = build_case_bytes()
        verifier_bytes = STANDALONE_PATH.read_bytes()
        entries = {"case.json": case_bytes, "verify.py": verifier_bytes}
        manifest = make_manifest(entries, case_id=case["case_sha256"])
        entries["manifest.json"] = canonical_json(manifest)
        bundle = pack_bundle(entries, deflate={"case.json"})
        report = self.mod.verify_bundle_bytes(bundle)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._check_status(report, "container_stored_only"), "fail")

    def test_unsorted_entries_fail(self):
        case_bytes, case = build_case_bytes()
        verifier_bytes = STANDALONE_PATH.read_bytes()
        entries = {"verify.py": verifier_bytes, "case.json": case_bytes}
        manifest = make_manifest(entries, case_id=case["case_sha256"])
        entries["manifest.json"] = canonical_json(manifest)
        bundle = pack_bundle(entries, sort=False)
        report = self.mod.verify_bundle_bytes(bundle)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._check_status(report, "container_sorted_entries"), "fail")

    def test_missing_manifest_fails(self):
        case_bytes, _ = build_case_bytes()
        entries = {"case.json": case_bytes, "verify.py": STANDALONE_PATH.read_bytes()}
        bundle = pack_bundle(entries)
        report = self.mod.verify_bundle_bytes(bundle)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._check_status(report, "container_required_entries"), "fail")

    def test_garbage_bytes_fail(self):
        report = self.mod.verify_bundle_bytes(b"not a zip at all")
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._check_status(report, "container_eocd"), "fail")

    def test_expect_digest(self):
        bundle, _, _ = build_bundle()
        digest = hashlib.sha256(bundle).hexdigest()
        report = self.mod.verify_bundle_bytes(bundle, expected_digest=digest)
        self.assertEqual(report["exit_code"], 0)
        self.assertEqual(self._check_status(report, "seal_expected_digest"), "pass")
        report = self.mod.verify_bundle_bytes(bundle, expected_digest="0" * 64)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._check_status(report, "seal_expected_digest"), "fail")
        report = self.mod.verify_bundle_bytes(bundle)
        self.assertEqual(report["exit_code"], 0)
        self.assertTrue(any("origin not authenticated" in w for w in report["warnings"]))

    def test_entry_count_cap(self):
        entries = {f"entry-{i:04d}.txt": b"" for i in range(1025)}
        entries["manifest.json"] = canonical_json(make_manifest(entries))
        entries["case.json"] = b"{}"
        bundle = pack_bundle(entries)
        report = self.mod.verify_bundle_bytes(bundle)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._check_status(report, "container_entry_count"), "fail")

    def test_checklist_inconsistency_fails(self):
        bundle_dict = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle_dict, process={"items": {"D1": {"status": "satisfied"}}})
        self.assertFalse(verify_case_file(case)["valid"])
        bundle, _, _ = build_bundle(case_bytes=canonical_json(case), case=case)
        report = self.mod.verify_bundle_bytes(bundle)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self._check_status(report, "seal_checklist"), "fail")


class StandaloneSignatureTests(unittest.TestCase):
    def setUp(self):
        self.mod = load_standalone()

    def _signed_bundle(self, seed):
        from textforensics.dsse import sign_envelope
        from textforensics.sealing import public_key_from_seed

        case_bytes, case = build_case_bytes()
        verifier_bytes = STANDALONE_PATH.read_bytes()
        entries = {"case.json": case_bytes, "verify.py": verifier_bytes}
        manifest = make_manifest(entries, case_id=case["case_sha256"])
        manifest_bytes = canonical_json(manifest)
        envelope = sign_envelope("textforensics.sealed-bundle-manifest/v1", manifest_bytes, seed)
        manifest["context"]["signature"] = envelope
        manifest_bytes = canonical_json(manifest)
        entries["manifest.json"] = manifest_bytes
        bundle = pack_bundle(entries)
        return bundle, public_key_from_seed(seed)

    def test_signature_verifies_with_key(self):
        seed = bytes(range(32))
        bundle, public_key = self._signed_bundle(seed)
        report = self.mod.verify_bundle_bytes(bundle, public_key=public_key)
        self.assertEqual(report["exit_code"], 0, json.dumps(report, indent=2))
        self.assertEqual(report["signature"], "verified")
        self.assertIn("key fingerprint", report["scope_statement"])

    def test_signature_with_standard_alphabet_chars_verifies(self):
        # Regression (CI: Core Python 3.15 only): the standalone
        # verifier decoded the DSSE signature with urlsafe_b64decode,
        # which CPython 3.15 (CVE-2025-12781 / gh-125346) no longer
        # accepts '+'/'/' in. The signer writes standard base64, so a
        # signature containing those characters must verify.
        # bytes(range(32)) is such a seed — assert it, so this test is
        # never vacuous.
        from textforensics.dsse import sign_envelope

        seed = bytes(range(32))
        envelope = sign_envelope("textforensics.sealed-bundle-manifest/v1", b"probe", seed)
        sig = envelope["signatures"][0]["sig"]
        self.assertTrue("+" in sig or "/" in sig, sig)
        bundle, public_key = self._signed_bundle(seed)
        report = self.mod.verify_bundle_bytes(bundle, public_key=public_key)
        self.assertEqual(report["exit_code"], 0, json.dumps(report, indent=2))
        self.assertEqual(report["signature"], "verified")

    def test_urlsafe_only_base64_is_rejected(self):
        # The format is standard base64, not base64url: a value using
        # the URL-safe alphabet ('-'/'_') is not canonical here.
        with self.assertRaises(ValueError):
            self.mod._b64decode_strict("ab-_" * 11)
        # ...and a standard-base64 value containing '+'/'/' decodes.
        decoded = self.mod._b64decode_strict(
            "v27Gkws5pcEprzaQDArGwS8CxkifBC3t+U2g455evxX0l/"
            "Zed3KmDB69es9GI7JGRQ+clhHN78GaZe+TW6zSDg=="
        )
        self.assertEqual(len(decoded), 64)

    def test_signature_without_key_is_incomplete(self):
        seed = bytes(range(32))
        bundle, _ = self._signed_bundle(seed)
        report = self.mod.verify_bundle_bytes(bundle)
        self.assertEqual(report["exit_code"], 2)
        self.assertEqual(report["signature"], "unavailable")

    def test_signature_over_other_payload_fails(self):
        # A valid DSSE signature over bytes that are NOT this manifest
        # must not authenticate the bundle (payload binding).
        from textforensics.dsse import sign_envelope
        from textforensics.sealing import public_key_from_seed

        seed = bytes(range(32))
        case_bytes, case = build_case_bytes()
        verifier_bytes = STANDALONE_PATH.read_bytes()
        entries = {"case.json": case_bytes, "verify.py": verifier_bytes}
        manifest = make_manifest(entries, case_id=case["case_sha256"])
        envelope = sign_envelope(
            "textforensics.sealed-bundle-manifest/v1",
            b"some other manifest bytes",
            seed,
        )
        manifest["context"]["signature"] = envelope
        entries["manifest.json"] = canonical_json(manifest)
        bundle = pack_bundle(entries)
        report = self.mod.verify_bundle_bytes(bundle, public_key=public_key_from_seed(seed))
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(report["signature"], "failed")

    def test_signature_with_wrong_key_fails(self):
        seed = bytes(range(32))
        bundle, _ = self._signed_bundle(seed)
        from textforensics.sealing import public_key_from_seed

        wrong_key = public_key_from_seed(bytes([9]) * 32)
        report = self.mod.verify_bundle_bytes(bundle, public_key=wrong_key)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(report["signature"], "failed")


class StandaloneTimestampTests(unittest.TestCase):
    def setUp(self):
        self.mod = load_standalone()

    def test_token_over_case_bytes_verifies(self):
        case_bytes, case = build_case_bytes()
        digest = hashlib.sha256(case_bytes).digest()
        token = build_token_for_digest(digest)
        bundle, _, _ = build_bundle(token_der=token, case_bytes=case_bytes, case=case)
        report = self.mod.verify_bundle_bytes(bundle)
        self.assertEqual(report["exit_code"], 0, json.dumps(report, indent=2))
        self.assertIsNotNone(report["timestamp"])
        self.assertEqual(report["timestamp"]["gen_time"], "20261107120000Z")
        self.assertEqual(report["timestamp"]["qualified"], "unknown")
        self.assertIn("non-qualified", report["scope_statement"])

    def test_token_over_other_digest_fails(self):
        case_bytes, case = build_case_bytes()
        token = build_token_for_digest(hashlib.sha256(b"other").digest())
        bundle, _, _ = build_bundle(token_der=token, case_bytes=case_bytes, case=case)
        report = self.mod.verify_bundle_bytes(bundle)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(
            [c for c in report["checks"] if c["id"] == "seal_timestamp"][0]["status"],
            "fail",
        )

    def test_ec_curve_generators_are_on_curve_with_correct_order(self):
        # The standalone copy of the table is a separate literal (it
        # does not share timestamp.py's table), and it shipped with the
        # same wrong P-384 gy and n. Pin it the same way: each
        # generator on its curve, order below p, n*G the point at
        # infinity. Arithmetic is local to the test.
        def add(p1, p2, p, a):
            if p1 is None:
                return p2
            if p2 is None:
                return p1
            if p1[0] == p2[0] and (p1[1] + p2[1]) % p == 0:
                return None
            if p1 == p2:
                lam = (3 * p1[0] * p1[0] + a) * pow(2 * p1[1], -1, p) % p
            else:
                lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], -1, p) % p
            x3 = (lam * lam - p1[0] - p2[0]) % p
            return (x3, (lam * (p1[0] - x3) - p1[1]) % p)

        def mult(k, point, p, a):
            result = None
            addend = point
            while k:
                if k & 1:
                    result = add(result, addend, p, a)
                addend = add(addend, addend, p, a)
                k >>= 1
            return result

        for name in ("P-256", "P-384"):
            curve = self.mod._EC_CURVES[name]
            p, a, b, n = curve["p"], curve["a"], curve["b"], curve["n"]
            gx, gy = curve["gx"], curve["gy"]
            self.assertEqual((gy * gy) % p, (gx * gx * gx + a * gx + b) % p, f"{name} G on curve")
            self.assertLess(n, p, f"{name} order below p")
            self.assertIsNone(mult(n, (gx, gy), p, a), f"{name} n*G is infinity")


if __name__ == "__main__":
    unittest.main()
