"""CLI tests for sealed case files (Phase 3 U2, brief §(e)).

Covers ``case keygen``, ``case export --seal`` (T1/T2), and
``case verify`` over bare case files and sealed bundles, including the
MPL exit-code contract (0 verified, 1 seal failed, 2 checks could not
run) and the scope statement / gap declaration in the output.
"""

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from textforensics.constants import (
    EXIT_DOWNGRADED,
    EXIT_ERROR,
    EXIT_INCOMPLETE,
    EXIT_OK,
)

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


class CaseSealCliTests(unittest.TestCase):
    def run_cli(self, *args, input_text=None):
        return subprocess.run(
            [sys.executable, "-m", "textforensics.cli", *args],
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
        )

    def _export(self, tmp, extra=()):
        source = Path(tmp) / "source.txt"
        case = Path(tmp) / "case.json"
        source.write_text(TEXT, encoding="utf-8")
        result = self.run_cli(
            "case",
            "export",
            "--file",
            str(source),
            "--output",
            str(case),
            *extra,
        )
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)
        return case

    def test_keygen_creates_0600_key_and_public_half(self):
        with tempfile.TemporaryDirectory() as tmp:
            key_file = Path(tmp) / "sealing-key.json"
            public_file = Path(tmp) / "sealing-key.pub.json"
            result = self.run_cli(
                "case",
                "keygen",
                "--output",
                str(key_file),
                "--identity",
                "auditor",
                "--role",
                "sealer",
                "--public-out",
                str(public_file),
            )
            self.assertEqual(result.returncode, EXIT_OK, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["identity"], "auditor")
            self.assertEqual(payload["role"], "sealer")
            self.assertEqual(len(payload["public_key_hex"]), 64)
            self.assertEqual(payload["keyid"], payload["keyid"].lower())
            self.assertEqual(len(payload["keyid"]), 64)
            import os

            self.assertEqual(os.stat(key_file).st_mode & 0o777, 0o600)
            public = json.loads(public_file.read_text(encoding="utf-8"))
            self.assertEqual(public["keyid"], payload["keyid"])
            self.assertEqual(public["identity"], "auditor")
            # Refuses to overwrite an existing key file.
            again = self.run_cli(
                "case",
                "keygen",
                "--output",
                str(key_file),
            )
            self.assertEqual(again.returncode, EXIT_ERROR)
            self.assertIn("already exists", again.stderr)

    def test_export_seal_produces_verifiable_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._export(tmp, extra=("--seal",))
            bundle = Path(tmp) / "case.sealed.zip"
            record = Path(tmp) / "case.sealed.zip.seal.json"
            self.assertTrue(bundle.exists())
            self.assertTrue(record.exists())
            seal_record = json.loads(record.read_text(encoding="utf-8"))
            self.assertEqual(
                seal_record["archive_sha256"],
                hashlib.sha256(bundle.read_bytes()).hexdigest(),
            )
            verified = self.run_cli("case", "verify", str(bundle))
            self.assertEqual(verified.returncode, EXIT_OK, verified.stderr)
            report = json.loads(verified.stdout)
            self.assertEqual(report["standalone"]["exit_code"], 0)
            self.assertIn(
                "integrity since sealing only",
                report["standalone"]["scope_statement"],
            )

    def test_export_seal_with_signing_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            key_file = Path(tmp) / "sealing-key.json"
            public_file = Path(tmp) / "sealing-key.pub.json"
            keygen = self.run_cli(
                "case",
                "keygen",
                "--output",
                str(key_file),
                "--identity",
                "auditor",
                "--public-out",
                str(public_file),
            )
            self.assertEqual(keygen.returncode, EXIT_OK, keygen.stderr)
            public_hex = json.loads(keygen.stdout)["public_key_hex"]
            case = self._export(tmp, extra=("--seal", "--signing-key", str(key_file)))
            bundle = Path(tmp) / "case.sealed.zip"
            # Without the public key the signature cannot be checked:
            # MPL exit 2 (incomplete), not a pass.
            no_key = self.run_cli("case", "verify", str(bundle))
            self.assertEqual(no_key.returncode, EXIT_INCOMPLETE)
            self.assertEqual(json.loads(no_key.stdout)["standalone"]["signature"], "unavailable")
            # With the public key the T2 signature verifies.
            with_key = self.run_cli(
                "case",
                "verify",
                str(bundle),
                "--public-key",
                str(public_file),
            )
            self.assertEqual(with_key.returncode, EXIT_OK, with_key.stderr)
            self.assertEqual(json.loads(with_key.stdout)["standalone"]["signature"], "verified")
            # The hex form works too, and the case itself is T2-signed.
            with_hex = self.run_cli(
                "case",
                "verify",
                str(bundle),
                "--public-key",
                public_hex,
            )
            self.assertEqual(with_hex.returncode, EXIT_OK, with_hex.stderr)
            case_data = json.loads(case.read_text(encoding="utf-8"))
            self.assertIsNotNone(case_data["seal"]["signature"])

    def test_signing_key_without_seal_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            key_file = Path(tmp) / "sealing-key.json"
            self.run_cli("case", "keygen", "--output", str(key_file))
            source = Path(tmp) / "source.txt"
            source.write_text(TEXT, encoding="utf-8")
            result = self.run_cli(
                "case",
                "export",
                "--file",
                str(source),
                "--output",
                str(Path(tmp) / "case.json"),
                "--signing-key",
                str(key_file),
            )
            self.assertEqual(result.returncode, EXIT_ERROR)
            self.assertIn("require --seal", result.stderr)

    def test_verify_bundle_expect_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._export(tmp, extra=("--seal",))
            bundle = Path(tmp) / "case.sealed.zip"
            digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
            match = self.run_cli(
                "case",
                "verify",
                str(bundle),
                "--expect-digest",
                digest,
            )
            self.assertEqual(match.returncode, EXIT_OK, match.stderr)
            mismatch = self.run_cli(
                "case",
                "verify",
                str(bundle),
                "--expect-digest",
                "0" * 64,
            )
            self.assertEqual(mismatch.returncode, EXIT_DOWNGRADED)
            report = json.loads(mismatch.stdout)
            self.assertEqual(report["exit_code"], 1)
            self.assertIn("not verified", report["standalone"]["scope_statement"])

    def test_verify_bundle_tamper_is_exit_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._export(tmp, extra=("--seal",))
            bundle = Path(tmp) / "case.sealed.zip"
            raw = bytearray(bundle.read_bytes())
            raw[100] ^= 0xFF
            bundle.write_bytes(bytes(raw))
            result = self.run_cli("case", "verify", str(bundle))
            self.assertEqual(result.returncode, EXIT_DOWNGRADED)
            self.assertEqual(json.loads(result.stdout)["exit_code"], 1)

    def test_verify_bundle_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._export(tmp, extra=("--seal",))
            bundle = Path(tmp) / "case.sealed.zip"
            ok = self.run_cli("case", "verify", str(bundle), "--text", TEXT)
            self.assertEqual(ok.returncode, EXIT_OK, ok.stderr)
            self.assertTrue(json.loads(ok.stdout)["replay"]["valid"])
            wrong = self.run_cli(
                "case",
                "verify",
                str(bundle),
                "--text",
                "different text entirely",
            )
            self.assertEqual(wrong.returncode, EXIT_DOWNGRADED)
            self.assertIn(
                "text_hash_mismatch",
                json.loads(wrong.stdout)["replay"]["errors"],
            )

    def test_verify_bare_case_replay_and_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = self._export(tmp)
            result = self.run_cli("case", "verify", str(case), "--text", TEXT)
            self.assertEqual(result.returncode, EXIT_OK, result.stderr)
            payload = json.loads(result.stdout)
            self.assertTrue(payload["valid"])
            self.assertTrue(payload["replay"]["valid"])
            self.assertIn("gaps", payload)
            self.assertIsInstance(payload["gaps"], list)
            self.assertIn("integrity since sealing only", payload["scope"])
            self.assertIn("T1 hash seal only", payload["scope"])
            wrong = self.run_cli(
                "case",
                "verify",
                str(case),
                "--text",
                "different text entirely",
            )
            self.assertEqual(wrong.returncode, EXIT_DOWNGRADED)
            self.assertIn(
                "text_hash_mismatch",
                json.loads(wrong.stdout)["replay"]["errors"],
            )

    def test_verify_bare_case_expect_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = self._export(tmp)
            digest = hashlib.sha256(case.read_bytes()).hexdigest()
            match = self.run_cli(
                "case",
                "verify",
                str(case),
                "--expect-digest",
                digest,
            )
            self.assertEqual(match.returncode, EXIT_OK, match.stderr)
            mismatch = self.run_cli(
                "case",
                "verify",
                str(case),
                "--expect-digest",
                "0" * 64,
            )
            self.assertEqual(mismatch.returncode, EXIT_DOWNGRADED)
            self.assertIn(
                "expected digest mismatch",
                json.loads(mismatch.stdout)["errors"][0],
            )

    def test_verify_bare_case_timestamp_token(self):
        from _token_fixture import build_token_for_digest

        from textforensics.sealed_bundle import canonical_json_bytes

        with tempfile.TemporaryDirectory() as tmp:
            case = self._export(tmp)
            case_data = json.loads(case.read_text(encoding="utf-8"))
            case_bytes = canonical_json_bytes(case_data)
            token = build_token_for_digest(hashlib.sha256(case_bytes).digest())
            token_path = Path(tmp) / "token.der"
            token_path.write_bytes(token)
            ok = self.run_cli(
                "case",
                "verify",
                str(case),
                "--timestamp-token",
                str(token_path),
            )
            self.assertEqual(ok.returncode, EXIT_OK, ok.stderr)
            payload = json.loads(ok.stdout)
            self.assertTrue(payload["timestamp"]["valid"])
            self.assertIn("non-qualified", payload["scope"])
            bad_token = build_token_for_digest(hashlib.sha256(b"other").digest())
            bad_path = Path(tmp) / "bad.der"
            bad_path.write_bytes(bad_token)
            bad = self.run_cli(
                "case",
                "verify",
                str(case),
                "--timestamp-token",
                str(bad_path),
            )
            self.assertEqual(bad.returncode, EXIT_DOWNGRADED)
            self.assertFalse(json.loads(bad.stdout)["timestamp"]["valid"])


if __name__ == "__main__":
    unittest.main()
