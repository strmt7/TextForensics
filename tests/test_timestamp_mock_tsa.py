"""Tests for the RFC 3161 TSA client against a local mock TSA.

Phase 5 U2-leftovers, item 2.  No test touches the network beyond
loopback: the mock is a stdlib ``http.server`` on 127.0.0.1 that
accepts a TimeStampReq and returns a TimeStampResp carrying a real
CMS token built with the production DER encoder (``_token_fixture``)
plus ``cryptography`` RSA signing.  The client verifies the mock's
token through ``verify_timestamp_token`` exactly as it would a live
TSA's token.  Live-TSA interop is a manual development check,
recorded in ``docs/TSA_INTEROP.md``, not a CI test.
"""

import hashlib
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from _token_fixture import build_token_for_digest

from textforensics.timestamp import (
    TimestampError,
    _children,
    _der_integer,
    _der_sequence,
    _parse_all,
    _parse_integer,
    request_timestamp,
)

DIGEST = hashlib.sha256(b"mock-tsa-round-trip-fixture").digest()
WRONG_DIGEST = hashlib.sha256(b"mock-tsa-wrong-digest").digest()
NONCE = 987654321098765432


def _parse_request(digest_and_nonce):
    """Extract (digest, nonce) from a TimeStampReq with the production parser."""
    root = _parse_all(digest_and_nonce)
    fields = _children(root)
    imprint = _children(fields[1])
    digest = imprint[1].content
    nonce = _parse_integer(fields[2])
    return digest, nonce


def _response_for_token(token_der):
    """Wrap a TimeStampToken in a granted TimeStampResp."""
    return _der_sequence(_der_sequence(_der_integer(0)), token_der)


class _MockTSAHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # keep the test output clean
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.server.last_request = {
            "content_type": self.headers.get("Content-Type"),
            "body": body,
        }
        mode = self.server.mode
        if mode == "http-500":
            payload = b"mock TSA failure"
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if mode == "rejection":
            payload = _der_sequence(_der_sequence(_der_integer(2)))
            self._send_token_response(payload)
            return
        digest, nonce = _parse_request(body)
        if mode == "wrong-digest":
            token = build_token_for_digest(WRONG_DIGEST, nonce=nonce)
        else:  # "ok"
            token = build_token_for_digest(digest, nonce=nonce)
        self._send_token_response(_response_for_token(token))

    def _send_token_response(self, payload):
        self.send_response(200)
        self.send_header("Content-Type", "application/timestamp-reply")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class MockTSAClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _MockTSAHandler)
        cls.server.daemon_threads = True
        cls.server.mode = "ok"
        cls.server.last_request = {}
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}/tsr"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=10)

    def test_round_trip_through_request_timestamp(self):
        self.server.mode = "ok"
        report = request_timestamp(DIGEST, self.url, nonce=NONCE, timeout=10.0)
        self.assertTrue(report["valid"], report["errors"])
        self.assertEqual(report["gen_time"], "20261107120000Z")
        self.assertEqual(report["policy"], "1.2.3.4.5")
        self.assertEqual(report["serial_number"], 1)
        self.assertEqual(report["nonce"], NONCE)
        self.assertIsNotNone(report["signer_cert_fingerprint"])
        self.assertIsNotNone(report.get("token_der"))
        self.assertEqual(report["tsa_url"], self.url)
        # Offline: qualification is always unknown, honestly labelled.
        self.assertEqual(report["qualified"], "unknown")
        # The mock saw a real TimeStampReq for exactly this digest.
        seen = self.server.last_request
        self.assertEqual(seen["content_type"], "application/timestamp-query")
        seen_digest, seen_nonce = _parse_request(seen["body"])
        self.assertEqual(seen_digest, DIGEST)
        self.assertEqual(seen_nonce, NONCE)

    def test_wrong_digest_token_rejected(self):
        self.server.mode = "wrong-digest"
        with self.assertRaises(TimestampError) as ctx:
            request_timestamp(DIGEST, self.url, nonce=NONCE, timeout=10.0)
        self.assertIn("message_imprint_mismatch", str(ctx.exception))

    def test_non_200_response_handled(self):
        self.server.mode = "http-500"
        with self.assertRaises(TimestampError) as ctx:
            request_timestamp(DIGEST, self.url, nonce=NONCE, timeout=10.0)
        self.assertIn("TSA HTTP error: 500", str(ctx.exception))

    def test_rejection_status_handled(self):
        self.server.mode = "rejection"
        with self.assertRaises(TimestampError) as ctx:
            request_timestamp(DIGEST, self.url, nonce=NONCE, timeout=10.0)
        self.assertIn("did not grant", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
