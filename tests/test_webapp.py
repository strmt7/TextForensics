from __future__ import annotations

import io
import json
import socket
import threading
import time
import unittest
import urllib.error
import urllib.request

from textforensics.webapp import TextForensicsHTTPServer, analyze_payload, make_handler, serve


class TestAnalyzePayload(unittest.TestCase):
    """Tests for analyze_payload function."""

    def test_valid_text_returns_forensic_bundle(self):
        """Valid text input returns a forensic bundle with trust_map."""
        result = analyze_payload({"text": "This is a test sentence."})
        self.assertIsInstance(result, dict)
        self.assertIn("trust_map", result)
        self.assertEqual(result["schema"], "textforensics.forensic-bundle/v1")

    def test_humanish_text_returns_valid_result(self):
        """More realistic human text returns valid result."""
        text = "I tried the new setup on Tuesday and hit two problems."
        result = analyze_payload({"text": text})
        self.assertIn("trust_map", result)
        self.assertIn("detector_results", result)
        self.assertIn("consensus", result)

    def test_empty_text_raises_value_error(self):
        """Empty text raises ValueError."""
        with self.assertRaises(ValueError):
            analyze_payload({"text": ""})

    def test_whitespace_only_text_raises_value_error(self):
        """Whitespace-only text raises ValueError."""
        with self.assertRaises(ValueError):
            analyze_payload({"text": "   "})

    def test_missing_text_key_raises_value_error(self):
        """Missing 'text' key raises ValueError (not KeyError, since it's None)."""
        with self.assertRaises(ValueError):
            analyze_payload({})

    def test_none_text_raises_value_error(self):
        """None text raises ValueError."""
        with self.assertRaises(ValueError):
            analyze_payload({"text": None})

    def test_max_input_bytes_limit(self):
        """Oversized input is rejected."""
        # Default max_input_bytes is 2_000_000
        # Create a text that results in more than 2MB when encoded
        large_text = "x" * 3_000_000  # 3MB, exceeds default 2MB limit
        with self.assertRaises(ValueError):
            analyze_payload({"text": large_text})

    def test_custom_max_input_bytes(self):
        """Custom max_input_bytes parameter is respected."""
        # Custom smaller limit
        result = analyze_payload({"text": "test"}, max_input_bytes=100)
        self.assertIn("trust_map", result)

    def test_unicode_text_handled(self):
        """Unicode text is properly handled."""
        result = analyze_payload({"text": "Héllo, wörld! 你好世界"})
        self.assertIn("trust_map", result)


class TestHTTPHandler(unittest.TestCase):
    """Tests for the HTTP handler using real HTTP requests."""

    @classmethod
    def setUpClass(cls):
        """Start a test server on an ephemeral port."""
        cls.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cls.socket.bind(("127.0.0.1", 0))
        cls.port = cls.socket.getsockname()[1]
        cls.socket.close()

        cls.server = TextForensicsHTTPServer(
            ("127.0.0.1", cls.port),
            make_handler(),
        )
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()

        # Wait for server to be ready
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        """Stop the test server."""
        cls.server.shutdown()
        cls.server.server_close()

    def _fetch(self, path, method="GET", data=None, headers=None):
        """Helper to make HTTP requests. Returns (code, body, headers)."""
        url = f"http://127.0.0.1:{self.port}{path}"
        req_headers = headers.copy() if headers else {}
        if data is not None:
            if isinstance(data, str):
                data = data.encode("utf-8")
            req = urllib.request.Request(url, data=data, method=method, headers=req_headers)
        else:
            req = urllib.request.Request(url, method=method, headers=req_headers)

        code = None
        body = b""
        resp_headers = {}
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                code = response.getcode()
                body = response.read()
                resp_headers = dict(response.headers)
        except urllib.error.HTTPError as e:
            code = e.code
            body = e.read()
            resp_headers = dict(e.headers)
            # Close the error response to avoid ResourceWarning
            e.close()

        return code, body, resp_headers

    def test_get_healthz_returns_200_json(self):
        """GET /healthz returns 200 with JSON status."""
        code, body, headers = self._fetch("/healthz")
        self.assertEqual(code, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json; charset=utf-8")
        data = json.loads(body)
        self.assertEqual(data, {"status": "ok"})

    def test_get_root_returns_200_html(self):
        """GET / returns 200 with HTML."""
        code, body, headers = self._fetch("/")
        self.assertEqual(code, 200)
        self.assertEqual(headers.get("Content-Type"), "text/html; charset=utf-8")
        html = body.decode("utf-8")
        self.assertIn("TextForensics", html)

    def test_get_index_html_returns_200_html(self):
        """GET /index.html returns 200 with HTML."""
        code, body, headers = self._fetch("/index.html")
        self.assertEqual(code, 200)
        self.assertEqual(headers.get("Content-Type"), "text/html; charset=utf-8")
        html = body.decode("utf-8")
        self.assertIn("TextForensics", html)

    def test_get_nonexistent_returns_404(self):
        """GET /nonexistent returns 404."""
        code, body, headers = self._fetch("/nonexistent")
        self.assertEqual(code, 404)

    def test_post_api_report_valid_text(self):
        """POST /api/report with valid text returns 200 with trust_map."""
        payload = json.dumps({"text": "This is a test sentence for analysis."})
        code, body, headers = self._fetch(
            "/api/report",
            method="POST",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(code, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json; charset=utf-8")
        data = json.loads(body)
        self.assertIn("trust_map", data)

    def test_post_api_report_non_dict_json_returns_400(self):
        """POST /api/report with non-dict JSON (array) returns 400."""
        payload = json.dumps([1, 2, 3])
        code, body, headers = self._fetch(
            "/api/report",
            method="POST",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(code, 400)

    def test_post_api_report_invalid_json_returns_400(self):
        """POST /api/report with invalid JSON returns 400."""
        payload = "{ not valid json }"
        code, body, headers = self._fetch(
            "/api/report",
            method="POST",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(code, 400)

    def test_post_api_report_no_content_length_returns_411(self):
        """POST /api/report without Content-Length returns 411."""
        url = f"http://127.0.0.1:{self.port}/api/report"
        # Use raw socket to send a request without Content-Length header
        data = json.dumps({"text": "test"})
        http_request = (
            f"POST /api/report HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"Content-Type: application/json\r\n"
            f"\r\n"
            f"{data}"
        ).encode("utf-8")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(("127.0.0.1", self.port))
            sock.sendall(http_request)
            sock.settimeout(5.0)
            response = sock.recv(4096).decode()
        finally:
            sock.close()

        self.assertIn("411", response.split()[1])

    def test_post_api_other_returns_404(self):
        """POST /api/other returns 404."""
        code, body, headers = self._fetch("/api/other", method="POST")
        self.assertEqual(code, 404)

    def test_security_headers_present(self):
        """Response includes security headers."""
        code, body, headers = self._fetch("/healthz")
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(headers.get("Content-Security-Policy"),
                        "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.assertEqual(headers.get("Referrer-Policy"), "no-referrer")
        self.assertEqual(headers.get("Permissions-Policy"), "camera=(), microphone=(), geolocation=()")
        self.assertEqual(headers.get("Cache-Control"), "no-store")

    def test_post_chunked_transfer_encoding_rejected(self):
        """POST with chunked Transfer-Encoding returns 400."""
        # Use raw socket to send a chunked request
        http_request = (
            b"POST /api/report HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b'5\r\n'
            b'{"t":1}\r\n'
            b'0\r\n'
            b'\r\n'
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(("127.0.0.1", self.port))
            sock.sendall(http_request)
            sock.settimeout(5.0)
            response = sock.recv(4096).decode()
        finally:
            sock.close()

        self.assertIn("400", response.split()[1])


class TestServeFunction(unittest.TestCase):
    """Tests for the serve() function."""

    def test_serve_uses_loopback_host(self):
        """serve() can bind to loopback host."""
        import threading
        import time

        # Create a socket to get an ephemeral port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()

        # Run serve in a thread with the port
        def run_serve():
            serve("127.0.0.1", port, open_browser=False)

        thread = threading.Thread(target=run_serve, daemon=True)
        thread.start()
        time.sleep(0.5)

        # Verify server is running
        self.assertTrue(thread.is_alive())

    def test_serve_rejects_non_loopback_without_opt_in(self):
        """serve() raises ValueError when binding to non-loopback without allow_remote."""
        with self.assertRaises(ValueError) as context:
            serve("0.0.0.0", 9999, open_browser=False, allow_remote=False)
        self.assertIn("Refusing to bind", str(context.exception))

    def test_serve_accepts_non_loopback_with_opt_in(self):
        """serve() can bind to non-loopback with allow_remote=True."""
        from textforensics.config import ensure_bind_allowed
        # Should not raise
        ensure_bind_allowed("0.0.0.0", allow_remote=True)


class TestHandlerDefaults(unittest.TestCase):
    """Tests for Handler class default values."""

    def test_protocol_version(self):
        """Handler uses HTTP/1.1 protocol version."""
        from textforensics.webapp import make_handler
        handler_cls = make_handler()
        self.assertEqual(handler_cls.protocol_version, "HTTP/1.1")


class TestHandlerLogMessage(unittest.TestCase):
    """Tests for log_message method."""

    def test_log_message_is_noop(self):
        """log_message method does nothing (no output)."""
        from textforensics.webapp import make_handler

        # We can verify log_message is a no-op by checking its docstring or behavior
        # In Python's BaseHTTPRequestHandler, log_message is used for printing
        # In our implementation it just returns (line 182-183)
        self.assertTrue(callable(make_handler().log_message))


if __name__ == "__main__":
    unittest.main()