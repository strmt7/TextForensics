"""Live-host smoke tests: real uvicorn on a loopback socket, real HTTP.

Existing API coverage (tests/test_api.py) uses FastAPI's in-process
TestClient; it never binds a socket, never runs uvicorn, and never
exercises the actual ``textforensics serve`` transport. These tests
close that gap: they boot the real server on 127.0.0.1 with an
ephemeral port and talk to it over stdlib HTTP, mirroring the manual
live-host verification (docs/live-host-api-verification.md).

They deliberately assert transport behaviour only (status codes,
well-formed JSON, error bodies) and never detector accuracy.
"""

from __future__ import annotations

import http.client
import importlib.util
import json
import threading
import time
import unittest

from textforensics.config import Settings

HAS_LIVE_API = (
    importlib.util.find_spec("fastapi") is not None
    and importlib.util.find_spec("uvicorn") is not None
)

# Short, clearly human-written paragraph used for the round-trip check.
HUMAN_TEXT = (
    "I spent last Tuesday afternoon trying to fix the squeaky hinge on the back door, "
    "which mostly meant standing in the hallway with a can of WD-40 and a screwdriver, "
    "wondering why the previous owner had used three different screw heads on the same hinge."
)


@unittest.skipUnless(HAS_LIVE_API, "API dependencies (fastapi, uvicorn) are not installed")
class LiveHostSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import uvicorn

        from textforensics.api import create_app

        app = create_app(
            Settings(
                host="127.0.0.1",
                port=0,  # ephemeral loopback port; read back after bind
                max_input_bytes=1024,
                allow_remote=False,
                access_log=False,
                log_level="ERROR",
            )
        )
        cls._config = uvicorn.Config(
            app, host="127.0.0.1", port=0, log_level="error", access_log=False
        )
        cls._server = uvicorn.Server(cls._config)
        cls._thread = threading.Thread(target=cls._server.run, daemon=True)
        cls._thread.start()
        deadline = time.monotonic() + 30
        while not cls._server.started and time.monotonic() < deadline:
            time.sleep(0.1)
        if not cls._server.started:
            raise RuntimeError("live-host smoke server did not start within 30s")
        cls.port = cls._server.servers[0].sockets[0].getsockname()[1]
        # Poll /healthz until the socket answers (startup flag alone is not proof).
        deadline = time.monotonic() + 30
        while True:
            status, _body = cls._request("GET", "/healthz")
            if status == 200:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("/healthz did not answer 200 within 30s of startup")
            time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls._server.should_exit = True
        cls._thread.join(timeout=10)

    @classmethod
    def _request(cls, method, path, body=None, content_type="application/json"):
        conn = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=10)
        try:
            headers = {}
            if body is not None:
                headers["Content-Type"] = content_type
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()

    def _post_json(self, path, payload):
        return self._request("POST", path, body=json.dumps(payload))

    def test_health_ready_version_detectors(self):
        for path, expected in (
            ("/healthz", {"status": "ok"}),
            ("/readyz", {"status": "ready"}),
        ):
            status, body = self._request("GET", path)
            self.assertEqual(status, 200, path)
            self.assertEqual(json.loads(body), expected)
        status, body = self._request("GET", "/version")
        self.assertEqual(status, 200)
        version = json.loads(body)
        self.assertEqual(version["name"], "TextForensics")
        self.assertTrue(version["version"])
        status, body = self._request("GET", "/v1/detectors")
        self.assertEqual(status, 200)
        detectors = json.loads(body)
        self.assertIn("detectors", detectors)
        self.assertTrue(detectors["detectors"])

    def test_analyze_round_trip_is_well_formed(self):
        status, body = self._post_json("/v1/analyze", {"text": HUMAN_TEXT})
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertIsInstance(result["score"], float)
        self.assertGreaterEqual(result["score"], 0.0)
        self.assertLessEqual(result["score"], 1.0)
        self.assertIsInstance(result["verdict"], str)
        self.assertTrue(result["verdict"])
        self.assertGreater(result["word_count"], 0)

    def test_missing_text_field_is_422(self):
        status, body = self._post_json("/v1/analyze", {})
        self.assertEqual(status, 422)
        self.assertIn(b"Field required", body)

    def test_empty_text_is_422(self):
        status, body = self._post_json("/v1/analyze", {"text": ""})
        self.assertEqual(status, 422)
        self.assertEqual(json.loads(body), {"detail": "Invalid text input."})

    def test_malformed_json_is_422(self):
        status, body = self._request("POST", "/v1/analyze", body='{"text": "abc')
        self.assertEqual(status, 422)
        self.assertIn(b"json_invalid", body)

    def test_oversized_text_is_413(self):
        status, body = self._post_json("/v1/analyze", {"text": "x" * 1025})
        self.assertEqual(status, 413)
        self.assertEqual(json.loads(body), {"detail": "Invalid text input."})

    def test_get_on_analyze_is_405(self):
        status, _body = self._request("GET", "/v1/analyze")
        self.assertEqual(status, 405)


if __name__ == "__main__":
    unittest.main()
