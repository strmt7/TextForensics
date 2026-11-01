from __future__ import annotations

import importlib.util
import unittest

from textforensics.config import Settings

HAS_API = (
    importlib.util.find_spec("fastapi") is not None
    and importlib.util.find_spec("httpx") is not None
)


@unittest.skipUnless(HAS_API, "API development dependencies are not installed")
class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient

        from textforensics.api import create_app

        app = create_app(
            Settings(
                host="127.0.0.1",
                port=8765,
                max_input_bytes=1024,
                allow_remote=False,
                access_log=False,
                log_level="INFO",
            )
        )
        cls.client = TestClient(app)

    def _post(self, path, payload, **headers):
        return self.client.post(
            path,
            json=payload,
            headers={"content-type": "application/json", **headers},
        )

    def test_health_and_security_headers(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.headers["referrer-policy"], "no-referrer")

    def test_readyz_endpoint(self):
        response = self.client.get("/readyz")
        self.assertEqual(response.status_code, 200)

    def test_version_endpoint(self):
        response = self.client.get("/version")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["name"], "TextForensics")

    def test_oversized_content_length_is_rejected_before_parsing(self):
        response = self.client.post(
            "/v1/report",
            content=b'{"text":"small"}',
            headers={
                "content-type": "application/json",
                "content-length": "100000",
            },
        )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")

    def test_streaming_transfer_encoding_is_rejected(self):
        response = self.client.post(
            "/v1/report",
            content=b'{"text":"small"}',
            headers={
                "content-type": "application/json",
                "transfer-encoding": "chunked",
            },
        )
        self.assertEqual(response.status_code, 411)
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_invalid_content_length_is_rejected(self):
        # Non-numeric Content-Length should return 400
        response = self.client.post(
            "/v1/report",
            content=b'{"text":"small"}',
            headers={
                "content-type": "application/json",
                "content-length": "not-a-number",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_negative_content_length_is_rejected(self):
        response = self.client.post(
            "/v1/report",
            content=b'{"text":"small"}',
            headers={
                "content-type": "application/json",
                "content-length": "-1",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_report_endpoint(self):
        response = self._post(
            "/v1/report",
            {"text": "I tested this on Monday. The first run failed, so I "
                     "changed the cable and tried it again the next morning."},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("trust_map", payload)
        self.assertFalse(payload["input"]["raw_text_included"])
        self.assertIn("content_sha256", payload)

    def test_analyze_endpoint(self):
        response = self._post(
            "/v1/analyze",
            {"text": "A short test sentence for the analyze endpoint."},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("diagnostic_reliability", payload)
        self.assertIn("confidence_semantics", payload)

    def test_case_endpoint_omits_raw_text(self):
        response = self._post(
            "/v1/case",
            {"text": "This is a short but non-empty local test document."},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertFalse(payload["raw_text_included"])
        self.assertNotIn("This is a short", str(payload))
        self.assertEqual(payload["schema"], "textforensics.case-file/v1")

    def test_audit_endpoint(self):
        response = self._post(
            "/v1/audit",
            {"text": "Furthermore, it is important to note that this robust "
                     "solution seamlessly unlocks the potential."},
        )
        self.assertEqual(response.status_code, 200)
        issues = response.json()
        self.assertTrue(issues)
        self.assertTrue(
            all("issue" in item and "suggestion" in item for item in issues)
        )

    def test_compare_endpoint(self):
        response = self._post(
            "/v1/compare",
            {
                "before": "the quick brown fox",
                "after": "the quick brown fox jumps",
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("similarity", payload)
        self.assertIn("score_delta", payload)

    def test_input_limit(self):
        response = self._post("/v1/report", {"text": "x" * 2000})
        self.assertEqual(response.status_code, 413)

    def test_empty_input(self):
        response = self._post("/v1/report", {"text": "   "})
        self.assertEqual(response.status_code, 422)

    def test_malformed_json_body_fails_closed(self):
        # A body that is not a JSON object fails before any text is analyzed.
        response = self.client.post(
            "/v1/report",
            content=b'[]',
            headers={
                "content-type": "application/json",
                "content-length": "2",
            },
        )
        self.assertGreaterEqual(response.status_code, 400)
        self.assertLess(response.status_code, 500)

    def test_invalid_json_body_fails_closed(self):
        response = self.client.post(
            "/v1/report",
            content=b'not json',
            headers={
                "content-type": "application/json",
                "content-length": "8",
            },
        )
        self.assertGreaterEqual(response.status_code, 400)
        self.assertLess(response.status_code, 500)

    def test_detector_health_endpoint(self):
        response = self.client.get("/v1/detectors")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["detectors"])
        self.assertTrue(payload["plugin_health"])

    def test_unknown_route_returns_404(self):
        response = self.client.get("/v1/does-not-exist")
        self.assertEqual(response.status_code, 404)

    def test_case_file_round_trip_via_api(self):
        report = self._post(
            "/v1/report",
            {"text": "A normal sentence for a case file round trip test."},
        )
        self.assertEqual(report.status_code, 200)
        case = self._post(
            "/v1/case",
            {"text": "A normal sentence for a case file round trip test."},
        )
        self.assertEqual(case.status_code, 200)
        self.assertFalse(case.json()["raw_text_included"])


if __name__ == "__main__":
    unittest.main()
