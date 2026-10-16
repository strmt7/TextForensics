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

    def test_health_and_security_headers(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")
        self.assertEqual(
            response.headers["x-content-type-options"],
            "nosniff",
        )
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_report_endpoint(self):
        response = self.client.post(
            "/v1/report",
            json={
                "text": (
                    "I tested this on Monday. The first run failed, so I "
                    "changed the cable and tried it again the next morning."
                )
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("trust_map", payload)
        self.assertFalse(payload["input"]["raw_text_included"])

    def test_case_endpoint_omits_raw_text(self):
        response = self.client.post(
            "/v1/case",
            json={"text": "This is a short but non-empty local test document."},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertFalse(payload["raw_text_included"])
        self.assertNotIn(
            "This is a short",
            str(payload),
        )

    def test_input_limit(self):
        response = self.client.post(
            "/v1/report",
            json={"text": "x" * 2000},
        )
        self.assertEqual(response.status_code, 413)

    def test_empty_input(self):
        response = self.client.post(
            "/v1/report",
            json={"text": "   "},
        )
        self.assertEqual(response.status_code, 422)

    def test_detector_health_endpoint(self):
        response = self.client.get("/v1/detectors")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["detectors"])
        self.assertTrue(payload["plugin_health"])


if __name__ == "__main__":
    unittest.main()
