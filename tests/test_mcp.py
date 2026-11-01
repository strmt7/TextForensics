from __future__ import annotations

import asyncio
import importlib.util
import json
import unittest

HAS_MCP = importlib.util.find_spec("mcp") is not None


@unittest.skipUnless(HAS_MCP, "MCP development dependencies are not installed")
class McpServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from textforensics.mcp_server import _server

        cls.server = _server()

    def _call(self, name, **kwargs):
        server = self.server

        async def _run():
            return await server.call_tool(name, kwargs)

        return asyncio.run(_run())

    def _text(self, result):
        # call_tool returns a CallToolResult; extract the first text content.
        content = getattr(result, "content", None) or result
        if isinstance(content, list) and content:
            first = content[0]
            return getattr(first, "text", None) or str(first)
        return str(content)

    def test_server_metadata(self):
        self.assertEqual(self.server.name, "TextForensics")
        self.assertEqual(self.server.version, self.server.version)

    def test_all_expected_tools_are_registered(self):
        async def _names():
            return [tool.name for tool in await self.server.list_tools()]

        names = asyncio.run(_names())
        expected = {
            "analyze_ai_text",
            "build_forensic_report",
            "build_case_file",
            "detector_health",
            "localize_text_patterns",
            "compare_text_versions",
            "audit_writing_naturalness",
        }
        self.assertEqual(set(names), expected)

    def test_analyze_tool_returns_json(self):
        result = self._call(
            "analyze_ai_text",
            text="A test sentence for the MCP analyze tool.",
        )
        payload = json.loads(self._text(result))
        self.assertIn("diagnostic_reliability", payload)
        self.assertIn("confidence_semantics", payload)

    def test_forensic_report_tool_omits_raw_text(self):
        result = self._call(
            "build_forensic_report",
            text="A test sentence for the MCP forensic report tool.",
        )
        text = self._text(result)
        payload = json.loads(text)
        self.assertFalse(payload["input"]["raw_text_included"])
        self.assertNotIn("A test sentence", text)

    def test_case_file_tool_omits_raw_text(self):
        result = self._call(
            "build_case_file",
            text="A test sentence for the MCP case file tool.",
        )
        text = self._text(result)
        payload = json.loads(text)
        self.assertFalse(payload["raw_text_included"])
        self.assertNotIn("A test sentence", text)

    def test_detector_health_tool_returns_metadata(self):
        result = self._call("detector_health")
        payload = json.loads(self._text(result))
        self.assertTrue(payload["detectors"])
        self.assertTrue(payload["plugin_health"])

    def test_localize_tool_validates_segment_size(self):
        with self.assertRaises(Exception):
            self._call(
                "localize_text_patterns",
                text="A test sentence for localization.",
                sentences_per_segment=0,
            )

    def test_localize_tool_rejects_negative_segment_size(self):
        # Line 78: ValueError when sentences_per_segment < 1
        with self.assertRaises(Exception):
            self._call(
                "localize_text_patterns",
                text="A test sentence for localization.",
                sentences_per_segment=-1,
            )

    def test_localize_tool_with_valid_input(self):
        # Line 78: return dumped(...) for valid input
        result = self._call(
            "localize_text_patterns",
            text="First sentence. Second sentence. Third sentence. Fourth sentence.",
            sentences_per_segment=2,
        )
        payload = json.loads(self._text(result))
        self.assertIsInstance(payload, list)
        self.assertGreater(len(payload), 0)

    def test_compare_tool_returns_delta(self):
        result = self._call(
            "compare_text_versions",
            before="the quick brown fox",
            after="the quick brown fox jumps",
        )
        payload = json.loads(self._text(result))
        self.assertIn("similarity", payload)
        self.assertIn("score_delta", payload)

    def test_audit_tool_returns_issues(self):
        result = self._call(
            "audit_writing_naturalness",
            text="Furthermore, it is important to note that this robust "
                 "solution seamlessly unlocks the potential.",
        )
        issues = json.loads(self._text(result))
        self.assertTrue(issues)
        self.assertTrue(any("stock_phrasing" in i["issue"] for i in issues))

    def test_empty_input_is_rejected(self):
        with self.assertRaises(Exception):
            self._call("analyze_ai_text", text="   ")

    def test_oversized_input_is_rejected(self):
        # Default max_input_bytes is 2_000_000, so exceed it explicitly.
        with self.assertRaises(Exception):
            self._call("analyze_ai_text", text="x" * 3_000_000)


if __name__ == "__main__":
    unittest.main()
