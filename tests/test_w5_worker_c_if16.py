"""W5 Worker C regression tests: IF-16 (implemented MCP tools not registered).

Red-first tests, written from the audit's regression acceptance before
the source fix:

- Assert the EXACT intended tool names and schemas from the real
  ``_server().list_tools()`` — 19 tools after registration.
- Invoke the newly public operations through MCP dispatch
  (``call_tool``), not through direct helper calls.
- Compare structured results/error codes with the direct helper and
  with the CLI equivalent (``capability policy``) where one exists.
  The codec helpers have no CLI command; their API equivalent is the
  direct ``ResultCodec``/helper round-trip.

Coordinator decision (W5): the three helpers ARE public MCP tools and
are registered through the same ``params``-JSON-string channel as the
other dict-based tools (``capability_*``, ``verify_case_file``,
``drift_*``, ``fingerprint_dataset``, ``check_contamination``). They
take no text and run no detectors, so — like those tools — they are
not emergency-stop gated.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HAS_MCP = importlib.util.find_spec("mcp") is not None

from test_mcp_tools_new import MINIMAL_BUNDLE  # noqa: E402  (shared fixture)

from textforensics import constants  # noqa: E402
from textforensics.mcp_tools import (  # noqa: E402
    capability_policy_evaluate,
    result_decode,
    result_encode,
)
from textforensics.policy import (  # noqa: E402
    CapabilityClaim,
    CapabilityLedger,
    EvidenceLabel,
    EvidenceRef,
    EvidenceTier,
)

EXPECTED_TOOLS = {
    "analyze_ai_text",
    "build_forensic_report",
    "build_case_file",
    "detector_health",
    "localize_text_patterns",
    "compare_text_versions",
    "audit_writing_naturalness",
    "capability_register",
    "capability_check",
    "capability_list",
    "verify_case_file",
    "drift_snapshot",
    "drift_compare",
    "drift_report",
    "fingerprint_dataset",
    "check_contamination",
    # IF-16: newly public tools (W5).
    "result_encode",
    "result_decode",
    "capability_policy_evaluate",
}

NEW_TOOLS = ("result_encode", "result_decode", "capability_policy_evaluate")


def _validated_ledger() -> dict:
    """Ledger with one validated claim, as in test_mcp_tools_new."""
    ledger = CapabilityLedger()
    ledger.register(
        CapabilityClaim(
            detector_id="test/detector",
            capability="language_coverage",
            tier=EvidenceTier.VALIDATED,
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.EXECUTED,
                    tier=EvidenceTier.VALIDATED,
                    artifact="run-123",
                )
            ],
        )
    )
    ledger.register(
        CapabilityClaim(
            detector_id="test/detector",
            capability="length_robustness",
            tier=EvidenceTier.TOOL_BACKED,
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.CALCULATED,
                    tier=EvidenceTier.TOOL_BACKED,
                    artifact="calc-123",
                )
            ],
        )
    )
    ledger.register(
        CapabilityClaim(
            detector_id="test/detector",
            capability="domain_accuracy",
            tier=EvidenceTier.TOOL_BACKED,
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.CALCULATED,
                    tier=EvidenceTier.TOOL_BACKED,
                    artifact="calc-456",
                )
            ],
        )
    )
    return ledger.to_dict()


def _ledger_missing_domain_accuracy() -> dict:
    """Same ledger minus the ``domain_accuracy`` claim, so the
    production policy fails exactly one rule."""
    ledger = CapabilityLedger()
    for capability, tier, label, artifact in (
        ("language_coverage", EvidenceTier.VALIDATED, EvidenceLabel.EXECUTED, "run-123"),
        ("length_robustness", EvidenceTier.TOOL_BACKED, EvidenceLabel.CALCULATED, "calc-123"),
    ):
        ledger.register(
            CapabilityClaim(
                detector_id="test/detector",
                capability=capability,
                tier=tier,
                evidence=[EvidenceRef(label=label, tier=tier, artifact=artifact)],
            )
        )
    return ledger.to_dict()


@unittest.skipUnless(HAS_MCP, "MCP development dependencies are not installed")
class IF16McpRegistrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from textforensics.mcp_server import _server

        cls.server = _server()

    def _call(self, name, **kwargs):
        async def _run():
            return await self.server.call_tool(name, kwargs)

        return asyncio.run(_run())

    def _text(self, result):
        content = getattr(result, "content", None) or result
        if isinstance(content, list) and content:
            first = content[0]
            return getattr(first, "text", None) or str(first)
        return str(content)

    def _tool_map(self):
        async def _names():
            return await self.server.list_tools()

        return {tool.name: tool for tool in asyncio.run(_names())}

    def test_exact_tool_inventory_is_19(self):
        tools = self._tool_map()
        self.assertEqual(set(tools), EXPECTED_TOOLS)
        self.assertEqual(len(tools), 19)

    def test_new_tool_schemas_require_params_string(self):
        tools = self._tool_map()
        for name in NEW_TOOLS:
            with self.subTest(tool=name):
                schema = tools[name].input_schema
                self.assertEqual(schema.get("type"), "object")
                self.assertEqual(schema.get("required"), ["params"])
                params = schema["properties"]["params"]
                self.assertEqual(params.get("type"), "string")
            self.assertTrue((tools[name].description or "").strip())

    def test_result_encode_via_mcp_matches_helper(self):
        params = {"data": MINIMAL_BUNDLE, "schema": "forensic-bundle"}
        expected = result_encode(params)
        self.assertTrue(expected["success"])
        result = self._call("result_encode", params=json.dumps(params))
        payload = json.loads(self._text(result))
        self.assertEqual(payload, expected)

    def test_result_decode_via_mcp_roundtrip_matches_helper(self):
        encoded = result_encode({"data": MINIMAL_BUNDLE, "schema": "forensic-bundle"})["encoded"]
        params = {"encoded": encoded, "schema": "forensic-bundle"}
        expected = result_decode(params)
        self.assertTrue(expected["success"])
        result = self._call("result_decode", params=json.dumps(params))
        payload = json.loads(self._text(result))
        self.assertEqual(payload, expected)
        self.assertEqual(payload["decoded"]["consensus"]["verdict"], "ai_like")
        self.assertEqual(payload["decoded"]["schema"], "textforensics.forensic-bundle/v2")

    def test_result_encode_error_parity_via_mcp(self):
        params = {"data": MINIMAL_BUNDLE, "schema": "unknown-schema"}
        expected = result_encode(params)
        self.assertFalse(expected["success"])
        self.assertEqual(expected["exit_code"], constants.EXIT_ERROR)
        result = self._call("result_encode", params=json.dumps(params))
        payload = json.loads(self._text(result))
        self.assertEqual(payload, expected)

    def test_result_decode_strict_version_error_via_mcp(self):
        data = dict(MINIMAL_BUNDLE)
        data["schema"] = "textforensics.forensic-bundle/v1"
        params = {
            "encoded": json.dumps(data),
            "schema": "forensic-bundle",
            "strict_version": True,
        }
        expected = result_decode(params)
        self.assertFalse(expected["success"])
        self.assertEqual(expected["exit_code"], constants.EXIT_DOWNGRADED)
        result = self._call("result_decode", params=json.dumps(params))
        payload = json.loads(self._text(result))
        self.assertEqual(payload, expected)
        self.assertIn("Version migration error", payload["error"])

    def test_capability_policy_evaluate_via_mcp_matches_helper(self):
        params = {
            "ledger": _validated_ledger(),
            "detector_id": "test/detector",
            "policy": "production",
        }
        expected = capability_policy_evaluate(params)
        self.assertTrue(expected["success"])
        result = self._call("capability_policy_evaluate", params=json.dumps(params))
        payload = json.loads(self._text(result))
        self.assertEqual(payload, expected)

    def test_capability_policy_evaluate_via_mcp_matches_cli(self):
        """MCP dispatch vs the CLI equivalent (``tf capability policy``).

        The per-rule structured results must agree. Exit codes differ
        by design across surfaces (CLI: EXIT_INCOMPLETE=2 on failure;
        MCP helper: EXIT_DOWNGRADED=1), so only the passing case
        asserts the exit code; the failing case asserts the rule
        payloads and records the mapping difference.
        """
        ledger_dict = _validated_ledger()
        with tempfile.TemporaryDirectory() as tmp:
            ledger_path = Path(tmp) / "ledger.json"
            ledger_path.write_text(json.dumps(ledger_dict), encoding="utf-8")
            cli = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "textforensics.cli",
                    "capability",
                    "policy",
                    "test/detector",
                    "--ledger",
                    str(ledger_path),
                    "--policy",
                    "production",
                    "--json",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(cli.returncode, 0, cli.stderr)
        cli_results = json.loads(cli.stdout)
        mcp_result = self._call(
            "capability_policy_evaluate",
            params=json.dumps(
                {
                    "ledger": ledger_dict,
                    "detector_id": "test/detector",
                    "policy": "production",
                }
            ),
        )
        mcp_payload = json.loads(self._text(mcp_result))
        self.assertTrue(mcp_payload["success"])
        self.assertEqual(mcp_payload["exit_code"], constants.EXIT_OK)
        # Same rules, same pass/fail, same missing claims/gaps.
        self.assertEqual(
            [
                (r["rule_id"], r["passed"], r["missing_claims"], r["evidence_gaps"])
                for r in mcp_payload["results"]
            ],
            [
                (r["rule_id"], r["passed"], r["missing_claims"], r["evidence_gaps"])
                for r in cli_results
            ],
        )
        self.assertEqual(mcp_payload["all_passed"], all(r["passed"] for r in cli_results))
        self.assertTrue(mcp_payload["all_passed"])

    def test_capability_policy_failing_case_matches_cli_rules(self):
        """Failing policy: rule payloads agree across MCP and CLI.

        Exit codes differ by design across surfaces (CLI returns
        EXIT_INCOMPLETE=2, the MCP helper returns EXIT_DOWNGRADED=1),
        so the exit codes are asserted as that mapping, not as equal.
        """
        ledger_dict = _ledger_missing_domain_accuracy()
        with tempfile.TemporaryDirectory() as tmp:
            ledger_path = Path(tmp) / "ledger.json"
            ledger_path.write_text(json.dumps(ledger_dict), encoding="utf-8")
            cli = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "textforensics.cli",
                    "capability",
                    "policy",
                    "test/detector",
                    "--ledger",
                    str(ledger_path),
                    "--policy",
                    "production",
                    "--json",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(cli.returncode, constants.EXIT_INCOMPLETE, cli.stderr)
        cli_results = json.loads(cli.stdout)
        self.assertFalse(all(r["passed"] for r in cli_results))
        mcp_result = self._call(
            "capability_policy_evaluate",
            params=json.dumps(
                {
                    "ledger": ledger_dict,
                    "detector_id": "test/detector",
                    "policy": "production",
                }
            ),
        )
        mcp_payload = json.loads(self._text(mcp_result))
        self.assertTrue(mcp_payload["success"])
        self.assertEqual(mcp_payload["exit_code"], constants.EXIT_DOWNGRADED)
        self.assertFalse(mcp_payload["all_passed"])
        self.assertEqual(
            [
                (r["rule_id"], r["passed"], r["missing_claims"], r["evidence_gaps"])
                for r in mcp_payload["results"]
            ],
            [
                (r["rule_id"], r["passed"], r["missing_claims"], r["evidence_gaps"])
                for r in cli_results
            ],
        )


if __name__ == "__main__":
    unittest.main()
