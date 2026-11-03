"""Tests for MCP tools - result codec and capability policy."""

from __future__ import annotations

import json

import pytest

from textforensics.mcp_tools import (
    capability_policy_evaluate,
    result_decode,
    result_encode,
)

# Reuse the minimal bundle from test_result_codec
MINIMAL_BUNDLE = {
    "schema": "textforensics.forensic-bundle/v1",
    "generated_at_utc": "2024-01-01T00:00:00+00:00",
    "content_sha256": "0" * 64,
    "input": {
        "word_count": 100,
        "sentence_count": 5,
        "paragraph_count": 2,
        "raw_text_included": False,
    },
    "detector_results": [],
    "detector_failures": [],
    "plugin_health": [],
    "consensus": {
        "verdict": "ai_like",
        "ai_probability": 0.75,
        "independent_families": 1,
    },
    "trust_map": {
        "schema": "textforensics.trust-map/v1",
        "overall": "strong",
        "dimensions": [],
        "limitations": [],
    },
    "verdict_integrity": {},
    "robustness": {},
    "provenance": None,
    "limitations": [],
}


class TestResultCodecMCP:
    def test_result_encode_decode_roundtrip(self):
        """Encode then decode should preserve data."""
        result = result_encode({"data": MINIMAL_BUNDLE, "schema": "forensic-bundle"})
        assert result["success"] is True
        assert "encoded" in result

        encoded = result["encoded"]
        result2 = result_decode({"encoded": encoded, "schema": "forensic-bundle"})
        assert result2["success"] is True
        assert result2["decoded"]["consensus"]["verdict"] == "ai_like"

    def test_result_encode_adds_schema(self):
        """Encode should add schema if missing."""
        data = dict(MINIMAL_BUNDLE)
        del data["schema"]
        result = result_encode({"data": data, "schema": "forensic-bundle"})
        assert result["success"] is True
        encoded = result["encoded"]
        decoded = json.loads(encoded)
        assert decoded["schema"] == "textforensics.forensic-bundle/v1"

    def test_result_encode_canonical_false(self):
        """Non-canonical encoding should work."""
        result = result_encode(
            {"data": MINIMAL_BUNDLE, "schema": "forensic-bundle", "canonical": False}
        )
        assert result["success"] is True

    def test_result_encode_validate_false(self):
        """Encode without validation should work."""
        result = result_encode(
            {"data": MINIMAL_BUNDLE, "schema": "forensic-bundle", "validate": False}
        )
        assert result["success"] is True

    def test_result_decode_validate_false(self):
        """Decode without validation should work."""
        encoded = result_encode({"data": MINIMAL_BUNDLE, "schema": "forensic-bundle"})["encoded"]
        result = result_decode(
            {"encoded": encoded, "schema": "forensic-bundle", "validate": False}
        )
        assert result["success"] is True

    def test_result_decode_strict_version(self):
        """Strict version mode should reject mismatched versions."""
        data = dict(MINIMAL_BUNDLE)
        data["schema"] = "textforensics.forensic-bundle/v2"
        encoded = json.dumps(data).encode()
        result = result_decode(
            {"encoded": encoded.decode(), "schema": "forensic-bundle", "strict_version": True}
        )
        assert result["success"] is False
        assert "Version migration error" in result["error"]

    def test_result_encode_invalid_schema(self):
        """Invalid schema name should fail."""
        result = result_encode({"data": MINIMAL_BUNDLE, "schema": "unknown-schema"})
        assert result["success"] is False

    def test_result_encode_missing_data(self):
        """Missing data should fail."""
        result = result_encode({"schema": "forensic-bundle"})
        assert result["success"] is False

    def test_result_encode_invalid_data(self):
        """Non-object data should fail."""
        result = result_encode({"data": "not an object", "schema": "forensic-bundle"})
        assert result["success"] is False

    def test_result_decode_invalid_json(self):
        """Invalid JSON should fail."""
        result = result_decode({"encoded": "not valid json", "schema": "forensic-bundle"})
        assert result["success"] is False

    def test_result_decode_wrong_schema(self):
        """Wrong schema name should fail."""
        result = result_decode({"encoded": "{}", "schema": "unknown-schema"})
        assert result["success"] is False


class TestCapabilityPolicyMCP:
    def test_capability_policy_evaluate_production(self):
        """Evaluate production policy."""
        from textforensics.capability_ledger import (
            CapabilityClaim,
            CapabilityLedger,
            EvidenceLabel,
            EvidenceRef,
            EvidenceTier,
        )

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

        ledger_dict = ledger.to_dict()
        result = capability_policy_evaluate(
            {"ledger": ledger_dict, "detector_id": "test/detector", "policy": "production"}
        )
        assert result["success"] is True
        assert "results" in result
        assert "all_passed" in result

    def test_capability_policy_evaluate_report(self):
        """Evaluate report policy."""
        from textforensics.capability_ledger import (
            CapabilityClaim,
            CapabilityLedger,
            EvidenceLabel,
            EvidenceRef,
            EvidenceTier,
        )

        ledger = CapabilityLedger()
        ledger.register(
            CapabilityClaim(
                detector_id="test/detector",
                capability="trust_map_generation",
                tier=EvidenceTier.TOOL_BACKED,
                evidence=[
                    EvidenceRef(
                        label=EvidenceLabel.EXECUTED,
                        tier=EvidenceTier.TOOL_BACKED,
                        artifact="run-123",
                    )
                ],
            )
        )

        ledger_dict = ledger.to_dict()
        result = capability_policy_evaluate(
            {"ledger": ledger_dict, "detector_id": "test/detector", "policy": "report"}
        )
        assert result["success"] is True

    def test_capability_policy_evaluate_calibration(self):
        """Evaluate calibration policy."""
        from textforensics.capability_ledger import (
            CapabilityClaim,
            CapabilityLedger,
            EvidenceLabel,
            EvidenceRef,
            EvidenceTier,
        )

        ledger = CapabilityLedger()
        ledger.register(
            CapabilityClaim(
                detector_id="test/detector",
                capability="probability_calibration",
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

        ledger_dict = ledger.to_dict()
        result = capability_policy_evaluate(
            {"ledger": ledger_dict, "detector_id": "test/detector", "policy": "calibration"}
        )
        assert result["success"] is True

    def test_capability_policy_evaluate_minimum(self):
        """Evaluate minimum policy."""
        from textforensics.capability_ledger import (
            CapabilityClaim,
            CapabilityLedger,
            EvidenceTier,
        )

        ledger = CapabilityLedger()
        ledger.register(
            CapabilityClaim(
                detector_id="test/detector",
                capability="language_coverage",
                tier=EvidenceTier.READABLE,
                evidence=[],
            )
        )

        ledger_dict = ledger.to_dict()
        result = capability_policy_evaluate(
            {"ledger": ledger_dict, "detector_id": "test/detector", "policy": "minimum"}
        )
        assert result["success"] is True

    def test_capability_policy_evaluate_unknown_policy(self):
        """Unknown policy name should fail."""
        result = capability_policy_evaluate(
            {"ledger": {}, "detector_id": "test/detector", "policy": "unknown-policy"}
        )
        assert result["success"] is False

    def test_capability_policy_evaluate_custom_policy(self):
        """Custom policy rules should work."""
        from textforensics.capability_ledger import (
            CapabilityClaim,
            CapabilityLedger,
            EvidenceTier,
        )

        ledger = CapabilityLedger()
        ledger.register(
            CapabilityClaim(
                detector_id="test/detector",
                capability="custom_capability",
                tier=EvidenceTier.READABLE,
                evidence=[],
            )
        )

        ledger_dict = ledger.to_dict()
        result = capability_policy_evaluate(
            {
                "ledger": ledger_dict,
                "detector_id": "test/detector",
                "custom_policy": [
                    {
                        "rule_id": "custom-rule",
                        "description": "Test rule",
                        "required_capabilities": [["custom_capability", "readable"]],
                        "detector_pattern": "*",
                        "action_on_failure": "reject",
                    }
                ],
            }
        )
        assert result["success"] is True

    def test_capability_policy_evaluate_missing_ledger(self):
        """Missing ledger should fail."""
        result = capability_policy_evaluate({"detector_id": "test/detector"})
        assert result["success"] is False

    def test_capability_policy_evaluate_invalid_ledger(self):
        """Invalid ledger format should fail."""
        result = capability_policy_evaluate({"ledger": "not a dict", "detector_id": "test/detector"})
        assert result["success"] is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
