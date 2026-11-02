"""Tests for the Capability Ledger module."""

from __future__ import annotations

import json
import unittest

from textforensics.capability_ledger import (
    CapabilityClaim,
    CapabilityLedger,
    EvidenceLabel,
    EvidenceRef,
    EvidenceTier,
    ledger_to_trust_dimension,
    validate_claim,
)


class TestRegistrationAndRetrieval(unittest.TestCase):
    def test_register_and_get(self):
        ledger = CapabilityLedger()
        claim = CapabilityClaim(
            detector_id="det-a",
            capability="language_coverage.en",
            tier=EvidenceTier.TOOL_BACKED,
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.CALCULATED,
                    tier=EvidenceTier.TOOL_BACKED,
                    artifact="bench/raid-en.json",
                )
            ],
        )
        ledger.register(claim)
        result = ledger.get("det-a", "language_coverage.en")
        self.assertIsNotNone(result)
        self.assertEqual(result.capability, "language_coverage.en")

    def test_get_missing_capability(self):
        ledger = CapabilityLedger()
        result = ledger.get("det-a", "missing.cap")
        self.assertIsNone(result)

    def test_get_missing_detector(self):
        ledger = CapabilityLedger()
        result = ledger.get("nonexistent", "anything")
        self.assertIsNone(result)

    def test_multiple_capabilities_per_detector(self):
        ledger = CapabilityLedger()
        ledger.register(CapabilityClaim(
            detector_id="det-a",
            capability="lang.en",
            tier=EvidenceTier.READABLE,
            evidence=[],
        ))
        ledger.register(CapabilityClaim(
            detector_id="det-a",
            capability="lang.de",
            tier=EvidenceTier.VALIDATED,
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.EXECUTED,
                    tier=EvidenceTier.VALIDATED,
                    artifact="run/de-v2.json",
                )
            ],
        ))
        self.assertEqual(ledger.get("det-a", "lang.en").tier, EvidenceTier.READABLE)
        self.assertEqual(ledger.get("det-a", "lang.de").tier, EvidenceTier.VALIDATED)


class TestTierEnforcement(unittest.TestCase):
    def test_is_validated_true(self):
        ledger = CapabilityLedger()
        ledger.register(CapabilityClaim(
            detector_id="det-b",
            capability="length.medium",
            tier=EvidenceTier.VALIDATED,
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.EXECUTED,
                    tier=EvidenceTier.VALIDATED,
                    artifact="run/length.json",
                )
            ],
        ))
        self.assertTrue(ledger.is_validated("det-b", "length.medium"))

    def test_is_validated_false_readable(self):
        ledger = CapabilityLedger()
        ledger.register(CapabilityClaim(
            detector_id="det-b",
            capability="length.medium",
            tier=EvidenceTier.READABLE,
            evidence=[],
        ))
        self.assertFalse(ledger.is_validated("det-b", "length.medium"))

    def test_is_validated_false_missing(self):
        ledger = CapabilityLedger()
        self.assertFalse(ledger.is_validated("det-b", "missing"))

    def test_enforce_success(self):
        ledger = CapabilityLedger()
        claim = CapabilityClaim(
            detector_id="det-c",
            capability="lang.en",
            tier=EvidenceTier.VALIDATED,
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.EXECUTED,
                    tier=EvidenceTier.VALIDATED,
                    artifact="run/en.json",
                )
            ],
        )
        ledger.register(claim)
        result = ledger.enforce("det-c", "lang.en")
        self.assertEqual(result.tier, EvidenceTier.VALIDATED)

    def test_enforce_raises(self):
        ledger = CapabilityLedger()
        with self.assertRaises(ValueError) as ctx:
            ledger.enforce("det-x", "nonexistent.cap")
        self.assertIn("No capability claim", str(ctx.exception))
        self.assertIn("det-x/nonexistent.cap", str(ctx.exception))


class TestSerialization(unittest.TestCase):
    def test_roundtrip(self):
        ledger = CapabilityLedger()
        ledger.register(CapabilityClaim(
            detector_id="det-1",
            capability="lang.en",
            tier=EvidenceTier.VALIDATED,
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.EXECUTED,
                    tier=EvidenceTier.VALIDATED,
                    artifact="run/en.json",
                    detail="RAID held-out slice",
                )
            ],
            valid_until="2027-01-01",
        ))
        data = ledger.to_dict()
        self.assertEqual(data["schema"], "textforensics.capability-ledger/v1")
        self.assertIn("generated_at_utc", data)
        restored = CapabilityLedger.from_dict(data)
        claim = restored.get("det-1", "lang.en")
        self.assertIsNotNone(claim)
        self.assertEqual(claim.tier, EvidenceTier.VALIDATED)
        self.assertEqual(claim.valid_until, "2027-01-01")
        self.assertEqual(len(claim.evidence), 1)
        self.assertEqual(claim.evidence[0].detail, "RAID held-out slice")

    def test_json_roundtrip(self):
        ledger = CapabilityLedger()
        ledger.register(CapabilityClaim(
            detector_id="det-2",
            capability="length.short",
            tier=EvidenceTier.TOOL_BACKED,
            evidence=[],
        ))
        raw = json.dumps(ledger.to_dict())
        restored = CapabilityLedger.from_dict(json.loads(raw))
        self.assertEqual(
            restored.get("det-2", "length.short").tier,
            EvidenceTier.TOOL_BACKED,
        )

    def test_empty_ledger(self):
        ledger = CapabilityLedger()
        data = ledger.to_dict()
        self.assertEqual(data["claims"], {})
        restored = CapabilityLedger.from_dict(data)
        self.assertIsNone(restored.get("x", "y"))


class TestEvidenceLabelValidation(unittest.TestCase):
    def test_empty_evidence_flagged(self):
        claim = CapabilityClaim(
            detector_id="det-x",
            capability="lang.en",
            tier=EvidenceTier.TOOL_BACKED,
            evidence=[],
        )
        issues = validate_claim(claim)
        self.assertTrue(any("No evidence" in i for i in issues))

    def test_validated_without_executed(self):
        claim = CapabilityClaim(
            detector_id="det-x",
            capability="lang.en",
            tier=EvidenceTier.VALIDATED,
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.CALCULATED,
                    tier=EvidenceTier.TOOL_BACKED,
                    artifact="calc.json",
                )
            ],
        )
        issues = validate_claim(claim)
        self.assertTrue(any("EXECUTED" in i for i in issues))

    def test_validated_with_executed_clean(self):
        claim = CapabilityClaim(
            detector_id="det-x",
            capability="lang.en",
            tier=EvidenceTier.VALIDATED,
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.EXECUTED,
                    tier=EvidenceTier.VALIDATED,
                    artifact="run/en.json",
                )
            ],
        )
        issues = validate_claim(claim)
        self.assertEqual(issues, [])

    def test_readable_no_evidence(self):
        claim = CapabilityClaim(
            detector_id="det-x",
            capability="lang.en",
            tier=EvidenceTier.READABLE,
            evidence=[],
        )
        issues = validate_claim(claim)
        # READABLE still requires at least one evidence ref (just documented)
        self.assertTrue(any("No evidence" in i for i in issues))

    def test_tool_backed_with_calculated(self):
        claim = CapabilityClaim(
            detector_id="det-x",
            capability="lang.en",
            tier=EvidenceTier.TOOL_BACKED,
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.CALCULATED,
                    tier=EvidenceTier.TOOL_BACKED,
                    artifact="calc.json",
                )
            ],
        )
        issues = validate_claim(claim)
        self.assertEqual(issues, [])


class TestTrustMapIntegration(unittest.TestCase):
    def test_validated_claim_maps_to_supported(self):
        ledger = CapabilityLedger()
        ledger.register(CapabilityClaim(
            detector_id="det-a",
            capability="lang_coverage.en",
            tier=EvidenceTier.VALIDATED,
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.EXECUTED,
                    tier=EvidenceTier.VALIDATED,
                    artifact="run/en.json",
                )
            ],
        ))
        dim = ledger_to_trust_dimension(ledger, "det-a", "lang_coverage")
        self.assertEqual(dim.state, "supported")
        self.assertIn("run/en.json", dim.evidence_refs)

    def test_tool_backed_claim_maps_to_partial(self):
        ledger = CapabilityLedger()
        ledger.register(CapabilityClaim(
            detector_id="det-a",
            capability="length_robust.medium",
            tier=EvidenceTier.TOOL_BACKED,
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.CALCULATED,
                    tier=EvidenceTier.TOOL_BACKED,
                    artifact="calc/length.json",
                )
            ],
        ))
        dim = ledger_to_trust_dimension(ledger, "det-a", "length_robust")
        self.assertEqual(dim.state, "partial")

    def test_readable_claim_maps_to_partial(self):
        ledger = CapabilityLedger()
        ledger.register(CapabilityClaim(
            detector_id="det-a",
            capability="domain.news",
            tier=EvidenceTier.READABLE,
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.REPORTED,
                    tier=EvidenceTier.READABLE,
                    artifact="docs/domain-report.pdf",
                )
            ],
        ))
        dim = ledger_to_trust_dimension(ledger, "det-a", "domain")
        self.assertEqual(dim.state, "partial")

    def test_no_claims_maps_to_unknown(self):
        ledger = CapabilityLedger()
        dim = ledger_to_trust_dimension(ledger, "det-a", "missing_prefix")
        self.assertEqual(dim.state, "unknown")
        self.assertIn("No capability claims registered", dim.reason)

    def test_valid_until_becomes_limitation(self):
        ledger = CapabilityLedger()
        ledger.register(CapabilityClaim(
            detector_id="det-a",
            capability="lang.en",
            tier=EvidenceTier.VALIDATED,
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.EXECUTED,
                    tier=EvidenceTier.VALIDATED,
                    artifact="run/en.json",
                )
            ],
            valid_until="2026-12-31",
        ))
        dim = ledger_to_trust_dimension(ledger, "det-a", "lang")
        self.assertTrue(any("2026-12-31" in lim for lim in dim.limitations))

    def test_mixed_tiers_elevates_to_validated(self):
        ledger = CapabilityLedger()
        ledger.register(CapabilityClaim(
            detector_id="det-a",
            capability="lang.en",
            tier=EvidenceTier.VALIDATED,
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.EXECUTED,
                    tier=EvidenceTier.VALIDATED,
                    artifact="run/en.json",
                )
            ],
        ))
        ledger.register(CapabilityClaim(
            detector_id="det-a",
            capability="lang.de",
            tier=EvidenceTier.TOOL_BACKED,
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.CALCULATED,
                    tier=EvidenceTier.TOOL_BACKED,
                    artifact="calc/de.json",
                )
            ],
        ))
        dim = ledger_to_trust_dimension(ledger, "det-a", "lang")
        self.assertEqual(dim.state, "supported")


if __name__ == "__main__":
    unittest.main()
