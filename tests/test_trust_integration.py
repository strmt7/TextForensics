"""Integration tests for Trust Map and Capability Ledger functionality.

These are golden tests that verify byte-identical output for reproducible case file generation.
"""
from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from textforensics.casefile import seal_case_file
from textforensics.capability_ledger import (
    CapabilityClaim,
    CapabilityLedger,
    EvidenceLabel,
    EvidenceRef,
    EvidenceTier,
)
from textforensics.report import build_forensic_bundle
from textforensics.trust import trust_map_from_capability_ledger


# Test text for case file generation
GOLDEN_TEST_TEXT = (
    "I tested this text to verify the golden case file generation. "
    "It contains enough words for detection in some detectors."
)

# Path to the golden case file
GOLDEN_CASE_FILE = Path(__file__).parent / "golden" / "case-file-valid.json"


class TrustMapFromLedgerTests(unittest.TestCase):
    """Tests for trust_map_from_capability_ledger function."""

    def test_validated_claim_maps_to_supported(self):
        """VALIDATED tier should map to TrustDimension.state='supported'."""
        ledger = CapabilityLedger()
        ledger.register(CapabilityClaim(
            detector_id="test-detector",
            capability="language_coverage.en",
            tier=EvidenceTier.VALIDATED,
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.EXECUTED,
                    tier=EvidenceTier.VALIDATED,
                    artifact="run/validation.json",
                )
            ],
        ))

        trust_map = trust_map_from_capability_ledger(ledger)

        # Find the dimension for language_coverage.en
        dim = None
        for d in trust_map.dimensions:
            if d.dimension == "language_coverage_en":
                dim = d
                break

        self.assertIsNotNone(dim)
        self.assertEqual(dim.state, "supported")
        self.assertIn("VALIDATED-tier evidence", dim.reason)

    def test_tool_backed_claim_maps_to_partial(self):
        """TOOL_BACKED tier should map to TrustDimension.state='partial'."""
        ledger = CapabilityLedger()
        ledger.register(CapabilityClaim(
            detector_id="test-detector",
            capability="length_robustness.medium",
            tier=EvidenceTier.TOOL_BACKED,
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.CALCULATED,
                    tier=EvidenceTier.TOOL_BACKED,
                    artifact="bench/length.json",
                )
            ],
        ))

        trust_map = trust_map_from_capability_ledger(ledger)

        dim = None
        for d in trust_map.dimensions:
            if d.dimension == "length_robustness_medium":
                dim = d
                break

        self.assertIsNotNone(dim)
        self.assertEqual(dim.state, "partial")
        self.assertIn("TOOL_BACKED", dim.reason)

    def test_readable_claim_maps_to_partial(self):
        """READABLE tier should map to TrustDimension.state='partial'."""
        ledger = CapabilityLedger()
        ledger.register(CapabilityClaim(
            detector_id="test-detector",
            capability="domain_news",
            tier=EvidenceTier.READABLE,
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.REPORTED,
                    tier=EvidenceTier.READABLE,
                    artifact="docs/domain.pdf",
                )
            ],
        ))

        trust_map = trust_map_from_capability_ledger(ledger)

        dim = None
        for d in trust_map.dimensions:
            if d.dimension == "domain_news":
                dim = d
                break

        self.assertIsNotNone(dim)
        self.assertEqual(dim.state, "partial")
        self.assertIn("documented but not machine-verifiable", dim.reason)

    def test_no_claim_maps_to_unknown(self):
        """No capability claim should map to TrustDimension.state='unknown'."""
        ledger = CapabilityLedger()

        trust_map = trust_map_from_capability_ledger(ledger)

        self.assertEqual(len(trust_map.dimensions), 0)
        self.assertEqual(trust_map.overall, "insufficient")

    def test_evidence_refs_are_collected(self):
        """Evidence artifact refs should be collected in the TrustDimension."""
        ledger = CapabilityLedger()
        ledger.register(CapabilityClaim(
            detector_id="test-detector",
            capability="lang.en",
            tier=EvidenceTier.VALIDATED,
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.EXECUTED,
                    tier=EvidenceTier.VALIDATED,
                    artifact="run/lang-en.json",
                    detail="RAID benchmark",
                ),
                EvidenceRef(
                    label=EvidenceLabel.EXECUTED,
                    tier=EvidenceTier.VALIDATED,
                    artifact="run/lang-en-2.json",
                ),
            ],
        ))

        trust_map = trust_map_from_capability_ledger(ledger)

        dim = next(d for d in trust_map.dimensions if d.dimension == "lang_en")
        self.assertIn("run/lang-en.json", dim.evidence_refs)
        self.assertIn("run/lang-en-2.json", dim.evidence_refs)

    def test_valid_until_becomes_limitation(self):
        """valid_until date should become a limitation in the TrustDimension."""
        ledger = CapabilityLedger()
        ledger.register(CapabilityClaim(
            detector_id="test-detector",
            capability="lang.fr",
            tier=EvidenceTier.VALIDATED,
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.EXECUTED,
                    tier=EvidenceTier.VALIDATED,
                    artifact="run/lang-fr.json",
                )
            ],
            valid_until="2026-12-31",
        ))

        trust_map = trust_map_from_capability_ledger(ledger)

        dim = next(d for d in trust_map.dimensions if d.dimension == "lang_fr")
        self.assertTrue(any("2026-12-31" in lim for lim in dim.limitations))

    def test_empty_ledger_returns_insufficient_trust_map(self):
        """Empty ledger should produce an 'insufficient' TrustMap."""
        ledger = CapabilityLedger()

        trust_map = trust_map_from_capability_ledger(ledger)

        self.assertEqual(trust_map.overall, "insufficient")
        self.assertTrue(any("No capability claims" in lim for lim in trust_map.limitations))


class GoldenCaseFileTests(unittest.TestCase):
    """Golden tests for deterministic case file generation."""

    def test_golden_case_file_exists(self):
        """The golden case file must exist."""
        self.assertTrue(GOLDEN_CASE_FILE.exists(), f"Golden case file not found: {GOLDEN_CASE_FILE}")

    def test_golden_case_file_is_valid(self):
        """The golden case file must be a valid case file."""
        with open(GOLDEN_CASE_FILE, encoding="utf-8") as f:
            payload = json.load(f)

        from textforensics.casefile import verify_case_file
        result = verify_case_file(payload)
        self.assertTrue(result["valid"], f"Golden case file validation failed: {result['errors']}")

    def test_case_file_generation_is_deterministic(self):
        """Generating the same case file twice should produce identical output."""
        bundle = build_forensic_bundle(
            GOLDEN_TEST_TEXT,
            ledger_path=None,
        )
        bundle_dict = bundle.to_dict()

        # Strip runtime_ms for deterministic output
        for r in bundle_dict.get("detector_results", []):
            r.pop("runtime_ms", None)
        for f in bundle_dict.get("detector_failures", []):
            f.pop("runtime_ms", None)

        case1 = seal_case_file(bundle_dict, deterministic=True, fixed_timestamp="1970-01-01T00:00:00+00:00")
        case2 = seal_case_file(bundle_dict, deterministic=True, fixed_timestamp="1970-01-01T00:00:00+00:00")

        self.assertEqual(case1["case_sha256"], case2["case_sha256"])

    def test_golden_file_can_be_regenerated(self):
        """Verify that generating a case file matches the golden file byte-for-byte."""
        bundle = build_forensic_bundle(
            GOLDEN_TEST_TEXT,
            ledger_path=None,
        )
        bundle_dict = bundle.to_dict()

        # Strip runtime_ms for deterministic output
        for r in bundle_dict.get("detector_results", []):
            r.pop("runtime_ms", None)
        for f in bundle_dict.get("detector_failures", []):
            f.pop("runtime_ms", None)

        generated = seal_case_file(bundle_dict, deterministic=True, fixed_timestamp="1970-01-01T00:00:00+00:00")

        # Read golden file
        with open(GOLDEN_CASE_FILE, encoding="utf-8") as f:
            golden = json.load(f)

        # Compare SHA256 hashes
        generated_hash = self._compute_case_hash(generated)
        golden_hash = self._compute_case_hash(golden)

        self.assertEqual(generated_hash, golden_hash,
                         f"Generated case hash {generated_hash} does not match golden hash {golden_hash}")

    def _compute_case_hash(self, case: dict) -> str:
        """Compute the SHA256 hash of a case file in canonical form."""
        # Create a copy without the case_sha256 field for hashing
        case_copy = {k: v for k, v in case.items() if k != "case_sha256"}
        canonical = json.dumps(
            case_copy,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class CapabilityLedgerIntegrationTests(unittest.TestCase):
    """Tests integrating Capability Ledger with Trust Map."""

    def test_ledger_with_validated_claim_affects_trust_map(self):
        """A ledger with validated claims should affect the Trust Map state."""
        ledger = CapabilityLedger()
        ledger.register(CapabilityClaim(
            detector_id="detector-a",
            capability="language.en",
            tier=EvidenceTier.VALIDATED,
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.EXECUTED,
                    tier=EvidenceTier.VALIDATED,
                    artifact="bench/raid-en.json",
                )
            ],
        ))

        trust_map = trust_map_from_capability_ledger(ledger)

        # Find the language.en dimension
        lang_dim = next((d for d in trust_map.dimensions if d.dimension == "language_en"), None)

        self.assertIsNotNone(lang_dim)
        self.assertEqual(lang_dim.state, "supported")

    def test_ledger_serialization_roundtrip(self):
        """A ledger with claims should serialize and deserialize correctly."""
        ledger = CapabilityLedger()
        ledger.register(CapabilityClaim(
            detector_id="detector-x",
            capability="lang.es",
            tier=EvidenceTier.VALIDATED,
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.EXECUTED,
                    tier=EvidenceTier.VALIDATED,
                    artifact="run/es-validation-v1.json",
                    detail="Spanish language validation",
                )
            ],
            valid_until="2027-06-01",
        ))

        # Serialize and deserialize
        data = ledger.to_dict()
        restored = CapabilityLedger.from_dict(data)

        claim = restored.get("detector-x", "lang.es")
        self.assertIsNotNone(claim)
        self.assertEqual(claim.tier, EvidenceTier.VALIDATED)
        self.assertEqual(claim.valid_until, "2027-06-01")
        self.assertEqual(claim.evidence[0].artifact, "run/es-validation-v1.json")


if __name__ == "__main__":
    unittest.main()