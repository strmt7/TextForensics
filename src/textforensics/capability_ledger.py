"""Capability Ledger: mechanical claim gating for TextForensics.

Three-tier claim classification:
- READABLE: claim is documented but not machine-verifiable
- TOOL_BACKED: claim is backed by a tool that can re-derive it
- VALIDATED: claim is backed by a committed, reproducible run artifact

Every detector capability (language coverage, length robustness, domain accuracy)
must declare which tier it's in, with named evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from textforensics.trust import TrustDimension


class EvidenceTier(Enum):
    READABLE = "readable"       # documented but not machine-verifiable
    TOOL_BACKED = "tool_backed" # backed by a tool that can re-derive
    VALIDATED = "validated"     # backed by committed, reproducible run artifact


class EvidenceLabel(Enum):
    REPORTED = "reported"       # source finding, not reproduced
    CALCULATED = "calculated"   # architecture-derived estimate
    PROPOSED = "proposed"       # engineering choice to test
    EXECUTED = "executed"       # check actually run and recorded


@dataclass(slots=True)
class EvidenceRef:
    """Reference to evidence backing a claim."""
    label: EvidenceLabel
    tier: EvidenceTier
    artifact: str  # path or run ID
    detail: str | None = None


@dataclass(slots=True)
class CapabilityClaim:
    """A single capability claim."""
    detector_id: str
    capability: str  # e.g. "language_coverage.en", "length_robustness.medium"
    tier: EvidenceTier
    evidence: list[EvidenceRef] = field(default_factory=list)
    valid_until: str | None = None  # ISO date when this claim expires


class CapabilityLedger:
    """Mechanical claim gating for detector capabilities."""

    def __init__(self):
        self._claims: dict[str, list[CapabilityClaim]] = {}

    def register(self, claim: CapabilityClaim) -> None:
        """Register a capability claim."""
        if claim.detector_id not in self._claims:
            self._claims[claim.detector_id] = []
        self._claims[claim.detector_id].append(claim)

    def get(self, detector_id: str, capability: str) -> CapabilityClaim | None:
        """Get the current claim for a detector+capability."""
        claims = self._claims.get(detector_id, [])
        for c in claims:
            if c.capability == capability:
                return c
        return None

    def is_validated(self, detector_id: str, capability: str) -> bool:
        """Check if a claim has VALIDATED evidence tier."""
        claim = self.get(detector_id, capability)
        return claim is not None and claim.tier == EvidenceTier.VALIDATED

    def enforce(self, detector_id: str, capability: str) -> CapabilityClaim:
        """Get claim or raise if no claim exists."""
        claim = self.get(detector_id, capability)
        if claim is None:
            raise ValueError(
                f"No capability claim for {detector_id}/{capability}. "
                f"Register a claim before using this capability."
            )
        return claim

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "schema": "textforensics.capability-ledger/v1",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "claims": {
                det_id: [
                    {
                        "capability": c.capability,
                        "tier": c.tier.value,
                        "evidence": [
                            {
                                "label": e.label.value,
                                "tier": e.tier.value,
                                "artifact": e.artifact,
                                "detail": e.detail,
                            }
                            for e in c.evidence
                        ],
                        "valid_until": c.valid_until,
                    }
                    for c in claims
                ]
                for det_id, claims in self._claims.items()
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CapabilityLedger:
        """Deserialize from dict."""
        ledger = cls()
        for det_id, claims in data.get("claims", {}).items():
            for c in claims:
                claim = CapabilityClaim(
                    detector_id=det_id,
                    capability=c["capability"],
                    tier=EvidenceTier(c["tier"]),
                    evidence=[
                        EvidenceRef(
                            label=EvidenceLabel(e["label"]),
                            tier=EvidenceTier(e["tier"]),
                            artifact=e["artifact"],
                            detail=e.get("detail"),
                        )
                        for e in c.get("evidence", [])
                    ],
                    valid_until=c.get("valid_until"),
                )
                ledger.register(claim)
        return ledger


def validate_claim(claim: CapabilityClaim) -> list[str]:
    """Validate a capability claim. Returns list of issues (empty = valid)."""
    issues = []
    if not claim.evidence:
        issues.append(
            f"No evidence for claim {claim.detector_id}/{claim.capability}. "
            f"Every claim must carry at least one evidence reference."
        )
    if claim.tier == EvidenceTier.VALIDATED:
        has_executed = any(e.label == EvidenceLabel.EXECUTED for e in claim.evidence)
        if not has_executed:
            issues.append(
                f"VALIDATED claim {claim.detector_id}/{claim.capability} "
                f"requires at least one EXECUTED evidence reference."
            )
    return issues


def ledger_to_trust_dimension(
    ledger: CapabilityLedger,
    detector_id: str,
    capability_prefix: str,
) -> TrustDimension:
    """Map ledger claims for a detector to a TrustDimension for the Trust Map.

    Claims at VALIDATED tier map to 'supported'; TOOL_BACKED to 'partial';
    READABLE to 'partial'; no claims to 'unknown'.
    """
    claims = ledger._claims.get(detector_id, [])
    relevant = [c for c in claims if c.capability.startswith(capability_prefix)]

    if not relevant:
        return TrustDimension(
            dimension=capability_prefix.replace(".", "_"),
            state="unknown",
            reason=(
                f"No capability claims registered for {detector_id} "
                f"under prefix '{capability_prefix}'."
            ),
        )

    has_validated = any(c.tier == EvidenceTier.VALIDATED for c in relevant)
    has_tool_backed = any(c.tier == EvidenceTier.TOOL_BACKED for c in relevant)

    if has_validated:
        state = "supported"
        reason = (
            f"Capability '{capability_prefix}' for {detector_id} has "
            f"VALIDATED-tier evidence."
        )
    elif has_tool_backed:
        state = "partial"
        reason = (
            f"Capability '{capability_prefix}' for {detector_id} is "
            f"TOOL_BACKED but not yet VALIDATED."
        )
    else:
        state = "partial"
        reason = (
            f"Capability '{capability_prefix}' for {detector_id} is "
            f"only READABLE (documented but not machine-verifiable)."
        )

    evidence_refs = []
    limitations = []
    for c in relevant:
        for e in c.evidence:
            evidence_refs.append(e.artifact)
        if c.valid_until:
            limitations.append(
                f"Claim for {c.capability} expires {c.valid_until}."
            )

    return TrustDimension(
        dimension=capability_prefix.replace(".", "_"),
        state=state,
        reason=reason,
        evidence_refs=evidence_refs,
        limitations=limitations,
    )
