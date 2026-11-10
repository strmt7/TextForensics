"""Capability and enterprise policy for TextForensics.

This module is the single home for claim gating and policy enforcement.
It merges the former ``capability_ledger``, ``capability_policy`` and
``enterprise_policy`` modules; their public names and on-disk formats
are preserved exactly.

- Claim gating: :class:`CapabilityLedger` holds tiered capability claims
  (:class:`EvidenceTier` / :class:`EvidenceLabel` / :class:`EvidenceRef`),
  validated by :func:`validate_claim` and mapped to Trust Map dimensions
  by :func:`ledger_to_trust_dimension`.
- Claim-tier policy: :class:`CapabilityPolicyEngine` evaluates glob-matched
  rules with warn/reject/abstain actions; four prebuilt bundles
  (production, report generation, calibration, minimum viable).
- Enterprise policy: :class:`EnterprisePolicy` documents validated against
  the enterprise-policy JSON Schema, with a Fernet-encrypted monotonic
  revision floor (:class:`PolicyRevisionFloor`) enforced by
  :class:`EnterprisePolicyEngine`. The content-digest recipe exists exactly
  once (:func:`compute_policy_digest`).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from enum import Enum
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any

from textforensics.trust import TrustDimension, _legacy_dimension_name

logger = logging.getLogger(__name__)

__all__ = [
    "CapabilityClaim",
    "CapabilityLedger",
    "CapabilityPolicy",
    "CapabilityPolicyEngine",
    "EnterprisePolicy",
    "EnterprisePolicyEngine",
    "EvidenceLabel",
    "EvidenceRef",
    "EvidenceTier",
    "PolicyKeyError",
    "PolicyResult",
    "PolicyRevisionFloor",
    "PolicyState",
    "PolicyStateCorruptError",
    "compute_policy_digest",
    "claim_is_expired",
    "create_calibration_policy",
    "create_minimum_viable_policy",
    "create_production_policy",
    "create_report_generation_policy",
    "ledger_to_trust_dimension",
    "validate_claim",
    "validate_enterprise_policy",
]

# ----------------------------------------------------------------------------
# Capability claim gating (was capability_ledger.py)
# ----------------------------------------------------------------------------


class EvidenceTier(Enum):
    READABLE = "readable"  # documented but not machine-verifiable
    TOOL_BACKED = "tool_backed"  # backed by a tool that can re-derive
    VALIDATED = "validated"  # backed by committed, reproducible run artifact


class EvidenceLabel(Enum):
    REPORTED = "reported"  # source finding, not reproduced
    CALCULATED = "calculated"  # architecture-derived estimate
    PROPOSED = "proposed"  # engineering choice to test
    EXECUTED = "executed"  # check actually run and recorded


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


def _parse_valid_until(value: str | None) -> date | None:
    """Parse an ISO ``valid_until`` value to a date, or ``None``.

    Returns ``None`` for an absent value and for an unparseable value
    (callers treat unparseable as expired — fail closed).
    """
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    try:
        return date.fromisoformat(text)
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(text).date()
    except ValueError:
        return None


def claim_is_expired(claim: CapabilityClaim, *, today: date | None = None) -> bool:
    """Return ``True`` iff the claim's ``valid_until`` has passed.

    ``valid_until`` is the last valid day (inclusive). A claim with no
    ``valid_until`` never expires on this rule; an unparseable
    ``valid_until`` is treated as expired (fail closed).
    """
    if claim.valid_until is None:
        return False
    expiry = _parse_valid_until(claim.valid_until)
    if expiry is None:
        return True
    return (today or date.today()) > expiry


def _claim_is_effective(claim: CapabilityClaim, *, today: date | None = None) -> bool:
    """Return ``True`` iff the claim is currently effective.

    Effective here means not expired. Evidence sufficiency for a tier
    (for example whether ``VALIDATED`` requires ``EXECUTED`` evidence)
    is the W2 eligibility model (S04) and is deliberately not folded
    into this predicate; :func:`validate_claim` reports it as a
    diagnostic issue instead.
    """
    return not claim_is_expired(claim, today=today)


class CapabilityLedger:
    """Mechanical claim gating for detector capabilities.

    Effectiveness view (``get`` / ``is_validated`` / ``enforce``)
    versus registry view (:meth:`claims` / :meth:`to_dict`):

    * The registry view lists every registered claim, including
      expired ones — the ledger stays an honest record of what was
      registered and when it expires.
    * The effectiveness view returns only claims that are *currently
      effective*, which here means not expired. An expired claim is
      therefore not ``validated`` anywhere: not in
      :func:`mcp_tools.capability_check` (which reads :meth:`get`),
      not in :meth:`enforce` (the CLI-equivalent path), and not in the
      Trust Map mapping. This is the W1 adjudication of the audit's
      cross-auditor lead (``mcp_expired_claim`` /
      ``cli_equivalent_expired_claim``): expiry is decided here, at
      the shared source, never by patching one wrapper's boolean.

    Deliberately NOT decided here: whether a ``VALIDATED`` claim
    without ``EXECUTED`` evidence is effective. :func:`validate_claim`
    already flags that as an issue, but the policy engine's intended
    tier semantics (a registered ``VALIDATED`` claim passes a
    ``validated+`` rule) treat evidence sufficiency as a separate
    eligibility question. That question is the W2 eligibility model
    (S04); W2 decides it and, if it changes effectiveness, changes it
    here at this same choke point — not in any wrapper.

    Expiry semantics: ``valid_until`` is the last day the claim is
    valid (inclusive). A claim is expired when today is after
    ``valid_until``. An unparseable ``valid_until`` is treated as
    expired (fail closed).
    """

    def __init__(self):
        self._claims: dict[str, list[CapabilityClaim]] = {}

    def register(self, claim: CapabilityClaim) -> None:
        """Register a capability claim."""
        if claim.detector_id not in self._claims:
            self._claims[claim.detector_id] = []
        self._claims[claim.detector_id].append(claim)

    def claims(self) -> dict[str, list[CapabilityClaim]]:
        """Return a shallow copy of all registered claims, by detector id.

        Callers outside this module must use this accessor instead of
        reaching into the private ``_claims`` mapping.
        """
        return {det_id: list(claims) for det_id, claims in self._claims.items()}

    def _find(self, detector_id: str, capability: str) -> CapabilityClaim | None:
        """Return the registered claim, regardless of effectiveness."""
        claims = self._claims.get(detector_id, [])
        for c in claims:
            if c.capability == capability:
                return c
        return None

    def get(self, detector_id: str, capability: str) -> CapabilityClaim | None:
        """Get the current claim for a detector+capability.

        Returns ``None`` when no claim is registered OR when the
        registered claim is expired. Use :meth:`claims` to inspect the
        raw registry, including expired claims.
        """
        claim = self._find(detector_id, capability)
        if claim is None or not _claim_is_effective(claim):
            return None
        return claim

    def is_validated(self, detector_id: str, capability: str) -> bool:
        """Check if a claim has VALIDATED evidence tier.

        Only a currently effective (unexpired) ``VALIDATED`` claim
        counts; expired claims return ``False``.
        """
        claim = self.get(detector_id, capability)
        return claim is not None and claim.tier == EvidenceTier.VALIDATED

    def enforce(self, detector_id: str, capability: str) -> CapabilityClaim:
        """Get claim or raise if no claim exists.

        Raises :class:`ValueError` when no claim is registered and when
        the registered claim is expired.
        """
        claim = self._find(detector_id, capability)
        if claim is None:
            raise ValueError(
                f"No capability claim for {detector_id}/{capability}. "
                f"Register a claim before using this capability."
            )
        if not _claim_is_effective(claim):
            raise ValueError(
                f"Capability claim for {detector_id}/{capability} expired on "
                f"{claim.valid_until}. Register a current claim before "
                f"using this capability."
            )
        return claim

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "schema": "textforensics.capability-ledger/v1",
            "generated_at_utc": datetime.now(UTC).isoformat(),
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
    if claim_is_expired(claim):
        issues.append(
            f"Claim {claim.detector_id}/{claim.capability} expired on {claim.valid_until}."
        )
    return issues


def ledger_to_trust_dimension(
    ledger: CapabilityLedger,
    detector_id: str,
    capability_prefix: str,
) -> TrustDimension:
    """Map ledger claims for a detector to a TrustDimension for the Trust Map.

    Claims at VALIDATED tier map to 'supported'; TOOL_BACKED to 'partial';
    READABLE to 'partial'; no claims to 'unknown'. Only currently
    effective (unexpired) claims are considered: an expired claim
    cannot lift a dimension to 'supported' — it maps to 'unknown' with
    the expiry stated.
    """
    claims = ledger._claims.get(detector_id, [])
    relevant = [c for c in claims if c.capability.startswith(capability_prefix)]
    effective = [c for c in relevant if _claim_is_effective(c)]

    if not relevant:
        return TrustDimension(
            dimension=_legacy_dimension_name(capability_prefix),
            state="unknown",
            reason=(
                f"No capability claims registered for {detector_id} "
                f"under prefix '{capability_prefix}'."
            ),
        )

    if not effective:
        return TrustDimension(
            dimension=_legacy_dimension_name(capability_prefix),
            state="unknown",
            reason=(
                f"Capability claims for {detector_id} under prefix "
                f"'{capability_prefix}' exist but none is currently "
                f"effective (all expired)."
            ),
            limitations=[
                f"Claim for {c.capability} expires {c.valid_until}."
                for c in relevant
                if c.valid_until
            ],
        )

    has_validated = any(c.tier == EvidenceTier.VALIDATED for c in effective)
    has_tool_backed = any(c.tier == EvidenceTier.TOOL_BACKED for c in effective)

    if has_validated:
        state = "supported"
        reason = f"Capability '{capability_prefix}' for {detector_id} has VALIDATED-tier evidence."
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
    for c in effective:
        for e in c.evidence:
            evidence_refs.append(e.artifact)
        if c.valid_until:
            limitations.append(f"Claim for {c.capability} expires {c.valid_until}.")

    dimension_name = _legacy_dimension_name(capability_prefix)
    return TrustDimension(
        dimension=dimension_name,
        state=state,
        reason=reason,
        evidence_refs=evidence_refs,
        limitations=limitations,
    )


# ----------------------------------------------------------------------------
# Claim-tier policy engine (was capability_policy.py)
# ----------------------------------------------------------------------------

# NOTE: CapabilityLedger lives in this module now; no TYPE_CHECKING import
# is needed (annotations are strings under `from __future__ import annotations`).


class PolicyResult:
    """Result of a policy evaluation."""

    def __init__(
        self,
        passed: bool,
        rule_id: str,
        message: str,
        missing_claims: list[str] = None,
        evidence_gaps: list[str] = None,
    ):
        self.passed = passed
        self.rule_id = rule_id
        self.message = message
        self.missing_claims = missing_claims or []
        self.evidence_gaps = evidence_gaps or []

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "rule_id": self.rule_id,
            "message": self.message,
            "missing_claims": self.missing_claims,
            "evidence_gaps": self.evidence_gaps,
        }


@dataclass(frozen=True, slots=True)
class CapabilityPolicy:
    """A policy requiring specific capability claims.

    Attributes:
        rule_id: Unique identifier for this policy rule.
        description: Human-readable description.
        detector_pattern: Optional pattern to match detector IDs (glob-style).
        required_capabilities: List of (capability_name, min_tier) tuples.
        action_on_failure: "warn", "reject", or "abstain"
    """

    rule_id: str
    description: str
    required_capabilities: list[tuple[str, str]]  # [(capability, min_tier)]
    detector_pattern: str = "*"
    action_on_failure: str = "reject"  # "warn", "reject", "abstain"


class CapabilityPolicyEngine:
    """Evaluates capability claims against policy rules."""

    def __init__(self):
        self.policies: list[CapabilityPolicy] = []

    def add_policy(self, policy: CapabilityPolicy) -> None:
        """Add a policy rule to the engine."""
        if policy.action_on_failure not in ("warn", "reject", "abstain"):
            raise ValueError(f"Invalid action_on_failure: {policy.action_on_failure}")
        self.policies.append(policy)

    def evaluate(
        self,
        ledger: CapabilityLedger,
        detector_id: str,
        operation: str = "use",
    ) -> list[PolicyResult]:
        """Evaluate all applicable policies for a detector operation.

        Returns list of PolicyResult objects, one per matching policy.
        """

        results: list[PolicyResult] = []

        for policy in self.policies:
            # Check if policy applies to this detector
            if not self._matches_pattern(detector_id, policy.detector_pattern):
                continue

            missing = []
            gaps = []

            for capability, min_tier_str in policy.required_capabilities:
                claim = ledger.get(detector_id, capability)
                if claim is None:
                    missing.append(f"{capability} (required: {min_tier_str}+)")
                    continue

                # Check tier meets minimum
                tier_order = {
                    "readable": 0,
                    "tool_backed": 1,
                    "validated": 2,
                }
                claim_tier = claim.tier.value if hasattr(claim.tier, "value") else str(claim.tier)
                min_tier = min_tier_str.lower()

                if tier_order.get(claim_tier, -1) < tier_order.get(min_tier, -1):
                    gaps.append(f"{capability}: claim tier={claim_tier}, required={min_tier}+")

            passed = len(missing) == 0 and len(gaps) == 0
            action = "PASS" if passed else policy.action_on_failure.upper()

            result = PolicyResult(
                passed=passed,
                rule_id=policy.rule_id,
                message=f"[{action}] {policy.description}",
                missing_claims=missing,
                evidence_gaps=gaps,
            )
            results.append(result)

        return results

    def _matches_pattern(self, detector_id: str, pattern: str) -> bool:
        """Simple glob-style pattern matching."""
        if pattern == "*":
            return True
        if "*" not in pattern:
            return detector_id == pattern
        # Simple prefix/suffix matching
        if pattern.startswith("*") and pattern.endswith("*"):
            return pattern[1:-1] in detector_id
        elif pattern.startswith("*"):
            return detector_id.endswith(pattern[1:])
        elif pattern.endswith("*"):
            return detector_id.startswith(pattern[:-1])
        return False


def create_production_policy() -> CapabilityPolicyEngine:
    """Create a policy engine for production use.

    Requires VALIDATED claims for core capabilities.
    """
    engine = CapabilityPolicyEngine()
    engine.add_policy(
        CapabilityPolicy(
            rule_id="prod-language-coverage",
            description="Production use requires VALIDATED language coverage claim",
            detector_pattern="*",
            required_capabilities=[("language_coverage", "validated")],
            action_on_failure="reject",
        )
    )
    engine.add_policy(
        CapabilityPolicy(
            rule_id="prod-length-robustness",
            description="Production use requires TOOL_BACKED length robustness",
            detector_pattern="*",
            required_capabilities=[("length_robustness", "tool_backed")],
            action_on_failure="warn",
        )
    )
    engine.add_policy(
        CapabilityPolicy(
            rule_id="prod-domain-accuracy",
            description="Production use requires TOOL_BACKED domain accuracy",
            detector_pattern="*",
            required_capabilities=[("domain_accuracy", "tool_backed")],
            action_on_failure="warn",
        )
    )
    return engine


def create_report_generation_policy() -> CapabilityPolicyEngine:
    """Create a policy engine for report generation.

    Ensures reports have minimum trust backing.
    """
    engine = CapabilityPolicyEngine()
    engine.add_policy(
        CapabilityPolicy(
            rule_id="report-trust-map",
            description="Report generation requires trust map claims",
            detector_pattern="*",
            required_capabilities=[("trust_map_generation", "tool_backed")],
            action_on_failure="abstain",
        )
    )
    return engine


def create_calibration_policy() -> CapabilityPolicyEngine:
    """Create a policy engine for calibrated probability outputs.

    Ensures calibrated outputs have EXECUTED evidence.
    """
    engine = CapabilityPolicyEngine()
    engine.add_policy(
        CapabilityPolicy(
            rule_id="cal-probability-output",
            description="Calibrated AI probability requires EXECUTED calibration evidence",
            detector_pattern="*",
            required_capabilities=[("probability_calibration", "validated")],
            action_on_failure="reject",
        )
    )
    return engine


def create_minimum_viable_policy() -> CapabilityPolicyEngine:
    """Create a minimal policy for basic operation.

    Requires READABLE claims as documentation.
    """
    engine = CapabilityPolicyEngine()
    engine.add_policy(
        CapabilityPolicy(
            rule_id="min-documentation",
            description="All detectors must have documented claims",
            detector_pattern="*",
            required_capabilities=[
                ("language_coverage", "readable"),
                ("length_robustness", "readable"),
            ],
            action_on_failure="warn",
        )
    )
    return engine


# ----------------------------------------------------------------------------
# Enterprise policy + revision floor (was enterprise_policy.py)
# ----------------------------------------------------------------------------


def compute_policy_digest(policy: EnterprisePolicy) -> str:
    """Compute a SHA-256 digest of the policy's revision, settings, and rules.

    The digest is the canonical integrity check.  It is deterministic: the
    same logical content always yields the same hash regardless of the
    ``digest`` field's current value.
    """
    blob = json.dumps(
        {
            "revision": policy.revision,
            "settings": policy.settings,
            "rules": [
                {
                    "id": r["id"],
                    "description": r["description"],
                    "action": r["action"],
                    "scope": r["scope"],
                }
                for r in policy.rules
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@lru_cache(maxsize=4)
def _load_enterprise_policy_schema() -> dict[str, Any]:
    resource = files("textforensics").joinpath("schemas", "enterprise-policy.schema.json")
    return json.loads(resource.read_text(encoding="utf-8"))


def validate_enterprise_policy(policy: dict[str, Any]) -> list[str]:
    """Validate a policy dictionary against the enterprise-policy JSON schema.

    Returns a list of human-readable error messages (empty if valid).
    """
    try:
        import jsonschema
    except ImportError as exc:
        raise RuntimeError(
            "jsonschema is required for policy validation. Install with 'pip install jsonschema'."
        ) from exc

    schema = _load_enterprise_policy_schema()
    try:
        validator = jsonschema.Draft202012Validator(schema)
    except jsonschema.exceptions.SchemaError:
        return ["The enterprise policy schema itself is invalid"]

    errors = sorted(validator.iter_errors(policy), key=lambda e: list(e.path))
    return [f"{'.'.join(str(p) for p in err.path)}: {err.message}" for err in errors]


@dataclass(frozen=True, slots=True)
class EnterprisePolicy:
    """An enterprise policy document.

    Attributes:
        revision: Non-negative monotonic revision number.
        digest: SHA-256 hex digest of the policy content.
        settings: Arbitrary settings dictionary.
        rules: List of enterprise rule dictionaries.
    """

    revision: int
    digest: str
    settings: dict[str, Any]
    rules: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "revision": self.revision,
            "digest": self.digest,
            "settings": self.settings,
            "rules": self.rules,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EnterprisePolicy:
        revision = int(data["revision"])
        digest = str(data.get("digest", ""))
        settings = dict(data.get("settings", {}))
        rules = [dict(r) for r in data.get("rules", [])]
        return cls(revision=revision, digest=digest, settings=settings, rules=rules)

    def __post_init__(self) -> None:
        if self.revision < 0:
            raise ValueError("Policy revision must be non-negative")
        if self.digest and len(self.digest) != 64:
            raise ValueError("Policy digest must be a 64-character hex string")


@dataclass
class PolicyState:
    """Persisted state for the revision floor mechanism."""

    floor_revision: int = 0
    floor_digest: str = ""
    history: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "floor_revision": self.floor_revision,
            "floor_digest": self.floor_digest,
            "history": self.history,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyState:
        return cls(
            floor_revision=int(data.get("floor_revision", 0)),
            floor_digest=str(data.get("floor_digest", "")),
            history=list(data.get("history", [])),
        )


class PolicyStateCorruptError(ValueError):
    """Raised when a persisted revision-floor state file exists but cannot
    be decrypted or parsed (tampered ciphertext, wrong key, truncated file,
    or malformed JSON).

    Fail closed: the floor must never silently reset to revision 0, which
    would let any policy re-base the floor and defeat anti-rollback. Only a
    MISSING state file yields defaults; a present-but-unreadable one is an
    error the operator must resolve explicitly. Subclasses :class:`ValueError`
    so CLI entry points report it as a clean ``error: ...`` instead of a
    traceback.
    """


class PolicyKeyError(ValueError):
    """Raised when an existing policy key file is not a valid Fernet key.

    A fresh key is never generated over an existing key file: the operator
    must delete or replace the file explicitly, otherwise the old encrypted
    state would become undecryptable. Subclasses :class:`ValueError` so CLI
    entry points report it as a clean ``error: ...`` instead of a traceback.
    """


class PolicyRevisionFloor:
    """Tracks and enforces a monotonic revision floor with encrypted persistence.

    Rejection-rejector guarantees:
    1. **No rollback** – a policy with ``revision < floor`` is rejected.
    2. **No same-revision drift** – a policy with ``revision == floor`` and a
       different digest is rejected (content changed at same revision number).
    3. **Monotonic advance** – the floor advances only when a higher revision
       is accepted.

    State is persisted encrypted with Fernet to a configurable path.
    """

    def __init__(
        self,
        state_path: Path | None = None,
        key: bytes | None = None,
        key_path: Path | None = None,
    ) -> None:
        # Lazy import cryptography for enterprise features
        try:
            from cryptography.fernet import Fernet
        except ImportError as exc:
            raise RuntimeError(
                "cryptography is required for enterprise policy features. "
                "Install with: pip install textforensics[enterprise]"
            ) from exc
        self._Fernet = Fernet

        self._state_path = (
            state_path
            if state_path is not None
            else Path(
                os.environ.get(
                    "TEXTFORENSICS_POLICY_STATE",
                    str(Path.home() / ".textforensics" / "policy-state.enc"),
                )
            )
        )
        self._key_path = (
            key_path
            if key_path is not None
            else Path(
                os.environ.get(
                    "TEXTFORENSICS_POLICY_KEY",
                    str(Path.home() / ".textforensics" / "policy-key.key"),
                )
            )
        )
        if key is not None:
            self._key = key
        else:
            self._key = self._load_or_generate_key()

        self._fernet = self._Fernet(self._key)
        self._state = self._load_state()

    # -- key management ----------------------------------------------------

    @staticmethod
    def _atomic_write_bytes(path: Path, data: bytes) -> None:
        """Write bytes atomically: temp file in the same directory + replace.

        A torn write must never leave a half-written key or state file
        behind; ``os.replace`` makes the switch atomic on one filesystem.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=f"{path.name}.", dir=path.parent)
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as tmp:
                tmp.write(data)
                tmp.flush()
                os.fsync(tmp.fileno())
            os.replace(tmp_path, path)
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise

    def _load_or_generate_key(self) -> bytes:
        """Load the Fernet key or generate and persist a new one.

        An existing key file is NEVER overwritten. A legacy 32-byte raw key
        is converted to its base64 form (same key material, only the
        encoding changes) and re-persisted in that form as an explicit
        one-time migration. Any other content raises :class:`PolicyKeyError`
        naming the key path. A new key is generated only when no key file
        exists. A candidate key is accepted only if ``Fernet()`` accepts
        it — validated by construction, not by length-sniffing alone.
        """
        if self._key_path.exists():
            raw = self._key_path.read_bytes()
            # Check the 32-byte legacy length BEFORE stripping: a raw key
            # may end (or start) in a whitespace byte that .strip() would
            # remove, shrinking it to 31 bytes and making a valid legacy
            # key look invalid (flaky PolicyKeyError, ~5% of random keys).
            if len(raw) == 32:
                # Legacy raw 32-byte key: convert to base64 form (same key
                # material, encoding only) and re-persist the converted form.
                converted = base64.urlsafe_b64encode(raw)
                self._Fernet(converted)  # validate by construction
                self._atomic_write_bytes(self._key_path, converted)
                return converted
            stripped = raw.strip()
            try:
                self._Fernet(stripped)
            except Exception as exc:
                raise PolicyKeyError(
                    f"invalid policy key file: {self._key_path}. The file is "
                    "not a valid Fernet key. Delete it (or replace it with "
                    "a valid key) to generate a fresh key explicitly; a new "
                    "key is never generated over an existing key file."
                ) from exc
            return stripped
        # Generate a new key (only when no key file exists).
        new_key = self._Fernet.generate_key()
        self._atomic_write_bytes(self._key_path, new_key)
        return new_key

    def get_key(self) -> bytes:
        return self._key

    def get_key_path(self) -> Path:
        return self._key_path

    # -- state persistence -------------------------------------------------

    def _load_state(self) -> PolicyState:
        """Load encrypted state from disk or return defaults.

        Only a MISSING state file yields defaults. A state file that exists
        but cannot be decrypted or parsed raises
        :class:`PolicyStateCorruptError` — the floor must never silently
        reset to revision 0, which would let any policy re-base it.
        """
        state_file = Path(self._state_path)
        if not state_file.exists():
            return PolicyState()
        try:
            token = state_file.read_bytes()
            decrypted = self._fernet.decrypt(token)
            data = json.loads(decrypted)
            return PolicyState.from_dict(data)
        except Exception as exc:
            # Log the path only — never the key or ciphertext.
            logger.error(
                "policy state file %s exists but cannot be decrypted or "
                "parsed; refusing to reset the revision floor",
                state_file,
            )
            raise PolicyStateCorruptError(
                f"policy state file {state_file} exists but cannot be "
                "decrypted or parsed (tampered, wrong key, truncated, or "
                "malformed). The revision floor is not reset; restore the "
                "state file or delete it explicitly to start from a fresh "
                "floor."
            ) from exc

    def save_state(self) -> None:
        """Encrypt and persist current state to disk (atomically)."""
        state_file = Path(self._state_path)
        state_file.parent.mkdir(parents=True, exist_ok=True)
        encrypted = self._fernet.encrypt(
            json.dumps(self._state.to_dict(), separators=(",", ":")).encode("utf-8")
        )
        self._atomic_write_bytes(state_file, encrypted)

    @property
    def state(self) -> PolicyState:
        return self._state

    @property
    def floor_revision(self) -> int:
        return self._state.floor_revision

    @property
    def floor_digest(self) -> str:
        return self._state.floor_digest

    # -- core rejection-rejector logic -------------------------------------

    def check_policy(self, policy: EnterprisePolicy) -> list[str]:
        """Check a policy against the revision floor.

        Returns a list of rejection reasons (empty if accepted).
        """
        rejections: list[str] = []

        if policy.revision < self._state.floor_revision:
            rejections.append(
                f"ROLLBACK: revision {policy.revision} < floor "
                f"{self._state.floor_revision}. Policy rollback is not allowed."
            )
        elif policy.revision == self._state.floor_revision:
            expected_digest = self._state.floor_digest
            if expected_digest and policy.digest != expected_digest:
                rejections.append(
                    f"DRIFT: same-revision drift detected at revision "
                    f"{policy.revision}. Expected digest {expected_digest[:16]}..., "
                    f"got {policy.digest[:16]}..."
                )

        return rejections

    def advance_floor(self, policy: EnterprisePolicy) -> None:
        """Advance the floor to the policy's revision and digest.

        Only advances if the policy revision is strictly greater than the
        current floor, or if the floor has never been set.
        """
        if policy.revision > self._state.floor_revision:
            self._state.floor_revision = policy.revision
            self._state.floor_digest = policy.digest
            self._state.history.append(
                {
                    "revision": policy.revision,
                    "digest": policy.digest,
                    "action": "advance",
                }
            )
            self.save_state()
        elif self._state.floor_revision == 0 and not self._state.floor_digest:
            # First policy loaded: set the floor
            self._state.floor_revision = policy.revision
            self._state.floor_digest = policy.digest
            self._state.history.append(
                {
                    "revision": policy.revision,
                    "digest": policy.digest,
                    "action": "initialize",
                }
            )
            self.save_state()

    def reset(self) -> None:
        """Reset the floor to initial state. Use with caution."""
        self._state = PolicyState()
        self.save_state()


class EnterprisePolicyEngine:
    """Enforces enterprise policy rules against operations.

    The engine loads a validated ``EnterprisePolicy``, checks the revision
    floor, and then evaluates the policy's rules. Each rule has an ``action``
    (enforce, warn, log, disable) and a ``scope``.

    Example usage::

        engine = EnterprisePolicyEngine(policy_file="enterprise.json")
        result = engine.evaluate("analysis")
        if result.violations:
            print("Policy violations detected!")
    """

    def __init__(
        self,
        policy: EnterprisePolicy | None = None,
        floor: PolicyRevisionFloor | None = None,
    ) -> None:
        self._policy = policy
        self._floor = floor

    @property
    def policy(self) -> EnterprisePolicy | None:
        return self._policy

    @policy.setter
    def policy(self, value: EnterprisePolicy) -> None:
        self._policy = value

    @property
    def floor(self) -> PolicyRevisionFloor | None:
        return self._floor

    def load_policy(
        self,
        policy_data: dict[str, Any],
        *,
        floor: PolicyRevisionFloor | None = None,
    ) -> list[str]:
        """Load and validate a policy from a dictionary.

        Steps:
        1. JSON Schema validation
        2. Compute digest
        3. Revision floor check
        4. Advance floor if valid

        Returns a list of rejection reasons.
        """
        # 1. Schema validation
        errors = validate_enterprise_policy(policy_data)
        if errors:
            return errors

        # 2. Compute digest (single implementation: compute_policy_digest)
        computed_digest = compute_policy_digest(
            EnterprisePolicy(
                revision=int(policy_data["revision"]),
                digest="",
                settings=dict(policy_data.get("settings", {})),
                rules=[dict(r) for r in policy_data.get("rules", [])],
            )
        )

        # If the policy has a digest field, compare
        if "digest" in policy_data and policy_data["digest"] != computed_digest:
            return [
                f"Digest mismatch: stored {policy_data['digest'][:16]}... "
                f"computed {computed_digest[:16]}..."
            ]

        policy = EnterprisePolicy(
            revision=int(policy_data["revision"]),
            digest=computed_digest,
            settings=dict(policy_data.get("settings", {})),
            rules=[dict(r) for r in policy_data.get("rules", [])],
        )

        # 3. Floor check
        rev_floor = floor or self._floor
        if rev_floor:
            rejections = rev_floor.check_policy(policy)
            if rejections:
                return rejections

        # 4. Advance floor
        if rev_floor:
            rev_floor.advance_floor(policy)

        self._policy = policy
        return []

    def evaluate(self, scope: str) -> dict[str, Any]:
        """Evaluate active policy rules for a given scope.

        A rule matches when its ``scope`` is ``"all"`` or equals ``scope``.
        Matching rules are collected by action:

        - ``"enforce"`` rules become ``violations``,
        - ``"warn"`` rules become ``warnings``,
        - ``"log"`` rules become ``logs``,
        - ``"disable"`` rules become ``disabled`` (the scope is disabled
          for the operation being evaluated).

        Status precedence is: violations beat warnings, warnings beat
        disabled, and disabled beats ok. A matching ``"disable"`` rule
        therefore reports status ``"disabled"`` only when no violation
        or warning applies; it is still listed in ``disabled`` when a
        violation or warning wins.

        Returns:
            A dict with:
            - ``scope``: the scope evaluated
            - ``revision``: current policy revision
            - ``rules_checked``: number of rules evaluated
            - ``violations``: list of violated rules
            - ``warnings``: list of warning rules
            - ``logs``: list of logged rules
            - ``disabled``: list of disable rules that matched, each
              with ``rule_id``, ``description`` and ``scope``
            - ``disabled_scopes``: distinct scopes of the matching
              disable rules, in order of first appearance
            - ``status``: "ok", "warning", "violation", "disabled",
              or "no_policy"
        """
        if self._policy is None:
            return {
                "scope": scope,
                "revision": None,
                "rules_checked": 0,
                "violations": [],
                "warnings": [],
                "logs": [],
                "disabled": [],
                "disabled_scopes": [],
                "status": "no_policy",
            }

        violations: list[dict[str, Any]] = []
        warnings: list[dict[str, Any]] = []
        logs: list[dict[str, Any]] = []
        disabled: list[dict[str, Any]] = []
        disabled_scopes: list[str] = []
        rules_checked = 0

        for rule in self._policy.rules:
            rule_scope = rule.get("scope", "")
            if rule_scope != "all" and rule_scope != scope:
                continue

            rules_checked += 1
            action = rule.get("action", "log")

            if action == "enforce":
                violations.append({"rule_id": rule["id"], "description": rule["description"]})
            elif action == "warn":
                warnings.append({"rule_id": rule["id"], "description": rule["description"]})
            elif action == "log":
                logs.append({"rule_id": rule["id"], "description": rule["description"]})
            elif action == "disable":
                disabled.append(
                    {
                        "rule_id": rule["id"],
                        "description": rule["description"],
                        "scope": rule_scope,
                    }
                )
                if rule_scope not in disabled_scopes:
                    disabled_scopes.append(rule_scope)

        if violations:
            status = "violation"
        elif warnings:
            status = "warning"
        elif disabled:
            status = "disabled"
        else:
            status = "ok"

        return {
            "scope": scope,
            "revision": self._policy.revision,
            "rules_checked": rules_checked,
            "violations": violations,
            "warnings": warnings,
            "logs": logs,
            "disabled": disabled,
            "disabled_scopes": disabled_scopes,
            "status": status,
        }

    def get_status(self) -> dict[str, Any]:
        """Return the current engine status including floor information."""
        result: dict[str, Any] = {"policy_loaded": self._policy is not None}
        if self._policy:
            result["revision"] = self._policy.revision
            result["digest"] = self._policy.digest
        if self._floor:
            result["floor_revision"] = self._floor.floor_revision
            result["floor_digest"] = self._floor.floor_digest
            result["history"] = self._floor.state.history
        return result

    def export(self) -> dict[str, Any]:
        """Export the current policy state including floor information."""
        result: dict[str, Any] = {}
        if self._policy:
            result["policy"] = self._policy.to_dict()
        if self._floor:
            result["floor"] = {
                "floor_revision": self._floor.floor_revision,
                "floor_digest": self._floor.floor_digest,
                "history": self._floor.state.history,
            }
        return result
