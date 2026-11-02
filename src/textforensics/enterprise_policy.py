"""Enterprise policy framework with revision-floor mechanism.

Rejection-rejector pattern:
- SHA-256 digests for policy content integrity
- Revision floor prevents rollback (revision < floor) and same-revision drift
  (revision == floor but digest changed)
- Encrypted state persistence via Fernet
- Policy schema validated against JSON Schema
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

__all__ = [
    "EnterprisePolicy",
    "PolicyRevisionFloor",
    "EnterprisePolicyEngine",
    "PolicyState",
    "validate_enterprise_policy",
    "compute_policy_digest",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# JSON Schema
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


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
            object.__setattr__(self, "revision", abs(self.revision))
            raise ValueError("Policy revision must be non-negative")
        if self.digest and len(self.digest) != 64:
            raise ValueError("Policy digest must be a 64-character hex string")


# ---------------------------------------------------------------------------
# Encrypted state persistence
# ---------------------------------------------------------------------------


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

        self._fernet = Fernet(self._key)
        self._state = self._load_state()

    # -- key management ----------------------------------------------------

    def _load_or_generate_key(self) -> bytes:
        """Load the Fernet key or generate and persist a new one."""
        if self._key_path.exists():
            raw = self._key_path.read_bytes()
            # Fernet keys are base64-encoded 32-byte keys
            if len(raw) in (32, 44):
                # 44 = base64 of 32 bytes; 32 = raw bytes (legacy)
                if len(raw) == 32:
                    return raw
                try:
                    return raw  # base64 encoded
                except Exception:
                    pass
        # Generate new key
        new_key = Fernet.generate_key()
        self._key_path.parent.mkdir(parents=True, exist_ok=True)
        self._key_path.write_bytes(new_key)
        return new_key

    def get_key(self) -> bytes:
        return self._key

    def get_key_path(self) -> Path:
        return self._key_path

    # -- state persistence -------------------------------------------------

    def _load_state(self) -> PolicyState:
        """Load encrypted state from disk or return defaults."""
        state_file = Path(self._state_path)
        if not state_file.exists():
            return PolicyState()
        try:
            token = state_file.read_bytes()
            decrypted = self._fernet.decrypt(token)
            data = json.loads(decrypted)
            return PolicyState.from_dict(data)
        except (InvalidToken, json.JSONDecodeError, Exception):
            return PolicyState()

    def save_state(self) -> None:
        """Encrypt and persist current state to disk."""
        state_file = Path(self._state_path)
        state_file.parent.mkdir(parents=True, exist_ok=True)
        encrypted = self._fernet.encrypt(
            json.dumps(self._state.to_dict(), separators=(",", ":")).encode("utf-8")
        )
        state_file.write_bytes(encrypted)

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


# ---------------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------------


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

        # 2. Compute digest
        computed_digest = hashlib.sha256(
            json.dumps(
                {
                    "revision": policy_data["revision"],
                    "settings": policy_data.get("settings", {}),
                    "rules": [
                        {
                            "id": r["id"],
                            "description": r["description"],
                            "action": r["action"],
                            "scope": r["scope"],
                        }
                        for r in policy_data.get("rules", [])
                    ],
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()

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

        Returns:
            A dict with:
            - ``scope``: the scope evaluated
            - ``revision``: current policy revision
            - ``rules_checked``: number of rules evaluated
            - ``violations``: list of violated rules
            - ``warnings``: list of warning rules
            - ``logs``: list of logged rules
            - ``status``: "ok", "warning", "violation", or "no_policy"
        """
        if self._policy is None:
            return {
                "scope": scope,
                "revision": None,
                "rules_checked": 0,
                "violations": [],
                "warnings": [],
                "logs": [],
                "status": "no_policy",
            }

        violations: list[dict[str, Any]] = []
        warnings: list[dict[str, Any]] = []
        logs: list[dict[str, Any]] = []
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

        if violations:
            status = "violation"
        elif warnings:
            status = "warning"
        else:
            status = "ok"

        return {
            "scope": scope,
            "revision": self._policy.revision,
            "rules_checked": rules_checked,
            "violations": violations,
            "warnings": warnings,
            "logs": logs,
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
