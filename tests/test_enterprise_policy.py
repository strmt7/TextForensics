"""Tests for enterprise policy framework with revision-floor mechanism."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from dataclasses import FrozenInstanceError
from datetime import date

import pytest
from cryptography.fernet import Fernet

import textforensics.policy as policy_module
from textforensics.policy import (
    CapabilityClaim,
    CapabilityLedger,
    CapabilityPolicy,
    CapabilityPolicyEngine,
    EnterprisePolicy,
    EnterprisePolicyEngine,
    EvidenceLabel,
    EvidenceRef,
    EvidenceTier,
    PolicyKeyError,
    PolicyRevisionFloor,
    PolicyState,
    PolicyStateCorruptError,
    _parse_valid_until,
    claim_is_expired,
    compute_policy_digest,
    create_calibration_policy,
    create_minimum_viable_policy,
    create_production_policy,
    create_report_generation_policy,
    ledger_to_trust_dimension,
    validate_claim,
    validate_enterprise_policy,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def policy_data():
    return {
        "revision": 1,
        "settings": {"enforce_local_first": True, "allow_remote": False},
        "rules": [
            {
                "id": "no-remote",
                "description": "Remote detectors must not be used",
                "action": "enforce",
                "scope": "all",
            },
            {
                "id": "require-provenance",
                "description": "All analyses require provenance",
                "action": "warn",
                "scope": "analysis",
            },
        ],
    }


@pytest.fixture
def valid_policy(policy_data):
    """Create a valid policy with computed digest."""
    # Compute digest directly from data
    digest = hashlib.sha256(
        json.dumps(
            {
                "revision": policy_data["revision"],
                "settings": policy_data["settings"],
                "rules": [
                    {
                        "id": r["id"],
                        "description": r["description"],
                        "action": r["action"],
                        "scope": r["scope"],
                    }
                    for r in policy_data["rules"]
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    return EnterprisePolicy(
        revision=policy_data["revision"],
        digest=digest,
        settings=policy_data["settings"],
        rules=policy_data["rules"],
    )


@pytest.fixture
def temp_state_dir(tmp_path):
    """Create a temporary directory for state files."""
    state_dir = tmp_path / ".textforensics"
    state_dir.mkdir()
    return state_dir


# ---------------------------------------------------------------------------
# EnterprisePolicy dataclass tests
# ---------------------------------------------------------------------------


class TestEnterprisePolicy:
    def test_from_dict(self, policy_data):
        policy = EnterprisePolicy.from_dict(policy_data)
        assert policy.revision == 1
        assert policy.digest == ""
        assert policy.settings["enforce_local_first"] is True
        assert len(policy.rules) == 2

    def test_to_dict_roundtrip(self, valid_policy):
        data = valid_policy.to_dict()
        policy = EnterprisePolicy.from_dict(data)
        assert policy.revision == valid_policy.revision
        assert policy.digest == valid_policy.digest
        assert policy.settings == valid_policy.settings
        assert len(policy.rules) == len(valid_policy.rules)

    def test_negative_revision_rejected(self, policy_data):
        policy_data["revision"] = -1
        with pytest.raises(ValueError, match="non-negative"):
            EnterprisePolicy(
                revision=policy_data["revision"],
                digest="a" * 64,
                settings=policy_data["settings"],
                rules=policy_data["rules"],
            )

    def test_invalid_digest_length(self, policy_data):
        with pytest.raises(ValueError, match="64-character"):
            EnterprisePolicy(
                revision=policy_data["revision"],
                digest="abc",
                settings=policy_data["settings"],
                rules=policy_data["rules"],
            )

    def test_frozen(self, valid_policy):
        with pytest.raises(Exception):
            valid_policy.revision = 99  # type: ignore


# ---------------------------------------------------------------------------
# compute_policy_digest tests
# ---------------------------------------------------------------------------


class TestComputePolicyDigest:
    def test_deterministic(self, valid_policy):
        digest1 = compute_policy_digest(valid_policy)
        digest2 = compute_policy_digest(valid_policy)
        assert digest1 == digest2
        assert len(digest1) == 64
        assert all(c in "0123456789abcdef" for c in digest1)

    def test_different_revision_different_digest(self, valid_policy):
        policy_v2 = EnterprisePolicy(
            revision=valid_policy.revision + 1,
            digest="",
            settings=valid_policy.settings,
            rules=valid_policy.rules,
        )
        digest1 = compute_policy_digest(valid_policy)
        digest2 = compute_policy_digest(policy_v2)
        assert digest1 != digest2

    def test_different_settings_different_digest(self, valid_policy):
        policy = EnterprisePolicy(
            revision=valid_policy.revision,
            digest="",
            settings={"enforce_local_first": False},
            rules=valid_policy.rules,
        )
        assert compute_policy_digest(valid_policy) != compute_policy_digest(policy)

    def test_different_rules_different_digest(self, valid_policy):
        policy = EnterprisePolicy(
            revision=valid_policy.revision,
            digest="",
            settings=valid_policy.settings,
            rules=[{"id": "other", "description": "x", "action": "log", "scope": "all"}],
        )
        assert compute_policy_digest(valid_policy) != compute_policy_digest(policy)

    def test_digest_field_does_not_affect_computation(self, valid_policy):
        policy_alt = EnterprisePolicy(
            revision=valid_policy.revision,
            digest="b" * 64,  # different digest field
            settings=valid_policy.settings,
            rules=valid_policy.rules,
        )
        # Digest computation ignores the digest field itself
        assert compute_policy_digest(valid_policy) == compute_policy_digest(policy_alt)


# ---------------------------------------------------------------------------
# JSON Schema validation tests
# ---------------------------------------------------------------------------


class TestValidateEnterprisePolicy:
    def test_valid_policy(self, policy_data):
        errors = validate_enterprise_policy(policy_data)
        assert errors == []

    def test_missing_revision(self, policy_data):
        del policy_data["revision"]
        errors = validate_enterprise_policy(policy_data)
        assert any("revision" in err for err in errors)

    def test_missing_rules(self, policy_data):
        del policy_data["rules"]
        errors = validate_enterprise_policy(policy_data)
        assert any("rules" in err for err in errors)

    def test_empty_rules_rejected(self, policy_data):
        policy_data["rules"] = []
        errors = validate_enterprise_policy(policy_data)
        assert any("rules" in err for err in errors)

    def test_invalid_rule_id(self, policy_data):
        policy_data["rules"][0]["id"] = "INVALID ID"
        errors = validate_enterprise_policy(policy_data)
        assert any("id" in err.lower() for err in errors)

    def test_invalid_action(self, policy_data):
        policy_data["rules"][0]["action"] = "explode"
        errors = validate_enterprise_policy(policy_data)
        assert any("action" in err.lower() for err in errors)

    def test_missing_rule_description(self, policy_data):
        del policy_data["rules"][0]["description"]
        errors = validate_enterprise_policy(policy_data)
        assert any("description" in err.lower() for err in errors)

    def test_negative_revision_rejected(self, policy_data):
        policy_data["revision"] = -1
        errors = validate_enterprise_policy(policy_data)
        assert any("revision" in err for err in errors)

    def test_digest_format(self, policy_data):
        policy_data["digest"] = "not-a-real-digest"
        errors = validate_enterprise_policy(policy_data)
        assert any("digest" in err.lower() for err in errors)

    def test_valid_digest_format(self, policy_data):
        policy_data["digest"] = hashlib.sha256(b"test").hexdigest()
        errors = validate_enterprise_policy(policy_data)
        assert not any("digest" in err.lower() for err in errors)


# ---------------------------------------------------------------------------
# PolicyState tests
# ---------------------------------------------------------------------------


class TestPolicyState:
    def test_defaults(self):
        state = PolicyState()
        assert state.floor_revision == 0
        assert state.floor_digest == ""
        assert state.history == []

    def test_to_dict(self):
        state = PolicyState(floor_revision=5, floor_digest="abc123", history=[{"revision": 1}])
        data = state.to_dict()
        assert data["floor_revision"] == 5
        assert data["floor_digest"] == "abc123"
        assert len(data["history"]) == 1

    def test_from_dict(self):
        data = {"floor_revision": 3, "floor_digest": "def456", "history": []}
        state = PolicyState.from_dict(data)
        assert state.floor_revision == 3
        assert state.floor_digest == "def456"
        assert state.history == []

    def test_from_dict_empty(self):
        state = PolicyState.from_dict({})
        assert state.floor_revision == 0
        assert state.floor_digest == ""


# ---------------------------------------------------------------------------
# PolicyRevisionFloor tests
# ---------------------------------------------------------------------------


class TestPolicyRevisionFloor:
    def test_initial_state(self, temp_state_dir):
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        assert floor.floor_revision == 0
        assert floor.floor_digest == ""

    def test_first_policy_initializes_floor(self, temp_state_dir, valid_policy):
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        floor.advance_floor(valid_policy)
        assert floor.floor_revision == valid_policy.revision
        assert floor.floor_digest == valid_policy.digest

    def test_same_policy_accepted(self, temp_state_dir, valid_policy):
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        floor.advance_floor(valid_policy)
        rejections = floor.check_policy(valid_policy)
        assert rejections == []

    def test_rollback_rejected(self, temp_state_dir, valid_policy):
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        floor.advance_floor(valid_policy)

        # Try to load a lower revision
        old_policy = EnterprisePolicy(
            revision=0,
            digest="a" * 64,
            settings=valid_policy.settings,
            rules=valid_policy.rules,
        )
        rejections = floor.check_policy(old_policy)
        assert len(rejections) == 1
        assert "ROLLBACK" in rejections[0]

    def test_same_revision_drift_rejected(self, temp_state_dir, valid_policy):
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        floor.advance_floor(valid_policy)

        # Same revision but different content (different digest)
        drifted_policy = EnterprisePolicy(
            revision=valid_policy.revision,
            digest="b" * 64,
            settings={"enforce_local_first": False},
            rules=valid_policy.rules,
        )
        rejections = floor.check_policy(drifted_policy)
        assert len(rejections) == 1
        assert "DRIFT" in rejections[0]

    def test_advance_accepted(self, temp_state_dir, valid_policy):
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        floor.advance_floor(valid_policy)

        # Higher revision is accepted
        new_policy = EnterprisePolicy(
            revision=2,
            digest="c" * 64,
            settings=valid_policy.settings,
            rules=valid_policy.rules,
        )
        rejections = floor.check_policy(new_policy)
        assert rejections == []
        floor.advance_floor(new_policy)
        assert floor.floor_revision == 2
        assert floor.floor_digest == new_policy.digest

    def test_state_encrypted(self, temp_state_dir, valid_policy):
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        floor.advance_floor(valid_policy)

        state_file = temp_state_dir / "state.enc"
        assert state_file.exists()
        # The file should NOT contain plaintext JSON
        raw = state_file.read_text()
        assert "floor_revision" not in raw

    def test_state_persists_across_instances(self, temp_state_dir, valid_policy):
        # First instance
        floor1 = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        floor1.advance_floor(valid_policy)

        # Second instance reads persisted state
        floor2 = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        assert floor2.floor_revision == valid_policy.revision
        assert floor2.floor_digest == valid_policy.digest

    def test_history_tracked(self, temp_state_dir, valid_policy):
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        floor.advance_floor(valid_policy)
        new_policy = EnterprisePolicy(
            revision=2,
            digest="d" * 64,
            settings=valid_policy.settings,
            rules=valid_policy.rules,
        )
        floor.advance_floor(new_policy)

        history = floor.state.history
        assert len(history) == 2
        assert history[0]["action"] in ("initialize", "advance")
        assert history[1]["action"] == "advance"
        assert history[1]["revision"] == 2

    def test_reset(self, temp_state_dir, valid_policy):
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        floor.advance_floor(valid_policy)
        floor.reset()
        assert floor.floor_revision == 0
        assert floor.floor_digest == ""

    def test_encrypted_state_corruption_raises(self, temp_state_dir, valid_policy):
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        floor.advance_floor(valid_policy)

        # Corrupt the encrypted state file
        state_file = temp_state_dir / "state.enc"
        state_file.write_bytes(b"corrupted-data")

        # Fail closed: a present-but-unreadable state must never silently
        # reset the floor to revision 0 (that would permit rollback).
        with pytest.raises(PolicyStateCorruptError) as excinfo:
            PolicyRevisionFloor(
                state_path=temp_state_dir / "state.enc",
                key_path=temp_state_dir / "key.key",
            )
        assert "state.enc" in str(excinfo.value)

    def test_wrong_key_file_raises(self, temp_state_dir, valid_policy):
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        floor.advance_floor(valid_policy)

        # Change the key to a 13-byte file: not a valid Fernet key, and a
        # fresh key must never be generated over an existing key file.
        (temp_state_dir / "new-key.key").write_text("different-key", encoding="utf-8")

        with pytest.raises(PolicyKeyError) as excinfo:
            PolicyRevisionFloor(
                state_path=temp_state_dir / "state.enc",
                key_path=temp_state_dir / "new-key.key",
            )
        assert "new-key.key" in str(excinfo.value)
        # The invalid key file was not overwritten with a fresh key.
        assert (temp_state_dir / "new-key.key").read_text(encoding="utf-8") == ("different-key")

    def test_valid_but_wrong_key_raises_corrupt_state(self, temp_state_dir, valid_policy):
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        floor.advance_floor(valid_policy)

        # A different VALID Fernet key cannot decrypt the state: fail
        # closed with PolicyStateCorruptError, not a silent floor reset.
        (temp_state_dir / "other-key.key").write_bytes(Fernet.generate_key())

        with pytest.raises(PolicyStateCorruptError):
            PolicyRevisionFloor(
                state_path=temp_state_dir / "state.enc",
                key_path=temp_state_dir / "other-key.key",
            )

    def test_legacy_32_byte_raw_key_converted(self, temp_state_dir, valid_policy):
        # Fixed key, not os.urandom(32): _load_or_generate_key strips the
        # key file's bytes, and a random key whose first/last byte is
        # ASCII whitespace loses a byte to .strip(), so the 32-byte check
        # fails ~4.5% of runs and the test flakes (PolicyKeyError instead
        # of conversion). bytes(range(32)) has no edge-whitespace byte,
        # so .strip() is a no-op and the test is deterministic.
        raw_key = bytes(range(32))
        (temp_state_dir / "key.key").write_bytes(raw_key)

        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        floor.advance_floor(valid_policy)
        assert floor.floor_revision == valid_policy.revision

        # Same key material, only the encoding changed; the file was
        # re-persisted in base64 form as an explicit one-time migration.
        converted = base64.urlsafe_b64encode(raw_key)
        assert floor.get_key() == converted
        assert (temp_state_dir / "key.key").read_bytes() == converted

        # A second instance loads the converted key and the saved state.
        floor2 = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        assert floor2.floor_revision == valid_policy.revision
        assert floor2.floor_digest == valid_policy.digest

    def test_legacy_32_byte_raw_key_with_whitespace_bytes(self, temp_state_dir, valid_policy):
        # A raw key may start or end in a byte .strip() would remove; the
        # 32-byte length check must run BEFORE stripping, or such a key is
        # wrongly rejected (regression: Core 3.15 failed the random-key
        # test above on exactly this, ~5% of random keys).
        raw_key = b" " + os.urandom(30) + b"\n"
        assert len(raw_key) == 32
        (temp_state_dir / "key.key").write_bytes(raw_key)

        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        floor.advance_floor(valid_policy)
        assert floor.floor_revision == valid_policy.revision

        converted = base64.urlsafe_b64encode(raw_key)
        assert floor.get_key() == converted
        assert (temp_state_dir / "key.key").read_bytes() == converted

    @pytest.mark.parametrize(
        "bad_key",
        [
            pytest.param(b"!" * 44, id="non-base64-44-bytes"),
            pytest.param(b"A" * 44, id="base64-decoding-to-33-bytes"),
            pytest.param(b"x" * 20, id="truncated-20-bytes"),
            pytest.param(b"", id="empty-file"),
        ],
    )
    def test_invalid_key_file_raises(self, temp_state_dir, bad_key):
        (temp_state_dir / "key.key").write_bytes(bad_key)

        with pytest.raises(PolicyKeyError) as excinfo:
            PolicyRevisionFloor(
                state_path=temp_state_dir / "state.enc",
                key_path=temp_state_dir / "key.key",
            )
        assert "key.key" in str(excinfo.value)
        # The invalid key file was not overwritten with a fresh key.
        assert (temp_state_dir / "key.key").read_bytes() == bad_key

    def test_missing_key_file_generates(self, temp_state_dir):
        key_path = temp_state_dir / "key.key"
        assert not key_path.exists()

        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=key_path,
        )
        assert key_path.exists()
        generated = key_path.read_bytes()
        assert len(generated) == 44
        Fernet(generated)  # valid Fernet key by construction
        assert floor.get_key() == generated

    def test_save_load_round_trip(self, temp_state_dir, valid_policy):
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        floor.advance_floor(valid_policy)
        floor.save_state()

        floor2 = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        assert floor2.floor_revision == floor.floor_revision
        assert floor2.floor_digest == floor.floor_digest
        assert floor2.state.history == floor.state.history
        # Atomic writes leave no temp files behind.
        assert list(temp_state_dir.glob("state.enc.*")) == []
        assert list(temp_state_dir.glob("key.key.*")) == []

    def test_env_config(self, temp_state_dir, valid_policy, monkeypatch):
        monkeypatch.setenv("TEXTFORENSICS_POLICY_STATE", str(temp_state_dir / "env-state.enc"))
        monkeypatch.setenv("TEXTFORENSICS_POLICY_KEY", str(temp_state_dir / "env-key.key"))

        floor = PolicyRevisionFloor()
        assert floor._state_path == temp_state_dir / "env-state.enc"
        assert floor._key_path == temp_state_dir / "env-key.key"


# ---------------------------------------------------------------------------
# EnterprisePolicyEngine tests
# ---------------------------------------------------------------------------


class TestEnterprisePolicyEngine:
    def test_engine_no_policy(self):
        engine = EnterprisePolicyEngine()
        assert engine.policy is None

    def test_load_valid_policy(self, temp_state_dir, policy_data):
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        engine = EnterprisePolicyEngine(floor=floor)
        errors = engine.load_policy(policy_data)
        assert errors == []
        assert engine.policy is not None
        assert engine.policy.revision == 1

    def test_load_invalid_policy(self, policy_data, temp_state_dir):
        del policy_data["rules"]
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        engine = EnterprisePolicyEngine(floor=floor)
        errors = engine.load_policy(policy_data)
        assert len(errors) > 0

    def test_load_rollback_rejected(self, temp_state_dir, policy_data, valid_policy):
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        engine = EnterprisePolicyEngine(floor=floor)

        # Load v1
        engine.load_policy(policy_data)

        # Try to load v0
        old_data = dict(policy_data)
        old_data["revision"] = 0
        errors = engine.load_policy(old_data)
        assert len(errors) > 0
        assert any("ROLLBACK" in e for e in errors)

    def test_evaluate_no_policy(self):
        engine = EnterprisePolicyEngine()
        result = engine.evaluate("analysis")
        assert result["status"] == "no_policy"
        assert result["disabled"] == []
        assert result["disabled_scopes"] == []

    def test_evaluate_all_scope(self, temp_state_dir, policy_data):
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        engine = EnterprisePolicyEngine(floor=floor)
        engine.load_policy(policy_data)

        result = engine.evaluate("analysis")
        assert result["status"] == "violation"
        assert len(result["violations"]) == 1
        assert result["violations"][0]["rule_id"] == "no-remote"

    def test_evaluate_scoped_rules(self, temp_state_dir, policy_data):
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        engine = EnterprisePolicyEngine(floor=floor)
        engine.load_policy(policy_data)

        # The "all" scope rule applies to every scope
        result = engine.evaluate("analysis")
        assert len(result["warnings"]) == 1
        assert result["warnings"][0]["rule_id"] == "require-provenance"

    def test_evaluate_log_action(self, temp_state_dir):
        policy = {
            "revision": 1,
            "settings": {},
            "rules": [
                {
                    "id": "log-all",
                    "description": "Log everything",
                    "action": "log",
                    "scope": "all",
                },
            ],
        }
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        engine = EnterprisePolicyEngine(floor=floor)
        engine.load_policy(policy)

        result = engine.evaluate("analysis")
        assert result["status"] == "ok"
        assert len(result["logs"]) == 1

    def test_evaluate_disable_action(self, temp_state_dir):
        policy = {
            "revision": 1,
            "settings": {},
            "rules": [
                {
                    "id": "disable-analysis",
                    "description": "Analysis is disabled",
                    "action": "disable",
                    "scope": "analysis",
                },
            ],
        }
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        engine = EnterprisePolicyEngine(floor=floor)
        engine.load_policy(policy)

        result = engine.evaluate("analysis")
        assert result["status"] == "disabled"
        assert result["disabled"] == [
            {
                "rule_id": "disable-analysis",
                "description": "Analysis is disabled",
                "scope": "analysis",
            }
        ]
        assert result["disabled_scopes"] == ["analysis"]
        assert result["violations"] == []
        assert result["warnings"] == []

    def test_evaluate_disable_non_matching_scope(self, temp_state_dir):
        policy = {
            "revision": 1,
            "settings": {},
            "rules": [
                {
                    "id": "disable-detection",
                    "description": "Detection is disabled",
                    "action": "disable",
                    "scope": "detection",
                },
            ],
        }
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        engine = EnterprisePolicyEngine(floor=floor)
        engine.load_policy(policy)

        result = engine.evaluate("analysis")
        assert result["status"] == "ok"
        assert result["rules_checked"] == 0
        assert result["disabled"] == []
        assert result["disabled_scopes"] == []

    def test_evaluate_disable_plus_violation(self, temp_state_dir):
        policy = {
            "revision": 1,
            "settings": {},
            "rules": [
                {
                    "id": "disable-analysis",
                    "description": "Analysis is disabled",
                    "action": "disable",
                    "scope": "analysis",
                },
                {
                    "id": "no-remote",
                    "description": "No remote detectors",
                    "action": "enforce",
                    "scope": "all",
                },
            ],
        }
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        engine = EnterprisePolicyEngine(floor=floor)
        engine.load_policy(policy)

        result = engine.evaluate("analysis")
        # Violations win over disabled, but the disable rule is still listed.
        assert result["status"] == "violation"
        assert len(result["violations"]) == 1
        assert result["violations"][0]["rule_id"] == "no-remote"
        assert [d["rule_id"] for d in result["disabled"]] == ["disable-analysis"]
        assert result["disabled_scopes"] == ["analysis"]

    def test_evaluate_disable_plus_warning(self, temp_state_dir):
        policy = {
            "revision": 1,
            "settings": {},
            "rules": [
                {
                    "id": "disable-analysis",
                    "description": "Analysis is disabled",
                    "action": "disable",
                    "scope": "analysis",
                },
                {
                    "id": "warn-provenance",
                    "description": "Require provenance",
                    "action": "warn",
                    "scope": "all",
                },
            ],
        }
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        engine = EnterprisePolicyEngine(floor=floor)
        engine.load_policy(policy)

        result = engine.evaluate("analysis")
        # Warnings win over disabled, but the disable rule is still listed.
        assert result["status"] == "warning"
        assert len(result["warnings"]) == 1
        assert [d["rule_id"] for d in result["disabled"]] == ["disable-analysis"]
        assert result["disabled_scopes"] == ["analysis"]

    def test_get_status(self, temp_state_dir, policy_data, valid_policy):
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        engine = EnterprisePolicyEngine(floor=floor)
        engine.load_policy(policy_data)

        status = engine.get_status()
        assert status["policy_loaded"] is True
        assert status["revision"] == 1
        assert "floor_revision" in status

    def test_export(self, temp_state_dir, policy_data):
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        engine = EnterprisePolicyEngine(floor=floor)
        engine.load_policy(policy_data)

        exported = engine.export()
        assert "policy" in exported
        assert "floor" in exported
        assert exported["policy"]["revision"] == 1

    def test_policy_setter(self, temp_state_dir, valid_policy):
        engine = EnterprisePolicyEngine()
        engine.policy = valid_policy
        assert engine.policy.revision == valid_policy.revision

    def test_load_same_revision_drift(self, temp_state_dir, policy_data):
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        engine = EnterprisePolicyEngine(floor=floor)
        engine.load_policy(policy_data)

        # Same revision but different settings
        drifted = dict(policy_data)
        drifted["settings"] = {"enforce_local_first": False}
        errors = engine.load_policy(drifted)
        assert len(errors) > 0
        assert any("DRIFT" in e for e in errors)


# ---------------------------------------------------------------------------
# CLI integration tests
# ---------------------------------------------------------------------------


class TestPolicyCLI:
    def _write_policy(self, tmp_path, data):
        f = tmp_path / "policy.json"
        f.write_text(json.dumps(data), encoding="utf-8")
        return f

    def test_load_valid_policy(self, tmp_path, policy_data):
        policy_file = self._write_policy(tmp_path, policy_data)
        state_dir = tmp_path / ".state"
        state_dir.mkdir()

        from textforensics.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(
            [
                "policy",
                "load",
                str(policy_file),
                "--state-path",
                str(state_dir / "state.enc"),
                "--key-path",
                str(state_dir / "key.key"),
            ]
        )
        from textforensics.cli import _run
        from textforensics.config import Settings

        result = _run(args, Settings())
        assert result == 0

    def test_load_invalid_policy(self, tmp_path, policy_data):
        del policy_data["rules"]
        policy_file = self._write_policy(tmp_path, policy_data)

        from textforensics.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(["policy", "load", str(policy_file)])
        from textforensics.cli import _run
        from textforensics.config import Settings

        result = _run(args, Settings())
        assert result != 0

    def test_check_command(self, tmp_path, policy_data):
        policy_file = self._write_policy(tmp_path, policy_data)
        state_dir = tmp_path / ".state"
        state_dir.mkdir()

        from textforensics.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(
            [
                "policy",
                "check",
                str(policy_file),
                "--state-path",
                str(state_dir / "state.enc"),
                "--key-path",
                str(state_dir / "key.key"),
            ]
        )
        from textforensics.cli import _run
        from textforensics.config import Settings

        result = _run(args, Settings())
        assert result == 0

    def test_check_no_file(self, tmp_path):
        state_dir = tmp_path / ".state"
        state_dir.mkdir()

        from textforensics.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(
            [
                "policy",
                "check",
                "--state-path",
                str(state_dir / "state.enc"),
                "--key-path",
                str(state_dir / "key.key"),
            ]
        )
        from textforensics.cli import _run
        from textforensics.config import Settings

        result = _run(args, Settings())
        assert result == 0

    def test_advance_command(self, tmp_path, policy_data):
        policy_file = self._write_policy(tmp_path, policy_data)
        state_dir = tmp_path / ".state"
        state_dir.mkdir()

        from textforensics.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(
            [
                "policy",
                "advance",
                str(policy_file),
                "--state-path",
                str(state_dir / "state.enc"),
                "--key-path",
                str(state_dir / "key.key"),
            ]
        )
        from textforensics.cli import _run
        from textforensics.config import Settings

        result = _run(args, Settings())
        assert result == 0

    def test_export_command(self, tmp_path):
        state_dir = tmp_path / ".state"
        state_dir.mkdir()

        from textforensics.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(
            [
                "policy",
                "export",
                "--state-path",
                str(state_dir / "state.enc"),
                "--key-path",
                str(state_dir / "key.key"),
            ]
        )
        from textforensics.cli import _run
        from textforensics.config import Settings

        result = _run(args, Settings())
        assert result == 0

    def test_load_with_no_advance(self, tmp_path, policy_data):
        policy_file = self._write_policy(tmp_path, policy_data)
        state_dir = tmp_path / ".state"
        state_dir.mkdir()

        from textforensics.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(
            [
                "policy",
                "load",
                str(policy_file),
                "--state-path",
                str(state_dir / "state.enc"),
                "--key-path",
                str(state_dir / "key.key"),
                "--no-advance",
            ]
        )
        from textforensics.cli import _run
        from textforensics.config import Settings

        result = _run(args, Settings())
        assert result == 0

    def test_load_bad_json(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("{invalid json", encoding="utf-8")

        from textforensics.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(["policy", "load", str(f)])
        from textforensics.cli import _run
        from textforensics.config import Settings

        result = _run(args, Settings())
        assert result != 0

    def test_advance_rollback_rejected(self, tmp_path, policy_data):
        state_dir = tmp_path / ".state"
        state_dir.mkdir()

        from textforensics.cli import build_parser

        parser = build_parser()
        from textforensics.cli import _run
        from textforensics.config import Settings

        # First advance with v1
        policy_file = self._write_policy(tmp_path, policy_data)
        args = parser.parse_args(
            [
                "policy",
                "advance",
                str(policy_file),
                "--state-path",
                str(state_dir / "state.enc"),
                "--key-path",
                str(state_dir / "key.key"),
            ]
        )
        result = _run(args, Settings())
        assert result == 0

        # Try to advance with v0
        old_data = dict(policy_data)
        old_data["revision"] = 0
        old_file = self._write_policy(tmp_path, old_data)
        args = parser.parse_args(
            [
                "policy",
                "advance",
                str(old_file),
                "--state-path",
                str(state_dir / "state.enc"),
                "--key-path",
                str(state_dir / "key.key"),
            ]
        )
        result = _run(args, Settings())
        assert result != 0


# ---------------------------------------------------------------------------
# Schema registration tests
# ---------------------------------------------------------------------------


class TestSchemaRegistration:
    def test_enterprise_policy_schema_in_schema_names(self):
        from textforensics.schema import _SCHEMA_NAMES

        assert "enterprise-policy" in _SCHEMA_NAMES

    def test_enterprise_policy_schema_loads(self):
        from textforensics.schema import load_schema

        schema = load_schema("enterprise-policy")
        assert schema["$schema"]
        assert "required" in schema
        assert "revision" in schema["required"]

    def test_list_schemas_includes_enterprise(self):
        from textforensics.schema import list_schemas

        names = list_schemas()
        assert "enterprise-policy" in names

    def test_validate_function_enterprise_policy(self, policy_data):
        from textforensics.schema import validate

        errors = validate(policy_data, "enterprise-policy")
        assert errors == []


# ---------------------------------------------------------------------------
# Mutation-kill tests (Phase 5 wave 4E)
# ---------------------------------------------------------------------------
# The per-mutant test command for textforensics.policy runs only this
# file, so the ledger / claim-tier policy behaviour — covered elsewhere
# by tests/test_capability_ledger.py and tests/test_capability_policy.py
# — had no killing tests here. The budget-200 repro run on 6159552
# (total 200, killed 58, surviving 142; 10 of the 58 kills were false
# kills from the flaky legacy-key test fixed above) left 70 killable
# survivors in this file's scope; these tests kill them. Each test
# names the mutants it kills as (operator, occurrence) in the
# budget-200 session. The 4 NumberReplacer survivors that no test can
# kill (occ 4, 8, 22, 23) and the 78 annotation BitOr survivors are
# equivalent and live in mutation-baseline.toml instead.


def _make_claim(
    detector="det-a",
    capability="language_coverage",
    tier=EvidenceTier.VALIDATED,
    evidence=None,
):
    if evidence is None:
        evidence = [
            EvidenceRef(
                label=EvidenceLabel.EXECUTED,
                tier=EvidenceTier.VALIDATED,
                artifact="run-1",
            )
        ]
    return CapabilityClaim(
        detector_id=detector,
        capability=capability,
        tier=tier,
        evidence=evidence,
    )


def _ledger_with_claim(claim):
    ledger = CapabilityLedger()
    ledger.register(claim)
    return ledger


def _engine_requiring(capability, min_tier, action="reject"):
    engine = CapabilityPolicyEngine()
    engine.add_policy(
        CapabilityPolicy(
            rule_id="test-rule",
            description="Test rule",
            required_capabilities=[(capability, min_tier)],
            detector_pattern="*",
            action_on_failure=action,
        )
    )
    return engine


class TestPolicyMutationKills:
    # -- CapabilityLedger: register / get / enforce / is_validated --------

    def test_register_second_claim_same_detector_kept(self):
        # Kills AddNot occ 0 (register: mutant resets the detector's
        # list on the second register, wiping the first claim) and
        # RemoveDecorator occ 0/1 (EvidenceRef / CapabilityClaim lose
        # their dataclass __init__).
        ledger = CapabilityLedger()
        ledger.register(_make_claim(capability="language_coverage"))
        ledger.register(_make_claim(capability="length_robustness"))
        claims = ledger.claims()["det-a"]
        assert len(claims) == 2
        assert {c.capability for c in claims} == {
            "language_coverage",
            "length_robustness",
        }
        assert ledger.get("det-a", "language_coverage") is not None
        assert ledger.get("det-a", "length_robustness") is not None

    def test_get_returns_matching_capability_not_first(self):
        # Kills AddNot occ 1 (get: mutant returns the first claim whose
        # capability does NOT match).
        ledger = CapabilityLedger()
        first = _make_claim(capability="language_coverage")
        second = _make_claim(capability="length_robustness")
        ledger.register(first)
        ledger.register(second)
        assert ledger.get("det-a", "length_robustness") is second
        assert ledger.get("det-a", "language_coverage") is first
        assert ledger.get("det-a", "missing_capability") is None
        assert ledger.get("missing-detector", "language_coverage") is None

    def test_enforce_missing_raises_and_present_returns(self):
        # Kills AddNot occ 2 (enforce: mutant raises when the claim
        # exists and returns None when it does not).
        ledger = CapabilityLedger()
        claim = _make_claim()
        ledger.register(claim)
        assert ledger.enforce("det-a", "language_coverage") is claim
        with pytest.raises(ValueError, match="No capability claim"):
            ledger.enforce("det-a", "missing_capability")
        with pytest.raises(ValueError, match="No capability claim"):
            ledger.enforce("missing-detector", "language_coverage")

    def test_is_validated_requires_validated_tier(self):
        # Kills ReplaceAndWithOr occ 0 (is_validated: mutant returns
        # True for a READABLE claim and raises AttributeError for a
        # missing one).
        ledger = CapabilityLedger()
        ledger.register(_make_claim(tier=EvidenceTier.VALIDATED))
        ledger.register(
            _make_claim(
                detector="det-b",
                tier=EvidenceTier.READABLE,
                evidence=[
                    EvidenceRef(
                        label=EvidenceLabel.REPORTED,
                        tier=EvidenceTier.READABLE,
                        artifact="doc-1",
                    )
                ],
            )
        )
        assert ledger.is_validated("det-a", "language_coverage") is True
        assert ledger.is_validated("det-b", "language_coverage") is False
        assert ledger.is_validated("det-a", "missing_capability") is False
        assert ledger.is_validated("missing-detector", "language_coverage") is False

    def test_ledger_from_dict_roundtrip(self):
        # Kills RemoveDecorator occ 2 (from_dict loses @classmethod, so
        # the call fails) and exercises register/get serialisation.
        ledger = CapabilityLedger()
        ledger.register(_make_claim(capability="language_coverage"))
        ledger.register(_make_claim(capability="length_robustness"))
        restored = CapabilityLedger.from_dict(ledger.to_dict())
        assert restored.get("det-a", "language_coverage") is not None
        assert restored.get("det-a", "length_robustness") is not None
        assert restored.get("det-a", "language_coverage").tier == EvidenceTier.VALIDATED

    # -- validate_claim ----------------------------------------------------

    def test_validate_claim_with_evidence_is_clean(self):
        # Kills AddNot occ 3 (mutant flags "No evidence" when evidence
        # IS present) and occ 4 (mutant demands EXECUTED evidence from
        # a non-VALIDATED claim).
        claim = _make_claim(
            tier=EvidenceTier.READABLE,
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.REPORTED,
                    tier=EvidenceTier.READABLE,
                    artifact="doc-1",
                )
            ],
        )
        assert validate_claim(claim) == []

    def test_validate_claim_validated_without_executed_flagged(self):
        # Kills AddNot occ 5 (mutant skips the EXECUTED requirement for
        # VALIDATED claims).
        claim = _make_claim(
            tier=EvidenceTier.VALIDATED,
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.REPORTED,
                    tier=EvidenceTier.VALIDATED,
                    artifact="doc-1",
                )
            ],
        )
        issues = validate_claim(claim)
        assert len(issues) == 1
        assert "EXECUTED" in issues[0]

    def test_validate_claim_validated_with_executed_clean(self):
        assert validate_claim(_make_claim(tier=EvidenceTier.VALIDATED)) == []

    def test_validate_claim_no_evidence_flagged(self):
        issues = validate_claim(_make_claim(tier=EvidenceTier.READABLE, evidence=[]))
        assert len(issues) == 1
        assert "No evidence" in issues[0]

    # -- ledger_to_trust_dimension -----------------------------------------

    def test_no_claims_maps_to_unknown(self):
        # Kills AddNot occ 6 (mutant takes the supported/partial path
        # when there are no relevant claims).
        dimension = ledger_to_trust_dimension(CapabilityLedger(), "det-a", "language_coverage")
        assert dimension.state == "unknown"

    def test_validated_claim_maps_to_supported(self):
        # Kills AddNot occ 7 (mutant demotes a VALIDATED claim to
        # partial).
        ledger = _ledger_with_claim(_make_claim(tier=EvidenceTier.VALIDATED))
        dimension = ledger_to_trust_dimension(ledger, "det-a", "language_coverage")
        assert dimension.state == "supported"

    def test_tool_backed_and_readable_map_to_partial(self):
        for tier in (EvidenceTier.TOOL_BACKED, EvidenceTier.READABLE):
            ledger = _ledger_with_claim(_make_claim(tier=tier))
            dimension = ledger_to_trust_dimension(ledger, "det-a", "language_coverage")
            assert dimension.state == "partial"

    def test_valid_until_becomes_limitation(self):
        # Kills AddNot occ 8 (mutant drops the expiry limitation).
        claim = CapabilityClaim(
            detector_id="det-a",
            capability="language_coverage",
            tier=EvidenceTier.VALIDATED,
            evidence=[],
            valid_until="2030-01-01",
        )
        ledger = _ledger_with_claim(claim)
        dimension = ledger_to_trust_dimension(ledger, "det-a", "language_coverage")
        assert dimension.limitations == ["Claim for language_coverage expires 2030-01-01."]
        assert dimension.evidence_refs == []

    def test_dimension_collects_evidence_artifacts(self):
        ledger = _ledger_with_claim(_make_claim(tier=EvidenceTier.VALIDATED))
        dimension = ledger_to_trust_dimension(ledger, "det-a", "language_coverage")
        assert dimension.evidence_refs == ["run-1"]

    # -- CapabilityPolicyEngine: add_policy / evaluate ----------------------

    def test_add_policy_rejects_invalid_action(self):
        # Kills AddNot occ 9 (mutant accepts an invalid action and
        # rejects every valid one) and RemoveDecorator occ 3
        # (CapabilityPolicy loses its dataclass __init__).
        engine = CapabilityPolicyEngine()
        with pytest.raises(ValueError, match="Invalid action_on_failure"):
            engine.add_policy(
                CapabilityPolicy(
                    rule_id="bad",
                    description="bad action",
                    required_capabilities=[],
                    action_on_failure="explode",
                )
            )
        for action in ("warn", "reject", "abstain"):
            engine.add_policy(
                CapabilityPolicy(
                    rule_id=f"ok-{action}",
                    description="ok",
                    required_capabilities=[],
                    action_on_failure=action,
                )
            )
        assert len(engine.policies) == 3

    def test_evaluate_matching_policy_produces_result(self):
        # Kills AddNot occ 10 (mutant skips every policy whose pattern
        # matches the detector).
        ledger = _ledger_with_claim(_make_claim(tier=EvidenceTier.VALIDATED))
        engine = _engine_requiring("language_coverage", "validated")
        results = engine.evaluate(ledger, "det-a")
        assert len(results) == 1
        assert results[0].passed is True
        assert results[0].rule_id == "test-rule"

    def test_evaluate_non_matching_pattern_skipped(self):
        # Kills AddNot occ 15 (_matches_pattern: mutant returns True
        # for every pattern, so a non-matching policy applies).
        ledger = _ledger_with_claim(_make_claim(tier=EvidenceTier.VALIDATED))
        engine = CapabilityPolicyEngine()
        engine.add_policy(
            CapabilityPolicy(
                rule_id="other-det-only",
                description="other detector",
                required_capabilities=[("language_coverage", "validated")],
                detector_pattern="other-det",
                action_on_failure="reject",
            )
        )
        assert engine.evaluate(ledger, "det-a") == []

    def test_evaluate_present_claim_passes(self):
        # Kills AddNot occ 11 (mutant reports a present claim as
        # missing), occ 12 (mutant str()s the tier, so the tier lookup
        # misses), occ 13 (mutant flags a gap when the tier is
        # sufficient) and occ 14 (mutant labels a pass with the failure
        # action); also kills NumberReplacer occ 11/13
        # (len(...) == -1 can never be True, so `passed` is always
        # False under the mutant).
        ledger = _ledger_with_claim(_make_claim(tier=EvidenceTier.VALIDATED))
        engine = _engine_requiring("language_coverage", "validated")
        (result,) = engine.evaluate(ledger, "det-a")
        assert result.passed is True
        assert result.missing_claims == []
        assert result.evidence_gaps == []
        assert result.message.startswith("[PASS]")

    def test_evaluate_missing_claim_reports_missing(self):
        # Kills NumberReplacer occ 10 (len(missing) == 1: mutant
        # passes with exactly one missing claim) and ReplaceAndWithOr
        # occ 1 (mutant passes when either list is empty).
        ledger = CapabilityLedger()
        engine = _engine_requiring("language_coverage", "validated")
        (result,) = engine.evaluate(ledger, "det-a")
        assert result.passed is False
        assert result.missing_claims == ["language_coverage (required: validated+)"]
        assert result.evidence_gaps == []
        assert result.message.startswith("[REJECT]")

    def test_evaluate_insufficient_tier_reports_gap(self):
        # Kills NumberReplacer occ 12 (len(gaps) == 1: mutant passes
        # with exactly one tier gap).
        ledger = _ledger_with_claim(_make_claim(tier=EvidenceTier.READABLE))
        engine = _engine_requiring("language_coverage", "validated")
        (result,) = engine.evaluate(ledger, "det-a")
        assert result.passed is False
        assert result.missing_claims == []
        assert len(result.evidence_gaps) == 1
        assert "claim tier=readable, required=validated+" in result.evidence_gaps[0]

    @pytest.mark.parametrize(
        "claim_tier,min_tier,expect_gap",
        [
            # Kills NumberReplacer occ 1 (readable 0 -> -1: mutant
            # flags a gap for readable-vs-readable).
            (EvidenceTier.READABLE, "readable", False),
            # Kills NumberReplacer occ 0 (readable 0 -> 1: mutant
            # passes readable-vs-tool_backed).
            (EvidenceTier.READABLE, "tool_backed", True),
            # Kills NumberReplacer occ 3 (tool_backed 1 -> 0: mutant
            # flags a gap for tool_backed-vs-tool_backed).
            (EvidenceTier.TOOL_BACKED, "tool_backed", False),
            # Kills NumberReplacer occ 2 (tool_backed 1 -> 2: mutant
            # passes tool_backed-vs-validated).
            (EvidenceTier.TOOL_BACKED, "validated", True),
            # Kills NumberReplacer occ 5 (validated 2 -> 1: mutant
            # flags a gap for validated-vs-validated).
            (EvidenceTier.VALIDATED, "validated", False),
        ],
    )
    def test_tier_ordering_boundaries(self, claim_tier, min_tier, expect_gap):
        ledger = _ledger_with_claim(_make_claim(tier=claim_tier))
        engine = _engine_requiring("language_coverage", min_tier)
        (result,) = engine.evaluate(ledger, "det-a")
        assert (len(result.evidence_gaps) > 0) == expect_gap
        assert result.passed is not expect_gap

    def test_unknown_tier_falls_back_to_default(self):
        # A non-Enum tier exercises the tier_order.get(..., -1)
        # defaults on both sides. Case (a) kills NumberReplacer occ 6
        # (claim default -1 -> -2: mutant flags a gap) and occ 9 (min
        # default -1 -> 0: mutant flags a gap); case (b) kills occ 7
        # (claim default -1 -> 0: mutant passes a bogus tier against a
        # readable requirement).
        claim = CapabilityClaim(
            detector_id="det-a",
            capability="language_coverage",
            tier="bogus",
            evidence=[],
        )
        ledger = _ledger_with_claim(claim)
        engine = _engine_requiring("language_coverage", "nonsense")
        (result,) = engine.evaluate(ledger, "det-a")
        assert result.passed is True
        assert result.evidence_gaps == []

        engine = _engine_requiring("language_coverage", "readable")
        (result,) = engine.evaluate(ledger, "det-a")
        assert result.passed is False
        assert len(result.evidence_gaps) == 1

    @pytest.mark.parametrize(
        "pattern,detector,expected",
        [
            ("*", "det-a", True),
            # Kills AddNot occ 16 (mutant returns False for exact
            # patterns).
            ("det-a", "det-a", True),
            # Kills AddNot occ 15 (mutant returns True for every
            # pattern).
            ("det-a", "other", False),
            # Kills AddNot occ 17 (mutant falls through to the
            # suffix branch) and NumberReplacer occ 15
            # (pattern[1:-1] -> [0:-1]: "*mid" is not in "amid").
            ("*mid*", "amid", True),
            # Kills NumberReplacer occ 14 ([2:-1]: "id" is in
            # "valid") and occ 17 ([1:-0] is "" — always contained).
            ("*mid*", "valid", False),
            # Kills NumberReplacer occ 16 ([1:-2]: "mi" is in "mild").
            ("*mid*", "mild", False),
            # Kills NumberReplacer occ 19 (pattern[1:] -> [0:]:
            # "xsuf" does not end with "*suf").
            ("*suf", "xsuf", True),
            # Kills NumberReplacer occ 18 (pattern[1:] -> [2:]:
            # "xuf" ends with "uf").
            ("*suf", "xuf", False),
            # Kills ReplaceAndWithOr occ 2 (mutant takes the contains
            # branch for a suffix-only pattern: "su" is in "xsux").
            ("*suf", "xsux", False),
            ("pre*", "prefix", True),
            # Kills NumberReplacer occ 21 (pattern[:-1] -> [:-0]:
            # "" is a prefix of everything).
            ("pre*", "xprefix", False),
            # Kills NumberReplacer occ 20 (pattern[:-1] -> [:-2]:
            # "prx" starts with "pr").
            ("pre*", "prx", False),
        ],
    )
    def test_matches_pattern_branches(self, pattern, detector, expected):
        engine = CapabilityPolicyEngine()
        assert engine._matches_pattern(detector, pattern) is expected

    def test_evaluate_action_message_pass_vs_fail(self):
        # Kills AddNot occ 14 (mutant labels a pass with the failure
        # action and vice versa).
        passing = _engine_requiring("language_coverage", "validated", action="reject")
        ledger = _ledger_with_claim(_make_claim(tier=EvidenceTier.VALIDATED))
        assert passing.evaluate(ledger, "det-a")[0].message.startswith("[PASS]")
        failing = _engine_requiring("language_coverage", "validated", action="warn")
        assert failing.evaluate(CapabilityLedger(), "det-a")[0].message.startswith("[WARN]")

    def test_create_policy_factories(self):
        production = create_production_policy()
        assert [p.rule_id for p in production.policies] == [
            "prod-language-coverage",
            "prod-length-robustness",
            "prod-domain-accuracy",
        ]
        assert [p.rule_id for p in create_report_generation_policy().policies] == [
            "report-trust-map"
        ]
        assert [p.rule_id for p in create_calibration_policy().policies] == [
            "cal-probability-output"
        ]
        assert [p.rule_id for p in create_minimum_viable_policy().policies] == ["min-documentation"]

    # -- PolicyRevisionFloor: messages / floor arithmetic ------------------

    def test_drift_message_shows_16_hex_chars(self, temp_state_dir, valid_policy):
        # Kills NumberReplacer occ 34-37 (the [:16] slices in the
        # DRIFT message become [:17] / [:15] under the mutants).
        # The assertion pins the exact 16-char prefix followed by
        # "...": with 17 chars the 16th char precedes "...", with 15
        # the 16th char is absent — both fail the substring check.
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        floor.advance_floor(valid_policy)
        drifted = EnterprisePolicy(
            revision=valid_policy.revision,
            digest="b" * 64,
            settings={"enforce_local_first": False},
            rules=valid_policy.rules,
        )
        (rejection,) = floor.check_policy(drifted)
        assert f"Expected digest {valid_policy.digest[:16]}..." in rejection
        assert f"got {'b' * 16}..." in rejection

    def test_advance_floor_rev0_on_fresh_floor_initializes(self, temp_state_dir, valid_policy):
        # Kills NumberReplacer occ 38/39 (floor_revision == 0 becomes
        # == 1 / == -1: the mutant never takes the initialize branch
        # for a revision-0 policy on a fresh floor).
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        rev0 = EnterprisePolicy(
            revision=0,
            digest="e" * 64,
            settings={},
            rules=[],
        )
        floor.advance_floor(rev0)
        assert floor.floor_revision == 0
        assert floor.floor_digest == "e" * 64
        assert len(floor.state.history) == 1
        assert floor.state.history[0]["action"] == "initialize"

    def test_advance_floor_second_rev0_does_not_reinitialize(self, temp_state_dir, valid_policy):
        # Kills ReplaceAndWithOr occ 5 (mutant re-initializes on the
        # second revision-0 advance because `== 0 or not digest` is
        # True once the revision is 0).
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        rev0 = EnterprisePolicy(
            revision=0,
            digest="e" * 64,
            settings={},
            rules=[],
        )
        floor.advance_floor(rev0)
        floor.advance_floor(rev0)
        assert len(floor.state.history) == 1

    def test_digest_mismatch_message_shows_16_hex_chars(self, temp_state_dir, policy_data):
        # Kills NumberReplacer occ 40-43 (the [:16] slices in the
        # digest-mismatch message become [:17] / [:15]).
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        engine = EnterprisePolicyEngine(floor=floor)
        policy_data["digest"] = "a" * 64
        (error,) = engine.load_policy(policy_data)
        assert f"stored {'a' * 16}..." in error
        computed = compute_policy_digest(
            EnterprisePolicy(
                revision=int(policy_data["revision"]),
                digest="",
                settings=dict(policy_data.get("settings", {})),
                rules=[dict(r) for r in policy_data.get("rules", [])],
            )
        )
        assert f"computed {computed[:16]}..." in error

    # -- EnterprisePolicyEngine.evaluate: rules_checked ---------------------

    def test_evaluate_no_policy_rules_checked_zero(self):
        # Kills NumberReplacer occ 44/45 ("rules_checked": 0 becomes
        # 1 / -1 in the no-policy branch).
        result = EnterprisePolicyEngine().evaluate("analysis")
        assert result["rules_checked"] == 0
        assert result["status"] == "no_policy"

    def test_evaluate_rules_checked_counts_matching_rules(self, temp_state_dir):
        # Kills NumberReplacer occ 46/47 (rules_checked starts at 1 /
        # -1) and occ 48/49 (each matching rule adds 2 / 0).
        policy = {
            "revision": 1,
            "settings": {},
            "rules": [
                {
                    "id": "in-scope",
                    "description": "in scope",
                    "action": "log",
                    "scope": "analysis",
                },
                {
                    "id": "out-of-scope",
                    "description": "out of scope",
                    "action": "log",
                    "scope": "export",
                },
            ],
        }
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        engine = EnterprisePolicyEngine(floor=floor)
        assert engine.load_policy(policy) == []
        result = engine.evaluate("analysis")
        assert result["rules_checked"] == 1
        assert len(result["logs"]) == 1

    # -- Exception handlers (dependency / schema / write failures) ---------

    def test_validate_policy_without_jsonschema_raises_runtime_error(
        self, policy_data, monkeypatch
    ):
        # Kills ExceptionReplacer occ 0 (the `except ImportError`
        # handler is replaced: a missing jsonschema then propagates
        # ImportError instead of the documented RuntimeError).
        monkeypatch.setitem(sys.modules, "jsonschema", None)
        with pytest.raises(RuntimeError, match="jsonschema is required"):
            validate_enterprise_policy(policy_data)

    def test_invalid_schema_returns_clean_error(self, policy_data, monkeypatch):
        # Kills ExceptionReplacer occ 1 (the `except SchemaError`
        # handler is replaced: an invalid schema then raises
        # AttributeError evaluating the handler instead of returning
        # the documented error list). Draft202012Validator never
        # raises SchemaError at construction under jsonschema 4.26,
        # so the handler is exercised by stubbing the constructor to
        # raise — the documented invalid-schema scenario.
        import jsonschema

        def _raise_schema_error(*args, **kwargs):
            raise jsonschema.exceptions.SchemaError("boom")

        monkeypatch.setattr(jsonschema, "Draft202012Validator", _raise_schema_error)
        assert validate_enterprise_policy(policy_data) == [
            "The enterprise policy schema itself is invalid"
        ]

    def test_floor_without_cryptography_raises_runtime_error(self, temp_state_dir, monkeypatch):
        # Kills ExceptionReplacer occ 2 (the `except ImportError`
        # handler in PolicyRevisionFloor.__init__ is replaced: a
        # missing cryptography then propagates ImportError instead of
        # the documented RuntimeError).
        monkeypatch.setitem(sys.modules, "cryptography.fernet", None)
        with pytest.raises(RuntimeError, match="cryptography is required"):
            PolicyRevisionFloor(
                state_path=temp_state_dir / "state.enc",
                key_path=temp_state_dir / "key.key",
            )

    def test_atomic_write_cleans_up_temp_file_on_failure(
        self, temp_state_dir, valid_policy, monkeypatch
    ):
        # Kills ExceptionReplacer occ 3 (the `except BaseException`
        # cleanup in _atomic_write_bytes is replaced: a failing
        # os.replace then leaves the temp file behind instead of
        # unlinking it before re-raising).
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        floor.advance_floor(valid_policy)

        def _boom(src, dst):
            raise OSError("injected replace failure")

        monkeypatch.setattr(os, "replace", _boom)
        with pytest.raises(OSError, match="injected replace failure"):
            floor.save_state()
        assert list(temp_state_dir.glob("state.enc.*")) == []

    # -- Key-length boundaries ----------------------------------------------

    @pytest.mark.parametrize("size", [31, 33])
    def test_off_by_one_key_length_rejected(self, temp_state_dir, size):
        # Kills NumberReplacer occ 32/33 (len(raw) == 32 becomes == 33
        # / == 31: a 33- / 31-byte key file is then treated as a legacy
        # raw key and raises a bare ValueError from Fernet instead of
        # the documented PolicyKeyError).
        # Fixed bytes, not os.urandom(size): _load_or_generate_key
        # strips the key file, and a random 33-byte key whose first or
        # last byte is ASCII whitespace strips down to 32 bytes and is
        # then ACCEPTED as a legacy key (~4.5% of runs) — the same flake
        # class as the legacy-key test fixed above, and it falsely
        # killed 3 mutants in the first proof run. bytes(range(1, ...))
        # has no edge-whitespace byte, so .strip() is a no-op.
        (temp_state_dir / "key.key").write_bytes(bytes(range(1, size + 1)))
        with pytest.raises(PolicyKeyError):
            PolicyRevisionFloor(
                state_path=temp_state_dir / "state.enc",
                key_path=temp_state_dir / "key.key",
            )

    # -- Decorators ----------------------------------------------------------

    def test_schema_loaded_once_via_cache(self, policy_data, monkeypatch):
        # Kills RemoveDecorator occ 4 (@lru_cache removed from
        # _load_enterprise_policy_schema: the schema file is then
        # re-read on every validation instead of once). The fake
        # serves the real schema text, so only the read count differs.
        from pathlib import Path

        real_schema = (
            Path(policy_module.__file__).parent / "schemas" / "enterprise-policy.schema.json"
        ).read_text(encoding="utf-8")
        calls = {"n": 0}

        class _FakeResource:
            def read_text(self, encoding="utf-8"):
                return real_schema

        class _FakeFiles:
            def joinpath(self, *parts):
                return _FakeResource()

        def _fake_files(package):
            calls["n"] += 1
            return _FakeFiles()

        monkeypatch.setattr(policy_module, "files", _fake_files)
        policy_module._load_enterprise_policy_schema.cache_clear()
        try:
            assert validate_enterprise_policy(policy_data) == []
            assert validate_enterprise_policy(policy_data) == []
        finally:
            policy_module._load_enterprise_policy_schema.cache_clear()
        assert calls["n"] == 1

    def test_engine_floor_property_returns_floor(self, temp_state_dir):
        # Kills RemoveDecorator occ 15 (the @property on
        # EnterprisePolicyEngine.floor is removed, so engine.floor is
        # a bound method instead of the floor).
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        engine = EnterprisePolicyEngine(floor=floor)
        assert engine.floor is floor
        assert engine.policy is None


# ---------------------------------------------------------------------------
# Mutation-kill tests (Phase 5 policy-298 full session)
# ---------------------------------------------------------------------------
# The full 506-item session on main 928dbc0 (total 506, killed 352,
# surviving 154) left 40 killable survivors in this file's scope; these
# tests kill them. Each test names the mutant it kills as (operator,
# occurrence) in the session, with the exact killing input from
# hidden_files/policy-298-classification.md §8 (G1–G40). The other 114
# survivors are equivalent and live in mutation-baseline.toml (99
# annotation + 4 unobservable-value + 10 domain-equivalent + 1
# unreachable-condition). The 3 Pow annotation mutants at L919/L927/L934
# (occurrences 6/7/8) are baselined, not killed: the only distinguishing
# observation is evaluating the annotation string, which the repo forbids
# (tests/test_mutation.py::test_no_annotation_evaluation_in_repo).


def _enterprise_engine(rules, revision=1):
    policy = EnterprisePolicy(revision=revision, digest="a" * 64, settings={}, rules=rules)
    return EnterprisePolicyEngine(policy=policy)


def _enterprise_rule(rule_id, scope, action="log"):
    return {
        "id": rule_id,
        "description": f"rule {rule_id}",
        "action": action,
        "scope": scope,
    }


def _floor_with(policy, temp_state_dir):
    floor = PolicyRevisionFloor(
        state_path=temp_state_dir / "state.enc",
        key_path=temp_state_dir / "key.key",
    )
    floor.advance_floor(policy)
    return floor


class TestPolicyMutationKills298:
    # -- CapabilityLedger.get (G1–G2) --------------------------------------

    def test_get_first_matching_capability_not_first_ge(self):
        # Kills ReplaceComparisonOperator_Eq_GtE occ 0 (get: `==` ->
        # `>=`; the mutant returns the first claim whose capability
        # sorts at or after the requested one).
        first = _make_claim(capability="b")
        second = _make_claim(capability="a")
        ledger = CapabilityLedger()
        ledger.register(first)
        ledger.register(second)
        assert ledger.get("det-a", "a") is second

    def test_get_runtime_built_capability_string(self):
        # Kills ReplaceComparisonOperator_Eq_Is occ 0 (get: `==` ->
        # `is`; a runtime-built string is equal but not identical).
        claim = _make_claim(capability="cap.alpha")
        ledger = _ledger_with_claim(claim)
        assert ledger.get("det-a", "".join(["cap", ".", "alpha"])) is claim

    # -- CapabilityPolicyEngine._matches_pattern (G3–G6) -------------------

    def test_matches_pattern_runtime_built_detector_id(self):
        # Kills ReplaceComparisonOperator_Eq_Is occ 7
        # (_matches_pattern: `==` -> `is`; distinct-but-equal strings).
        engine = CapabilityPolicyEngine()
        assert engine._matches_pattern("".join(["d", "e", "t"]), "det") is True

    @pytest.mark.parametrize("pattern", ["!x", " x", "#x", "(x"])
    def test_matches_pattern_first_char_before_star(self, pattern):
        # Kills ReplaceComparisonOperator_Eq_Lt occ 8 and
        # ReplaceComparisonOperator_Eq_LtE occ 8 (_matches_pattern:
        # `pattern == "*"` -> `<` / `<=`; any pattern whose first char
        # sorts before "*" is then taken as the wildcard).
        engine = CapabilityPolicyEngine()
        assert engine._matches_pattern("det", pattern) is False

    def test_matches_pattern_interior_star_returns_false(self):
        # Kills ReplaceFalseWithTrue occ 0 (_matches_pattern: the final
        # `return False` for an interior-`*` pattern becomes True).
        engine = CapabilityPolicyEngine()
        assert engine._matches_pattern("axb", "a*b") is False

    # -- ledger_to_trust_dimension (G7–G8) ---------------------------------

    def test_readable_only_reason_not_tool_backed(self):
        # Kills ReplaceComparisonOperator_Eq_IsNot occ 5 and
        # ReplaceComparisonOperator_Eq_NotEq occ 5
        # (ledger_to_trust_dimension: `c.tier == TOOL_BACKED` -> `is
        # not` / `!=`; a READABLE-only claim is then reported as
        # TOOL_BACKED).
        ledger = _ledger_with_claim(_make_claim(capability="cap", tier=EvidenceTier.READABLE))
        dimension = ledger_to_trust_dimension(ledger, "det-a", "cap")
        assert dimension.state == "partial"
        assert "only READABLE" in dimension.reason

    # -- CapabilityPolicyEngine.evaluate tier checks / loops (G9–G12) ------

    def test_evaluate_validated_claim_passes_readable_requirement(self):
        # Kills ReplaceComparisonOperator_Lt_IsNot occ 0 and
        # ReplaceComparisonOperator_Lt_NotEq occ 0 (evaluate: the tier
        # comparison `<` -> `is not` / `!=`; a VALIDATED claim then
        # fails a readable requirement it exceeds).
        ledger = _ledger_with_claim(_make_claim(tier=EvidenceTier.VALIDATED))
        engine = _engine_requiring("language_coverage", "readable")
        (result,) = engine.evaluate(ledger, "det-a")
        assert result.passed is True
        assert result.evidence_gaps == []

    def test_evaluate_nonmatching_pattern_then_matching(self):
        # Kills ReplaceContinueWithBreak occ 0 (evaluate: the
        # `continue` for a non-matching pattern becomes `break`, so
        # the loop stops and the matching policy is never evaluated).
        engine = CapabilityPolicyEngine()
        engine.add_policy(
            CapabilityPolicy(
                rule_id="other-only",
                description="other detector",
                required_capabilities=[("language_coverage", "validated")],
                detector_pattern="other*",
                action_on_failure="reject",
            )
        )
        engine.add_policy(
            CapabilityPolicy(
                rule_id="det-rule",
                description="detector rule",
                required_capabilities=[("language_coverage", "validated")],
                detector_pattern="det*",
                action_on_failure="reject",
            )
        )
        ledger = _ledger_with_claim(_make_claim(detector="det1", tier=EvidenceTier.READABLE))
        results = engine.evaluate(ledger, "det1")
        assert len(results) == 1
        assert results[0].rule_id == "det-rule"
        assert results[0].passed is False
        assert len(results[0].evidence_gaps) == 1

    def test_evaluate_two_missing_claims_both_reported(self):
        # Kills ReplaceContinueWithBreak occ 1 (evaluate: the
        # `continue` after a missing claim becomes `break`, so only
        # the first missing capability is reported).
        engine = CapabilityPolicyEngine()
        engine.add_policy(
            CapabilityPolicy(
                rule_id="two-missing",
                description="two missing",
                required_capabilities=[
                    ("c1", "readable"),
                    ("c2", "readable"),
                ],
                detector_pattern="*",
                action_on_failure="reject",
            )
        )
        (result,) = engine.evaluate(CapabilityLedger(), "det-a")
        assert result.passed is False
        assert result.missing_claims == [
            "c1 (required: readable+)",
            "c2 (required: readable+)",
        ]

    # -- compute_policy_digest (G13–G14) -----------------------------------

    def test_digest_sorts_keys(self):
        # Kills ReplaceTrueWithFalse occ 5 (compute_policy_digest:
        # `sort_keys=True` -> False; the blob key order becomes
        # revision/settings/rules instead of revision/rules/settings).
        policy = EnterprisePolicy(
            revision=1,
            digest="",
            settings={"z": 1, "a": 2},
            rules=[
                {
                    "id": "r1",
                    "description": "d",
                    "action": "log",
                    "scope": "all",
                }
            ],
        )
        expected = hashlib.sha256(
            json.dumps(
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
            ).encode("utf-8")
        ).hexdigest()
        assert compute_policy_digest(policy) == expected

    def test_digest_escapes_non_ascii(self):
        # Kills ReplaceTrueWithFalse occ 6 (compute_policy_digest:
        # `ensure_ascii=True` -> False; non-ASCII content is then
        # hashed as raw UTF-8 instead of \uXXXX escapes). Pure-ASCII
        # policies do NOT kill this mutant.
        policy = EnterprisePolicy(
            revision=1,
            digest="",
            settings={"note": "café"},
            rules=[
                {
                    "id": "r1",
                    "description": "café ☃",
                    "action": "log",
                    "scope": "all",
                }
            ],
        )
        expected = hashlib.sha256(
            json.dumps(
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
            ).encode("utf-8")
        ).hexdigest()
        assert compute_policy_digest(policy) == expected

    # -- Dataclass slots / frozen contracts (G15–G19) ----------------------
    # These pin the decorator contracts directly: slots=True means no
    # __dict__, frozen=True means assignment raises FrozenInstanceError.

    def test_evidence_ref_has_no_dict(self):
        # Kills ReplaceTrueWithFalse occ 0 (EvidenceRef: `slots=True`
        # -> False).
        ref = EvidenceRef(
            label=EvidenceLabel.REPORTED,
            tier=EvidenceTier.READABLE,
            artifact="doc-1",
        )
        assert hasattr(ref, "__dict__") is False

    def test_capability_claim_has_no_dict(self):
        # Kills ReplaceTrueWithFalse occ 1 (CapabilityClaim: `slots=True`
        # -> False).
        assert hasattr(_make_claim(), "__dict__") is False

    def test_capability_policy_is_frozen(self):
        # Kills ReplaceTrueWithFalse occ 2 (CapabilityPolicy:
        # `frozen=True` -> False; assignment then succeeds).
        policy = CapabilityPolicy(
            rule_id="r",
            description="d",
            required_capabilities=[],
            detector_pattern="*",
            action_on_failure="reject",
        )
        with pytest.raises(FrozenInstanceError):
            policy.rule_id = "x"

    def test_capability_policy_has_no_dict(self):
        # Kills ReplaceTrueWithFalse occ 3 (CapabilityPolicy: `slots=True`
        # -> False).
        policy = CapabilityPolicy(
            rule_id="r",
            description="d",
            required_capabilities=[],
            detector_pattern="*",
            action_on_failure="reject",
        )
        assert hasattr(policy, "__dict__") is False

    def test_enterprise_policy_has_no_dict(self):
        # Kills ReplaceTrueWithFalse occ 8 (EnterprisePolicy: `slots=True`
        # -> False).
        policy = EnterprisePolicy(revision=1, digest="a" * 64, settings={}, rules=[])
        assert hasattr(policy, "__dict__") is False

    # -- EnterprisePolicy.__post_init__ (G20) ------------------------------

    def test_digest_longer_than_64_rejected(self):
        # Kills ReplaceComparisonOperator_NotEq_Lt occ 0
        # (__post_init__: `len(digest) != 64` -> `< 64`; a 65-char
        # digest is then accepted). Lengths <= 64 do not kill.
        with pytest.raises(ValueError, match="64-character"):
            EnterprisePolicy(revision=1, digest="a" * 65, settings={}, rules=[])

    # -- Atomic writes / state persistence (G21–G22) -----------------------

    def test_atomic_write_creates_missing_parents(self, tmp_path):
        # Kills ReplaceTrueWithFalse occ 9 (_atomic_write_bytes:
        # `parents=True` -> False; writing under missing parents
        # then raises FileNotFoundError).
        target = tmp_path / "nested" / "a" / "b" / "file.bin"
        PolicyRevisionFloor._atomic_write_bytes(target, b"hello")
        assert target.read_bytes() == b"hello"

    def test_save_state_creates_missing_parents(self, temp_state_dir):
        # Kills ReplaceTrueWithFalse occ 12 (save_state:
        # `parents=True` -> False; saving under a repointed nested
        # missing path then raises FileNotFoundError).
        floor = PolicyRevisionFloor(
            state_path=temp_state_dir / "state.enc",
            key_path=temp_state_dir / "key.key",
        )
        floor._state_path = temp_state_dir / "new" / "deep" / "state.enc"
        floor.save_state()
        assert (temp_state_dir / "new" / "deep" / "state.enc").exists()

    # -- Revision floor: check_policy / advance_floor (G23–G28) ------------

    def test_check_policy_same_revision_distinct_int_objects(self, temp_state_dir):
        # Kills ReplaceComparisonOperator_Eq_Is occ 8 (check_policy:
        # `policy.revision == floor_revision` -> `is`; distinct int
        # objects at revision 1000 are then treated as different
        # revisions and the drift check is skipped). Small revisions
        # (<= 256) do NOT kill — CPython caches small ints, so `is`
        # holds.
        floor = _floor_with(
            EnterprisePolicy(revision=int("1000"), digest="f" * 64, settings={}, rules=[]),
            temp_state_dir,
        )
        drifted = EnterprisePolicy(revision=int("1000"), digest="a" * 64, settings={}, rules=[])
        (rejection,) = floor.check_policy(drifted)
        assert "DRIFT" in rejection

    def test_check_policy_smaller_digest_is_drift(self, temp_state_dir):
        # Kills ReplaceComparisonOperator_NotEq_Gt occ 1 (check_policy:
        # `policy.digest != expected_digest` -> `>`; a digest sorting
        # below the expected one is then accepted).
        floor = _floor_with(
            EnterprisePolicy(revision=5, digest="f" * 64, settings={}, rules=[]),
            temp_state_dir,
        )
        drifted = EnterprisePolicy(revision=5, digest="a" * 64, settings={}, rules=[])
        (rejection,) = floor.check_policy(drifted)
        assert "DRIFT" in rejection

    def test_check_policy_equal_digests_distinct_objects_accepted(self, temp_state_dir):
        # Kills ReplaceComparisonOperator_NotEq_IsNot occ 0
        # (check_policy: `policy.digest != expected_digest` -> `is
        # not`; two equal digests built as distinct objects are then
        # reported as drift). The test MUST use distinct objects — the
        # same object does not kill.
        floor = _floor_with(
            EnterprisePolicy(
                revision=5,
                digest="".join(["a"] * 64),
                settings={},
                rules=[],
            ),
            temp_state_dir,
        )
        same_digest = EnterprisePolicy(
            revision=5,
            digest="".join(["a"] * 64),
            settings={},
            rules=[],
        )
        assert floor.check_policy(same_digest) == []

    def test_advance_floor_empty_digest_does_not_lower_floor(self, temp_state_dir):
        # Kills ReplaceComparisonOperator_Eq_GtE occ 12 (advance_floor:
        # `floor_revision == 0` -> `>= 0` in the initialize branch;
        # advancing a lower revision then lowers the floor).
        floor = _floor_with(
            EnterprisePolicy(revision=5, digest="", settings={}, rules=[]),
            temp_state_dir,
        )
        floor.advance_floor(EnterprisePolicy(revision=3, digest="c" * 64, settings={}, rules=[]))
        assert floor.floor_revision == 5
        assert len(floor.state.history) == 1

    def test_advance_floor_lower_revision_is_noop(self, temp_state_dir):
        # Kills ReplaceComparisonOperator_Gt_IsNot occ 0 and
        # ReplaceComparisonOperator_Gt_NotEq occ 0 (advance_floor:
        # `policy.revision > floor_revision` -> `is not` / `!=`; a
        # lower revision then advances (lowers) the floor).
        floor = _floor_with(
            EnterprisePolicy(revision=5, digest="a" * 64, settings={}, rules=[]),
            temp_state_dir,
        )
        floor.advance_floor(EnterprisePolicy(revision=3, digest="b" * 64, settings={}, rules=[]))
        assert floor.floor_revision == 5
        assert floor.floor_digest == "a" * 64
        assert len(floor.state.history) == 1

    # -- EnterprisePolicyEngine.load_policy (G29–G32) -----------------------

    def test_load_policy_accepts_keyword_argument(self, policy_data):
        # Kills ReplaceBinaryOperator_Mul_Div occ 0 (load_policy: `*,`
        # -> `/,` makes policy_data positional-only, so a keyword call
        # raises TypeError).
        engine = EnterprisePolicyEngine()
        assert engine.load_policy(policy_data=policy_data) == []

    def test_load_policy_low_digest_is_mismatch(self, policy_data):
        # Kills ReplaceComparisonOperator_NotEq_Gt occ 2 (load_policy:
        # `policy_data["digest"] != computed_digest` -> `>`; a stored
        # digest sorting below the computed one is then loaded).
        engine = EnterprisePolicyEngine()
        policy_data["digest"] = "0" * 64
        errors = engine.load_policy(policy_data)
        assert len(errors) == 1
        assert "Digest mismatch" in errors[0]

    def test_load_policy_correct_digest_loads(self, policy_data):
        # Kills ReplaceComparisonOperator_NotEq_GtE occ 2 (load_policy:
        # `policy_data["digest"] != computed_digest` -> `>=`; a
        # correct (equal) digest is then reported as a mismatch).
        engine = EnterprisePolicyEngine()
        policy_data["digest"] = compute_policy_digest(
            EnterprisePolicy(
                revision=int(policy_data["revision"]),
                digest="",
                settings=dict(policy_data.get("settings", {})),
                rules=[dict(r) for r in policy_data.get("rules", [])],
            )
        )
        assert engine.load_policy(policy_data) == []

    def test_load_policy_correct_digest_distinct_object_loads(self, policy_data):
        # Kills ReplaceComparisonOperator_NotEq_IsNot occ 1
        # (load_policy: `policy_data["digest"] != computed_digest` ->
        # `is not`; the computed digest is a fresh hashlib hexdigest,
        # always a distinct object from the stored one, so a correct
        # digest is then reported as a mismatch).
        engine = EnterprisePolicyEngine()
        policy_data["digest"] = compute_policy_digest(
            EnterprisePolicy(
                revision=int(policy_data["revision"]),
                digest="",
                settings=dict(policy_data.get("settings", {})),
                rules=[dict(r) for r in policy_data.get("rules", [])],
            )
        )
        assert engine.load_policy(policy_data) == []

    # -- EnterprisePolicyEngine.evaluate scopes / actions (G33–G40) --------

    def test_evaluate_scope_before_all_not_applied(self):
        # Kills ReplaceComparisonOperator_NotEq_Gt occ 3 (evaluate:
        # `rule_scope != "all"` -> `>`; a rule scope sorting before
        # "all" is then wrongly applied to other scopes).
        engine = _enterprise_engine([_enterprise_rule("r-aaa", "aaa")])
        result = engine.evaluate("other")
        assert result["rules_checked"] == 0

    def test_evaluate_scope_after_rule_scope_not_applied(self):
        # Kills ReplaceComparisonOperator_NotEq_Gt occ 4 (evaluate:
        # `rule_scope != scope` -> `>`; a rule scope sorting before
        # the evaluated scope is then wrongly applied).
        engine = _enterprise_engine([_enterprise_rule("r-det", "detector-x")])
        result = engine.evaluate("zzz")
        assert result["rules_checked"] == 0

    def test_evaluate_runtime_built_scope_matches(self):
        # Kills ReplaceComparisonOperator_NotEq_IsNot occ 3 (evaluate:
        # `rule_scope != scope` -> `is not`; a runtime-built scope
        # string equal to the rule scope is then wrongly skipped).
        engine = _enterprise_engine([_enterprise_rule("r-an", "analysis")])
        result = engine.evaluate("".join(["ana", "lysis"]))
        assert result["rules_checked"] == 1

    def test_evaluate_nonmatching_scope_then_matching(self):
        # Kills ReplaceContinueWithBreak occ 2 (evaluate: the
        # `continue` for a non-matching rule scope becomes `break`,
        # so the matching rule is never evaluated).
        engine = _enterprise_engine(
            [
                _enterprise_rule("r-other", "other"),
                _enterprise_rule("r-m", "analysis"),
            ]
        )
        result = engine.evaluate("analysis")
        assert result["rules_checked"] == 1
        assert [entry["rule_id"] for entry in result["logs"]] == ["r-m"]

    def test_evaluate_unknown_action_is_not_warn(self):
        # Kills ReplaceComparisonOperator_Eq_GtE occ 14 (evaluate:
        # `action == "warn"` -> `>=`; an unknown action sorting at or
        # after "warn" is then recorded as a warning).
        engine = _enterprise_engine([_enterprise_rule("r-z", "all", "zzz")])
        result = engine.evaluate("analysis")
        assert result["status"] == "ok"
        assert result["warnings"] == []

    def test_evaluate_unknown_action_is_not_log(self):
        # Kills ReplaceComparisonOperator_Eq_GtE occ 15 (evaluate:
        # `action == "log"` -> `>=`; an unknown action sorting at or
        # after "log" is then recorded as a log entry).
        engine = _enterprise_engine([_enterprise_rule("r-z", "all", "zzz")])
        result = engine.evaluate("analysis")
        assert result["status"] == "ok"
        assert result["logs"] == []

    def test_evaluate_unknown_action_is_not_disable(self):
        # Kills ReplaceComparisonOperator_Eq_GtE occ 16 (evaluate:
        # `action == "disable"` -> `>=`; an unknown action sorting at
        # or after "disable" is then recorded as disabling the scope).
        engine = _enterprise_engine([_enterprise_rule("r-z", "all", "zzz")])
        result = engine.evaluate("analysis")
        assert result["status"] == "ok"
        assert result["disabled"] == []

    def test_evaluate_low_action_is_not_disable(self):
        # Kills ReplaceComparisonOperator_Eq_LtE occ 16 (evaluate:
        # `action == "disable"` -> `<=`; an unknown action sorting at
        # or before "disable" is then recorded as disabling the
        # scope).
        engine = _enterprise_engine([_enterprise_rule("r-a", "all", "audit")])
        result = engine.evaluate("analysis")
        assert result["status"] == "ok"
        assert result["disabled"] == []


# ---------------------------------------------------------------------------
# W1 follow-up mutation kills (audit-w1-worker-f)
#
# Each test kills the W1 new/changed-code mutants Worker E proved
# killable (audit-w1-e-stop-draft.py / audit-w1-e-probe-results.json,
# 148/148). Test IDs PO-01..PO-02 match the STOP draft.
# ---------------------------------------------------------------------------


class TestW1FollowUpMutationKills:
    def test_parse_valid_until_rejects_bad_values(self):
        # PO-01: 3 mutants in _parse_valid_until.
        assert _parse_valid_until(None) is None
        assert _parse_valid_until("") is None
        assert _parse_valid_until("   ") is None
        assert _parse_valid_until("not-a-date") is None
        assert _parse_valid_until(123) is None
        assert _parse_valid_until("2030-06-15") == date(2030, 6, 15)
        # The datetime leg: date.fromisoformat fails, datetime succeeds.
        assert _parse_valid_until("2030-06-15T10:30:00") == date(2030, 6, 15)

    def test_claim_expiry_boundaries(self):
        # PO-02: 2 mutants in claim_is_expired.
        no_expiry = CapabilityClaim(detector_id="d", capability="c", tier=EvidenceTier.READABLE)
        assert claim_is_expired(no_expiry) is False
        bad = CapabilityClaim(
            detector_id="d",
            capability="c",
            tier=EvidenceTier.READABLE,
            valid_until="not-a-date",
        )
        assert claim_is_expired(bad) is True  # unparseable -> expired (fail closed)
        boundary = CapabilityClaim(
            detector_id="d",
            capability="c",
            tier=EvidenceTier.READABLE,
            valid_until="2030-06-15",
        )
        assert claim_is_expired(boundary, today=date(2030, 6, 15)) is False
        # last valid day, inclusive
        assert claim_is_expired(boundary, today=date(2030, 6, 16)) is True
        assert claim_is_expired(boundary, today=date(2030, 6, 14)) is False
