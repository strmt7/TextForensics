"""Tests for enterprise policy framework with revision-floor mechanism."""

from __future__ import annotations

import base64
import hashlib
import json
import os

import pytest
from cryptography.fernet import Fernet

from textforensics.policy import (
    EnterprisePolicy,
    EnterprisePolicyEngine,
    PolicyKeyError,
    PolicyRevisionFloor,
    PolicyState,
    PolicyStateCorruptError,
    compute_policy_digest,
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
