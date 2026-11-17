"""W4 mutation kill tests: textforensics.policy (Worker F2).

Each test kills one or more phase-1 survivors from the W4 proof set
(audit-w4-f-proofset.json / audit-w4-f-survivors.json). Equivalent policy
mutants (enum identity, the dead tier_order default, len() non-negativity,
the _check_against elif subsumption, the never-negative floor, the dead
second load_policy except, the lock-guaranteed _persist mkdir) are
documented in audit-w4-f-equiv-reasons-policy.json and must SURVIVE
this file.
"""

from __future__ import annotations

import os
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet

from textforensics.policy import (
    CapabilityClaim,
    CapabilityLedger,
    CapabilityPolicy,
    CapabilityPolicyEngine,
    EnterprisePolicy,
    EnterprisePolicyEngine,
    EvidenceTier,
    PolicyRevisionFloor,
    _claim_is_effective,
    _is_known_tier,
    _policy_floor_lock,
    _validate_admitted_policy,
    _validate_policy_rules,
    ledger_to_trust_dimension,
)


def _readable_claim() -> CapabilityClaim:
    return CapabilityClaim(detector_id="det", capability="cap", tier=EvidenceTier.READABLE)


# ---------------------------------------------------------------------------
# _claim_is_effective / ledger_to_trust_dimension / evaluate signatures
# ---------------------------------------------------------------------------


def test_claim_is_effective_claim_is_positional_or_keyword() -> None:
    """The `*` in _claim_is_effective leaves `claim` positional-or-keyword:
    calling it with a keyword claim must work."""
    assert _claim_is_effective(claim=_readable_claim()) is True


def test_claim_is_effective_rejects_unsupported_tier() -> None:
    """An unsupported tier is never effective (fail closed). The tier is
    normally coerced/rejected by CapabilityClaim.__post_init__, so the
    guard is only reachable by bypassing that coercion -- the same
    object.__setattr__ surgery __post_init__ itself uses."""
    claim = _readable_claim()
    object.__setattr__(claim, "tier", "bogus")
    assert _claim_is_effective(claim) is False


def test_is_known_tier_is_version_safe_and_fail_closed() -> None:
    """``_is_known_tier`` is the version-safe replacement for
    ``tier in EvidenceTier``: on Python < 3.12 the ``in`` check raises
    ``TypeError`` for a non-member (CI-FIX-2, Core 3.11). Only a genuine
    member counts — a raw member *value* string such as ``"readable"``
    is NOT a known tier (the 3.12+ ``in`` operator would say True), so
    behaviour is identical on 3.11–3.15 and any bypassed-construction
    string tier fails closed."""
    assert _is_known_tier(EvidenceTier.READABLE) is True
    assert _is_known_tier(EvidenceTier.TOOL_BACKED) is True
    assert _is_known_tier(EvidenceTier.VALIDATED) is True
    assert _is_known_tier("bogus") is False
    assert _is_known_tier("readable") is False
    assert _is_known_tier(None) is False
    assert _is_known_tier(1) is False


def test_ledger_to_trust_dimension_positional_or_keyword() -> None:
    """The `*` in ledger_to_trust_dimension leaves its leading parameters
    positional-or-keyword."""
    dimension = ledger_to_trust_dimension(
        ledger=CapabilityLedger(), detector_id="det", capability_prefix="cap"
    )
    assert dimension.state == "unknown"


def test_capability_policy_rejects_empty_detector_pattern() -> None:
    """detector_pattern must be a non-empty string."""
    with pytest.raises(ValueError, match="detector_pattern"):
        CapabilityPolicy(
            rule_id="r",
            description="d",
            required_capabilities=[("cap", "readable")],
            detector_pattern="",
        )


def test_capability_engine_evaluate_positional_or_keyword() -> None:
    """The `*` in CapabilityPolicyEngine.evaluate leaves ledger,
    detector_id and operation positional-or-keyword."""
    engine = CapabilityPolicyEngine()
    assert engine.evaluate(ledger=CapabilityLedger(), detector_id="det", operation="use") == []


def test_readable_claim_satisfies_readable_requirement() -> None:
    """A READABLE claim satisfies a readable+ requirement: no gap, passed."""
    ledger = CapabilityLedger()
    ledger.register(_readable_claim())
    engine = CapabilityPolicyEngine()
    engine.add_policy(
        CapabilityPolicy(
            rule_id="r",
            description="d",
            required_capabilities=[("cap", "readable")],
        )
    )
    (result,) = engine.evaluate(ledger, "det")
    assert result.passed is True
    assert result.evidence_gaps == []


# ---------------------------------------------------------------------------
# _validate_policy_rules
# ---------------------------------------------------------------------------


def test_validate_policy_rules_reports_each_non_object_rule() -> None:
    """Every non-object rule is reported; validation continues past the first."""
    assert _validate_policy_rules([123, 456]) == [
        "rules[0] must be an object.",
        "rules[1] must be an object.",
    ]


def test_validate_policy_rules_checks_required_fields() -> None:
    """A rule missing a required field is reported."""
    errors = _validate_policy_rules([{"id": "r1", "scope": "all", "action": "log"}])
    assert "rules[0].description must be a non-empty string." in errors


def test_validate_policy_rules_rejects_empty_field() -> None:
    """A required field that is an empty string is reported."""
    errors = _validate_policy_rules(
        [{"id": "", "description": "d", "scope": "all", "action": "log"}]
    )
    assert "rules[0].id must be a non-empty string." in errors


# ---------------------------------------------------------------------------
# _policy_floor_lock (Windows branch, driven via a fake msvcrt)
# ---------------------------------------------------------------------------


class _FakeMsvcrt:
    """Stand-in for the msvcrt module: records locking calls with the
    file position at call time (the fd shares the handle's offset)."""

    LK_LOCK = 1
    LK_UNLCK = 0

    def __init__(self) -> None:
        self.calls: list[tuple[int, int, int]] = []

    def locking(self, fd: int, mode: int, nbytes: int) -> None:
        self.calls.append((mode, nbytes, os.lseek(fd, 0, os.SEEK_CUR)))


def _run_nt_lock(state_path: Path) -> tuple[bytes, list[tuple[int, int, int]]]:
    """Run _policy_floor_lock with os.name seen as "nt" by the policy
    module and a fake msvcrt; return the lock-file bytes and the
    recorded locking calls.

    NOTE: patching the global os.name would make pathlib.Path construct
    WindowsPath objects inside _policy_floor_lock (Path dispatches on
    os.name at construction time), so the lock file would land under a
    backslash name in the CWD instead of next to the state path. The
    patch therefore replaces only textforensics.policy's `os` reference
    with a copy of the os module whose name is "nt"; the real os.name
    (and pathlib) stay POSIX.
    """
    import textforensics.policy as policy_module

    fake = _FakeMsvcrt()
    module = types.ModuleType("msvcrt")
    module.LK_LOCK = fake.LK_LOCK
    module.LK_UNLCK = fake.LK_UNLCK
    module.locking = fake.locking
    fake_os = types.ModuleType("os")
    fake_os.__dict__.update(vars(os))
    fake_os.name = "nt"
    with (
        patch.object(policy_module, "os", fake_os),
        patch.dict(sys.modules, {"msvcrt": module}),
        _policy_floor_lock(state_path),
    ):
        pass
    lock_path = Path(str(state_path) + ".lock")
    return lock_path.read_bytes(), fake.calls


def test_policy_floor_lock_nt_branch_writes_marker_and_locks_byte_zero(tmp_path: Path) -> None:
    """On Windows the lock file is initialised with a marker byte and
    byte 0 is locked (then unlocked): locking(LK_LOCK, 1) at offset 0,
    locking(LK_UNLCK, 1) at offset 0."""
    content, calls = _run_nt_lock(tmp_path / "state.enc")
    assert content == b"\0"
    assert calls == [(1, 1, 0), (0, 1, 0)]


def test_policy_floor_lock_nt_branch_preserves_nonempty_file(tmp_path: Path) -> None:
    """On Windows a non-empty lock file is left untouched (no marker byte)."""
    state_path = tmp_path / "state.enc"
    lock_path = Path(str(state_path) + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_bytes(b"X")
    content, _calls = _run_nt_lock(state_path)
    assert content == b"X"


def test_policy_floor_lock_non_nt_platform_takes_posix_branch(tmp_path: Path) -> None:
    """On a non-Windows platform the msvcrt branch is not taken: no marker
    byte is written and no msvcrt call happens."""
    state_path = tmp_path / "state.enc"
    with patch.object(os, "name", "java"), _policy_floor_lock(state_path):
        pass
    lock_path = Path(str(state_path) + ".lock")
    assert lock_path.read_bytes() == b""


# ---------------------------------------------------------------------------
# PolicyRevisionFloor.check_and_advance
# ---------------------------------------------------------------------------


def test_check_and_advance_publishes_new_state(tmp_path: Path) -> None:
    """A successful advance publishes the new state to memory: after
    check_and_advance with a revision-1 policy the floor is 1."""
    floor = PolicyRevisionFloor(
        state_path=tmp_path / "nested" / "state.enc",
        key=Fernet.generate_key(),
    )
    policy = EnterprisePolicy(
        revision=1,
        digest="a" * 64,
        settings={},
        rules=[{"id": "r1", "description": "d", "scope": "all", "action": "log"}],
    )
    assert floor.check_and_advance(policy) == []
    assert floor.floor_revision == 1


# ---------------------------------------------------------------------------
# _validate_admitted_policy / EnterprisePolicyEngine
# ---------------------------------------------------------------------------


def test_validate_admitted_policy_accepts_empty_conditions() -> None:
    """An empty conditions mapping is not rejected (only a non-empty one
    is, since no condition grammar is implemented yet)."""
    policy = EnterprisePolicy(
        revision=1,
        digest="a" * 64,
        settings={},
        rules=[
            {
                "id": "r1",
                "description": "d",
                "scope": "all",
                "action": "log",
                "conditions": {},
            }
        ],
    )
    assert _validate_admitted_policy(policy) == []


def test_load_policy_returns_construction_value_error() -> None:
    """A policy that passes schema validation but fails EnterprisePolicy
    construction is reported as a rejection list, not raised: a
    whitespace-only description passes the schema (minLength 1) but
    fails the non-empty-string rule check in __post_init__."""
    engine = EnterprisePolicyEngine()
    result = engine.load_policy(
        {
            "revision": 1,
            "settings": {},
            "rules": [{"id": "r1", "description": " ", "action": "log", "scope": "all"}],
        }
    )
    assert result == ["rules[0].description must be a non-empty string."]


def test_evaluate_unknown_action_is_violation() -> None:
    """An unknown action never falls through to status ok (or to
    "disabled"): it is a violation. Construction rejects unknown
    actions, so the defence-in-depth branch is only reachable by a
    policy object that bypassed construction."""
    policy = object.__new__(EnterprisePolicy)
    object.__setattr__(policy, "revision", 1)
    object.__setattr__(policy, "digest", "a" * 64)
    object.__setattr__(policy, "settings", {})
    object.__setattr__(
        policy,
        "rules",
        [{"id": "r1", "description": "d", "scope": "all", "action": "block"}],
    )
    engine = object.__new__(EnterprisePolicyEngine)
    engine._policy = policy
    engine._floor = None
    result = engine.evaluate("all")
    assert result["status"] == "violation"
    assert result["disabled"] == []
    assert result["violations"][0]["rule_id"] == "r1"
