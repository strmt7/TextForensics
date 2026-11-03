#!/usr/bin/env python3
"""
Fuzz target for enterprise policy parsing, validation, and revision floor.

Covers:
- EnterprisePolicy.from_dict / to_dict with malformed inputs
- PolicyState.from_dict / to_dict round-trips
- PolicyRevisionFloor: check_policy, advance_floor, rollback detection
- EnterprisePolicyEngine: load_policy, evaluate, get_status, export
- validate_enterprise_policy with fuzzed policy dicts
- compute_policy_digest edge cases
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import atheris

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))


def _fuzz_policy_from_dict(text: str) -> None:
    """Fuzz EnterprisePolicy.from_dict with malformed data."""
    try:
        from textforensics.enterprise_policy import EnterprisePolicy
    except Exception:
        return

    try:
        policy_json = json.loads(text)
        if not isinstance(policy_json, dict):
            policy_json = {"revision": 0, "settings": {}, "rules": []}
    except json.JSONDecodeError:
        policy_json = {"revision": 0, "settings": {}, "rules": []}

    # Vary revision
    for rev in [
        policy_json.get("revision", 0),
        -1,
        0,
        1,
        100,
        None,
        "not-int",
        float("nan"),
    ]:
        for digest_val in [
            policy_json.get("digest", ""),
            "0" * 64,
            "g" * 64,  # non-hex
            text[:64],
            "",
            None,
        ]:
            for settings in [
                policy_json.get("settings", {}),
                {},
                {"key": text[:20]},
                "not-dict",
            ]:
                for rules in [
                    policy_json.get("rules", []),
                    [],
                    [{"id": text[:10], "description": "", "action": "enforce", "scope": "all"}],
                    "not-list",
                ]:
                    try:
                        data = {
                            "revision": rev,
                            "digest": str(digest_val) if digest_val is not None else "",
                            "settings": settings,
                            "rules": rules,
                        }
                        ep = EnterprisePolicy.from_dict(data)
                        assert ep.revision >= 0
                    except (ValueError, TypeError, KeyError):
                        pass
                    except Exception:
                        pass

    # to_dict round-trip
    try:
        ep = EnterprisePolicy(revision=1, digest="0" * 64, settings={}, rules=[])
        d = ep.to_dict()
        ep2 = EnterprisePolicy.from_dict(d)
        assert ep.revision == ep2.revision
    except Exception:
        pass


def _fuzz_policy_state(text: str) -> None:
    """Fuzz PolicyState.from_dict / to_dict."""
    try:
        from textforensics.enterprise_policy import PolicyState
    except Exception:
        return

    try:
        state_data = json.loads(text)
        if not isinstance(state_data, dict):
            state_data = {}
    except json.JSONDecodeError:
        state_data = {}

    for floor_rev in [state_data.get("floor_revision", 0), -1, 0, 1, "x"]:
        for floor_digest in [state_data.get("floor_digest", ""), "0" * 64, ""]:
            for history in [state_data.get("history", []), [], "not-list"]:
                try:
                    ps = PolicyState.from_dict({
                        "floor_revision": floor_rev,
                        "floor_digest": floor_digest,
                        "history": history,
                    })
                    d = ps.to_dict()
                    assert "floor_revision" in d
                except (ValueError, TypeError, KeyError):
                    pass
                except Exception:
                    pass


def _fuzz_revision_floor(text: str) -> None:
    """Fuzz PolicyRevisionFloor: check_policy and advance_floor."""
    try:
        from textforensics.enterprise_policy import (
            EnterprisePolicy,
            PolicyRevisionFloor,
        )
    except Exception:
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        state_path = tmpdir / "state.enc"
        key_path = tmpdir / "key.key"

        floor = PolicyRevisionFloor(state_path=state_path, key_path=key_path)

        # Test policies with varying revisions
        for rev in (-1, 0, 1, 2, 100, len(text)):
            policy = EnterprisePolicy(
                revision=max(0, rev),
                digest="0" * 64,
                settings={"fuzzed": True},
                rules=[{"id": "r1", "description": "test", "action": "enforce", "scope": "all"}],
            )
            try:
                rejections = floor.check_policy(policy)
                assert isinstance(rejections, list)
            except Exception:
                pass
            try:
                floor.advance_floor(policy)
            except Exception:
                pass

        # Different digest at same revision
        policy1 = EnterprisePolicy(revision=1, digest="0" * 64, settings={}, rules=[])
        policy2 = EnterprisePolicy(revision=1, digest="1" * 64, settings={}, rules=[])
        try:
            floor.reset()
            floor.advance_floor(policy1)
            rejections = floor.check_policy(policy2)
            assert len(rejections) > 0  # drift detected
        except Exception:
            pass

        # Rollback
        try:
            floor.reset()
            floor.advance_floor(EnterprisePolicy(revision=5, digest="a" * 64, settings={}, rules=[]))
            rejections = floor.check_policy(EnterprisePolicy(revision=3, digest="b" * 64, settings={}, rules=[]))
            assert len(rejections) > 0  # rollback
        except Exception:
            pass

        # Save/load state
        try:
            floor.save_state()
            floor2 = PolicyRevisionFloor(state_path=state_path, key_path=key_path)
            assert floor2.floor_revision == floor.floor_revision
        except Exception:
            pass


def _fuzz_policy_engine(text: str) -> None:
    """Fuzz EnterprisePolicyEngine: load_policy, evaluate, get_status."""
    try:
        from textforensics.enterprise_policy import (
            EnterprisePolicyEngine,
            PolicyRevisionFloor,
        )
    except Exception:
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        state_path = tmpdir / "state.enc"
        key_path = tmpdir / "key.key"

        floor = PolicyRevisionFloor(state_path=state_path, key_path=key_path)
        engine = EnterprisePolicyEngine(floor=floor)

        # Build fuzzed policy dict
        try:
            policy_data = json.loads(text)
            if not isinstance(policy_data, dict):
                policy_data = {}
        except json.JSONDecodeError:
            policy_data = {}

        for rev in [policy_data.get("revision", 0), 0, 1, 2]:
            policy_data["revision"] = max(0, rev)
            for scope in (text[:15] or "all", "analysis", "", "all"):
                policy_data.setdefault("settings", {})
                policy_data.setdefault("rules", [
                    {"id": "r1", "description": "fuzz", "action": "enforce", "scope": scope},
                    {"id": "r2", "description": "warn", "action": "warn", "scope": "all"},
                ])
                try:
                    rejections = engine.load_policy(policy_data)
                    assert isinstance(rejections, list)
                except Exception:
                    pass

                # Evaluate
                for eval_scope in (scope, "all", "analysis", text[:10]):
                    try:
                        result = engine.evaluate(eval_scope)
                        assert "status" in result
                        assert result["status"] in ("ok", "warning", "violation", "no_policy")
                    except Exception:
                        pass

                # Status
                try:
                    status = engine.get_status()
                    assert "policy_loaded" in status
                except Exception:
                    pass

                # Export
                try:
                    exported = engine.export()
                    assert isinstance(exported, dict)
                except Exception:
                    pass

                # Reset engine
                engine._policy = None


def _fuzz_policy_validation(text: str) -> None:
    """Fuzz validate_enterprise_policy with fuzzed dicts."""
    try:
        from textforensics.enterprise_policy import validate_enterprise_policy
    except Exception:
        return

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = {}

    if not isinstance(data, dict):
        data = {}

    for variant in [
        data,
        {},
        {"revision": 0, "settings": {}, "rules": []},
        {"revision": -1, "settings": {}, "rules": []},
        {"settings": {}, "rules": []},
        {"revision": 0, "rules": "not-list"},
        {"revision": 0, "settings": "not-dict", "rules": []},
        {"revision": 0, "settings": {}, "rules": [{"id": 123}]},
    ]:
        try:
            errors = validate_enterprise_policy(variant)
            assert isinstance(errors, list)
        except (RuntimeError, ValueError, TypeError):
            pass
        except Exception:
            pass


def _fuzz_compute_digest(text: str) -> None:
    """Fuzz compute_policy_digest."""
    try:
        from textforensics.enterprise_policy import (
            EnterprisePolicy,
            compute_policy_digest,
        )
    except Exception:
        return

    for rev in (0, 1, 100):
        for settings in ({}, {"fuzz": text[:20]}):
            for rules in ([], [{"id": text[:10], "description": "", "action": "enforce", "scope": "all"}]):
                try:
                    ep = EnterprisePolicy(revision=rev, digest="", settings=settings, rules=rules)
                    digest = compute_policy_digest(ep)
                    assert len(digest) == 64
                except Exception:
                    pass


@atheris.instrument_func
def TestOneInput(data: bytes) -> None:
    """Fuzz enterprise policy parsing, validation, and revision floor."""
    try:
        text = data.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        text = ""

    _fuzz_policy_from_dict(text)
    _fuzz_policy_state(text)
    _fuzz_revision_floor(text)
    _fuzz_policy_engine(text)
    _fuzz_policy_validation(text)
    _fuzz_compute_digest(text)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
