"""Unit tests for the shared W1 execution-policy channel.

Covers ``textforensics.execution_policy`` (IF-01/IF-03/IF-07 shared
contract) and the cross-auditor capability-expiry lead adjudicated at
``textforensics.policy.CapabilityLedger`` (shared source, not the MCP
boolean alone).

These tests are written from the stated expected results, not from
current product output (plan rule 3).
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import sys

import pytest
from pydantic import BaseModel as _PydanticBaseModel

from textforensics.emergency_stop import EmergencyStopError
from textforensics.execution_policy import (
    CancellationToken,
    CompletenessAccounting,
    ExecutionCancelled,
    ExecutionPolicy,
    ExecutionPolicyError,
    RemoteConsentError,
    assert_execution_allowed,
    check_execution_allowed,
    diagnostic_record,
    error_status_for_exception,
    is_execution_stopped,
    new_request_id,
    public_error_body,
    public_message_for_status,
)

# ---------------------------------------------------------------------------
# ExecutionPolicy
# ---------------------------------------------------------------------------


class TestExecutionPolicyDefaults:
    def test_default_is_local_only(self):
        policy = ExecutionPolicy.default_local_only()
        assert policy.remote_consent is False
        assert policy.remote_detector_ids == frozenset()
        assert policy.retain_raw_text is False
        assert not policy.allows_remote("anything/remote")
        assert policy.allows_detector("textforensics/builtin-heuristic", "local") is True
        assert policy.allows_detector("audit.example/recording-remote", "remote") is False

    def test_with_remote_consent_authorizes_only_selected_ids(self):
        policy = ExecutionPolicy.with_remote_consent(["audit.example/remote-a"])
        assert policy.remote_consent is True
        assert policy.allows_remote("audit.example/remote-a") is True
        assert policy.allows_remote("audit.example/remote-b") is False
        assert policy.allows_detector("audit.example/remote-a", "remote") is True
        assert policy.allows_detector("audit.example/remote-b", "remote") is False
        # Local detectors are unaffected by remote consent.
        assert policy.allows_detector("textforensics/builtin-heuristic", "local") is True

    def test_consent_without_ids_is_invalid(self):
        with pytest.raises(RemoteConsentError):
            ExecutionPolicy(remote_consent=True, remote_detector_ids=frozenset())

    def test_ids_without_consent_are_invalid(self):
        with pytest.raises(RemoteConsentError):
            ExecutionPolicy(
                remote_consent=False,
                remote_detector_ids=frozenset({"audit.example/remote-a"}),
            )

    def test_blank_remote_id_is_invalid(self):
        with pytest.raises(RemoteConsentError):
            ExecutionPolicy.with_remote_consent(["  "])

    def test_negative_byte_limit_is_invalid(self):
        with pytest.raises(ValueError):
            ExecutionPolicy.default_local_only(max_input_bytes=-1)

    def test_resolve_against_rejects_unknown_remote_id(self):
        policy = ExecutionPolicy.with_remote_consent(["audit.example/no-such-detector"])
        with pytest.raises(RemoteConsentError):
            policy.resolve_against({"textforensics/builtin-heuristic"})

    def test_resolve_against_accepts_known_remote_id(self):
        policy = ExecutionPolicy.with_remote_consent(["audit.example/remote-a"])
        resolved = policy.resolve_against(
            {"textforensics/builtin-heuristic", "audit.example/remote-a"}
        )
        assert resolved.allows_remote("audit.example/remote-a") is True

    def test_to_dict_is_deterministic_and_text_free(self):
        policy = ExecutionPolicy.with_remote_consent(
            ["audit.example/remote-b", "audit.example/remote-a"]
        )
        body = policy.to_dict()
        assert body["remote_detector_ids"] == [
            "audit.example/remote-a",
            "audit.example/remote-b",
        ]
        assert body["remote_consent"] is True
        assert body["retain_raw_text"] is False
        # Round-trip through from_dict preserves the authorization.
        assert ExecutionPolicy.from_dict(body).allows_remote("audit.example/remote-a") is True

    def test_from_dict_rejects_consent_without_ids(self):
        with pytest.raises(RemoteConsentError):
            ExecutionPolicy.from_dict({"remote_consent": True, "remote_detector_ids": []})


# ---------------------------------------------------------------------------
# CompletenessAccounting (CORE-07 shared type; consumed by trust.py in W2)
# ---------------------------------------------------------------------------


class TestCompletenessAccounting:
    def test_complete_stable_run_is_support_eligible(self):
        acc = CompletenessAccounting(selected=4, attempted=4, succeeded=4, abstained=0, failed=0)
        assert acc.is_complete is True
        assert acc.support_eligible is True

    def test_one_failure_is_never_support_eligible(self):
        acc = CompletenessAccounting(selected=4, attempted=4, succeeded=3, abstained=0, failed=1)
        assert acc.is_complete is True
        assert acc.support_eligible is False

    def test_partial_attempt_is_not_complete(self):
        acc = CompletenessAccounting(selected=4, attempted=2, succeeded=2, abstained=0, failed=0)
        assert acc.is_complete is False
        assert acc.support_eligible is False

    def test_all_abstentions_are_not_support_eligible(self):
        acc = CompletenessAccounting(selected=4, attempted=4, succeeded=0, abstained=4, failed=0)
        assert acc.is_complete is True
        assert acc.support_eligible is False

    def test_counts_must_partition_attempts(self):
        with pytest.raises(ValueError):
            CompletenessAccounting(selected=4, attempted=4, succeeded=3, abstained=1, failed=1)

    def test_attempted_cannot_exceed_selected(self):
        with pytest.raises(ValueError):
            CompletenessAccounting(selected=4, attempted=5, succeeded=5, abstained=0, failed=0)

    def test_to_dict_round_trip(self):
        acc = CompletenessAccounting(selected=4, attempted=4, succeeded=2, abstained=1, failed=1)
        body = acc.to_dict()
        assert body == {
            "selected": 4,
            "attempted": 4,
            "succeeded": 2,
            "abstained": 1,
            "failed": 1,
            "is_complete": True,
            "support_eligible": False,
        }
        assert CompletenessAccounting.from_dict(body) == acc


# ---------------------------------------------------------------------------
# Shared stop check + cancellation
# ---------------------------------------------------------------------------


class TestSharedStopCheck:
    def test_not_stopped_by_default(self, monkeypatch):
        monkeypatch.delenv("TEXTFORENSICS_EMERGENCY_STOP", raising=False)
        assert is_execution_stopped() is False
        assert_execution_allowed()  # must not raise

    def test_sentinel_file_blocks_execution(self, tmp_path, monkeypatch):
        sentinel = tmp_path / "stop"
        sentinel.write_text("stop\n", encoding="utf-8")
        monkeypatch.setenv("TEXTFORENSICS_EMERGENCY_STOP", str(sentinel))
        assert is_execution_stopped() is True
        with pytest.raises(EmergencyStopError):
            assert_execution_allowed()

    def test_malformed_sentinel_path_fails_closed(self):
        # Environment variables cannot hold a null byte, so the
        # malformed path is exercised through the sentinel API directly.
        from textforensics.emergency_stop import (
            EmergencyStopSentinel,
            check_emergency_stop,
        )

        assert check_emergency_stop("bad\x00path") is True
        sentinel = EmergencyStopSentinel("bad\x00path")
        assert sentinel.is_active() is True
        with pytest.raises(EmergencyStopError):
            sentinel.assert_not_stopped()

    def test_cancelled_token_blocks_execution(self):
        token = CancellationToken()
        assert_execution_allowed(cancellation=token)
        token.cancel()
        assert token.is_cancelled() is True
        with pytest.raises(ExecutionCancelled):
            assert_execution_allowed(cancellation=token)

    def test_stop_and_cancellation_are_both_checked(self, tmp_path, monkeypatch):
        sentinel = tmp_path / "stop"
        sentinel.write_text("stop\n", encoding="utf-8")
        monkeypatch.setenv("TEXTFORENSICS_EMERGENCY_STOP", str(sentinel))
        token = CancellationToken()
        token.cancel()
        # Emergency stop is reported first; either way execution is refused.
        with pytest.raises((EmergencyStopError, ExecutionCancelled)):
            assert_execution_allowed(cancellation=token)


# ---------------------------------------------------------------------------
# Shared redacting error-handler contract (IF-07)
# ---------------------------------------------------------------------------


class _TextInModel(_PydanticBaseModel):
    """Body model for the validation-echo test, defined at module level
    so FastAPI's type-hint resolution can find it: the file uses
    ``from __future__ import annotations``, so a method-local model
    annotation degrades to an unresolvable string and FastAPI treats
    the parameter as a query param (the test then passed vacuously)."""

    text: str


class TestRedactingErrorContract:
    def test_public_error_body_never_contains_rejected_input(self):
        canary = "SENSITIVE-PROBE-INPUT"
        body = public_error_body(422, request_id=new_request_id())
        assert canary not in str(body)
        assert body["detail"] == "Request validation failed."
        assert body["request_id"]
        assert body["error_code"] == "invalid_request"

    def test_public_error_body_for_oversize_is_413(self):
        body = public_error_body(413, request_id="req-1")
        assert body["detail"] == "Invalid text input."
        assert body["error_code"] == "invalid_text_input"

    def test_public_error_body_for_unexpected_error_is_500(self):
        body = public_error_body(500, request_id="req-2")
        assert body["detail"] == "Internal error."
        assert "Traceback" not in str(body)

    def test_error_status_for_exception(self):
        from fastapi import HTTPException

        assert error_status_for_exception(HTTPException(status_code=413)) == 413
        assert error_status_for_exception(HTTPException(status_code=404)) == 404
        assert error_status_for_exception(EmergencyStopError("stop")) == 503
        assert error_status_for_exception(ValueError("Text exceeds the limit of 1 bytes.")) == 413
        assert error_status_for_exception(ValueError("bad type")) == 422
        assert error_status_for_exception(RuntimeError("boom")) == 500

    def test_diagnostic_record_is_text_free(self):
        exc = RuntimeError("SENSITIVE-PROBE-ERROR leaked here")
        record = diagnostic_record(exc, request_id="req-9")
        assert "SENSITIVE-PROBE-ERROR" not in str(record)
        assert record["request_id"] == "req-9"
        assert record["error_type"] == "RuntimeError"

    def test_registered_handlers_redact_validation_echo(self):
        pytest.importorskip("fastapi")
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from textforensics.execution_policy import register_redacting_handlers

        app = FastAPI()

        @app.post("/echo")
        def echo(req: _TextInModel):  # noqa: ARG001 - route under test
            return {"ok": True}

        @app.get("/boom")
        def boom():
            raise RuntimeError("SENSITIVE-PROBE-ERROR")

        register_redacting_handlers(app)
        client = TestClient(app, raise_server_exceptions=False)

        response = client.post("/echo", json={"text": ["SENSITIVE-PROBE-INPUT"]})
        assert response.status_code == 422
        assert "SENSITIVE-PROBE-INPUT" not in response.text
        # Sanitized pydantic errors: stable loc/msg/type only — the
        # ``input``/``ctx`` fields that echoed the rejected value are
        # gone, while the stable message survives.
        body = response.json()
        assert isinstance(body["detail"], list)
        assert body["detail"]
        assert all(set(entry) <= {"loc", "msg", "type"} for entry in body["detail"])
        assert any("valid string" in entry.get("msg", "") for entry in body["detail"])
        assert body["request_id"]
        assert body["error_code"] == "invalid_request"
        assert response.headers["x-request-id"] == body["request_id"]

        response = client.get("/boom")
        assert response.status_code == 500
        assert "SENSITIVE-PROBE-ERROR" not in response.text
        assert "Traceback" not in response.text
        assert response.json()["detail"] == "Internal error."

    def test_registered_handlers_preserve_http_exception_status(self):
        pytest.importorskip("fastapi")
        from fastapi import FastAPI, HTTPException
        from fastapi.testclient import TestClient

        from textforensics.execution_policy import register_redacting_handlers

        app = FastAPI()

        @app.get("/too-big")
        def too_big():
            raise HTTPException(status_code=413, detail="Invalid text input.")

        @app.get("/structured")
        def structured():
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "remote_consent_required",
                    "message": "Explicit remote consent is required.",
                },
            )

        register_redacting_handlers(app)
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/too-big")
        assert response.status_code == 413
        # String detail preserved verbatim; the body stays exactly
        # {"detail": ...} (pinned live-host contract) and the request
        # ID travels in the header only.
        assert response.json() == {"detail": "Invalid text input."}
        assert response.headers["x-request-id"]

        response = client.get("/structured")
        assert response.status_code == 422
        assert response.json() == {
            "detail": {
                "code": "remote_consent_required",
                "message": "Explicit remote consent is required.",
            }
        }
        assert response.headers["x-request-id"]


# ---------------------------------------------------------------------------
# Cross-auditor lead: expired VALIDATED capability claim
# (reproduces the audit's mcp_expired_claim / cli_equivalent_expired_claim)
# ---------------------------------------------------------------------------


class TestExpiredCapabilityClaim:
    """The audit's exact case, adjudicated at the shared source.

    Claim: tier=validated, no evidence, valid_until=2000-01-01.
    Expected: not validated anywhere (MCP, CLI-equivalent enforce, ledger).
    """

    def _audit_ledger_dict(self):
        return {
            "schema": "textforensics.capability-ledger/v1",
            "claims": {
                "audit.example/detector": [
                    {
                        "capability": "language_coverage.en",
                        "tier": "validated",
                        "evidence": [],
                        "valid_until": "2000-01-01",
                    }
                ]
            },
        }

    def test_mcp_capability_check_rejects_expired_claim(self):
        from textforensics.mcp_tools import capability_check

        result = capability_check(
            {
                "ledger": self._audit_ledger_dict(),
                "detector_id": "audit.example/detector",
                "capability": "language_coverage.en",
            }
        )
        assert result["is_validated"] is False

    def test_ledger_enforce_raises_for_expired_claim(self):
        from textforensics.policy import CapabilityLedger

        ledger = CapabilityLedger.from_dict(self._audit_ledger_dict())
        assert ledger.get("audit.example/detector", "language_coverage.en") is None
        assert ledger.is_validated("audit.example/detector", "language_coverage.en") is False
        with pytest.raises(ValueError):
            ledger.enforce("audit.example/detector", "language_coverage.en")

    def test_validate_claim_flags_expiry(self):
        from textforensics.policy import CapabilityLedger, validate_claim

        ledger = CapabilityLedger.from_dict(self._audit_ledger_dict())
        claims = ledger.claims()["audit.example/detector"]
        assert len(claims) == 1  # registry listing stays honest
        issues = validate_claim(claims[0])
        assert any("expired" in issue.lower() for issue in issues)

    def test_unexpired_executed_claim_stays_validated(self):
        from textforensics.mcp_tools import capability_check
        from textforensics.policy import CapabilityLedger

        ledger_dict = {
            "schema": "textforensics.capability-ledger/v1",
            "claims": {
                "audit.example/detector": [
                    {
                        "capability": "language_coverage.en",
                        "tier": "validated",
                        "evidence": [
                            {
                                "label": "executed",
                                "tier": "validated",
                                "artifact": "run/en.json",
                            }
                        ],
                        "valid_until": "2099-01-01",
                    }
                ]
            },
        }
        ledger = CapabilityLedger.from_dict(ledger_dict)
        assert ledger.is_validated("audit.example/detector", "language_coverage.en")
        assert (
            ledger.enforce("audit.example/detector", "language_coverage.en").tier.value
            == "validated"
        )
        result = capability_check(
            {
                "ledger": ledger_dict,
                "detector_id": "audit.example/detector",
                "capability": "language_coverage.en",
            }
        )
        assert result["is_validated"] is True

    def test_unexpired_validated_without_executed_evidence_is_w2_gap(self):
        """Boundary pin (NOT a support claim): an unexpired VALIDATED
        claim whose only evidence is CALCULATED still reads as
        validated here. Whether that tier's evidence is sufficient is
        the W2 eligibility model (S04) — W1 adjudicates expiry only.
        ``validate_claim`` already flags the evidence gap as an issue.
        """
        from textforensics.policy import CapabilityLedger, validate_claim

        ledger = CapabilityLedger.from_dict(
            {
                "schema": "textforensics.capability-ledger/v1",
                "claims": {
                    "audit.example/detector": [
                        {
                            "capability": "language_coverage.en",
                            "tier": "validated",
                            "evidence": [
                                {
                                    "label": "calculated",
                                    "tier": "validated",
                                    "artifact": "calc-1",
                                }
                            ],
                            "valid_until": "2099-01-01",
                        }
                    ]
                },
            }
        )
        assert ledger.is_validated("audit.example/detector", "language_coverage.en") is True
        claim = ledger.claims()["audit.example/detector"][0]
        assert any("EXECUTED evidence" in issue for issue in validate_claim(claim))

    def test_expired_claim_does_not_lift_trust_dimension(self):
        from textforensics.policy import CapabilityLedger, ledger_to_trust_dimension

        ledger = CapabilityLedger.from_dict(self._audit_ledger_dict())
        dimension = ledger_to_trust_dimension(ledger, "audit.example/detector", "language_coverage")
        assert dimension.state != "supported"


# ---------------------------------------------------------------------------
# W1 follow-up mutation kills (audit-w1-worker-f)
#
# Each test kills the W1 new/changed-code mutants Worker E proved
# killable (audit-w1-e-stop-draft.py / audit-w1-e-probe-results.json,
# 148/148). Test IDs EP-01..EP-17 match the STOP draft.
# ---------------------------------------------------------------------------


class TestW1FollowUpMutationKills:
    def test_remaining_seconds_values(self):
        # EP-01: 26 mutants in remaining_seconds.
        from unittest.mock import patch

        p = ExecutionPolicy(deadline_seconds=60.0)
        with patch("textforensics.execution_policy.time.monotonic", return_value=100.5):
            assert p.remaining_seconds(100.0) == 59.5
        assert ExecutionPolicy().remaining_seconds(100.0) is None
        with patch("textforensics.execution_policy.time.monotonic", return_value=200.0):
            assert ExecutionPolicy(deadline_seconds=10.0).remaining_seconds(100.0) == 0.0

    def test_validate_boundaries(self):
        # EP-02: 11 mutants in validate (deadline / byte-limit bounds).
        ExecutionPolicy(max_input_bytes=1)  # smallest valid positive int
        ExecutionPolicy(deadline_seconds=1)  # smallest valid positive deadline
        ExecutionPolicy(deadline_seconds=0.5)
        with pytest.raises(ValueError):
            ExecutionPolicy(max_input_bytes=0)
        with pytest.raises(ValueError):
            ExecutionPolicy(max_input_bytes=0.0)
        with pytest.raises(ValueError):
            ExecutionPolicy(max_output_bytes=0)
        with pytest.raises(ValueError):
            ExecutionPolicy(deadline_seconds=0)
        with pytest.raises(ValueError):
            ExecutionPolicy(deadline_seconds=0.0)
        with pytest.raises(ValueError):
            ExecutionPolicy(deadline_seconds=-1)
        with pytest.raises(ValueError):
            ExecutionPolicy(deadline_seconds=True)

    def test_check_execution_allowed_paths(self, tmp_path, monkeypatch):
        # EP-03: 5 mutants in check_execution_allowed.
        assert check_execution_allowed() is True  # clear: no stop, no token, valid policy
        token = CancellationToken()
        token.cancel()
        assert check_execution_allowed(cancellation=token) is False
        sentinel = tmp_path / "stop"
        sentinel.write_text("stop\n", encoding="utf-8")
        monkeypatch.setenv("TEXTFORENSICS_EMERGENCY_STOP", str(sentinel))
        assert check_execution_allowed() is False

    def test_error_status_remote_consent_is_422(self):
        # EP-04: 2 mutants (RemoteConsent branch return 422).
        assert error_status_for_exception(RemoteConsentError("no consent")) == 422
        assert error_status_for_exception(ExecutionPolicyError("bad policy")) == 422

    def test_public_error_contract_all_statuses(self):
        # EP-05: 26 mutants (_ERROR_MESSAGES / _ERROR_CODES keys).
        expected = {
            400: ("Invalid request.", "invalid_request"),
            401: ("Authentication required.", "unauthorized"),
            403: ("Forbidden.", "forbidden"),
            404: ("Not found.", "not_found"),
            413: ("Invalid text input.", "invalid_text_input"),
            422: ("Request validation failed.", "invalid_request"),
            429: ("Too many requests.", "rate_limited"),
            500: ("Internal error.", "internal_error"),
            503: ("Emergency stop is active.", "emergency_stop_active"),
        }
        for status, (msg, code) in expected.items():
            assert public_message_for_status(status) == msg
            assert public_error_body(status, request_id="req-1")["error_code"] == code

    def test_public_error_body_request_id_passthrough(self):
        # EP-06: 1 mutant (request_id or new -> and).
        body = public_error_body(500, request_id="req-1")
        assert body["request_id"] == "req-1"
        body2 = public_error_body(500)
        assert body2["request_id"]  # fresh id when none given

    def test_default_policy_construction(self):
        # EP-07: 2 mutants (remote_consent / retain_raw_text defaults).
        p = ExecutionPolicy()
        assert p.remote_consent is False
        assert p.retain_raw_text is False
        assert p.remote_detector_ids == frozenset()
        assert p.to_dict()["retain_raw_text"] is False

    def test_from_dict_defaults(self):
        # EP-08: 2 mutants (from_dict remote_consent / retain_raw_text defaults).
        p = ExecutionPolicy.from_dict({})
        assert p.remote_consent is False
        assert p.retain_raw_text is False

    def test_cancellation_token_not_compared_or_repr(self):
        # EP-09: 2 mutants (cancellation compare=False / repr=False).
        a = ExecutionPolicy(cancellation=CancellationToken())
        b = ExecutionPolicy(cancellation=CancellationToken())
        assert a == b  # cancellation is compare=False
        assert "cancellation" not in repr(a)  # and repr=False

    def test_policies_are_frozen_and_slotted(self):
        # EP-10: 4 mutants (frozen / slots on both dataclasses).
        p = ExecutionPolicy()
        with pytest.raises(dataclasses.FrozenInstanceError):
            p.retain_raw_text = True
        assert not hasattr(p, "__dict__")
        acc = CompletenessAccounting(selected=1, attempted=1, succeeded=1, abstained=0, failed=0)
        with pytest.raises(dataclasses.FrozenInstanceError):
            acc.selected = 2
        assert not hasattr(acc, "__dict__")

    def test_completeness_rejects_bad_counts(self):
        # EP-11: 5 mutants in CompletenessAccounting.__post_init__.
        with pytest.raises(ValueError):
            CompletenessAccounting(selected=4, attempted=-1, succeeded=0, abstained=0, failed=0)
        with pytest.raises(ValueError):
            CompletenessAccounting(selected=-1, attempted=-1, succeeded=-1, abstained=0, failed=0)
        with pytest.raises(ValueError):
            CompletenessAccounting(selected=True, attempted=1, succeeded=1, abstained=0, failed=0)
        with pytest.raises(ValueError):
            CompletenessAccounting(selected=1.5, attempted=1, succeeded=1, abstained=0, failed=0)
        with pytest.raises(ValueError):
            CompletenessAccounting(selected=4, attempted=4, succeeded=2, abstained=0, failed=0)

    def test_completeness_large_counts_use_value_equality(self):
        # EP-12 (tier 2): 3 mutants (== vs `is` on large counts).
        n = int("300")  # distinct int object, outside the small-int cache
        m = 200 + 100  # a second distinct 300
        acc = CompletenessAccounting(selected=n, attempted=m, succeeded=m, abstained=0, failed=0)
        assert acc.is_complete is True
        assert acc.support_eligible is True
        acc2 = CompletenessAccounting(
            selected=n, attempted=m, succeeded=int("299"), abstained=0, failed=1
        )
        assert acc2.support_eligible is False

    def test_allows_detector_unknown_is_local(self):
        # EP-13: 1 mutant (allows_detector execution == 'remote' -> >=).
        p = ExecutionPolicy.default_local_only()
        assert p.allows_detector("x/detector", "unknown") is True
        assert p.allows_detector("x/detector", "local") is True
        assert p.allows_detector("x/detector", "remote") is False

    def test_request_id_header_passthrough(self):
        # EP-14: 2 mutants in _request_id_for.
        pytest.importorskip("fastapi")
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from textforensics.execution_policy import register_redacting_handlers

        app = FastAPI()

        @app.get("/boom")
        def boom():
            raise RuntimeError("x")

        register_redacting_handlers(app)
        client = TestClient(app, raise_server_exceptions=False)
        r = client.get("/boom", headers={"x-request-id": "req-abc"})
        assert r.headers["x-request-id"] == "req-abc"
        r2 = client.get("/boom")
        assert r2.headers["x-request-id"]  # fresh id when no header

    def test_validation_handler_keeps_loc_and_type(self):
        # EP-15: 2 mutants in _validation_handler ('loc' / 'type' checks).
        # Uses the module-level _TextInModel: this file uses
        # ``from __future__ import annotations``, so a method-local model
        # annotation would degrade to an unresolvable string (see the
        # _TextInModel docstring above).
        pytest.importorskip("fastapi")
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from textforensics.execution_policy import register_redacting_handlers

        app = FastAPI()

        @app.post("/echo")
        def echo(req: _TextInModel):  # noqa: ARG001 - route under test
            return {"ok": True}

        register_redacting_handlers(app)
        client = TestClient(app, raise_server_exceptions=False)
        r = client.post("/echo", json={"text": ["x"]})
        assert r.status_code == 422
        detail = r.json()["detail"]
        assert detail and all("loc" in e and "msg" in e and "type" in e for e in detail)

    def test_validation_handler_skips_non_dict_errors(self):
        # EP-16 (tier 2): 1 mutant (continue -> break on non-dict error).
        # Defensive branch — pydantic never yields a non-dict error, so
        # the test drives the handler directly with a fake exception.
        # The handler reads request.headers, so the request is a stub.
        pytest.importorskip("fastapi")
        from types import SimpleNamespace

        from fastapi.exceptions import RequestValidationError as _VE

        from textforensics.execution_policy import register_redacting_handlers

        class _FakeExc(Exception):
            def errors(self):
                return [
                    {"loc": ("text",), "msg": "first", "type": "string_type"},
                    "junk",
                    {"loc": ("text",), "msg": "third", "type": "string_type"},
                ]

        seen = {}

        class _App:
            def add_exception_handler(self, exc, handler):
                seen[exc] = handler

        register_redacting_handlers(_App())
        resp = asyncio.run(seen[_VE](SimpleNamespace(headers={}), _FakeExc()))
        detail = resp.body and json.loads(resp.body)["detail"]
        assert [e["msg"] for e in detail] == ["first", "third"]

    def test_error_status_without_fastapi(self):
        # EP-17 (tier 2): 1 mutant (except ImportError -> CosmicRayTestingException).
        # Core-only install: fastapi absent, so error_status_for_exception
        # must still map by type. The probe blocks fastapi via the
        # sys.modules None sentinel; the same mechanism is used here.
        saved = {}
        for _mod in ("fastapi", "fastapi.exceptions", "fastapi.testclient"):
            if _mod in sys.modules:
                saved[_mod] = sys.modules.pop(_mod)
        sys.modules["fastapi"] = None
        try:
            assert error_status_for_exception(ValueError("bad type")) == 422
            assert error_status_for_exception(RuntimeError("boom")) == 500
        finally:
            sys.modules.pop("fastapi", None)
            sys.modules.update(saved)
