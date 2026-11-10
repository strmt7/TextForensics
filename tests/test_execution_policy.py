"""Unit tests for the shared W1 execution-policy channel.

Covers ``textforensics.execution_policy`` (IF-01/IF-03/IF-07 shared
contract) and the cross-auditor capability-expiry lead adjudicated at
``textforensics.policy.CapabilityLedger`` (shared source, not the MCP
boolean alone).

These tests are written from the stated expected results, not from
current product output (plan rule 3).
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel as _PydanticBaseModel

from textforensics.emergency_stop import EmergencyStopError
from textforensics.execution_policy import (
    CancellationToken,
    CompletenessAccounting,
    ExecutionCancelled,
    ExecutionPolicy,
    RemoteConsentError,
    assert_execution_allowed,
    diagnostic_record,
    error_status_for_exception,
    is_execution_stopped,
    new_request_id,
    public_error_body,
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
