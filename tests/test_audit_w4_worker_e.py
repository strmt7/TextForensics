"""W4 Worker E regression tests: S15/S16 (retry), S17/S18/S19 (health),
S20 (probe-run manifests) and the W2 handoff (EmergencyStopError
propagation from probe runs).

Every test states the expected behaviour from the audit plan/spec, not
from current output. Timing tests use fake clocks (explicit ``now``) or
short real timeouts (<=0.05 s); no long real sleeps.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from textforensics.emergency_stop import EmergencyStopError
from textforensics.execution_policy import CancellationToken, ExecutionCancelled
from textforensics.observatory import (
    AlertSeverity,
    DetectorHealthMonitor,
    DetectorHealthReport,
    HealthAlert,
    HealthState,
)
from textforensics.probe_runs import (
    ProbeRunError,
    build_run_manifest,
    load_run,
    load_run_history,
    perform_probe_run,
    save_run,
    validate_run_manifest,
)
from textforensics.retry import (
    CircuitState,
    CircuitTransition,
    RetryPolicy,
    create_retry_gate,
    with_retry_gate,
)

HEX64 = "a" * 64
HEX64_B = "b" * 64


# ---------------------------------------------------------------------------
# S15 — retry readiness / backoff / Retry-After / single half-open probe
# ---------------------------------------------------------------------------


class TestS15RetryReadiness:
    def test_closed_gate_respects_backoff(self):
        gate = create_retry_gate(base_delay=1.0, max_delay=300.0, jitter_factor=0.0)
        t0 = 1000.0
        delay, _ = gate.failure(now=t0, retry_after=30.0)
        assert delay == 30.0
        allowed, wait = gate.ready(now=t0)
        assert allowed is False
        assert wait == pytest.approx(30.0)
        allowed, _ = gate.ready(now=t0 + 29.9)
        assert allowed is False
        allowed, wait = gate.ready(now=t0 + 30.0)
        assert allowed is True
        assert wait == 0.0

    def test_opening_does_not_shorten_retry_after(self):
        gate = create_retry_gate(circuit_open_after=1, circuit_reset_timeout=5.0, jitter_factor=0.0)
        t0 = 2000.0
        _, transition = gate.failure(now=t0, retry_after=60.0)
        assert transition == CircuitTransition.OPENED
        assert gate.state == CircuitState.OPEN
        # At t+5 the short reset timeout has elapsed but the 60 s
        # provider deadline has not: still not ready.
        allowed, wait = gate.ready(now=t0 + 5.0)
        assert allowed is False
        assert wait == pytest.approx(55.0)
        allowed, _ = gate.ready(now=t0 + 59.9)
        assert allowed is False
        allowed, _ = gate.ready(now=t0 + 60.0)
        assert allowed is True
        assert gate.state == CircuitState.HALF_OPEN

    def test_half_open_admits_single_probe(self):
        gate = create_retry_gate(circuit_open_after=1, circuit_reset_timeout=5.0, jitter_factor=0.0)
        t0 = 3000.0
        gate.failure(now=t0, retry_after=60.0)
        assert gate.state == CircuitState.OPEN
        allowed, _ = gate.ready(now=t0 + 60.0)
        assert allowed is True  # first caller owns the single probe
        allowed, wait = gate.ready(now=t0 + 60.0)
        assert allowed is False  # second caller must wait
        assert wait > 0.0
        # A third caller is denied too.
        allowed, _ = gate.ready(now=t0 + 60.0)
        assert allowed is False
        # The probe succeeds: circuit closes and callers may proceed.
        assert gate.success(now=t0 + 61.0) == CircuitTransition.CLOSED
        allowed, _ = gate.ready(now=t0 + 61.0)
        assert allowed is True

    def test_half_open_failed_probe_reopens(self):
        gate = create_retry_gate(circuit_open_after=1, circuit_reset_timeout=5.0, jitter_factor=0.0)
        t0 = 4000.0
        gate.failure(now=t0, retry_after=60.0)
        allowed, _ = gate.ready(now=t0 + 60.0)
        assert allowed is True
        _, transition = gate.failure(now=t0 + 61.0, retry_after=60.0)
        assert transition == CircuitTransition.OPENED
        assert gate.state == CircuitState.OPEN
        allowed, _ = gate.ready(now=t0 + 61.0)
        assert allowed is False

    def test_half_open_probe_claim_expires(self):
        # A granted probe that never resolves must not wedge the gate
        # forever: after the claim deadline a fresh probe may be granted.
        gate = create_retry_gate(circuit_open_after=1, circuit_reset_timeout=5.0, jitter_factor=0.0)
        t0 = 5000.0
        gate.failure(now=t0)
        allowed, _ = gate.ready(now=t0 + 5.0)
        assert allowed is True
        allowed, _ = gate.ready(now=t0 + 5.0)
        assert allowed is False
        allowed, _ = gate.ready(now=t0 + 5.0 + 5.0)
        assert allowed is True

    def test_concurrent_half_open_single_probe(self):
        gate = create_retry_gate(
            circuit_open_after=1, circuit_reset_timeout=0.05, jitter_factor=0.0
        )
        gate.failure()
        assert gate.state == CircuitState.OPEN
        time.sleep(0.06)
        results: list[bool] = []
        barrier = threading.Barrier(8)

        def _try_ready() -> None:
            barrier.wait(timeout=5)
            allowed, _ = gate.ready()
            results.append(allowed)

        threads = [threading.Thread(target=_try_ready) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        assert len(results) == 8
        assert results.count(True) == 1

    def test_policy_rejects_nonfinite_values(self):
        for kwargs in (
            {"base_delay": float("nan")},
            {"base_delay": float("inf")},
            {"max_delay": float("nan")},
            {"circuit_reset_timeout": float("inf")},
            {"circuit_reset_timeout": float("nan")},
            {"max_provider_retry_after": float("nan")},
            {"max_provider_retry_after": float("inf")},
            {"jitter_factor": float("nan")},
        ):
            with pytest.raises(ValueError):
                RetryPolicy(**kwargs)

    def test_failure_rejects_nonfinite_or_negative_retry_after(self):
        gate = create_retry_gate()
        for bad in (float("nan"), float("inf"), -1.0):
            with pytest.raises(ValueError):
                gate.failure(retry_after=bad)

    def test_retry_policy_rejects_non_integer_counts(self):
        with pytest.raises(ValueError):
            RetryPolicy(max_retries=1.5)
        with pytest.raises(ValueError):
            RetryPolicy(circuit_open_after=True)


# ---------------------------------------------------------------------------
# S16 — waiting on an open gate must not consume an attempt
# ---------------------------------------------------------------------------


class TestS16OpenGateDoesNotConsumeAttempt:
    @pytest.mark.asyncio
    async def test_open_gate_wait_then_successful_first_call(self):
        gate = create_retry_gate(circuit_open_after=1, circuit_reset_timeout=0.05, max_retries=0)
        gate.failure()
        assert gate.state == CircuitState.OPEN
        calls = 0

        async def operation():
            nonlocal calls
            calls += 1
            return "ok"

        result = await with_retry_gate(gate, operation)
        assert result == "ok"
        assert calls == 1
        assert gate.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_retry_budget_counts_calls_only(self):
        gate = create_retry_gate(base_delay=0.01, max_delay=0.05, max_retries=1)
        calls = 0

        async def operation():
            nonlocal calls
            calls += 1
            if calls < 2:
                raise ConnectionError("transient")
            return "ok"

        result = await with_retry_gate(gate, operation, retry_on=(ConnectionError,))
        assert result == "ok"
        assert calls == 2

    @pytest.mark.asyncio
    async def test_exhaustion_raises_last_exception_with_call_count(self):
        gate = create_retry_gate(base_delay=0.01, max_delay=0.05, max_retries=1)
        calls = 0

        async def operation():
            nonlocal calls
            calls += 1
            raise ConnectionError("persistent")

        with pytest.raises(ConnectionError, match="persistent"):
            await with_retry_gate(gate, operation, retry_on=(ConnectionError,))
        # Initial attempt + 1 retry = 2 calls; never a bare RuntimeError.
        assert calls == 2

    @pytest.mark.asyncio
    async def test_open_gate_wait_then_failing_first_call(self):
        gate = create_retry_gate(circuit_open_after=1, circuit_reset_timeout=0.05, max_retries=0)
        gate.failure()
        calls = 0

        async def operation():
            nonlocal calls
            calls += 1
            raise ConnectionError("still down")

        with pytest.raises(ConnectionError, match="still down"):
            await with_retry_gate(gate, operation, retry_on=(ConnectionError,))
        assert calls == 1


# ---------------------------------------------------------------------------
# S17 — built-in health thresholds implement their own contracts
# ---------------------------------------------------------------------------


class TestS17HealthThresholdDirection:
    def test_latency_warning_at_3000(self):
        m = DetectorHealthMonitor()
        for _ in range(25):
            m.record_latency("d1", 4000.0)
        r = m.get_report("d1")
        assert r.overall_state == HealthState.DEGRADED
        assert any(
            a.severity == AlertSeverity.WARNING and a.metric_name == "latency_ms" for a in r.alerts
        )

    def test_latency_boundaries(self):
        m = DetectorHealthMonitor()
        for _ in range(25):
            m.record_latency("d1", 2999.0)
        assert m.get_report("d1").overall_state == HealthState.HEALTHY

        m2 = DetectorHealthMonitor()
        for _ in range(25):
            m2.record_latency("d1", 3000.0)
        assert m2.get_report("d1").overall_state == HealthState.DEGRADED

        m3 = DetectorHealthMonitor()
        for _ in range(25):
            m3.record_latency("d1", 10000.0)
        assert m3.get_report("d1").overall_state == HealthState.CRITICAL

    def test_throughput_critical_below_0_1(self):
        # Two requests in the last minute: 2/60 = 0.0333 rps, below the
        # declared 0.1 critical threshold.
        m = DetectorHealthMonitor()
        m.record_request("d1")
        m.record_request("d1")
        r = m.get_report("d1")
        assert r.overall_state == HealthState.CRITICAL
        assert any(
            a.severity == AlertSeverity.CRITICAL and a.metric_name == "throughput_rps"
            for a in r.alerts
        )

    def test_throughput_boundaries(self):
        # 6 requests -> 0.1 rps exactly: at the critical threshold.
        m = DetectorHealthMonitor()
        for _ in range(6):
            m.record_request("d1")
        assert m.get_report("d1").overall_state == HealthState.CRITICAL

        # 7 requests -> ~0.117 rps: between critical and warning.
        m2 = DetectorHealthMonitor()
        for _ in range(7):
            m2.record_request("d1")
        assert m2.get_report("d1").overall_state == HealthState.DEGRADED

        # 30 requests -> 0.5 rps exactly: at the warning threshold, passes.
        m3 = DetectorHealthMonitor()
        for _ in range(30):
            m3.record_request("d1")
        assert m3.get_report("d1").overall_state == HealthState.HEALTHY

    def test_entropy_warning_between_0_3_and_0_5(self):
        # 17/1/1/1 across four bins: entropy ratio ~= 0.42, inside the
        # declared warning interval (critical 0.3, warning 0.5).
        m = DetectorHealthMonitor()
        for _ in range(17):
            m.record_score("d1", 0.05)
        m.record_score("d1", 0.15)
        m.record_score("d1", 0.25)
        m.record_score("d1", 0.35)
        r = m.get_report("d1")
        assert r.overall_state == HealthState.DEGRADED
        assert any(
            a.severity == AlertSeverity.WARNING and a.metric_name == "score_entropy_ratio"
            for a in r.alerts
        )

    def test_error_rate_warning_at_0_05(self):
        m = DetectorHealthMonitor()
        for _ in range(19):
            m.record_error("d1", False)
        m.record_error("d1", True)
        r = m.get_report("d1")
        assert r.overall_state == HealthState.DEGRADED


# ---------------------------------------------------------------------------
# S18 — undefined / stale observations are never healthy
# ---------------------------------------------------------------------------


class TestS18HealthStalenessAndUnknown:
    def test_nan_latency_rejected(self):
        m = DetectorHealthMonitor()
        with pytest.raises(ValueError):
            m.record_latency("d1", float("nan"))
        with pytest.raises(ValueError):
            m.record_latency("d1", float("inf"))
        with pytest.raises(ValueError):
            m.record_latency("d1", -1.0)

    def test_nan_score_rejected(self):
        m = DetectorHealthMonitor()
        with pytest.raises(ValueError):
            m.record_score("d1", float("nan"))
        with pytest.raises(ValueError):
            m.record_metric("d1", "latency_ms", float("inf"))

    def test_stale_observation_is_not_healthy(self):
        m = DetectorHealthMonitor()
        m.record_latency("d1", 100.0, timestamp="2000-01-01T00:00:00+00:00")
        r = m.get_report("d1")
        assert r.overall_state == HealthState.UNKNOWN
        assert r.health_score == 0.0
        # The report must not present the ancient observation as fresh.
        assert r.last_updated == "2000-01-01T00:00:00+00:00"

    def test_stale_read_does_not_refresh_timestamp(self):
        m = DetectorHealthMonitor()
        m.record_latency("d1", 100.0, timestamp="2000-01-01T00:00:00+00:00")
        first = m.get_report("d1").last_updated
        second = m.get_report("d1").last_updated
        assert first == second == "2000-01-01T00:00:00+00:00"

    def test_no_data_is_unknown(self):
        m = DetectorHealthMonitor()
        r = m.get_report("d1")
        assert r.overall_state == HealthState.UNKNOWN
        assert r.health_score == 0.0

    def test_fresh_finite_data_can_be_healthy(self):
        m = DetectorHealthMonitor()
        for _ in range(25):
            m.record_latency("d1", 100.0)
        r = m.get_report("d1")
        assert r.overall_state == HealthState.HEALTHY
        assert r.health_score == 1.0

    def test_fewer_than_minimum_entropy_samples_is_not_a_pass(self):
        # 5 identical scores are below the entropy check's 10-sample
        # minimum: no check has sufficient evidence, so the report is
        # UNKNOWN rather than HEALTHY.
        m = DetectorHealthMonitor()
        for _ in range(5):
            m.record_score("d1", 0.5)
        r = m.get_report("d1")
        assert r.overall_state == HealthState.UNKNOWN
        assert r.health_score == 0.0


# ---------------------------------------------------------------------------
# S19 — alert persistence keeps the enum type; history is bounded
# ---------------------------------------------------------------------------


class TestS19HealthAlertPersistence:
    def _report_with_all_severities(self) -> DetectorHealthReport:
        alerts = [
            HealthAlert(
                alert_id=f"alert-{sev.value}",
                detector_id="d1",
                severity=sev,
                message=f"{sev.value} alert",
                metric_name="latency_ms",
                metric_value=5000.0,
                threshold=3000.0,
                timestamp="2026-11-14T00:00:00+00:00",
            )
            for sev in AlertSeverity
        ]
        return DetectorHealthReport(
            detector_id="d1",
            overall_state=HealthState.CRITICAL,
            health_score=0.2,
            alerts=alerts,
        )

    def test_save_load_save_roundtrip_preserves_severity_enum(self, tmp_path):
        report = self._report_with_all_severities()
        path = tmp_path / "report.json"
        assert report.save(path) is True
        loaded = DetectorHealthReport.load(path)
        assert loaded is not None
        assert all(isinstance(a.severity, AlertSeverity) for a in loaded.alerts)
        assert [a.severity for a in loaded.alerts] == list(AlertSeverity)
        # Reserializing the loaded report must not raise AttributeError.
        reserialized = loaded.to_dict()
        assert [a["severity"] for a in reserialized["alerts"]] == [s.value for s in AlertSeverity]
        path2 = tmp_path / "report2.json"
        assert loaded.save(path2) is True
        assert json.loads(path2.read_text(encoding="utf-8")) == json.loads(
            path.read_text(encoding="utf-8")
        )

    def test_load_rejects_bad_stored_severity(self, tmp_path):
        report = self._report_with_all_severities()
        path = tmp_path / "report.json"
        assert report.save(path) is True
        data = json.loads(path.read_text(encoding="utf-8"))
        data["alerts"][0]["severity"] = "nonsense"
        path.write_text(json.dumps(data), encoding="utf-8")
        assert DetectorHealthReport.load(path) is None

    def test_alert_history_bounded_by_max_history(self):
        m = DetectorHealthMonitor(max_history=2)
        for i in range(6):
            for _ in range(5):
                m.record_error(f"d{i}", True)
        assert len(m._alerts) <= 2
        assert len(m.get_all_alerts()) <= 2

    def test_sustained_anomaly_deduplicated_by_transition(self):
        hits: list[HealthAlert] = []
        m = DetectorHealthMonitor(alert_callback=hits.append)
        for _ in range(5):
            m.record_error("d1", True)
        assert len(m._alerts) == 1
        assert len(hits) == 1

    def test_repeat_incident_after_recovery_alerts_again(self):
        hits: list[HealthAlert] = []
        m = DetectorHealthMonitor(alert_callback=hits.append)
        for _ in range(5):
            m.record_error("d1", True)
        assert len(hits) == 1
        # Recovery: enough successes to drop the error rate below 5%.
        # The rate passes through the WARNING band on the way down,
        # which is its own transition: CRITICAL -> WARNING -> clear.
        for _ in range(96):
            m.record_error("d1", False)
        assert m.get_report("d1").overall_state == HealthState.HEALTHY
        assert [a.severity for a in hits] == [
            AlertSeverity.CRITICAL,
            AlertSeverity.WARNING,
        ]
        for _ in range(5):
            m.record_error("d1", True)
        # 10 errors in 106 events is ~9.4%: back in the WARNING band,
        # a new transition after the recovery cleared the old state.
        assert len(hits) == 3
        assert [a.severity for a in hits] == [
            AlertSeverity.CRITICAL,
            AlertSeverity.WARNING,
            AlertSeverity.WARNING,
        ]
        assert len(m._alerts) == 3


# ---------------------------------------------------------------------------
# S20 — strict run-manifest validation, append-only history
# ---------------------------------------------------------------------------


def _manifest(**overrides):
    kwargs = {
        "scope": "full",
        "corpus_version": "1.0.0",
        "corpus_fingerprint": HEX64,
        "corpus_manifest_sha256": HEX64_B,
        "detector_id": "textforensics/builtin-heuristic",
        "detector_version": "0.1.0",
        "provider_metadata": {},
        "code_sha": "c" * 40,
        "baseline_run_id": None,
        "is_baseline": True,
        "rebaselined_from": None,
        "previous_run_id": None,
        "metrics": {"detector_id": "textforensics/builtin-heuristic"},
        "alerts": [],
        "breaches": [],
    }
    kwargs.update(overrides)
    return build_run_manifest(**kwargs)


class TestS20RunManifestValidation:
    def test_rejects_missing_schema_required_fields(self):
        for missing in (
            "code_sha",
            "thresholds",
            "alpha_per_run",
            "is_baseline",
            "previous_run_id",
            "baseline_run_id",
            "demotions_applied",
            "demotions_cleared",
            "watches",
            "gaps",
            "limitations",
        ):
            manifest = _manifest()
            del manifest[missing]
            with pytest.raises(ProbeRunError, match=missing):
                validate_run_manifest(manifest)

    def test_rejects_nan_scores_and_metrics(self):
        manifest = _manifest()
        manifest["score_series"] = {"item-1": {"score": float("nan"), "verdict": "human_like"}}
        with pytest.raises(ProbeRunError):
            validate_run_manifest(manifest)
        manifest = _manifest()
        manifest["metrics"] = {"nested": float("inf")}
        with pytest.raises(ProbeRunError):
            validate_run_manifest(manifest)
        manifest = _manifest()
        manifest["alpha_per_run"] = float("nan")
        with pytest.raises(ProbeRunError):
            validate_run_manifest(manifest)

    def test_rejects_unknown_top_level_keys(self):
        manifest = _manifest()
        manifest["surprise_field"] = 1
        with pytest.raises(ProbeRunError, match="surprise_field"):
            validate_run_manifest(manifest)

    def test_rejects_naive_or_non_utc_run_at(self):
        for bad_at in (
            "2026-11-01T00:00:00",
            "2026-11-01T00:00:00+02:00",
            "not-a-date",
        ):
            manifest = _manifest()
            manifest["run_at_utc"] = bad_at
            with pytest.raises(ProbeRunError):
                validate_run_manifest(manifest)
            # The builder enforces the same rule at build time.
            with pytest.raises(ProbeRunError):
                _manifest(run_at_utc=bad_at)

    def test_rejects_unsafe_run_id(self):
        # The filename is "run-<run_id>.json", so bare dots are
        # harmless; only separators are unsafe.
        for bad_id in ("../escape", "a/b"):
            manifest = _manifest()
            manifest["run_id"] = bad_id
            with pytest.raises(ProbeRunError):
                validate_run_manifest(manifest)
            # The builder enforces the same rule at build time.
            with pytest.raises(ProbeRunError):
                _manifest(run_id=bad_id)
        # An empty id is rejected by the validator; the builder
        # substitutes a UUID for it by design, so it is not built here.
        manifest = _manifest()
        manifest["run_id"] = ""
        with pytest.raises(ProbeRunError):
            validate_run_manifest(manifest)

    def test_rejects_incomplete_alerts_and_thresholds(self):
        manifest = _manifest()
        manifest["alerts"] = [{"tier": 1, "rule": "x"}]
        with pytest.raises(ProbeRunError):
            validate_run_manifest(manifest)
        manifest = _manifest()
        del manifest["thresholds"]["psi_action"]
        with pytest.raises(ProbeRunError):
            validate_run_manifest(manifest)
        manifest = _manifest()
        manifest["thresholds"]["bogus"] = 1.0
        with pytest.raises(ProbeRunError):
            validate_run_manifest(manifest)
        manifest = _manifest()
        manifest["thresholds"]["fpr_cap"] = 1.5
        with pytest.raises(ProbeRunError):
            validate_run_manifest(manifest)

    def test_rejects_self_linkage(self):
        manifest = _manifest(run_id="r1")
        manifest["previous_run_id"] = "r1"
        with pytest.raises(ProbeRunError):
            validate_run_manifest(manifest)

    def test_rejects_metric_totals_inconsistent_with_series(self):
        manifest = _manifest()
        manifest["score_series"] = {
            f"item-{i}": {"score": 0.5, "verdict": "human_like"} for i in range(3)
        }
        manifest["metrics"] = {
            "detector_id": "textforensics/builtin-heuristic",
            "overall": {"n": 4},
        }
        with pytest.raises(ProbeRunError):
            validate_run_manifest(manifest)
        manifest["metrics"] = {
            "detector_id": "textforensics/builtin-heuristic",
            "overall": {"n": 3},
            "slices": {"s1": {"n": 2}, "s2": {"n": 2}},
        }
        with pytest.raises(ProbeRunError):
            validate_run_manifest(manifest)
        manifest["metrics"] = {
            "detector_id": "some/other-detector",
            "overall": {"n": 3},
            "slices": {"s1": {"n": 3}},
        }
        with pytest.raises(ProbeRunError):
            validate_run_manifest(manifest)
        manifest["metrics"] = {
            "detector_id": "textforensics/builtin-heuristic",
            "overall": {"n": 3},
            "slices": {"s1": {"n": 3}},
            "holm": {"alpha_per_run": 0.01},
        }
        with pytest.raises(ProbeRunError):
            validate_run_manifest(manifest)

    def test_rejects_bad_score_series_entries(self):
        manifest = _manifest()
        manifest["score_series"] = {
            "item-1": {
                "score": 0.5,
                "verdict": "human_like",
                "calibrated_ai_probability": 1.5,
            }
        }
        with pytest.raises(ProbeRunError):
            validate_run_manifest(manifest)
        manifest = _manifest()
        manifest["score_series"] = {"item-1": {"score": 0.5, "verdict": "human_like", "extra": 1}}
        with pytest.raises(ProbeRunError):
            validate_run_manifest(manifest)
        manifest = _manifest()
        manifest["score_series"] = {"item-1": {"score": 0.5, "verdict": "maybe"}}
        with pytest.raises(ProbeRunError):
            validate_run_manifest(manifest)

    def test_validator_required_fields_match_shipped_schema(self):
        schema_path = (
            Path(__file__).resolve().parent.parent
            / "src"
            / "textforensics"
            / "schemas"
            / "probe-run.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        manifest = _manifest()
        # A manifest missing any schema-required field must be rejected.
        for field in schema["required"]:
            tampered = dict(manifest)
            del tampered[field]
            with pytest.raises(ProbeRunError, match=field):
                validate_run_manifest(tampered)
        for field in schema["properties"]["thresholds"]["required"]:
            tampered = _manifest()
            del tampered["thresholds"][field]
            with pytest.raises(ProbeRunError):
                validate_run_manifest(tampered)

    def test_built_manifest_validates_against_shipped_schema(self):
        # The custom validator and the shipped JSON Schema must agree:
        # a manifest the builder produces — including score-series
        # entries carrying the S09 direction/range round-trip — must
        # validate against the schema file itself, and the validator
        # must accept every score-series property the schema allows.
        import jsonschema

        schema_path = (
            Path(__file__).resolve().parent.parent
            / "src"
            / "textforensics"
            / "schemas"
            / "probe-run.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        manifest = _manifest()
        manifest["score_series"] = {
            "item-1": {
                "score": 0.5,
                "verdict": "human_like",
                "calibrated_ai_probability": 0.4,
                "calibration_id": "cal-1",
                "native_score_direction": "higher_means_ai",
                "score_range": [0.0, 1.0],
            }
        }
        validate_run_manifest(manifest)
        errors = list(jsonschema.Draft202012Validator(schema).iter_errors(manifest))
        assert errors == []
        # Every schema-allowed series property is accepted by the
        # validator; an unknown one is not.
        entry_props = set(
            schema["properties"]["score_series"]["additionalProperties"]["properties"]
        )
        assert {
            "score",
            "verdict",
            "calibrated_ai_probability",
            "calibration_id",
            "native_score_direction",
            "score_range",
        } <= entry_props
        manifest["score_series"]["item-1"]["surprise"] = 1
        with pytest.raises(ProbeRunError):
            validate_run_manifest(manifest)
        assert list(jsonschema.Draft202012Validator(schema).iter_errors(manifest))

    def test_save_run_refuses_overwrite(self, tmp_path):
        first = _manifest(run_id="a" * 32, run_at_utc="2026-11-01T00:00:00+00:00")
        second = _manifest(run_id="a" * 32, run_at_utc="2026-11-02T00:00:00+00:00")
        saved = save_run(first, tmp_path)
        assert saved.exists()
        original_bytes = saved.read_bytes()
        with pytest.raises(ProbeRunError, match="already exists"):
            save_run(second, tmp_path)
        assert saved.read_bytes() == original_bytes
        assert len(list(tmp_path.glob("run-*.json"))) == 1

    def test_save_run_idempotent_exact_resave(self, tmp_path):
        manifest = _manifest(run_id="b" * 32)
        first = save_run(manifest, tmp_path)
        second = save_run(manifest, tmp_path)
        assert first == second
        assert first.read_bytes() == second.read_bytes()
        assert len(list(tmp_path.glob("run-*.json"))) == 1

    def test_load_run_history_rejects_duplicate_run_id(self, tmp_path):
        first = _manifest(run_id="c" * 32, run_at_utc="2026-11-01T00:00:00+00:00")
        second = _manifest(run_id="c" * 32, run_at_utc="2026-11-02T00:00:00+00:00")
        (tmp_path / "run-1.json").write_text(json.dumps(first), encoding="utf-8")
        (tmp_path / "run-2.json").write_text(json.dumps(second), encoding="utf-8")
        with pytest.raises(ProbeRunError, match="duplicate"):
            load_run_history(tmp_path)

    def test_load_run_history_orders_by_parsed_utc_time(self, tmp_path):
        # "2026-11-01T08:00:00Z" sorts AFTER "2026-11-01T08:00:00.500+00:00"
        # as raw strings ('Z' > '.'), but chronologically it is earlier.
        earlier = _manifest(run_id="d" * 32, run_at_utc="2026-11-01T08:00:00Z")
        later = _manifest(run_id="e" * 32, run_at_utc="2026-11-01T08:00:00.500+00:00")
        save_run(later, tmp_path)
        save_run(earlier, tmp_path)
        history = load_run_history(tmp_path)
        assert [r["run_id"] for r in history] == ["d" * 32, "e" * 32]

    def test_load_run_rejects_nan_literal(self, tmp_path):
        manifest = _manifest()
        path = tmp_path / "run-x.json"
        text = json.dumps(manifest)
        text = text.replace('"alpha_per_run": 0.05', '"alpha_per_run": NaN')
        path.write_text(text, encoding="utf-8")
        with pytest.raises(ProbeRunError):
            load_run(path)


# ---------------------------------------------------------------------------
# S20 handoff — EmergencyStopError propagation from probe runs (W1 channel)
# ---------------------------------------------------------------------------


class TestS20EmergencyStopPropagation:
    def test_stop_before_run_blocks_and_saves_nothing(self, tmp_path, monkeypatch):
        from tests.test_probe_runs_e2e import _build_corpus, _run

        manifest, texts, holdback = _build_corpus()
        sentinel = tmp_path / "stop"
        sentinel.write_text("stop\n", encoding="utf-8")
        monkeypatch.setenv("TEXTFORENSICS_EMERGENCY_STOP", str(sentinel))
        runs_dir = tmp_path / "runs"
        with pytest.raises(EmergencyStopError):
            _run(manifest, texts, holdback, _stub_detector(), runs_dir)
        assert not list(runs_dir.glob("run-*.json"))

    def test_stop_activated_after_scoring_blocks_save(self, tmp_path, monkeypatch):
        from tests.test_probe_runs_e2e import (
            StubDetector,
            _build_corpus,
            _make_stub_primitives,
        )

        manifest, texts, holdback = _build_corpus()
        sentinel = tmp_path / "stop"
        monkeypatch.setenv("TEXTFORENSICS_EMERGENCY_STOP", str(sentinel))
        runs_dir = tmp_path / "runs"

        def activating_loader():
            # The holdback loader runs only after scoring: activating
            # the stop here must abort the run before any demotion
            # or save, never produce a clean-run record.
            sentinel.write_text("stop\n", encoding="utf-8")
            return holdback

        with pytest.raises(EmergencyStopError):
            perform_probe_run(
                manifest=manifest,
                texts=texts,
                holdback_loader=activating_loader,
                detector=StubDetector(),
                scope="full",
                runs_dir=runs_dir,
                primitives=_make_stub_primitives(),
            )
        assert not list(runs_dir.glob("run-*.json"))

    def test_cancelled_token_blocks_run_and_saves_nothing(self, tmp_path):
        from tests.test_probe_runs_e2e import (
            StubDetector,
            _build_corpus,
            _make_stub_primitives,
        )

        manifest, texts, holdback = _build_corpus()
        token = CancellationToken()
        token.cancel()
        runs_dir = tmp_path / "runs"
        with pytest.raises(ExecutionCancelled):
            perform_probe_run(
                manifest=manifest,
                texts=texts,
                holdback_loader=lambda: holdback,
                detector=StubDetector(),
                scope="full",
                runs_dir=runs_dir,
                primitives=_make_stub_primitives(),
                cancellation=token,
            )
        assert not list(runs_dir.glob("run-*.json"))


def _stub_detector():
    from tests.test_probe_runs_e2e import StubDetector

    return StubDetector()
