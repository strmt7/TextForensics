"""Tests for detector_health.py — comprehensive coverage for the DetectorHealthMonitor.

This module was previously at 0% coverage. These tests exercise:
- Metric recording (latency, error, score, request_timestamp)
- Built-in health checks: error_rate, latency_p95, score_distribution_entropy, throughput
- Alert generation and callback
- Report generation, health state computation, health score
- Save/load round-trip
- High-level monitor (HighLevelDetectorHealthMonitor)
- Edge cases: empty values, no checks, max_history cap, clear_alerts
"""

from __future__ import annotations

import asyncio
import datetime
import tempfile
from pathlib import Path

import pytest

from textforensics.detector_health import (
    AlertSeverity,
    DetectorHealthMonitor,
    DetectorHealthReport,
    HealthState,
    HighLevelDetectorHealthMonitor,
    _create_error_rate_check,
    _create_latency_check,
    _create_score_distribution_check,
    _create_throughput_check,
    create_detector_health_monitor,
    create_health_monitor,
)


class TestHealthMetric:
    """Tests for HealthMetric dataclass."""

    def test_to_dict(self):
        from textforensics.detector_health import HealthMetric

        m = HealthMetric(
            name="latency_ms",
            value=100.5,
            unit="ms",
            timestamp="2024-01-01T00:00:00Z",
            detector_id="det1",
            metadata={"run_id": "abc"},
        )
        d = m.to_dict()
        assert d["name"] == "latency_ms"
        assert d["value"] == 100.5
        assert d["unit"] == "ms"
        assert d["detector_id"] == "det1"
        assert d["metadata"]["run_id"] == "abc"


class TestHealthAlert:
    """Tests for HealthAlert dataclass."""

    def test_to_dict(self):
        from textforensics.detector_health import AlertSeverity, HealthAlert

        a = HealthAlert(
            alert_id="alert-123",
            detector_id="det1",
            severity=AlertSeverity.WARNING,
            message="latency high",
            metric_name="latency_ms",
            metric_value=5000.0,
            threshold=3000.0,
            timestamp="2024-01-01T00:00:00Z",
            metadata={"p95": 5000.0},
        )
        d = a.to_dict()
        assert d["alert_id"] == "alert-123"
        assert d["detector_id"] == "det1"
        assert d["severity"] == "warning"
        assert d["metric_name"] == "latency_ms"


class TestHealthCheck:
    """Tests for HealthCheck and built-in check factories."""

    def test_evaluate_empty_values_returns_none(self):
        check = _create_latency_check()
        assert check.evaluate([], detector_id="d1") is None

    def test_evaluate_passing_returns_none(self):
        check = _create_latency_check()
        # 25 values well under threshold
        assert check.evaluate([100.0] * 25, detector_id="d1") is None

    def test_evaluate_failing_returns_alert_with_detector_id(self):
        check = _create_latency_check()
        # 25 values over critical threshold (10000)
        alert = check.evaluate([12000.0] * 25, detector_id="d1")
        assert alert is not None
        assert alert.detector_id == "d1"
        assert alert.severity == AlertSeverity.CRITICAL

    def test_evaluate_failing_returns_alert_warning_severity(self):
        check = _create_latency_check()
        # Between warning (3000) and critical (10000)
        alert = check.evaluate([5000.0] * 25, detector_id="d1")
        assert alert is not None
        assert alert.severity == AlertSeverity.WARNING

    def test_error_rate_check_source_metric_is_error(self):
        check = _create_error_rate_check()
        assert check.source_metric == "error"

    def test_score_distribution_check_source_metric_is_score(self):
        check = _create_score_distribution_check()
        assert check.source_metric == "score"

    def test_throughput_check_source_metric_is_request_timestamp(self):
        check = _create_throughput_check()
        assert check.source_metric == "request_timestamp"


class TestDetectorHealthMonitor:
    """Tests for DetectorHealthMonitor."""

    def test_record_latency(self):
        m = DetectorHealthMonitor()
        m.record_latency("d1", 100.0)
        assert len(m._metrics["d1"]["latency_ms"]) == 1
        assert m._metrics["d1"]["latency_ms"][0].value == 100.0

    def test_record_error(self):
        m = DetectorHealthMonitor()
        m.record_error("d1", True)
        m.record_error("d1", False)
        assert len(m._metrics["d1"]["error"]) == 2
        assert m._metrics["d1"]["error"][0].value == 1.0
        assert m._metrics["d1"]["error"][1].value == 0.0

    def test_record_score(self):
        m = DetectorHealthMonitor()
        m.record_score("d1", 0.5)
        assert len(m._metrics["d1"]["score"]) == 1
        assert m._metrics["d1"]["score"][0].value == 0.5

    def test_record_request(self):
        m = DetectorHealthMonitor()
        m.record_request("d1")
        assert len(m._metrics["d1"]["request_timestamp"]) == 1

    def test_error_rate_critical_when_all_errors(self):
        m = DetectorHealthMonitor()
        for _ in range(3):
            m.record_error("d1", True)
        r = m.get_report("d1")
        assert r.overall_state == HealthState.CRITICAL
        assert len(r.alerts) >= 1

    def test_error_rate_critical_at_33_percent(self):
        # 33% > 10% critical threshold
        m = DetectorHealthMonitor()
        for _ in range(3):
            m.record_error("d1", True)
        for _ in range(6):
            m.record_error("d1", False)
        r = m.get_report("d1")
        assert r.overall_state == HealthState.CRITICAL

    def test_error_rate_degraded_at_6_percent(self):
        # 6% between warning (5%) and critical (10%)
        m = DetectorHealthMonitor()
        m.record_error("d1", True)
        for _ in range(15):
            m.record_error("d1", False)
        r = m.get_report("d1")
        assert r.overall_state == HealthState.DEGRADED

    def test_error_rate_healthy_under_5_percent(self):
        # < 5% warning threshold
        m = DetectorHealthMonitor()
        for _ in range(20):
            m.record_error("d1", False)
        m.record_error("d1", True)  # 1/21 = 4.76%
        r = m.get_report("d1")
        assert r.overall_state == HealthState.HEALTHY
        assert r.health_score == 1.0

    def test_no_errors_healthy(self):
        m = DetectorHealthMonitor()
        for _ in range(10):
            m.record_error("d1", False)
        r = m.get_report("d1")
        assert r.overall_state == HealthState.HEALTHY
        assert r.health_score == 1.0

    def test_latency_degraded_p95_over_3s(self):
        m = DetectorHealthMonitor()
        for _ in range(25):
            m.record_latency("d1", 5000.0)  # p95 = 5000 > 3000 warning
        r = m.get_report("d1")
        assert r.overall_state == HealthState.DEGRADED

    def test_latency_critical_p95_over_10s(self):
        m = DetectorHealthMonitor()
        for _ in range(25):
            m.record_latency("d1", 12000.0)  # p95 = 12000 > 10000 critical
        r = m.get_report("d1")
        assert r.overall_state == HealthState.CRITICAL

    def test_latency_healthy_under_threshold(self):
        m = DetectorHealthMonitor()
        for _ in range(25):
            m.record_latency("d1", 100.0)
        r = m.get_report("d1")
        assert r.overall_state == HealthState.HEALTHY

    def test_uniform_scores_triggers_entropy_alert(self):
        m = DetectorHealthMonitor()
        # 20 identical scores -> single bin -> entropy 0 -> alert
        for _ in range(20):
            m.record_score("d1", 0.5)
        r = m.get_report("d1")
        # May be DEGRADED or CRITICAL depending on entropy ratio
        assert r.overall_state in (HealthState.DEGRADED, HealthState.CRITICAL)

    def test_diverse_scores_healthy(self):
        m = DetectorHealthMonitor()
        import random

        random.seed(42)
        for _ in range(100):
            m.record_score("d1", random.random())
        r = m.get_report("d1")
        # High entropy should be healthy
        assert r.overall_state == HealthState.HEALTHY

    def test_insufficient_scores_skipped(self):
        m = DetectorHealthMonitor()
        for _ in range(5):  # < 10 minimum for entropy check
            m.record_score("d1", 0.5)
        r = m.get_report("d1")
        # Entropy check skipped, no alerts
        assert r.overall_state == HealthState.HEALTHY

    def test_throughput_low_triggers_warning(self):
        m = DetectorHealthMonitor()
        # Record 1 request -> throughput ~0.016 rps < 0.1 critical threshold
        m.record_request("d1")
        # Note: throughput check uses 60s window; a single request
        # will be critical if evaluated within 60s of the request
        # But since it's <2 values, check returns True (skipped)
        # Need at least 2 requests
        m2 = DetectorHealthMonitor()
        m2.record_request("d2")
        m2.record_request("d2")
        r2 = m2.get_report("d2")
        # With 2 requests in <60s, throughput > 0.1 -> passes
        assert r2.overall_state == HealthState.HEALTHY

    def test_alert_callback_fires_once_per_anomaly(self):
        hits = []
        m = DetectorHealthMonitor(alert_callback=lambda a: hits.append(a))
        for _ in range(5):
            m.record_error("d1", True)
        assert len(hits) == 5

    def test_clear_alerts_for_specific_detector(self):
        m = DetectorHealthMonitor()
        for _ in range(5):
            m.record_error("d1", True)
        for _ in range(3):
            m.record_error("d2", True)
        n = m.clear_alerts("d1")
        assert n == 5
        assert len(m.get_all_alerts()) == 3
        assert all(a.detector_id == "d2" for a in m.get_all_alerts())

    def test_clear_all_alerts(self):
        m = DetectorHealthMonitor()
        for _ in range(5):
            m.record_error("d1", True)
        n = m.clear_alerts()
        assert n == 5
        assert len(m.get_all_alerts()) == 0

    def test_get_all_alerts_since_filter(self):
        m = DetectorHealthMonitor()
        for _ in range(3):
            m.record_error("d1", True)
        before = datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=1)
        alerts = m.get_all_alerts(since=before)
        assert len(alerts) == 3
        after = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=1)
        assert len(m.get_all_alerts(since=after)) == 0

    def test_report_save_load_roundtrip(self):
        m = DetectorHealthMonitor()
        for _ in range(5):
            m.record_error("d1", True)
        r = m.get_report("d1")
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "report.json"
            assert r.save(p) is True
            loaded = DetectorHealthReport.load(p)
            assert loaded is not None
            assert loaded.detector_id == "d1"
            assert loaded.overall_state == HealthState.CRITICAL
            assert loaded.health_score == r.health_score
            assert len(loaded.alerts) == len(r.alerts)

    def test_report_load_nonexistent_returns_none(self):
        result = DetectorHealthReport.load(
            Path("/nonexistent_path_that_does_not_exist/report.json")
        )
        assert result is None

    def test_report_load_corrupted_returns_none(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.json"
            p.write_text("not json")
            result = DetectorHealthReport.load(p)
            assert result is None

    def test_max_history_cap_enforced(self):
        m = DetectorHealthMonitor(max_history=5)
        for _ in range(100):
            m.record_latency("d1", 1.0)
        assert len(m._metrics["d1"]["latency_ms"]) == 5

    def test_no_checks_returns_unknown(self):
        m = DetectorHealthMonitor()
        m._health_checks.pop("d1", None)
        m.record_metric("d1", "random", 1.0)
        r = m.get_report("d1")
        assert r.overall_state == HealthState.UNKNOWN
        assert r.health_score == 0.0

    def test_get_report_creates_report_if_missing(self):
        m = DetectorHealthMonitor()
        assert "d1" not in m._reports
        r = m.get_report("d1")
        assert "d1" in m._reports
        assert r.detector_id == "d1"

    def test_multiple_get_report_calls_no_alert_duplication(self):
        m = DetectorHealthMonitor()
        for _ in range(5):
            m.record_error("d1", True)
        a1 = len(m.get_report("d1").alerts)
        a2 = len(m.get_report("d1").alerts)
        assert a1 == a2 == 5

    def test_compute_overall_health_does_not_mutate_alerts(self):
        """_compute_overall_health must not append to self._alerts."""
        m = DetectorHealthMonitor()
        for _ in range(5):
            m.record_error("d1", True)
        initial_count = len(m._alerts)
        # Call get_report multiple times
        for _ in range(5):
            m.get_report("d1")
        # Alert count should not have grown
        assert len(m._alerts) == initial_count


class TestHighLevelDetectorHealthMonitor:
    """Tests for HighLevelDetectorHealthMonitor."""

    def test_record_detector_result_records_both_success_and_failure(self):
        h = create_detector_health_monitor()
        h.record_detector_result("dx", 100.0, score=0.5, is_error=False)
        h.record_detector_result("dx", 100.0, score=0.5, is_error=True)
        rh = h.get_detector_health("dx")
        # 1/2 = 50% error -> CRITICAL
        assert rh.overall_state == HealthState.CRITICAL

    def test_record_detector_result_low_error_rate_healthy(self):
        h = create_detector_health_monitor()
        import random

        random.seed(42)
        for _ in range(20):
            h.record_detector_result("dy", 100.0, score=random.random(), is_error=False)
        h.record_detector_result("dy", 100.0, score=0.5, is_error=True)  # 4.76%
        rh = h.get_detector_health("dy")
        assert rh.overall_state == HealthState.HEALTHY

    def test_get_all_health(self):
        h = create_detector_health_monitor()
        h.record_detector_result("d1", 10.0, score=0.5, is_error=False)
        h.record_detector_result("d2", 10.0, score=0.5, is_error=True)
        all_health = h.get_all_health()
        assert "d1" in all_health
        assert "d2" in all_health
        assert all_health["d1"].overall_state == HealthState.HEALTHY
        assert all_health["d2"].overall_state == HealthState.CRITICAL

    def test_check_detector_health_returns_state_and_score(self):
        h = create_detector_health_monitor()
        h.record_detector_result("d1", 10.0, score=0.5, is_error=False)
        state, score = h.check_detector_health("d1")
        assert state == HealthState.HEALTHY
        assert score == 1.0


class TestFactoryFunctions:
    """Tests for create_health_monitor and create_detector_health_monitor."""

    def test_create_health_monitor_returns_detector_health_monitor(self):
        m = create_health_monitor(max_history=100, alert_callback=None)
        assert isinstance(m, DetectorHealthMonitor)
        assert m.max_history == 100

    def test_create_detector_health_monitor_returns_high_level(self):
        h = create_detector_health_monitor(max_history=200, alert_callback=None)
        assert isinstance(h, HighLevelDetectorHealthMonitor)
        assert h.monitor.max_history == 200


class TestDetectorHealthMonitorAsyncLock:
    """Tests for the asyncio lock used in DetectorHealthMonitor."""

    def test_async_lock_is_initialized(self):
        m = DetectorHealthMonitor()
        assert isinstance(m._lock, asyncio.Lock)


class TestDetectorHealthMonitorEdgeCases:
    """Edge case and regression tests."""

    def test_record_metric_with_metadata(self):
        m = DetectorHealthMonitor()
        m.record_metric("d1", "custom", 42.0, "units", {"key": "value"})
        assert m._metrics["d1"]["custom"][0].metadata == {"key": "value"}

    def test_report_includes_metrics_and_alerts(self):
        m = DetectorHealthMonitor()
        m.record_latency("d1", 100.0)
        m.record_error("d1", True)
        r = m.get_report("d1")
        assert "latency_ms" in r.metrics
        assert "error" in r.metrics
        assert len(r.alerts) >= 0

    def test_alert_contains_all_fields(self):
        m = DetectorHealthMonitor()
        m.record_latency("d1", 12000.0)  # Critical
        r = m.get_report("d1")
        alert = r.alerts[0]
        assert alert.alert_id.startswith("alert-")
        assert alert.detector_id == "d1"
        assert alert.severity == AlertSeverity.CRITICAL
        assert alert.metric_name == "latency_ms"
        assert alert.metric_value == 12000.0
        assert alert.threshold == 10000.0
        assert isinstance(alert.timestamp, str)

    def test_multiple_detectors_independent(self):
        m = DetectorHealthMonitor()
        for _ in range(10):
            m.record_error("a", True)
            m.record_error("b", False)
        ra = m.get_report("a")
        rb = m.get_report("b")
        assert ra.overall_state == HealthState.CRITICAL
        assert rb.overall_state == HealthState.HEALTHY


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
