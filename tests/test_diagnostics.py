"""Tests for Diagnostics Engine."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from textforensics.diagnostics import (
    MetricsCollector,
    MetricsSnapshot,
    OperationalIndicators,
    ReadinessAssessor,
    ReadinessState,
    StorageHealth,
    create_diagnostics_engine,
)


class TestMetricsSnapshot:
    def test_snapshot_creation(self):
        snapshot = MetricsSnapshot()
        assert snapshot.schema_version == 3
        assert snapshot.service_name == "textforensics"

    def test_add_metric(self):
        snapshot = MetricsSnapshot()
        snapshot.add_metric("cpu_percent", 50.0)
        snapshot.add_metric("memory_percent", 60.0, {"type": "ram"})
        assert "cpu_percent" in snapshot.metrics
        assert snapshot.metrics["cpu_percent"] == 50.0

    def test_to_dict(self):
        snapshot = MetricsSnapshot()
        snapshot.add_metric("cpu_percent", 50.0)
        d = snapshot.to_dict()
        assert d["schema_version"] == 3
        assert d["service_name"] == "textforensics"
        assert "cpu_percent" in d["metrics"]

    def test_prometheus_format(self):
        snapshot = MetricsSnapshot()
        snapshot.add_metric("cpu_percent", 50.0)
        prom = snapshot.to_prometheus_format()
        assert "cpu_percent" in prom


class TestReadinessState:
    def test_state_values(self):
        assert ReadinessState.HEALTHY.value == "healthy"
        assert ReadinessState.DEGRADED.value == "degraded"
        assert ReadinessState.CRITICAL.value == "critical"
        assert ReadinessState.EMERGENCY_STOP.value == "emergency_stop"
        assert ReadinessState.MAINTENANCE.value == "maintenance"


class TestReadinessAssessor:
    def test_empty_checks(self):
        assessor = ReadinessAssessor()
        state, results = assessor.assess()
        assert state == ReadinessState.HEALTHY
        assert results == []

    def test_passing_check(self):
        assessor = ReadinessAssessor()
        assessor.register_check("test", lambda: (True, "ok"))
        state, results = assessor.assess()
        assert state == ReadinessState.HEALTHY
        assert len(results) == 1
        assert results[0]["passed"] is True

    def test_failing_check(self):
        assessor = ReadinessAssessor()
        assessor.register_check("test", lambda: (False, "failed"))
        state, results = assessor.assess()
        assert state == ReadinessState.CRITICAL  # All failed checks are now critical
        assert results[0]["passed"] is False

    def test_mixed_checks(self):
        assessor = ReadinessAssessor()
        assessor.register_check("pass", lambda: (True, "ok"))
        assessor.register_check("fail", lambda: (False, "error"))
        state, results = assessor.assess()
        assert state == ReadinessState.CRITICAL  # Mixed checks with failure = CRITICAL
        assert len(results) == 2

    def test_exception_in_check(self):
        assessor = ReadinessAssessor()
        assessor.register_check("error", lambda: (_ for _ in ()).throw(ValueError("error")))
        state, results = assessor.assess()
        assert state == ReadinessState.CRITICAL
        assert results[0]["passed"] is False
        assert "exception" in results[0]["message"].lower()


class TestOperationalIndicators:
    def test_defaults(self):
        indicators = OperationalIndicators()
        assert indicators.database_connected is False
        assert indicators.storage_writeable is False
        assert indicators.detectors_available == 0
        assert indicators.error_rate == 0.0

    def test_to_dict(self):
        indicators = OperationalIndicators(
            database_connected=True,
            cpu_percent=50.0,
            memory_percent=60.0,
        )
        d = indicators.to_dict()
        assert d["database_connected"] is True
        assert d["cpu_percent"] == 50.0


class TestStorageHealth:
    def test_storage_health_creation(self):
        health = StorageHealth(
            path="/data",
            total_bytes=1000,
            free_bytes=500,
            used_bytes=500,
            percent_used=50.0,
            writeable=True,
        )
        assert health.total_bytes == 1000
        assert health.free_gb == 500 / (1024**3)

    def test_to_dict(self):
        health = StorageHealth(
            path="/data",
            total_bytes=1000,
            free_bytes=500,
            used_bytes=500,
            percent_used=50.0,
            writeable=True,
        )
        d = health.to_dict()
        assert d["path"] == "/data"
        assert d["free_gb"] == 500 / (1024**3)


class TestMetricsCollector:
    def test_record_latency(self):
        collector = MetricsCollector()
        collector.record_latency(100.0)
        collector.record_latency(200.0)
        assert len(collector._latencies) == 2

    def test_record_error(self):
        collector = MetricsCollector()
        collector.record_error()
        collector.record_error()
        assert len(collector._errors) == 2

    def test_record_request(self):
        collector = MetricsCollector()
        collector.record_request()
        collector.record_request()
        collector.record_request()
        assert len(collector._requests) == 3

    def test_percentile(self):
        collector = MetricsCollector()
        for v in [10, 20, 30, 40, 50]:
            collector.record_latency(float(v))
        assert collector.get_percentile(50) == 30.0
        assert collector.get_percentile(0) == 10.0
        assert collector.get_percentile(100) == 50.0

    def test_get_stats(self):
        collector = MetricsCollector()
        collector.record_latency(100.0)
        collector.record_latency(200.0)
        collector.record_request()
        collector.record_request()
        collector.record_error()

        stats = collector.get_stats()
        assert stats["avg_latency_ms"] == 150.0
        assert (
            stats["p50_latency_ms"] == 200.0
        )  # p50 with 2 values [100, 200] using nearest-rank = 200
        assert stats["total_requests"] == 2
        assert stats["total_errors"] == 1
        assert stats["error_rate"] == 0.5

    def test_trim_old(self):
        collector = MetricsCollector(window_seconds=1)
        collector.record_latency(100.0)
        import time

        time.sleep(1.1)  # Wait for window to expire
        collector.record_latency(200.0)
        collector._trim_old()
        assert len(collector._latencies) == 1
        assert collector._latencies[0][1] == 200.0


class TestDiagnosticsEngine:
    def test_engine_creation(self):
        engine = create_diagnostics_engine()
        assert engine is not None
        assert engine.metrics_collector is not None
        assert engine.readiness_assessor is not None

    def test_disk_space_check(self):
        engine = create_diagnostics_engine(storage_paths=[Path.cwd()])
        passed, msg = engine._check_disk_space()
        # On some systems disk might be low, so we just check that the function runs
        assert isinstance(passed, bool)
        assert "disk space" in msg.lower()

    def test_memory_check(self):
        engine = create_diagnostics_engine()
        passed, msg = engine._check_memory()
        assert passed is True
        assert "memory" in msg.lower()

    def test_record_latency(self):
        engine = create_diagnostics_engine()
        engine.record_latency(100.0)
        engine.record_latency(200.0)
        stats = engine.metrics_collector.get_stats()
        assert stats["avg_latency_ms"] == 150.0

    def test_record_error(self):
        engine = create_diagnostics_engine()
        engine.record_error()
        engine.record_error()
        assert len(engine.metrics_collector._errors) == 2

    def test_record_request(self):
        engine = create_diagnostics_engine()
        engine.record_request()
        engine.record_request()
        engine.record_request()
        assert len(engine.metrics_collector._requests) == 3

    def test_operational_indicators(self):
        engine = create_diagnostics_engine()
        indicators = engine.get_operational_indicators()
        assert isinstance(indicators, OperationalIndicators)
        assert isinstance(indicators.cpu_percent, float)
        assert isinstance(indicators.memory_percent, float)

    def test_storage_health(self):
        engine = create_diagnostics_engine(storage_paths=[Path.cwd()])
        health = engine.get_storage_health()
        assert len(health) >= 1
        for h in health:
            assert isinstance(h, StorageHealth)
            assert h.path
            # On some systems total_bytes might be 0 for certain paths
            assert h.total_bytes >= 0
            assert h.free_bytes >= 0
            assert h.used_bytes >= 0

    def test_metrics_snapshot(self):
        engine = create_diagnostics_engine()
        snapshot = engine.get_metrics_snapshot()
        assert isinstance(snapshot, MetricsSnapshot)
        assert snapshot.schema_version == 3
        assert snapshot.service_name == "textforensics"

    def test_prometheus_format(self):
        engine = create_diagnostics_engine()
        prom = engine.get_metrics_prometheus()
        assert isinstance(prom, str)
        assert len(prom) > 0

    def test_run_diagnostics(self):
        engine = create_diagnostics_engine(storage_paths=[Path.cwd()])
        report = engine.run_diagnostics()

        assert "report_version" in report
        assert "generated_at" in report
        assert "privacy" in report
        assert report["privacy"]["contains_input_text"] is False
        assert "readiness" in report
        assert "operational" in report
        assert "storage" in report
        assert "metrics" in report
        assert "system" in report

    def test_readiness_assessment(self):
        engine = create_diagnostics_engine(storage_paths=[Path.cwd()])
        report = engine.run_diagnostics()
        readiness = report["readiness"]
        assert "state" in readiness
        assert "checks" in readiness
        assert readiness["state"] in [
            "healthy",
            "degraded",
            "critical",
            "emergency_stop",
            "maintenance",
        ]

    def test_storage_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            engine = create_diagnostics_engine(storage_paths=[path])
            health = engine.get_storage_health()
            assert len(health) == 1
            assert health[0].path == str(Path(tmp).resolve())

    def test_metrics_prometheus_format(self):
        engine = create_diagnostics_engine()
        prom = engine.get_metrics_prometheus()
        lines = prom.strip().split("\n")
        assert len(lines) > 0


class TestQuickHealthCheck:
    @pytest.mark.asyncio
    async def test_quick_health_check(self):
        from textforensics.diagnostics import quick_health_check

        report = await quick_health_check()
        assert "readiness" in report
        assert "operational" in report


class TestMetricsSnapshotSerialization:
    def test_snapshot_serialization(self):
        snapshot = MetricsSnapshot()
        snapshot.add_metric("cpu", 50.0)
        snapshot.add_metric("mem", 60.0, {"type": "ram"})
        d = snapshot.to_dict()
        assert d["metrics"]["cpu"] == 50.0
        assert any(k.startswith("mem") for k in d["metrics"])

    def test_prometheus_output(self):
        snapshot = MetricsSnapshot()
        snapshot.add_metric("cpu_percent", 50.0)
        prom = snapshot.to_prometheus_format()
        assert "cpu_percent" in prom
        assert "50.0" in prom


class TestReadinessAssessorEdgeCases:
    def test_no_checks(self):
        assessor = ReadinessAssessor()
        state, results = assessor.assess()
        assert state == ReadinessState.HEALTHY
        assert results == []

    def test_exception_in_check_returns_critical(self):
        assessor = ReadinessAssessor()
        assessor.register_check("error", lambda: (_ for _ in ()).throw(ValueError("boom")))
        state, results = assessor.assess()
        assert state == ReadinessState.CRITICAL
        assert len(results) == 1
        assert results[0]["passed"] is False
        assert "exception" in results[0]["message"].lower()


class TestMetricsCollectorEdgeCases:
    def test_empty_stats(self):
        collector = MetricsCollector()
        stats = collector.get_stats()
        assert stats["avg_latency_ms"] == 0.0
        assert stats["p50_latency_ms"] == 0.0
        assert stats["total_requests"] == 0
        assert stats["total_errors"] == 0
        assert stats["error_rate"] == 0.0

    def test_percentile_empty(self):
        collector = MetricsCollector()
        assert collector.get_percentile(50) == 0.0
        assert collector.get_percentile(95) == 0.0
        assert collector.get_percentile(99) == 0.0


class TestStorageHealthEdgeCases:
    def test_zero_values(self):
        health = StorageHealth(
            path="/",
            total_bytes=0,
            free_bytes=0,
            used_bytes=0,
            percent_used=0.0,
            writeable=False,
        )
        assert health.total_bytes == 0
        assert health.free_gb == 0.0
        assert health.used_gb == 0.0
        assert health.total_gb == 0.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
