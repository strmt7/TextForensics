"""W5 Worker C regression tests: IF-17 (diagnostics placeholders).

Red-first tests, written from the audit's regression acceptance before
the source fix:

- A deliberately unavailable dependency must NOT produce a
  connected/writable claim.
- Optional failure degrades while critical failure is critical, and
  the declared criticality is retained in the check records.
- Custom version/service round-trip unchanged (``audit-version`` must
  not serialize as ``0.1.0``); the default version comes from build
  info, not a hardcoded placeholder.
- Metrics parse with a real exposition parser (prometheus_client,
  where installed) using quotes, backslashes, newlines, and multiple
  label sets; TYPE declarations carry no labels and appear once per
  family. Structural assertions also run without the parser so the
  fix is guarded in minimal environments.

S17 thresholds (latency p95 < 3000, entropy > 0.5, throughput
>= 0.5 rps) are audit contracts and are NOT touched here.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from textforensics._build_info import get_version
from textforensics.diagnostics import (
    DiagnosticsEngine,
    MetricsSnapshot,
    ReadinessAssessor,
    ReadinessState,
    create_diagnostics_engine,
)


class TestDefaultChecksAreNotPlaceholders:
    def test_default_database_check_does_not_claim_connected(self):
        engine = create_diagnostics_engine()
        state, results = engine.readiness_assessor.assess()
        db = next(r for r in results if r["name"] == "database")
        assert db["passed"] is False
        assert "connected" not in db["message"].lower()
        assert "not configured" in db["message"].lower()

    def test_default_database_failure_is_not_critical(self):
        # No database is configured: the explicit not-configured state
        # degrades readiness, it must not report critical.
        engine = create_diagnostics_engine()
        state, _ = engine.readiness_assessor.assess()
        assert state == ReadinessState.DEGRADED

    def test_unavailable_database_check_never_claims_connected(self):
        engine = create_diagnostics_engine(
            database_check=lambda: (False, "connection refused: synthetic unavailable DB")
        )
        state, results = engine.readiness_assessor.assess()
        db = next(r for r in results if r["name"] == "database")
        assert db["passed"] is False
        assert "connected" not in db["message"].lower()
        assert state == ReadinessState.DEGRADED

    def test_unavailable_storage_check_never_claims_writable(self):
        engine = create_diagnostics_engine(
            storage_check=lambda: (False, "storage probe failed: synthetic unavailable disk")
        )
        state, results = engine.readiness_assessor.assess()
        storage = next(r for r in results if r["name"] == "storage")
        assert storage["passed"] is False
        assert "writable" not in storage["message"].lower()

    def test_default_storage_check_probes_real_writability(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = create_diagnostics_engine(storage_paths=[Path(tmp)])
            state, results = engine.readiness_assessor.assess()
            storage = next(r for r in results if r["name"] == "storage")
            assert storage["passed"] is True
            assert "writable" in storage["message"].lower()

    def test_storage_check_on_missing_path_fails(self):
        engine = create_diagnostics_engine(
            storage_paths=[Path("/nonexistent-textforensics-probe-path-xyz")]
        )
        _, results = engine.readiness_assessor.assess()
        storage = next(r for r in results if r["name"] == "storage")
        assert storage["passed"] is False
        # The failure must be stated as NOT writable — never as a
        # writable claim.
        assert "not writable" in storage["message"].lower()

    def test_injected_passing_checks_report_real_state(self):
        engine = create_diagnostics_engine(
            database_check=lambda: (True, "Database connected: synthetic probe ok"),
            storage_check=lambda: (True, "Storage writable: synthetic probe ok"),
        )
        _, results = engine.readiness_assessor.assess()
        # Overall state also depends on host disk/memory, which the
        # test does not control, so assert the injected records.
        db = next(r for r in results if r["name"] == "database")
        storage = next(r for r in results if r["name"] == "storage")
        assert db["passed"] is True
        assert "connected" in db["message"].lower()
        assert storage["passed"] is True
        assert "writable" in storage["message"].lower()

    def test_operational_indicators_do_not_claim_unchecked_resources(self):
        engine = create_diagnostics_engine()
        indicators = engine.get_operational_indicators()
        # No database is configured, so no connected claim may appear.
        assert indicators.database_connected is False
        # Storage writability follows the real probe of the configured paths.
        assert indicators.storage_writeable is True


class TestReadinessCriticalityRetained:
    def test_optional_failure_degrades_not_critical(self):
        assessor = ReadinessAssessor()
        assessor.register_check("optional", lambda: (False, "optional fault"), critical=False)
        state, results = assessor.assess()
        assert state == ReadinessState.DEGRADED
        assert results[0]["critical"] is False
        assert results[0]["passed"] is False

    def test_critical_failure_is_critical(self):
        assessor = ReadinessAssessor()
        assessor.register_check("critical", lambda: (False, "critical fault"), critical=True)
        state, results = assessor.assess()
        assert state == ReadinessState.CRITICAL
        assert results[0]["critical"] is True

    def test_optional_failure_plus_critical_pass_is_degraded(self):
        assessor = ReadinessAssessor()
        assessor.register_check("opt", lambda: (False, "optional fault"), critical=False)
        assessor.register_check("crit", lambda: (True, "ok"), critical=True)
        state, results = assessor.assess()
        assert state == ReadinessState.DEGRADED
        assert {r["name"]: r["critical"] for r in results} == {"opt": False, "crit": True}

    def test_exception_in_optional_check_degrades(self):
        assessor = ReadinessAssessor()

        def _boom():
            raise ValueError("synthetic optional failure")

        assessor.register_check("opt", _boom, critical=False)
        state, results = assessor.assess()
        assert state == ReadinessState.DEGRADED
        assert results[0]["critical"] is False
        assert results[0]["passed"] is False

    def test_exception_in_critical_check_is_critical(self):
        assessor = ReadinessAssessor()

        def _boom():
            raise ValueError("synthetic critical failure")

        assessor.register_check("crit", _boom, critical=True)
        state, results = assessor.assess()
        assert state == ReadinessState.CRITICAL
        assert results[0]["critical"] is True


class TestVersionAndServiceRoundTrip:
    def test_custom_version_round_trips_unchanged(self):
        snapshot = MetricsSnapshot(
            service_name="audit-service", application_version="audit-version"
        )
        data = snapshot.to_dict()
        assert data["application_version"] == "audit-version"
        assert data["service_name"] == "audit-service"
        assert data["application_version"] != "0.1.0"

    def test_default_version_comes_from_build_info(self):
        snapshot = MetricsSnapshot()
        assert snapshot.application_version == get_version()
        assert snapshot.to_dict()["application_version"] == get_version()

    def test_engine_snapshot_uses_build_info_version(self):
        engine = create_diagnostics_engine()
        snapshot = engine.get_metrics_snapshot()
        assert snapshot.application_version == get_version()


class TestPrometheusExposition:
    LABELS_A = {"path": 'a"b\\c\nd', "env": "test"}
    LABELS_B = {"path": "plain", "env": "test"}

    def _snapshot(self):
        snapshot = MetricsSnapshot()
        snapshot.add_metric("test_metric", 1.5, self.LABELS_A)
        snapshot.add_metric("test_metric", 2.5, self.LABELS_B)
        snapshot.add_metric("plain_metric", 3.0)
        return snapshot

    def test_type_lines_carry_no_labels_and_appear_once_per_family(self):
        prom = self._snapshot().to_prometheus_format()
        type_lines = [line for line in prom.splitlines() if line.startswith("# TYPE")]
        assert type_lines == ["# TYPE test_metric gauge", "# TYPE plain_metric gauge"]
        for line in type_lines:
            assert "{" not in line

    def test_label_values_are_escaped_in_exposition(self):
        prom = self._snapshot().to_prometheus_format()
        # Backslash, quote and newline inside a label value must be
        # escaped at source; no literal newline may appear inside a
        # label (every line must parse as one sample).
        assert 'a\\"b\\\\c\\nd' in prom
        assert len(prom.splitlines()) == 5  # 2 TYPE lines + 3 samples

    def test_real_parser_round_trips_labels_and_values(self):
        parser = pytest.importorskip("prometheus_client.parser")
        prom = self._snapshot().to_prometheus_format()
        families = {f.name: f for f in parser.text_string_to_metric_families(prom)}
        assert set(families) == {"test_metric", "plain_metric"}
        samples = {
            (tuple(sorted(s.labels.items())), s.value) for s in families["test_metric"].samples
        }
        assert samples == {
            ((("env", "test"), ("path", 'a"b\\c\nd')), 1.5),
            ((("env", "test"), ("path", "plain")), 2.5),
        }
        assert [(s.value) for s in families["plain_metric"].samples] == [3.0]

    def test_real_parser_rejects_label_newline_in_old_format(self):
        # Guard the audit's exact defect: a literal newline inside a
        # label value is not valid exposition.
        parser = pytest.importorskip("prometheus_client.parser")
        broken = '# TYPE test_metric{label="a\nb"} gauge\ntest_metric{label="a\nb"} 1.0\n'
        with pytest.raises(Exception):
            list(parser.text_string_to_metric_families(broken))

    def test_invalid_metric_name_is_rejected(self):
        snapshot = MetricsSnapshot()
        with pytest.raises(ValueError):
            snapshot.add_metric("bad name!", 1.0)

    def test_invalid_label_name_is_rejected(self):
        snapshot = MetricsSnapshot()
        with pytest.raises(ValueError):
            snapshot.add_metric("ok_metric", 1.0, {"bad label": "v"})


class TestDiagnosticsEngineInit:
    def test_engine_accepts_injected_checks(self):
        engine = DiagnosticsEngine(
            database_check=lambda: (True, "ok"),
            storage_check=lambda: (True, "ok"),
        )
        _, results = engine.readiness_assessor.assess()
        # Overall state also depends on host disk/memory; assert the
        # injected records rather than the host-dependent total.
        assert next(r for r in results if r["name"] == "database")["passed"] is True
        assert next(r for r in results if r["name"] == "storage")["passed"] is True
