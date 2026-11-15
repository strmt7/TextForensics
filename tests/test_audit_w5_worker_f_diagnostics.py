"""W5 Worker F kill tests for diagnostics (audit-w5-f).

Kill evidence for the 23 runtime survivors in textforensics.diagnostics:

* ``MetricsSnapshot._check_name`` RemoveDecorator (line 233): calling
  the classmethod on the class must work; without the decorator the
  call raises TypeError (missing ``cls``).
* ``MetricsSnapshot._format_value`` Gt_LtE / Gt_NotEq (line 243):
  +Inf formats as "+Inf", -Inf as "-Inf".
* ``DiagnosticsEngine._register_default_checks`` ReplaceTrueWithFalse
  (lines 461, 466): the storage and disk-space checks are critical.
* ``_check_database`` / ``_check_storage`` ReplaceFalseWithTrue
  (lines 480, 492): an injected check that raises reports failure,
  not success.
* ``get_operational_indicators`` NumberReplacer / Div_* mutants
  (lines 564-581): the zero defaults and the memory conversion
  ``mem.available / (1024 * 1024)``. The stats-default mutants
  (avg_latency_ms / throughput_rps 0.0 -> -1.0) are killed with a
  collector returning no stats, so the ``.get`` defaults apply; the
  memory mutants are killed with available=1048577, which is not
  divisible by 1048576 (an exactly divisible value would let FloorDiv
  pass: ``8192 == 8192.0``).
"""

import math
from pathlib import Path
from types import SimpleNamespace

import pytest

import textforensics.diagnostics as diag
from textforensics.diagnostics import DiagnosticsEngine, MetricsSnapshot


def test_check_name_callable_on_class():
    """_check_name works when called on the class (classmethod)."""
    MetricsSnapshot._check_name("valid_metric", "metric")
    with pytest.raises(ValueError, match="Invalid Prometheus"):
        MetricsSnapshot._check_name("bad name!", "metric")


def test_format_value_infinities():
    """+Inf formats as '+Inf' and -Inf as '-Inf'."""
    assert MetricsSnapshot._format_value(math.inf) == "+Inf"
    assert MetricsSnapshot._format_value(-math.inf) == "-Inf"


def test_default_checks_storage_and_disk_space_are_critical(tmp_path: Path):
    """The registered storage and disk-space checks are critical."""
    engine = DiagnosticsEngine(storage_paths=[tmp_path])
    _, results = engine.readiness_assessor.assess()
    by_name = {r["name"]: r for r in results}
    assert by_name["storage"]["critical"] is True
    assert by_name["disk_space"]["critical"] is True


def _boom():
    raise RuntimeError("boom")


def test_database_check_exception_is_failure():
    """A database check that raises reports (False, ...), not True."""
    engine = DiagnosticsEngine(database_check=_boom)
    passed, message = engine._check_database()
    assert passed is False
    assert "boom" in message


def test_storage_check_exception_is_failure():
    """A storage check that raises reports (False, ...), not True."""
    engine = DiagnosticsEngine(storage_check=_boom)
    passed, message = engine._check_storage()
    assert passed is False
    assert "boom" in message


def test_operational_indicators_zero_defaults_and_memory_math(tmp_path: Path, monkeypatch):
    """Indicators report zero defaults and exact memory conversion."""
    monkeypatch.setattr(diag.psutil, "cpu_percent", lambda interval=None: 1.5)
    monkeypatch.setattr(
        diag.psutil,
        "virtual_memory",
        lambda: SimpleNamespace(available=1048577, percent=42.0),
    )
    monkeypatch.setattr(diag.psutil, "disk_usage", lambda path: SimpleNamespace(percent=55.0))
    engine = DiagnosticsEngine(storage_paths=[tmp_path])
    # No stats at all, so the .get(..., 0.0) defaults must apply.
    monkeypatch.setattr(engine.metrics_collector, "get_stats", lambda: {})
    ind = engine.get_operational_indicators()
    assert ind.detectors_available == 0
    assert ind.failed_pipelines == 0
    assert ind.calibrated_detectors == 0
    assert ind.uncalibrated_detectors == 0
    assert ind.active_alerts == 0
    assert ind.cache_hit_rate == 0.0
    assert ind.avg_latency_ms == 0.0
    assert ind.throughput_rps == 0.0
    assert ind.memory_available_mb == 1048577 / (1024 * 1024)
