"""OpenTelemetry metrics instrumentation for TextForensics.

This module provides optional OpenTelemetry metrics instrumentation.
The opentelemetry imports are lazy - they are only imported when
the telemetry is actually initialized, allowing the module to be
imported without opentelemetry being installed.
"""

from __future__ import annotations

import contextlib
import threading
import time
from typing import Any

# Global state for telemetry
_telemetry_initialized = False
_telemetry_lock = threading.Lock()
_meter_provider: Any = None
_meter: Any = None

# Metrics
_analyses_total: Any = None
_analysis_latency: Any = None
_verdicts_total: Any = None
_detector_scores: Any = None
_active_detectors: Any = None
_errors_total: Any = None

# Runtime state for gauges
_active_detector_count = 0
_active_detector_lock = threading.Lock()


def _import_opentelemetry():
    """Lazily import opentelemetry modules."""
    try:
        from opentelemetry import metrics
        from opentelemetry.exporter.prometheus import PrometheusMetricReader
        from opentelemetry.metrics import CallbackOptions, Observation
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import MetricExporter, MetricExportResult
        from opentelemetry.sdk.resources import SERVICE_NAME, Resource
    except ImportError as exc:
        raise RuntimeError(
            "opentelemetry is required for telemetry features. "
            "Install with: pip install textforensics[dev]"
        ) from exc

    return {
        "metrics": metrics,
        "PrometheusMetricReader": PrometheusMetricReader,
        "CallbackOptions": CallbackOptions,
        "Observation": Observation,
        "MeterProvider": MeterProvider,
        "MetricExporter": MetricExporter,
        "MetricExportResult": MetricExportResult,
        "SERVICE_NAME": SERVICE_NAME,
        "Resource": Resource,
    }


# Global state for telemetry
_telemetry_initialized = False
_telemetry_lock = threading.Lock()
_meter_provider: Any = None
_meter: Any = None

# Metrics
_analyses_total: Any = None
_analysis_latency: Any = None
_verdicts_total: Any = None
_detector_scores: Any = None
_active_detectors: Any = None
_errors_total: Any = None

# Runtime state for gauges
_active_detector_count = 0
_active_detector_lock = threading.Lock()


class _ConsoleExporter:
    """Simple console exporter for debugging that implements the MetricExporter interface."""

    def __init__(self) -> None:
        self._preferred_temporality = None
        self._preferred_aggregation = None

    def export(
        self,
        metrics_data: Any,
        timeout_millis: float = 30_000,
        **kwargs: Any,
    ) -> Any:
        # No-op for now, can be used for debugging
        from opentelemetry.sdk.metrics.export import MetricExportResult

        return MetricExportResult.SUCCESS

    def shutdown(self, timeout_millis: float = 30_000, **kwargs: Any) -> None:
        pass

    def force_flush(self, timeout_millis: float = 30_000) -> bool:
        return True


def initialize_telemetry(
    *,
    service_name: str = "textforensics",
    export_interval_millis: int = 10000,
    prometheus_port: int | None = None,
) -> bool:
    """Initialize OpenTelemetry metrics with Prometheus exporter.

    Args:
        service_name: Name of the service for resource attributes.
        export_interval_millis: Export interval for periodic exporting.
        prometheus_port: If provided, also start a Prometheus HTTP server on this port.
                        Note: opentelemetry-exporter-prometheus starts its own HTTP server.

    Returns:
        True if initialization succeeded, False if already initialized.
    """
    global _telemetry_initialized, _meter_provider, _meter
    global _analyses_total, _analysis_latency, _verdicts_total
    global _detector_scores, _active_detectors, _errors_total

    with _telemetry_lock:
        if _telemetry_initialized:
            return False

        # Lazy import opentelemetry
        otel = _import_opentelemetry()

        # Create readers
        readers = []

        # Prometheus reader (for Prometheus scraping)
        prometheus_reader = otel["PrometheusMetricReader"]()
        readers.append(prometheus_reader)

        # Create meter provider
        _meter_provider = otel["MeterProvider"](
            resource=otel["Resource"].create({otel["SERVICE_NAME"]: service_name}),
            metric_readers=[otel["PrometheusMetricReader"]()],
        )
        otel["metrics"].set_meter_provider(_meter_provider)

        # Get meter
        global _meter
        _meter = _meter_provider.get_meter("textforensics")

        # Create instruments
        global _analyses_total, _analysis_latency, _verdicts_total
        global _detector_scores, _active_detectors, _errors_total

        _analyses_total = _meter.create_counter(
            name="textforensics.analyses.total",
            description="Total number of text analyses performed",
            unit="1",
        )

        _analysis_latency = _meter.create_histogram(
            name="textforensics.analysis.latency",
            description="Latency of text analysis operations",
            unit="ms",
        )

        _verdicts_total = _meter.create_counter(
            name="textforensics.verdicts.total",
            description="Total number of verdicts by type",
            unit="1",
        )

        _detector_scores = _meter.create_histogram(
            name="textforensics.detector.scores",
            description="Detector scores distribution",
            unit="1",
        )

        _active_detectors = _meter.create_observable_gauge(
            name="textforensics.detectors.active",
            description="Number of active detectors",
            unit="1",
            callbacks=[_active_detectors_callback],
        )

        _errors_total = _meter.create_counter(
            name="textforensics.errors.total",
            description="Total number of errors by type",
            unit="1",
        )

        _telemetry_initialized = True

        # Register shutdown handler
        import atexit

        atexit.register(shutdown_telemetry)

        return True


def _active_detectors_callback(options) -> list:
    """Callback for active detectors gauge."""
    global _active_detector_count
    from opentelemetry.metrics import Observation

    with _active_detector_lock:
        return [Observation(_active_detector_count, {})]


def set_active_detectors(count: int) -> None:
    """Set the number of active detectors for the gauge."""
    global _active_detector_count
    with _active_detector_lock:
        _active_detector_count = max(0, count)


def increment_active_detectors(delta: int = 1) -> None:
    """Increment the active detectors count."""
    global _active_detector_count
    with _active_detector_lock:
        _active_detector_count = max(0, _active_detector_count + delta)


def record_analysis(
    *,
    latency_ms: float,
    verdict: str,
    detector_scores: list[float] | None = None,
    detector_names: list[str] | None = None,
) -> None:
    """Record metrics for a completed analysis.

    Args:
        latency_ms: Analysis latency in milliseconds.
        verdict: The verdict string (e.g., "machine_like_patterns", "human_like_patterns", "indeterminate", "insufficient_evidence").
        detector_scores: Optional list of detector scores.
        detector_names: Optional list of detector names corresponding to scores.
    """
    if not _telemetry_initialized:
        return

    # Record total analyses
    global _analyses_total
    if _analyses_total:
        _analyses_total.add(1)

    # Record latency
    global _analysis_latency
    if _analysis_latency:
        _analysis_latency.record(latency_ms)

    # Record verdict
    global _verdicts_total
    if _verdicts_total:
        verdict_normalized = verdict.lower().replace(" ", "_").replace("-", "_")
        _verdicts_total.add(1, {"verdict": verdict_normalized})

    # Record detector scores
    global _detector_scores
    if detector_scores and _detector_scores:
        for i, score in enumerate(detector_scores):
            attributes = {}
            if detector_names and i < len(detector_names):
                attributes["detector"] = detector_names[i]
            _detector_scores.record(score, attributes)


def record_error(error_type: str, component: str | None = None) -> None:
    """Record an error metric.

    Args:
        error_type: Type of error (e.g., "timeout", "validation_error", "detector_error").
        component: Optional component where error occurred.
    """
    if not _telemetry_initialized:
        return

    global _errors_total
    if _errors_total:
        attributes = {"error_type": error_type}
        if component:
            attributes["component"] = component
        _errors_total.add(1, attributes)


def is_telemetry_initialized() -> bool:
    """Check if telemetry has been initialized."""
    return _telemetry_initialized


def shutdown_telemetry() -> None:
    """Shutdown telemetry and flush metrics."""
    global _telemetry_initialized, _meter_provider

    with _telemetry_lock:
        if not _telemetry_initialized:
            return

        if _meter_provider:
            with contextlib.suppress(Exception):
                _meter_provider.shutdown()
            _meter_provider = None

        _telemetry_initialized = False


# Context manager for timing analysis
class AnalysisTimer:
    """Context manager for timing and recording analysis metrics."""

    def __init__(
        self,
        *,
        verdict: str | None = None,
        detector_scores: list[float] | None = None,
        detector_names: list[str] | None = None,
    ) -> None:
        self.verdict = verdict
        self.detector_scores = detector_scores
        self.detector_names = detector_names
        self.start_time: float | None = None
        self.end_time: float | None = None

    def __enter__(self) -> AnalysisTimer:
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.end_time = time.perf_counter()
        if self.start_time is not None:
            latency_ms = (self.end_time - self.start_time) * 1000
            verdict = self.verdict or "unknown"
            record_analysis(
                latency_ms=latency_ms,
                verdict=verdict,
                detector_scores=self.detector_scores,
                detector_names=self.detector_names,
            )
        if exc_type is not None:
            record_error("analysis_exception", "engine")


# Module-level convenience functions
@contextlib.contextmanager
def timed_analysis(
    verdict: str | None = None,
    detector_scores: list[float] | None = None,
    detector_names: list[str] | None = None,
):
    """Context manager for timing an analysis and recording metrics."""
    timer = AnalysisTimer(
        verdict=verdict,
        detector_scores=detector_scores,
        detector_names=detector_names,
    )
    try:
        yield timer
    finally:
        timer.__exit__(None, None, None)


__all__ = [
    "initialize_telemetry",
    "shutdown_telemetry",
    "is_telemetry_initialized",
    "record_analysis",
    "record_error",
    "set_active_detectors",
    "increment_active_detectors",
    "AnalysisTimer",
    "timed_analysis",
]
