"""Detector Health Monitor for TextForensics.

Provides continuous monitoring of detector health and performance with:
- Real-time metric tracking (latency, throughput, error rates, score distributions)
- Anomaly detection in detector behavior using statistical methods
- Automated alerts and health scoring
- Historical trend analysis
- Integration with Pipeline Orchestrator for automated failover
- Health report generation

Design principles:
- Local-first: No network dependencies
- Observable: Full metrics and audit trail
- Extensible: Plugin architecture for custom health checks
- Fail-closed: Conservative health assessments
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import statistics
import time
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

__all__ = [
    "HealthState",
    "AlertSeverity",
    "HealthMetric",
    "HealthAlert",
    "DetectorHealthReport",
    "HealthCheck",
    "DetectorHealthMonitor",
    "create_health_monitor",
]


class HealthState(str, Enum):
    """Overall health state of a detector."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    UNKNOWN = "unknown"
    OFFLINE = "offline"


class AlertSeverity(str, Enum):
    """Severity level of health alerts."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class HealthMetric:
    """A single health metric measurement."""
    name: str
    value: float
    unit: str
    timestamp: str
    detector_id: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "unit": self.unit,
            "timestamp": self.timestamp,
            "detector_id": self.detector_id,
            "metadata": self.metadata,
        }


@dataclass(frozen=True, slots=True)
class HealthAlert:
    """A health alert triggered by anomaly detection."""
    alert_id: str
    detector_id: str
    severity: AlertSeverity
    message: str
    metric_name: str
    metric_value: float
    threshold: float
    timestamp: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "detector_id": self.detector_id,
            "severity": self.severity.value,
            "message": self.message,
            "metric_name": self.metric_name,
            "metric_value": self.metric_value,
            "threshold": self.threshold,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


@dataclass
class DetectorHealthReport:
    """Comprehensive health report for a detector."""
    detector_id: str
    overall_state: HealthState
    health_score: float  # 0.0 - 1.0
    metrics: dict[str, list[HealthMetric]] = field(default_factory=dict)
    alerts: list[HealthAlert] = field(default_factory=list)
    last_updated: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector_id": self.detector_id,
            "overall_state": self.overall_state.value,
            "health_score": self.health_score,
            "metrics": {k: [m.to_dict() for m in v] for k, v in self.metrics.items()},
            "alerts": [a.to_dict() for a in self.alerts],
            "last_updated": self.last_updated,
            "metadata": self.metadata,
        }

    def save(self, path: Path) -> bool:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            return True
        except Exception:
            return False

    @classmethod
    def load(cls, path: Path) -> DetectorHealthReport | None:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return cls(
                detector_id=data["detector_id"],
                overall_state=HealthState(data["overall_state"]),
                health_score=data["health_score"],
                metrics={
                    k: [HealthMetric(**m) for m in v]
                    for k, v in data.get("metrics", {}).items()
                },
                alerts=[HealthAlert(**a) for a in data.get("alerts", [])],
                last_updated=data.get("last_updated", datetime.now(timezone.utc).isoformat()),
                metadata=data.get("metadata", {}),
            )
        except Exception:
            return None


class HealthCheck:
    """A single health check definition."""

    def __init__(
        self,
        name: str,
        metric_name: str,
        check_fn: Callable[[list[float]], tuple[bool, float]],
        warning_threshold: float,
        critical_threshold: float,
        severity: AlertSeverity = AlertSeverity.WARNING,
        description: str = "",
        source_metric: str | None = None,
        inverted: bool = False,
    ):
        self.name = name
        self.metric_name = metric_name
        self.check_fn = check_fn
        self.warning_threshold = warning_threshold
        self.critical_threshold = critical_threshold
        self.severity = severity
        self.description = description
        # The raw per-event series this check reads. Defaults to metric_name
        # when the check consumes the same series it reports on.
        self.source_metric = source_metric or metric_name
        # If True, LOWER values are worse (e.g., entropy ratio).
        # If False (default), HIGHER values are worse (e.g., error rate, latency).
        self.inverted = inverted

    def evaluate(
        self, values: list[float], detector_id: str = ""
    ) -> HealthAlert | None:
        """Evaluate the health check against a series of values."""
        if not values:
            return None

        passed, value = self.check_fn(values)
        if passed:
            return None

        # For inverted checks (e.g., entropy), LOWER value is worse
        if self.inverted:
            if value <= self.critical_threshold:
                severity = AlertSeverity.CRITICAL
            elif value <= self.warning_threshold:
                severity = AlertSeverity.WARNING
            else:
                return None
            cmp_word = "below"
        else:
            # Normal: HIGHER value is worse
            if value >= self.critical_threshold:
                severity = AlertSeverity.CRITICAL
            elif value >= self.warning_threshold:
                severity = AlertSeverity.WARNING
            else:
                return None
            cmp_word = "exceeds"

        return HealthAlert(
            alert_id=f"alert-{hashlib.sha256(f'{self.name}{time.time()}'.encode()).hexdigest()[:8]}",
            detector_id=detector_id,
            severity=severity,
            message=f"{self.name}: {value} {cmp_word} {self.critical_threshold if severity == AlertSeverity.CRITICAL else self.warning_threshold}",
            metric_name=self.metric_name,
            metric_value=value,
            threshold=self.critical_threshold if severity == AlertSeverity.CRITICAL else self.warning_threshold,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )


# Built-in health checks
def _create_latency_check() -> HealthCheck:
    def check(values: list[float]) -> tuple[bool, float]:
        p95 = statistics.quantiles(values, n=20)[18] if len(values) >= 20 else max(values)
        return p95 < 5000.0, p95  # 5 second p95 threshold
    return HealthCheck(
        name="latency_p95",
        metric_name="latency_ms",
        check_fn=check,
        warning_threshold=3000.0,
        critical_threshold=10000.0,
        severity=AlertSeverity.WARNING,
        description="P95 latency exceeds threshold",
    )


def _create_error_rate_check() -> HealthCheck:
    def check(values: list[float]) -> tuple[bool, float]:
        error_rate = sum(1 for v in values if v > 0) / len(values)
        return error_rate < 0.05, error_rate  # 5% error rate threshold
    return HealthCheck(
        name="error_rate",
        metric_name="error_rate",
        check_fn=check,
        warning_threshold=0.05,
        critical_threshold=0.10,
        severity=AlertSeverity.CRITICAL,
        description="Error rate exceeds threshold",
        source_metric="error",
    )


def _create_score_distribution_check() -> HealthCheck:
    def check(values: list[float]) -> tuple[bool, float]:
        # Check for suspicious score distributions (too uniform = low entropy)
        # Returns (passed, entropy_ratio) where passed=True means healthy (high entropy)
        if len(values) < 10:
            return True, 1.0
        # Calculate entropy of score distribution
        bins = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
        if np is not None:
            hist, _ = np.histogram(values, bins=bins)
        else:
            # Manual histogram (numpy is an optional dependency)
            hist = [0] * 10
            for v in values:
                idx = min(int(v * 10), 9)
                hist[idx] += 1
        total = sum(hist)
        if total == 0:
            return True, 1.0
        probs = [h/total for h in hist if h > 0]
        entropy = -sum(p * math.log2(p) for p in probs)
        max_entropy = math.log2(len([h for h in hist if h > 0]))
        entropy_ratio = entropy / max_entropy if max_entropy > 0 else 0.0
        # Healthy if entropy_ratio > 0.3 (not too uniform)
        return entropy_ratio > 0.3, entropy_ratio
    return HealthCheck(
        name="score_distribution_entropy",
        metric_name="score_entropy_ratio",
        check_fn=check,
        warning_threshold=0.5,
        critical_threshold=0.3,
        severity=AlertSeverity.WARNING,
        description="Score distribution entropy too low (suspiciously uniform)",
        source_metric="score",
        inverted=True,
    )


def _create_throughput_check() -> HealthCheck:
    def check(values: list[float]) -> tuple[bool, float]:
        # values are timestamps of requests
        if len(values) < 2:
            return True, 0.0
        # Calculate requests per second over last window
        now = time.time()
        recent = [v for v in values if now - v < 60]  # Last minute
        throughput = len(recent) / 60.0  # req/s
        return throughput >= 0.1, throughput  # At least 0.1 req/s
    return HealthCheck(
        name="throughput",
        metric_name="throughput_rps",
        check_fn=check,
        warning_threshold=0.5,
        critical_threshold=0.1,
        severity=AlertSeverity.WARNING,
        source_metric="request_timestamp",
        description="Throughput below threshold",
    )


# Import json and hashlib at module level
try:
    import numpy as np
except ImportError:
    np = None


class DetectorHealthMonitor:
    """Monitors detector health with anomaly detection and alerting."""

    def __init__(
        self,
        max_history: int = 10000,
        alert_callback: Callable[[HealthAlert], None] | None = None,
    ):
        self.max_history = max_history
        self.alert_callback = alert_callback
        self._metrics: dict[str, dict[str, deque]] = defaultdict(lambda: defaultdict(deque))
        self._health_checks: dict[str, list[HealthCheck]] = defaultdict(list)
        self._reports: dict[str, DetectorHealthReport] = {}
        self._alerts: list[HealthAlert] = []
        self._lock = asyncio.Lock()

        # Register default health checks
        self._register_default_checks()

    def _register_default_checks(self) -> None:
        """Register default health checks for all detectors."""
        # These will be added per-detector when first metric is recorded
        pass

    def _ensure_detector_checks(self, detector_id: str) -> None:
        if detector_id not in self._health_checks:
            self._health_checks[detector_id] = [
                _create_latency_check(),
                _create_error_rate_check(),
                _create_score_distribution_check(),
                _create_throughput_check(),
            ]

    def record_metric(
        self,
        detector_id: str,
        metric_name: str,
        value: float,
        unit: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Record a metric value for a detector."""
        metric = HealthMetric(
            name=metric_name,
            value=value,
            unit=unit,
            timestamp=datetime.now(timezone.utc).isoformat(),
            detector_id=detector_id,
            metadata=metadata or {},
        )

        self._metrics[detector_id][metric_name].append(metric)
        if len(self._metrics[detector_id][metric_name]) > self.max_history:
            self._metrics[detector_id][metric_name].popleft()

        # Run health checks
        self._evaluate_health_checks(detector_id)

    def record_latency(self, detector_id: str, latency_ms: float) -> None:
        self.record_metric(detector_id, "latency_ms", latency_ms, "ms")

    def record_error(self, detector_id: str, is_error: bool) -> None:
        # Record the per-event error flag. The error_rate health check reads
        # this series and derives its rate, so every event must be recorded —
        # recording only on failure would make the series all-1.0.
        self.record_metric(detector_id, "error", 1.0 if is_error else 0.0, "count")

    def record_score(self, detector_id: str, score: float) -> None:
        self.record_metric(detector_id, "score", score, "ratio")

    def record_request(self, detector_id: str) -> None:
        self.record_metric(detector_id, "request_timestamp", time.time(), "timestamp")

    def _evaluate_health_checks(self, detector_id: str) -> None:
        self._ensure_detector_checks(detector_id)

        for check in self._health_checks[detector_id]:
            values = [m.value for m in self._metrics[detector_id].get(check.source_metric, [])]
            if not values:
                continue

            alert = check.evaluate(values, detector_id=detector_id)
            if alert:
                self._alerts.append(alert)
                if self.alert_callback:
                    self.alert_callback(alert)

    def get_report(self, detector_id: str) -> DetectorHealthReport:
        """Generate a health report for a detector."""
        if detector_id not in self._reports:
            self._reports[detector_id] = DetectorHealthReport(
                detector_id=detector_id,
                overall_state=HealthState.UNKNOWN,
                health_score=0.0,
            )

        report = self._reports[detector_id]
        report.metrics = {
            k: list(v) for k, v in self._metrics.get(detector_id, {}).items()
        }
        report.alerts = [a for a in self._alerts if a.detector_id == detector_id]
        report.last_updated = datetime.now(timezone.utc).isoformat()
        report.overall_state, report.health_score = self._compute_overall_health(detector_id)

        return report

    def _compute_overall_health(self, detector_id: str) -> tuple[HealthState, float]:
        """Compute overall health state and score.

        Evaluates the checks for state/scoring only — it must not append to
        ``self._alerts``. ``_evaluate_health_checks`` is the single place that
        records alerts; re-firing here on every report call would duplicate
        them indefinitely.
        """
        checks = self._health_checks.get(detector_id, [])
        if not checks:
            return HealthState.UNKNOWN, 0.0

        critical_count = 0
        warning_count = 0
        total_checks = 0

        for check in checks:
            values = [m.value for m in self._metrics[detector_id].get(check.source_metric, [])]
            if not values:
                continue
            total_checks += 1
            alert = check.evaluate(values, detector_id=detector_id)
            if alert:
                if alert.severity == AlertSeverity.CRITICAL:
                    critical_count += 1
                elif alert.severity == AlertSeverity.WARNING:
                    warning_count += 1

        if total_checks == 0:
            return HealthState.UNKNOWN, 0.0

        if critical_count > 0:
            return HealthState.CRITICAL, max(0.0, 1.0 - (critical_count / total_checks) * 0.8)
        elif warning_count > 0:
            return HealthState.DEGRADED, max(0.5, 1.0 - (warning_count / total_checks) * 0.5)
        else:
            return HealthState.HEALTHY, 1.0

    def get_all_alerts(self, since: datetime | None = None) -> list[HealthAlert]:
        if since is None:
            return list(self._alerts)
        cutoff = since.isoformat()
        return [a for a in self._alerts if a.timestamp >= cutoff]

    def clear_alerts(self, detector_id: str | None = None) -> int:
        if detector_id:
            before = len(self._alerts)
            self._alerts = [a for a in self._alerts if a.detector_id != detector_id]
            return before - len(self._alerts)
        else:
            count = len(self._alerts)
            self._alerts.clear()
            return count


class HighLevelDetectorHealthMonitor:
    """High-level detector health monitor with orchestration integration."""

    def __init__(
        self,
        max_history: int = 10000,
        alert_callback: Callable[[HealthAlert], None] | None = None,
    ):
        self.monitor = DetectorHealthMonitor(max_history, alert_callback)

    def record_detector_result(
        self,
        detector_id: str,
        latency_ms: float,
        score: float | None = None,
        verdict: str | None = None,
        is_error: bool = False,
    ) -> None:
        self.monitor.record_latency(detector_id, latency_ms)
        if score is not None:
            self.monitor.record_score(detector_id, score)
        # Always record the per-event error flag: the error-rate health check
        # derives its rate from this series, and recording only on failure
        # would leave the series all-1.0 (100% error rate forever).
        self.monitor.record_error(detector_id, is_error)
        self.monitor.record_request(detector_id)

    def get_detector_health(self, detector_id: str) -> DetectorHealthReport:
        return self.monitor.get_report(detector_id)

    def get_all_health(self) -> dict[str, DetectorHealthReport]:
        all_ids = set(self.monitor._metrics.keys()) | set(self.monitor._health_checks.keys())
        return {d: self.monitor.get_report(d) for d in all_ids}

    def get_alerts(self, since: datetime | None = None) -> list[HealthAlert]:
        return self.monitor.get_all_alerts(since)

    def check_detector_health(self, detector_id: str) -> tuple[HealthState, float]:
        report = self.get_detector_health(detector_id)
        return report.overall_state, report.health_score


def create_health_monitor(
    max_history: int = 10000,
    alert_callback: Callable[[HealthAlert], None] | None = None,
) -> DetectorHealthMonitor:
    """Create a detector health monitor."""
    return DetectorHealthMonitor(max_history=max_history, alert_callback=alert_callback)


def create_detector_health_monitor(
    max_history: int = 10000,
    alert_callback: Callable[[HealthAlert], None] | None = None,
) -> HighLevelDetectorHealthMonitor:
    """Create a high-level detector health monitor."""
    return HighLevelDetectorHealthMonitor(max_history=max_history, alert_callback=alert_callback)
