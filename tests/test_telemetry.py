"""Tests for OpenTelemetry metrics instrumentation."""

from __future__ import annotations

import time

import pytest

from textforensics.engine import analyze_text
from textforensics.telemetry import (
    AnalysisTimer,
    initialize_telemetry,
    is_telemetry_initialized,
    record_analysis,
    record_error,
    shutdown_telemetry,
    timed_analysis,
)


class TestTelemetryInitialization:
    """Test telemetry initialization and shutdown."""

    def setup_method(self) -> None:
        """Ensure clean state before each test."""
        shutdown_telemetry()

    def teardown_method(self) -> None:
        """Clean up after each test."""
        shutdown_telemetry()

    def test_initialize_telemetry_returns_true_on_first_call(self) -> None:
        """First initialization should return True."""
        result = initialize_telemetry()
        assert result is True
        assert is_telemetry_initialized() is True

    def test_initialize_telemetry_returns_false_on_subsequent_calls(self) -> None:
        """Subsequent initializations should return False."""
        initialize_telemetry()
        result = initialize_telemetry()
        assert result is False

    def test_shutdown_telemetry_resets_state(self) -> None:
        """Shutdown should reset initialization state."""
        initialize_telemetry()
        shutdown_telemetry()
        assert is_telemetry_initialized() is False

    def test_multiple_shutdowns_safe(self) -> None:
        """Multiple shutdown calls should be safe."""
        initialize_telemetry()
        shutdown_telemetry()
        shutdown_telemetry()  # Should not raise
        assert is_telemetry_initialized() is False


class TestRecordAnalysis:
    """Test recording analysis metrics."""

    def setup_method(self) -> None:
        shutdown_telemetry()

    def teardown_method(self) -> None:
        shutdown_telemetry()

    def test_record_analysis_before_init_no_op(self) -> None:
        """Recording before init should be a no-op (not raise)."""
        record_analysis(latency_ms=100.0, verdict="machine_like_patterns")
        # Should not raise

    def test_record_analysis_after_init(self) -> None:
        """Recording after init should work."""
        initialize_telemetry()
        record_analysis(
            latency_ms=150.5,
            verdict="human_like_patterns",
            detector_scores=[0.2, 0.3, 0.25],
            detector_names=["detector_a", "detector_b", "detector_c"],
        )
        # Should not raise

    def test_record_analysis_with_none_detector_scores(self) -> None:
        """Recording with None detector_scores should work."""
        initialize_telemetry()
        record_analysis(latency_ms=50.0, verdict="indeterminate", detector_scores=None)
        # Should not raise


class TestRecordError:
    """Test recording error metrics."""

    def setup_method(self) -> None:
        shutdown_telemetry()

    def teardown_method(self) -> None:
        shutdown_telemetry()

    def test_record_error_before_init_no_op(self) -> None:
        """Recording error before init should be a no-op."""
        record_error("timeout", "detector")
        # Should not raise

    def test_record_error_after_init(self) -> None:
        """Recording error after init should work."""
        initialize_telemetry()
        record_error("validation_error", "engine")
        record_error("timeout", "network")
        # Should not raise


class TestAnalysisTimer:
    """Test AnalysisTimer context manager."""

    def setup_method(self) -> None:
        shutdown_telemetry()

    def teardown_method(self) -> None:
        shutdown_telemetry()

    def test_timer_records_on_exit(self) -> None:
        """Timer should record metrics on exit."""
        initialize_telemetry()
        with AnalysisTimer(verdict="machine_like_patterns"):
            time.sleep(0.01)  # Small delay to ensure measurable latency
        # Should not raise

    def test_timer_records_detector_info(self) -> None:
        """Timer should record detector scores and names."""
        initialize_telemetry()
        with AnalysisTimer(
            verdict="human_like_patterns",
            detector_scores=[0.1, 0.2],
            detector_names=["a", "b"],
        ):
            time.sleep(0.01)
        # Should not raise

    def test_timer_records_exception(self) -> None:
        """Timer should record error on exception."""
        initialize_telemetry()
        try:
            with AnalysisTimer(verdict="indeterminate"):
                raise ValueError("test error")
        except ValueError:
            pass
        # Should not raise


class TestTimedAnalysisContextManager:
    """Test timed_analysis context manager."""

    def setup_method(self) -> None:
        shutdown_telemetry()

    def teardown_method(self) -> None:
        shutdown_telemetry()

    def test_timed_analysis_works(self) -> None:
        """timed_analysis should work as context manager."""
        initialize_telemetry()
        with timed_analysis(verdict="machine_like_patterns"):
            time.sleep(0.01)
        # Should not raise


class TestEngineIntegration:
    """Test engine integration with telemetry."""

    def setup_method(self) -> None:
        shutdown_telemetry()

    def teardown_method(self) -> None:
        shutdown_telemetry()

    def test_analyze_text_without_telemetry(self) -> None:
        """Engine should work without telemetry initialized."""
        result = analyze_text(
            "This is a test sentence with enough words to meet the minimum length requirement for analysis."
        )
        assert result.verdict in [
            "machine_like_patterns",
            "human_like_patterns",
            "indeterminate",
            "insufficient_evidence",
        ]

    def test_analyze_text_with_telemetry(self) -> None:
        """Engine should work with telemetry initialized."""
        initialize_telemetry()
        result = analyze_text(
            "This is a test sentence with enough words to meet the minimum length requirement for analysis."
        )
        assert result.verdict in [
            "machine_like_patterns",
            "human_like_patterns",
            "indeterminate",
            "insufficient_evidence",
        ]

    def test_analyze_text_records_metrics(self) -> None:
        """Engine should record metrics when telemetry is enabled."""
        initialize_telemetry()
        # This should not raise and should record metrics internally
        result = analyze_text(
            "This is a test sentence with enough words to meet the minimum length requirement for analysis."
        )
        assert result is not None


class TestActiveDetectorsGauge:
    """Test active detectors gauge functions."""

    def setup_method(self) -> None:
        shutdown_telemetry()

    def teardown_method(self) -> None:
        shutdown_telemetry()

    def test_set_active_detectors(self) -> None:
        """Setting active detectors should work."""
        from textforensics.telemetry import set_active_detectors

        initialize_telemetry()
        set_active_detectors(5)
        # Should not raise

    def test_increment_active_detectors(self) -> None:
        """Incrementing active detectors should work."""
        from textforensics.telemetry import increment_active_detectors

        initialize_telemetry()
        increment_active_detectors(3)
        increment_active_detectors(-1)
        # Should not raise

    def test_negative_count_clamped_to_zero(self) -> None:
        """Negative detector count should be clamped to zero."""
        from textforensics.telemetry import set_active_detectors

        initialize_telemetry()
        set_active_detectors(-5)
        # Should not raise, internal count should be 0


class TestTelemetryExports:
    """Test that telemetry functions are properly exported."""

    def test_telemetry_imports_from_main_module(self) -> None:
        """Telemetry functions should be importable from textforensics."""
        from textforensics import (
            AnalysisTimer,
            initialize_telemetry,
            is_telemetry_initialized,
            record_analysis,
            record_error,
            shutdown_telemetry,
            timed_analysis,
        )

        # Just verify they're accessible
        assert initialize_telemetry is not None
        assert is_telemetry_initialized is not None
        assert record_analysis is not None
        assert record_error is not None
        assert shutdown_telemetry is not None
        assert AnalysisTimer is not None
        assert timed_analysis is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
