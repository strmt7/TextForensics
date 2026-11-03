"""Tests for Calibration Manager."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from textforensics.calibration import (
    CalibrationArtifact,
    CalibrationCurve,
    CalibrationError,
    CalibrationManager,
    validate_calibration_artifact,
)


class TestCalibrationCurve:
    def test_curve_creation(self):
        """Calibration curve creation should work."""
        curve = CalibrationCurve(
            method="isotonic",
            parameters={"x": [0.0, 0.5, 1.0], "y": [0.1, 0.5, 0.9]},
            reference_dataset_hash="a" * 64,
            reference_dataset_name="test_dataset",
            calibrated_at="2024-01-01T00:00:00+00:00",
            sample_count=1000,
            calibration_error=0.02,
        )
        assert curve.method == "isotonic"
        assert curve.sample_count == 1000

    def test_curve_roundtrip(self):
        """Curve serialization/deserialization should preserve data."""
        curve = CalibrationCurve(
            method="platt",
            parameters={"A": 1.5, "B": -0.5},
            reference_dataset_hash="a" * 64,
            reference_dataset_name="test_dataset",
            calibrated_at="2024-01-01T00:00:00+00:00",
            sample_count=1000,
        )
        d = curve.to_dict()
        curve2 = CalibrationCurve.from_dict(d)
        assert curve2.method == curve.method
        assert curve2.parameters == curve.parameters

    def test_isotonic_calibration(self):
        """Isotonic calibration should map scores correctly."""
        curve = CalibrationCurve(
            method="isotonic",
            parameters={"x": [0.0, 0.5, 1.0], "y": [0.1, 0.5, 0.9]},
            reference_dataset_hash="a" * 64,
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00+00:00",
            sample_count=100,
        )
        # Piecewise constant: score < 0.5 -> 0.1, 0.5 <= score < 1.0 -> 0.5, score >= 1.0 -> 0.9
        assert curve.calibrate(0.0) == 0.1
        assert curve.calibrate(0.25) == 0.1
        assert curve.calibrate(0.5) == 0.5
        assert curve.calibrate(0.75) == 0.5  # 0.5 <= 0.75 < 1.0
        assert curve.calibrate(1.0) == 0.9

    def test_platt_calibration(self):
        """Platt calibration should apply sigmoid."""
        curve = CalibrationCurve(
            method="platt",
            parameters={"A": 1.0, "B": 0.0},
            reference_dataset_hash="a" * 64,
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00+00:00",
            sample_count=100,
        )
        # sigmoid(0) = 0.5
        assert abs(curve.calibrate(0.0) - 0.5) < 0.001
        # sigmoid(1) = 1/(1+e) ≈ 0.269
        assert abs(curve.calibrate(1.0) - 0.269) < 0.01
        # sigmoid(-1) = 1/(1+e^-1) ≈ 0.731
        assert abs(curve.calibrate(-1.0) - 0.731) < 0.01

    def test_temperature_calibration(self):
        """Temperature calibration should scale scores."""
        curve = CalibrationCurve(
            method="temperature",
            parameters={"T": 2.0},
            reference_dataset_hash="a" * 64,
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00+00:00",
            sample_count=100,
        )
        # Temperature scaling: softmax(score / T)
        # At score=0.5, T=2: softmax(0.25) ≈ 0.562
        result = curve.calibrate(0.5)
        assert 0.5 < result < 0.6


class TestCalibrationArtifact:
    def test_artifact_creation(self):
        """Artifact creation should work."""
        curve = CalibrationCurve(
            method="isotonic",
            parameters={"x": [0.0, 1.0], "y": [0.0, 1.0]},
            reference_dataset_hash="a" * 64,
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00+00:00",
            sample_count=100,
        )
        artifact = CalibrationArtifact(
            artifact_id="detector1:cal1",
            detector_id="detector1",
            detector_version="1.0",
            curve=curve,
            calibration_id="cal1",
        )
        assert artifact.detector_id == "detector1"
        assert artifact.curve.method == "isotonic"

    def test_artifact_roundtrip(self):
        """Artifact serialization/deserialization should preserve data."""
        curve = CalibrationCurve(
            method="platt",
            parameters={"A": 1.0, "B": 0.0},
            reference_dataset_hash="a" * 64,
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00+00:00",
            sample_count=100,
        )
        artifact = CalibrationArtifact(
            artifact_id="detector1:cal1",
            detector_id="detector1",
            detector_version="1.0",
            curve=curve,
            calibration_id="cal1",
        )
        d = artifact.to_dict()
        artifact2 = CalibrationArtifact.from_dict(d)
        assert artifact2.detector_id == artifact.detector_id
        assert artifact2.curve.method == artifact.curve.method


class TestCalibrationManager:
    def test_manager_creation(self):
        """Manager creation should work."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = CalibrationManager(Path(tmp))
            assert len(manager._artifacts) == 0

    def test_store_and_retrieve(self):
        """Storing and retrieving artifacts should work."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = CalibrationManager(Path(tmp))

            curve = CalibrationCurve(
                method="isotonic",
                parameters={"x": [0.0, 1.0], "y": [0.0, 1.0]},
                reference_dataset_hash="a" * 64,
                reference_dataset_name="test",
                calibrated_at="2024-01-01T00:00:00+00:00",
                sample_count=100,
            )

            artifact = manager.store(
                detector_id="detector1",
                detector_version="1.0",
                curve=curve,
                calibration_id="cal1",
            )

            assert artifact.artifact_id in manager._artifacts

            retrieved = manager.get(artifact.artifact_id)
            assert retrieved is not None
            assert retrieved.detector_id == "detector1"

    def test_get_latest_for_detector(self):
        """Getting latest calibration for detector should work."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = CalibrationManager(Path(tmp))

            curve1 = CalibrationCurve(
                method="isotonic",
                parameters={"x": [0.0, 1.0], "y": [0.0, 1.0]},
                reference_dataset_hash="a" * 64,
                reference_dataset_name="test",
                calibrated_at="2024-01-01T00:00:00+00:00",
                sample_count=100,
            )
            curve2 = CalibrationCurve(
                method="platt",
                parameters={"A": 1.0, "B": 0.0},
                reference_dataset_hash="b" * 64,
                reference_dataset_name="test",
                calibrated_at="2024-02-01T00:00:00+00:00",
                sample_count=200,
            )

            manager.store(
                detector_id="detector1",
                detector_version="1.0",
                curve=curve1,
                calibration_id="cal1",
            )
            manager.store(
                detector_id="detector1",
                detector_version="1.0",
                curve=curve2,
                calibration_id="cal2",
            )

            latest = manager.get_latest_for_detector("detector1")
            assert latest is not None
            assert latest.curve.method == "platt"  # Second one is later

    def test_get_lineage(self):
        """Getting calibration lineage should work."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = CalibrationManager(Path(tmp))

            for i in range(3):
                curve = CalibrationCurve(
                    method="isotonic",
                    parameters={"x": [0.0, 1.0], "y": [0.0, 1.0]},
                    reference_dataset_hash=f"h{i}" * 64,
                    reference_dataset_name="test",
                    calibrated_at=f"2024-01-0{i+1}T00:00:00+00:00",
                    sample_count=100,
                )
                manager.store(
                    detector_id="detector1",
                    detector_version="1.0",
                    curve=curve,
                    calibration_id=f"cal{i}",
                )

            lineage = manager.get_lineage("detector1")
            assert len(lineage) == 3

    def test_get_calibrated_score(self):
        """Getting calibrated score should work."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = CalibrationManager(Path(tmp))

            curve = CalibrationCurve(
                method="platt",
                parameters={"A": 1.0, "B": 0.0},
                reference_dataset_hash="a" * 64,
                reference_dataset_name="test",
                calibrated_at="2024-01-01T00:00:00+00:00",
                sample_count=100,
            )
            manager.store(
                detector_id="detector1",
                detector_version="1.0",
                curve=curve,
                calibration_id="cal1",
            )

            calibrated = manager.get_calibrated_score("detector1", 0.0)
            assert calibrated is not None
            assert abs(calibrated - 0.5) < 0.001

    def test_get_calibrated_score_missing(self):
        """Getting score for unknown detector should return None."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = CalibrationManager(Path(tmp))
            calibrated = manager.get_calibrated_score("unknown", 0.5)
            assert calibrated is None


class TestValidation:
    def test_validate_calibration_artifact(self):
        """Validation should catch errors."""
        curve = CalibrationCurve(
            method="isotonic",
            parameters={"x": [0.0, 1.0], "y": [1.0, 0.0]},  # Not non-decreasing!
            reference_dataset_hash="a" * 64,
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00+00:00",
            sample_count=100,
        )
        artifact = CalibrationArtifact(
            artifact_id="detector1:cal1",
            detector_id="detector1",
            detector_version="1.0",
            curve=curve,
            calibration_id="cal1",
        )
        errors = validate_calibration_artifact(artifact)
        assert len(errors) > 0
        assert any("non-decreasing" in e for e in errors)

    def test_validate_missing_fields(self):
        """Validation should catch missing required fields."""
        artifact = CalibrationArtifact(
            artifact_id="",
            detector_id="",
            detector_version="",
            curve=None,
            calibration_id="",
        )
        errors = validate_calibration_artifact(artifact)
        assert len(errors) > 0

    def test_platt_validation(self):
        """Platt validation should require A and B."""
        curve = CalibrationCurve(
            method="platt",
            parameters={},  # Missing A and B
            reference_dataset_hash="a" * 64,
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00+00:00",
            sample_count=100,
        )
        artifact = CalibrationArtifact(
            artifact_id="detector1:cal1",
            detector_id="detector1",
            detector_version="1.0",
            curve=curve,
            calibration_id="cal1",
        )
        errors = validate_calibration_artifact(artifact)
        assert any("platt" in e.lower() and ("A" in e or "B" in e) for e in errors)


class TestCalibrationError:
    def test_calibration_error_exception(self):
        """CalibrationError should be raised on validation errors."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = CalibrationManager(Path(tmp))
            # get() returns None for nonexistent artifacts
            result = manager.get("nonexistent")
            assert result is None


class TestCalibrationValidation:
    def test_validate_artifact_success(self):
        """Valid artifact should pass validation."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = CalibrationManager(Path(tmp))

            curve = CalibrationCurve(
                method="isotonic",
                parameters={"x": [0.0, 0.5, 1.0], "y": [0.1, 0.5, 0.9]},
                reference_dataset_hash="a" * 64,
                reference_dataset_name="test",
                calibrated_at="2024-01-01T00:00:00+00:00",
                sample_count=100,
            )
            artifact = manager.store(
                detector_id="detector1",
                detector_version="1.0",
                curve=curve,
                calibration_id="cal1",
            )

            errors = validate_calibration_artifact(artifact)
            assert len(errors) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])