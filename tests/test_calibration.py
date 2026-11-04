"""Tests for calibration.py — comprehensive coverage for the CalibrationManager.

This module was previously at 54% coverage. These tests exercise:
- CalibrationCurve: all methods (isotonic, platt, temperature, beta)
- CalibrationArtifact: serialization, validation, content_hash
- CalibrationManager: store, get, get_latest, get_lineage, validate_artifact
- validate_calibration_artifact: all validation rules
- Convenience functions: create_calibration_manager, load/save artifact
- Edge cases: missing artifacts, invalid JSON, strict/non-strict validation
"""

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
    create_calibration_manager,
    load_calibration_artifact,
    save_calibration_artifact,
    validate_calibration_artifact,
)


class TestCalibrationCurve:
    """Tests for CalibrationCurve dataclass and methods."""

    def test_isotonic_curve(self):
        curve = CalibrationCurve(
            method="isotonic",
            parameters={"x": [0.0, 0.5, 1.0], "y": [0.0, 0.5, 1.0]},
            reference_dataset_hash="abc123",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        # Test boundaries
        assert curve.calibrate(-0.1) == 0.0
        assert curve.calibrate(0.0) == 0.0
        assert curve.calibrate(0.25) == 0.0  # < 0.5 -> first segment
        assert curve.calibrate(0.5) == 0.5
        assert curve.calibrate(0.75) == 0.5  # between 0.5 and 1.0 -> second segment
        assert curve.calibrate(1.0) == 1.0
        assert curve.calibrate(1.5) == 1.0

    def test_isotonic_curve_empty_params(self):
        curve = CalibrationCurve(
            method="isotonic",
            parameters={},
            reference_dataset_hash="abc123",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        assert curve.calibrate(0.5) == 0.5  # Returns raw score

    def test_platt_curve(self):
        curve = CalibrationCurve(
            method="platt",
            parameters={"A": 1.0, "B": 0.0},
            reference_dataset_hash="abc123",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        # sigmoid(0) = 0.5
        assert abs(curve.calibrate(0.0) - 0.5) < 0.001
        # sigmoid(1) ≈ 0.73
        assert 0.7 < curve.calibrate(1.0) < 0.8
        # sigmoid(-1) ≈ 0.27
        assert 0.2 < curve.calibrate(-1.0) < 0.3

    def test_temperature_curve(self):
        curve = CalibrationCurve(
            method="temperature",
            parameters={"T": 2.0},
            reference_dataset_hash="abc123",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        # T=2 softens probabilities
        assert 0.0 <= curve.calibrate(0.0) <= 1.0
        assert 0.0 <= curve.calibrate(1.0) <= 1.0
        assert 0.0 <= curve.calibrate(0.5) <= 1.0

    def test_beta_curve(self):
        curve = CalibrationCurve(
            method="beta",
            parameters={"a": 2.0, "b": 2.0},
            reference_dataset_hash="abc123",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        assert curve.calibrate(0.0) == 0.0
        assert curve.calibrate(1.0) == 1.0
        assert 0.0 < curve.calibrate(0.5) < 1.0

    def test_unknown_method_returns_raw_score(self):
        curve = CalibrationCurve(
            method="unknown",
            parameters={},
            reference_dataset_hash="abc123",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            assert curve.calibrate(0.7) == 0.7

    def test_to_dict_and_from_dict(self):
        original = CalibrationCurve(
            method="platt",
            parameters={"A": 1.5, "B": -0.5},
            reference_dataset_hash="abc123",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=200,
            calibration_error=0.02,
        )
        d = original.to_dict()
        restored = CalibrationCurve.from_dict(d)
        assert restored.method == "platt"
        assert restored.parameters == {"A": 1.5, "B": -0.5}
        assert restored.reference_dataset_hash == "abc123"
        assert restored.sample_count == 200
        assert restored.calibration_error == 0.02
        # Verify calibration still works
        assert abs(restored.calibrate(0.5) - original.calibrate(0.5)) < 0.001


class TestCalibrationArtifact:
    """Tests for CalibrationArtifact dataclass."""

    def test_to_dict_and_from_dict(self):
        curve = CalibrationCurve(
            method="isotonic",
            parameters={"x": [0.0, 1.0], "y": [0.0, 1.0]},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=50,
        )
        artifact = CalibrationArtifact(
            artifact_id="det1:cal1",
            detector_id="det1",
            detector_version="1.0",
            curve=curve,
            calibration_id="cal1",
            parent_calibration_id="cal0",
            validation_results={"brier": 0.1},
            metadata={"note": "test"},
        )
        d = artifact.to_dict()
        restored = CalibrationArtifact.from_dict(d)
        assert restored.artifact_id == "det1:cal1"
        assert restored.detector_id == "det1"
        assert restored.detector_version == "1.0"
        assert restored.calibration_id == "cal1"
        assert restored.parent_calibration_id == "cal0"
        assert restored.validation_results == {"brier": 0.1}
        assert restored.metadata == {"note": "test"}
        assert restored.curve.method == "isotonic"

    def test_content_hash(self):
        curve = CalibrationCurve(
            method="platt",
            parameters={"A": 1.0, "B": 0.0},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=50,
        )
        artifact1 = CalibrationArtifact(
            artifact_id="det1:cal1",
            detector_id="det1",
            detector_version="1.0",
            curve=curve,
            calibration_id="cal1",
        )
        artifact2 = CalibrationArtifact(
            artifact_id="det1:cal1",  # same artifact_id
            detector_id="det1",
            detector_version="1.0",
            curve=curve,
            calibration_id="cal1",
        )
        # Same content (including calibration_id) -> same content_hash
        assert artifact1.content_hash == artifact2.content_hash

        # Different calibration_id -> different content_hash
        artifact3 = CalibrationArtifact(
            artifact_id="det1:cal2",
            detector_id="det1",
            detector_version="1.0",
            curve=curve,
            calibration_id="cal2",
        )
        assert artifact1.content_hash != artifact3.content_hash

    def test_content_hash_changes_on_curve_change(self):
        curve1 = CalibrationCurve(
            method="platt",
            parameters={"A": 1.0, "B": 0.0},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=50,
        )
        curve2 = CalibrationCurve(
            method="platt",
            parameters={"A": 2.0, "B": 0.0},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=50,
        )
        artifact1 = CalibrationArtifact(
            artifact_id="det1:cal1",
            detector_id="det1",
            detector_version="1.0",
            curve=curve1,
            calibration_id="cal1",
        )
        artifact2 = CalibrationArtifact(
            artifact_id="det1:cal1",
            detector_id="det1",
            detector_version="1.0",
            curve=curve2,
            calibration_id="cal1",
        )
        assert artifact1.content_hash != artifact2.content_hash


class TestCalibrationManager:
    """Tests for CalibrationManager."""

    @pytest.fixture
    def temp_storage(self):
        with tempfile.TemporaryDirectory() as td:
            yield Path(td)

    def test_store_and_get(self, temp_storage):
        mgr = CalibrationManager(temp_storage)
        curve = CalibrationCurve(
            method="platt",
            parameters={"A": 1.0, "B": 0.0},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        artifact = mgr.store(
            detector_id="det1",
            detector_version="1.0",
            curve=curve,
            calibration_id="cal1",
        )
        assert artifact.artifact_id == "det1:cal1"
        assert artifact.detector_id == "det1"
        retrieved = mgr.get("det1:cal1")
        assert retrieved is not None
        assert retrieved.curve.parameters == {"A": 1.0, "B": 0.0}

    def test_store_generates_calibration_id_if_none(self, temp_storage):
        mgr = CalibrationManager(temp_storage)
        curve = CalibrationCurve(
            method="platt",
            parameters={"A": 1.0, "B": 0.0},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        artifact = mgr.store(
            detector_id="det2",
            detector_version="1.0",
            curve=curve,
        )
        assert artifact.calibration_id is not None
        assert artifact.artifact_id == f"det2:{artifact.calibration_id}"

    def test_get_nonexistent_returns_none(self, temp_storage):
        mgr = CalibrationManager(temp_storage)
        assert mgr.get("nonexistent") is None

    def test_get_latest_for_detector(self, temp_storage):
        mgr = CalibrationManager(temp_storage)
        curve = CalibrationCurve(
            method="platt",
            parameters={"A": 1.0, "B": 0.0},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        mgr.store("det3", "1.0", curve, "cal1")
        mgr.store("det3", "1.0", curve, "cal2")
        mgr.store("det3", "1.0", curve, "cal3")
        latest = mgr.get_latest_for_detector("det3")
        assert latest is not None
        assert latest.calibration_id == "cal3"

    def test_get_latest_for_unknown_detector(self, temp_storage):
        mgr = CalibrationManager(temp_storage)
        assert mgr.get_latest_for_detector("unknown") is None

    def test_get_lineage(self, temp_storage):
        mgr = CalibrationManager(temp_storage)
        curve = CalibrationCurve(
            method="platt",
            parameters={"A": 1.0, "B": 0.0},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        mgr.store("det4", "1.0", curve, "cal3")
        mgr.store("det4", "1.0", curve, "cal1")
        mgr.store("det4", "1.0", curve, "cal2")
        lineage = mgr.get_lineage("det4")
        assert len(lineage) == 3
        # Should be sorted by created_at (oldest first)
        assert lineage[0].calibration_id == "cal3"
        assert lineage[1].calibration_id == "cal1"
        assert lineage[2].calibration_id == "cal2"

    def test_validate_artifact_strict_mode(self, temp_storage):
        mgr = CalibrationManager(temp_storage)
        curve = CalibrationCurve(
            method="platt",
            parameters={"A": 1.0, "B": 0.0},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        artifact = mgr.store("det5", "1.0", curve, "cal1")

        # Create validation dataset
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            for i in range(20):
                f.write(json.dumps({"score": 0.5, "label": "ai"}) + "\n")
            val_path = f.name

        try:
            results = mgr.validate_artifact("det5:cal1", val_path, strict=True)
            assert "brier_score" in results
            assert "ece" in results
            assert "log_loss" in results
            assert results["sample_count"] == 20
        finally:
            Path(val_path).unlink()

    def test_validate_artifact_missing_artifact(self, temp_storage):
        mgr = CalibrationManager(temp_storage)
        with pytest.raises(CalibrationError, match="Artifact not found"):
            mgr.validate_artifact("nonexistent", "dummy.jsonl")

    def test_validate_artifact_invalid_json_strict(self, temp_storage):
        mgr = CalibrationManager(temp_storage)
        curve = CalibrationCurve(
            method="platt",
            parameters={"A": 1.0, "B": 0.0},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        mgr.store("det6", "1.0", curve, "cal1")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write("not json\n")
            val_path = f.name

        try:
            with pytest.raises(CalibrationError, match="invalid JSON"):
                mgr.validate_artifact("det6:cal1", val_path, strict=True)
        finally:
            Path(val_path).unlink()

    def test_validate_artifact_invalid_json_non_strict(self, temp_storage):
        mgr = CalibrationManager(temp_storage)
        curve = CalibrationCurve(
            method="platt",
            parameters={"A": 1.0, "B": 0.0},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        mgr.store("det7", "1.0", curve, "cal1")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write("not json\n")
            f.write(json.dumps({"score": 0.5, "label": "ai"}) + "\n")
            val_path = f.name

        try:
            # Non-strict should skip bad lines
            results = mgr.validate_artifact("det7:cal1", val_path, strict=False)
            assert results["sample_count"] == 1
        finally:
            Path(val_path).unlink()

    def test_validate_artifact_missing_fields_strict(self, temp_storage):
        mgr = CalibrationManager(temp_storage)
        curve = CalibrationCurve(
            method="platt",
            parameters={"A": 1.0, "B": 0.0},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        mgr.store("det8", "1.0", curve, "cal1")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps({"score": 0.5}) + "\n")  # missing label
            val_path = f.name

        try:
            with pytest.raises(CalibrationError, match="missing score or label"):
                mgr.validate_artifact("det8:cal1", val_path, strict=True)
        finally:
            Path(val_path).unlink()

    def test_get_calibrated_score_with_calibration(self, temp_storage):
        mgr = CalibrationManager(temp_storage)
        curve = CalibrationCurve(
            method="platt",
            parameters={"A": 1.0, "B": 0.0},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        mgr.store("det9", "1.0", curve, "cal1")
        calibrated = mgr.get_calibrated_score("det9", 0.5)
        assert calibrated is not None
        assert 0.0 <= calibrated <= 1.0

    def test_get_calibrated_score_without_calibration(self, temp_storage):
        mgr = CalibrationManager(temp_storage)
        calibrated = mgr.get_calibrated_score("unknown", 0.5)
        assert calibrated is None

    def test_load_all_skips_corrupt_files(self, temp_storage):
        # Create a corrupt JSON file
        (temp_storage / "bad.json").write_text("not json")
        # Create a valid file
        curve = CalibrationCurve(
            method="platt",
            parameters={"A": 1.0, "B": 0.0},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            mgr = CalibrationManager(temp_storage)
        mgr.store("det10", "1.0", curve, "cal1")
        # Should load only valid files (corrupt skipped, valid stored)
        assert len(mgr._artifacts) == 1


class TestValidateCalibrationArtifact:
    """Tests for validate_calibration_artifact function."""

    def test_valid_artifact_isotonic(self):
        curve = CalibrationCurve(
            method="isotonic",
            parameters={"x": [0.0, 0.5, 1.0], "y": [0.0, 0.5, 1.0]},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        artifact = CalibrationArtifact(
            artifact_id="det1:cal1",
            detector_id="det1",
            detector_version="1.0",
            curve=curve,
            calibration_id="cal1",
        )
        errors = validate_calibration_artifact(artifact)
        assert errors == []

    def test_valid_artifact_platt(self):
        curve = CalibrationCurve(
            method="platt",
            parameters={"A": 1.0, "B": 0.0},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        artifact = CalibrationArtifact(
            artifact_id="det1:cal1",
            detector_id="det1",
            detector_version="1.0",
            curve=curve,
            calibration_id="cal1",
        )
        errors = validate_calibration_artifact(artifact)
        assert errors == []

    def test_valid_artifact_temperature(self):
        curve = CalibrationCurve(
            method="temperature",
            parameters={"T": 2.0},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        artifact = CalibrationArtifact(
            artifact_id="det1:cal1",
            detector_id="det1",
            detector_version="1.0",
            curve=curve,
            calibration_id="cal1",
        )
        errors = validate_calibration_artifact(artifact)
        assert errors == []

    def test_missing_detector_id(self):
        curve = CalibrationCurve(
            method="platt",
            parameters={"A": 1.0, "B": 0.0},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        artifact = CalibrationArtifact(
            artifact_id="det1:cal1",
            detector_id="",
            detector_version="1.0",
            curve=curve,
            calibration_id="cal1",
        )
        errors = validate_calibration_artifact(artifact)
        assert "detector_id is required" in errors

    def test_missing_detector_version(self):
        curve = CalibrationCurve(
            method="platt",
            parameters={"A": 1.0, "B": 0.0},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        artifact = CalibrationArtifact(
            artifact_id="det1:cal1",
            detector_id="det1",
            detector_version="",
            curve=curve,
            calibration_id="cal1",
        )
        errors = validate_calibration_artifact(artifact)
        assert "detector_version is required" in errors

    def test_missing_curve(self):
        artifact = CalibrationArtifact(
            artifact_id="det1:cal1",
            detector_id="det1",
            detector_version="1.0",
            curve=None,  # type: ignore
            calibration_id="cal1",
        )
        errors = validate_calibration_artifact(artifact)
        assert "curve is required" in errors

    def test_missing_calibration_id(self):
        curve = CalibrationCurve(
            method="platt",
            parameters={"A": 1.0, "B": 0.0},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        artifact = CalibrationArtifact(
            artifact_id="det1:cal1",
            detector_id="det1",
            detector_version="1.0",
            curve=curve,
            calibration_id="",
        )
        errors = validate_calibration_artifact(artifact)
        assert "calibration_id is required" in errors

    def test_invalid_curve_method(self):
        curve = CalibrationCurve(
            method="",
            parameters={"A": 1.0, "B": 0.0},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        artifact = CalibrationArtifact(
            artifact_id="det1:cal1",
            detector_id="det1",
            detector_version="1.0",
            curve=curve,
            calibration_id="cal1",
        )
        errors = validate_calibration_artifact(artifact)
        assert "curve.method is required" in errors

    def test_invalid_sample_count(self):
        curve = CalibrationCurve(
            method="platt",
            parameters={"A": 1.0, "B": 0.0},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=0,
        )
        artifact = CalibrationArtifact(
            artifact_id="det1:cal1",
            detector_id="det1",
            detector_version="1.0",
            curve=curve,
            calibration_id="cal1",
        )
        errors = validate_calibration_artifact(artifact)
        assert "sample_count must be positive" in errors[0]

    def test_isotonic_missing_params(self):
        curve = CalibrationCurve(
            method="isotonic",
            parameters={},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        artifact = CalibrationArtifact(
            artifact_id="det1:cal1",
            detector_id="det1",
            detector_version="1.0",
            curve=curve,
            calibration_id="cal1",
        )
        errors = validate_calibration_artifact(artifact)
        assert "isotonic method requires 'x' and 'y' parameters" in errors

    def test_isotonic_x_y_length_mismatch(self):
        curve = CalibrationCurve(
            method="isotonic",
            parameters={"x": [0.0, 0.5], "y": [0.0]},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        artifact = CalibrationArtifact(
            artifact_id="det1:cal1",
            detector_id="det1",
            detector_version="1.0",
            curve=curve,
            calibration_id="cal1",
        )
        errors = validate_calibration_artifact(artifact)
        assert "isotonic 'x' and 'y' must have same length" in errors

    def test_isotonic_y_not_non_decreasing(self):
        curve = CalibrationCurve(
            method="isotonic",
            parameters={"x": [0.0, 0.5, 1.0], "y": [0.0, 1.0, 0.5]},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        artifact = CalibrationArtifact(
            artifact_id="det1:cal1",
            detector_id="det1",
            detector_version="1.0",
            curve=curve,
            calibration_id="cal1",
        )
        errors = validate_calibration_artifact(artifact)
        assert "isotonic 'y' must be non-decreasing" in errors

    def test_platt_missing_params(self):
        curve = CalibrationCurve(
            method="platt",
            parameters={},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        artifact = CalibrationArtifact(
            artifact_id="det1:cal1",
            detector_id="det1",
            detector_version="1.0",
            curve=curve,
            calibration_id="cal1",
        )
        errors = validate_calibration_artifact(artifact)
        assert "platt method requires 'A' and 'B' parameters" in errors

    def test_temperature_missing_T(self):
        curve = CalibrationCurve(
            method="temperature",
            parameters={},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        artifact = CalibrationArtifact(
            artifact_id="det1:cal1",
            detector_id="det1",
            detector_version="1.0",
            curve=curve,
            calibration_id="cal1",
        )
        errors = validate_calibration_artifact(artifact)
        assert "temperature method requires 'T' parameter" in errors

    def test_temperature_T_not_positive(self):
        curve = CalibrationCurve(
            method="temperature",
            parameters={"T": -1.0},
            reference_dataset_hash="hash1",
            reference_dataset_name="test",
            calibrated_at="2024-01-01T00:00:00Z",
            sample_count=100,
        )
        artifact = CalibrationArtifact(
            artifact_id="det1:cal1",
            detector_id="det1",
            detector_version="1.0",
            curve=curve,
            calibration_id="cal1",
        )
        errors = validate_calibration_artifact(artifact)
        assert "temperature 'T' must be positive" in errors


class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    def test_create_calibration_manager(self):
        with tempfile.TemporaryDirectory() as td:
            mgr = create_calibration_manager(td)
            assert isinstance(mgr, CalibrationManager)
            assert mgr.storage_path == Path(td)

    def test_load_save_calibration_artifact(self):
        with tempfile.TemporaryDirectory() as td:
            curve = CalibrationCurve(
                method="platt",
                parameters={"A": 1.0, "B": 0.0},
                reference_dataset_hash="hash1",
                reference_dataset_name="test",
                calibrated_at="2024-01-01T00:00:00Z",
                sample_count=100,
            )
            artifact = CalibrationArtifact(
                artifact_id="det1:cal1",
                detector_id="det1",
                detector_version="1.0",
                curve=curve,
                calibration_id="cal1",
            )
            path = Path(td) / "artifact.json"
            save_calibration_artifact(artifact, path)
            loaded = load_calibration_artifact(path)
            assert loaded.artifact_id == artifact.artifact_id
            assert loaded.detector_id == artifact.detector_id
            assert loaded.curve.method == artifact.curve.method


if __name__ == "__main__":
    pytest.main([__file__, "-v"])