"""Tests for calibration.py — the fail-closed calibration contract (v2).

Contract under test (docs/REVAMP_SPEC.md):
- A detector score is not a probability; only a probability-eligible artifact
  may emit one, and eligibility is derived from recorded provenance.
- Unknown calibration methods, missing parameters, and out-of-range scores
  fail closed: they raise instead of silently passing raw values through.
- Artifacts are content-hashed; tampering is detected.
- The manager is a local registry that refuses ambiguous state (duplicate
  content or artifact ids), stores artifacts atomically, and never invents
  calibration from detector output.
"""

from __future__ import annotations

import json
import math
import os
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from textforensics.benchmark import dataset_sha256
from textforensics.calibration import (
    MIN_CALIBRATION_SAMPLES,
    THRESHOLD_SELECTION_SCHEMA,
    CalibrationArtifact,
    CalibrationCurve,
    CalibrationError,
    CalibrationManager,
    CalibrationResult,
    DatasetReference,
    ThresholdSelectionResult,
    _coerce_label,
    _parse_iso8601,
    _probability_metrics,
    create_calibration_manager,
    evaluate_threshold,
    load_calibration_artifact,
    load_threshold_artifact,
    run_calibration_evaluation,
    save_calibration_artifact,
    select_threshold,
    validate_calibration_artifact,
    validate_no_contamination,
)


def hex64(seed: int) -> str:
    return f"{seed:064x}"


def platt_curve() -> CalibrationCurve:
    return CalibrationCurve(
        method="platt",
        parameters={"A": 1.0, "B": 0.0},
        reference_dataset_hash=hex64(1),
        reference_dataset_name="test",
        calibrated_at="2024-01-01T00:00:00Z",
        sample_count=200,
    )


def eligible_artifact_kwargs() -> dict:
    return {
        "fit_dataset": DatasetReference(
            name="fit", fingerprint_sha256=hex64(2), split="train", sample_count=200
        ),
        "evaluation_dataset": DatasetReference(
            name="eval", fingerprint_sha256=hex64(3), split="test", sample_count=200
        ),
        "disjointness": {"strategy": "disjoint_sample_ids", "evidence": "ids differ"},
        "metrics": {"brier": 0.10, "ece": 0.05, "log_loss": 0.30},
        "code_version": "abc123",
        "run_artifact_sha256": hex64(4),
    }


def eligible_artifact() -> CalibrationArtifact:
    return CalibrationArtifact(
        artifact_id="det1:cal1",
        detector_id="det1",
        detector_version="1.0",
        curve=platt_curve(),
        calibration_id="cal1",
        created_at="2024-01-01T00:00:00+00:00",
        **eligible_artifact_kwargs(),
    )


def store_eligible(
    mgr: CalibrationManager, detector_id: str, calibration_id: str
) -> CalibrationArtifact:
    return mgr.store(
        detector_id=detector_id,
        detector_version="1.0",
        curve=platt_curve(),
        calibration_id=calibration_id,
        created_at="2024-01-01T00:00:00+00:00",
        **eligible_artifact_kwargs(),
    )


# ---------------------------------------------------------------------------
# CalibrationCurve
# ---------------------------------------------------------------------------


class TestCalibrationCurveConstruction:
    def test_unknown_method_raises(self):
        with pytest.raises(CalibrationError, match="Unsupported calibration method"):
            CalibrationCurve(method="unknown", parameters={})

    def test_empty_method_raises(self):
        with pytest.raises(CalibrationError):
            CalibrationCurve(method="", parameters={})

    def test_invalid_schema_raises(self):
        with pytest.raises(CalibrationError, match="schema"):
            CalibrationCurve(method="platt", parameters={"A": 1.0, "B": 0.0}, schema="wrong")

    def test_invalid_native_score_direction_raises(self):
        with pytest.raises(CalibrationError, match="native_score_direction"):
            CalibrationCurve(
                method="platt", parameters={"A": 1.0, "B": 0.0}, native_score_direction="sideways"
            )

    def test_negative_sample_count_raises(self):
        with pytest.raises(CalibrationError, match="sample_count"):
            CalibrationCurve(method="platt", parameters={"A": 1.0, "B": 0.0}, sample_count=-1)

    def test_bool_sample_count_raises(self):
        with pytest.raises(CalibrationError, match="sample_count"):
            CalibrationCurve(method="platt", parameters={"A": 1.0, "B": 0.0}, sample_count=True)

    def test_calibration_error_out_of_range_raises(self):
        with pytest.raises(CalibrationError, match="calibration_error"):
            CalibrationCurve(method="platt", parameters={"A": 1.0, "B": 0.0}, calibration_error=1.5)

    def test_non_mapping_parameters_raise(self):
        with pytest.raises(CalibrationError, match="parameters"):
            CalibrationCurve(method="platt", parameters=["A", 1.0])  # type: ignore[arg-type]

    def test_score_range_invalid_raises(self):
        with pytest.raises(CalibrationError, match="score_range"):
            CalibrationCurve(
                method="platt",
                parameters={"A": 1.0, "B": 0.0},
                score_range=(1.0, 0.0),
            )

    def test_score_range_wrong_length_raises(self):
        with pytest.raises(CalibrationError, match="score_range"):
            CalibrationCurve(
                method="platt",
                parameters={"A": 1.0, "B": 0.0},
                score_range=(0.0, 0.5, 1.0),  # type: ignore[arg-type]
            )

    def test_is_diagnostic_only_for_identity(self):
        curve = CalibrationCurve(method="identity", parameters={})
        assert curve.is_diagnostic_only is True

    def test_platt_is_not_diagnostic(self):
        assert platt_curve().is_diagnostic_only is False


class TestCalibrationCurvePlatt:
    def test_sigmoid_math(self):
        curve = CalibrationCurve(method="platt", parameters={"A": 1.0, "B": 0.0})
        assert curve.calibrate(0.0) == pytest.approx(0.5)
        assert curve.calibrate(1.0) == pytest.approx(1.0 / (1.0 + math.exp(-1.0)))
        assert curve.calibrate(0.5) == pytest.approx(1.0 / (1.0 + math.exp(-0.5)))

    def test_extreme_scores_stay_finite(self):
        curve = CalibrationCurve(method="platt", parameters={"A": 100.0, "B": 0.0})
        assert curve.calibrate(1.0) == pytest.approx(1.0)
        assert curve.calibrate(0.0) == pytest.approx(0.5)

    def test_zero_coefficient_rejected(self):
        with pytest.raises(CalibrationError, match="non-zero"):
            CalibrationCurve(method="platt", parameters={"A": 0.0, "B": 0.0})

    def test_missing_parameters_raise(self):
        with pytest.raises(CalibrationError, match="parameters.A"):
            CalibrationCurve(method="platt", parameters={"B": 0.0})

    def test_non_finite_parameter_raises(self):
        with pytest.raises(CalibrationError, match="finite"):
            CalibrationCurve(method="platt", parameters={"A": float("nan"), "B": 0.0})


class TestCalibrationCurveTemperature:
    def test_softens_scores(self):
        curve = CalibrationCurve(method="temperature", parameters={"T": 2.0})
        assert curve.calibrate(0.0) == pytest.approx(0.5)
        assert curve.calibrate(1.0) == pytest.approx(1.0 / (1.0 + math.exp(-0.5)))
        assert curve.calibrate(0.5) == pytest.approx(1.0 / (1.0 + math.exp(-0.25)))

    def test_missing_T_raises(self):
        with pytest.raises(CalibrationError, match="parameters.T"):
            CalibrationCurve(method="temperature", parameters={})

    def test_non_positive_T_raises(self):
        with pytest.raises(CalibrationError, match="positive"):
            CalibrationCurve(method="temperature", parameters={"T": -1.0})
        with pytest.raises(CalibrationError, match="positive"):
            CalibrationCurve(method="temperature", parameters={"T": 0.0})


class TestCalibrationCurveIsotonic:
    def test_linear_map(self):
        curve = CalibrationCurve(
            method="isotonic", parameters={"x": [0.0, 0.5, 1.0], "y": [0.0, 0.5, 1.0]}
        )
        assert curve.calibrate(0.0) == pytest.approx(0.0)
        assert curve.calibrate(0.25) == pytest.approx(0.25)
        assert curve.calibrate(0.5) == pytest.approx(0.5)
        assert curve.calibrate(0.75) == pytest.approx(0.75)
        assert curve.calibrate(1.0) == pytest.approx(1.0)

    def test_non_linear_map_interpolates(self):
        curve = CalibrationCurve(
            method="isotonic", parameters={"x": [0.0, 0.5, 1.0], "y": [0.1, 0.2, 0.9]}
        )
        assert curve.calibrate(0.0) == pytest.approx(0.1)
        assert curve.calibrate(0.25) == pytest.approx(0.15)
        assert curve.calibrate(0.75) == pytest.approx(0.55)
        assert curve.calibrate(1.0) == pytest.approx(0.9)

    def test_out_of_range_score_raises(self):
        curve = CalibrationCurve(
            method="isotonic", parameters={"x": [0.0, 0.5, 1.0], "y": [0.0, 0.5, 1.0]}
        )
        with pytest.raises(CalibrationError, match=r"\[0, 1\]"):
            curve.calibrate(-0.1)
        with pytest.raises(CalibrationError, match=r"\[0, 1\]"):
            curve.calibrate(1.5)

    def test_x_not_strictly_increasing_raises(self):
        with pytest.raises(CalibrationError, match="strictly increasing"):
            CalibrationCurve(
                method="isotonic", parameters={"x": [0.0, 0.5, 0.5], "y": [0.0, 0.5, 1.0]}
            )

    def test_y_not_non_decreasing_raises(self):
        with pytest.raises(CalibrationError, match="non-decreasing"):
            CalibrationCurve(
                method="isotonic", parameters={"x": [0.0, 0.5, 1.0], "y": [0.0, 1.0, 0.5]}
            )

    def test_length_mismatch_raises(self):
        with pytest.raises(CalibrationError, match="same length"):
            CalibrationCurve(method="isotonic", parameters={"x": [0.0, 0.5], "y": [0.0]})

    def test_too_few_points_raises(self):
        with pytest.raises(CalibrationError, match="at least two"):
            CalibrationCurve(method="isotonic", parameters={"x": [0.0], "y": [0.5]})

    def test_missing_params_raise(self):
        with pytest.raises(CalibrationError, match="x and y sequences"):
            CalibrationCurve(method="isotonic", parameters={})

    def test_out_of_range_knot_raises(self):
        with pytest.raises(CalibrationError, match=r"\[0, 1\]"):
            CalibrationCurve(method="isotonic", parameters={"x": [0.0, 1.5], "y": [0.0, 1.0]})


class TestCalibrationCurveBeta:
    def test_symmetric_identity_at_half(self):
        curve = CalibrationCurve(method="beta", parameters={"a": 2.0, "b": 2.0})
        assert curve.calibrate(0.5) == pytest.approx(0.5)

    def test_boundaries_with_positive_coefficients(self):
        curve = CalibrationCurve(method="beta", parameters={"a": 2.0, "b": 2.0})
        assert curve.calibrate(0.0) == 0.0
        assert curve.calibrate(1.0) == 1.0

    def test_boundary_with_zero_a(self):
        # a=0: x=0 contributes 0, so the map is sigmoid(c) at the boundary.
        curve = CalibrationCurve(method="beta", parameters={"a": 0.0, "b": 2.0, "c": 0.0})
        assert curve.calibrate(0.0) == pytest.approx(0.5)
        assert curve.calibrate(1.0) == 1.0

    def test_boundary_with_zero_b(self):
        curve = CalibrationCurve(method="beta", parameters={"a": 2.0, "b": 0.0, "c": 0.0})
        assert curve.calibrate(0.0) == 0.0
        assert curve.calibrate(1.0) == pytest.approx(0.5)

    def test_monotone_in_score(self):
        curve = CalibrationCurve(method="beta", parameters={"a": 3.0, "b": 1.0})
        values = [curve.calibrate(x / 10) for x in range(11)]
        assert all(b >= a for a, b in zip(values, values[1:], strict=False))

    def test_both_zero_rejected(self):
        with pytest.raises(CalibrationError, match="degenerate"):
            CalibrationCurve(method="beta", parameters={"a": 0.0, "b": 0.0})

    def test_negative_coefficient_rejected(self):
        with pytest.raises(CalibrationError, match="non-negative"):
            CalibrationCurve(method="beta", parameters={"a": -1.0, "b": 0.0})

    def test_missing_params_raise(self):
        with pytest.raises(CalibrationError, match="parameters.a"):
            CalibrationCurve(method="beta", parameters={})


class TestCalibrationCurveIdentity:
    def test_passthrough(self):
        curve = CalibrationCurve(method="identity", parameters={})
        assert curve.calibrate(0.7) == 0.7

    def test_parameters_rejected(self):
        with pytest.raises(CalibrationError, match="no parameters"):
            CalibrationCurve(method="identity", parameters={"A": 1.0})

    def test_out_of_range_score_raises(self):
        curve = CalibrationCurve(method="identity", parameters={})
        with pytest.raises(CalibrationError):
            curve.calibrate(1.2)


class TestCalibrationCurveSerialization:
    @pytest.mark.parametrize(
        "curve",
        [
            platt_curve(),
            CalibrationCurve(method="temperature", parameters={"T": 2.0}),
            CalibrationCurve(
                method="isotonic", parameters={"x": [0.0, 0.5, 1.0], "y": [0.0, 0.5, 1.0]}
            ),
            CalibrationCurve(method="beta", parameters={"a": 2.0, "b": 1.0, "c": 0.5}),
            CalibrationCurve(method="identity", parameters={}),
        ],
        ids=["platt", "temperature", "isotonic", "beta", "identity"],
    )
    def test_round_trip_preserves_behavior(self, curve: CalibrationCurve):
        restored = CalibrationCurve.from_dict(curve.to_dict())
        for score in (0.0, 0.25, 0.5, 0.75, 1.0):
            assert restored.calibrate(score) == pytest.approx(curve.calibrate(score))

    def test_round_trip_preserves_metadata(self):
        original = platt_curve()
        restored = CalibrationCurve.from_dict(original.to_dict())
        assert restored.method == "platt"
        assert restored.parameters == {"A": 1.0, "B": 0.0}
        assert restored.reference_dataset_hash == hex64(1)
        assert restored.sample_count == 200
        assert restored.calibrated_at == "2024-01-01T00:00:00Z"

    def test_from_dict_non_mapping_raises(self):
        with pytest.raises(CalibrationError, match="mapping"):
            CalibrationCurve.from_dict("nope")  # type: ignore[arg-type]

    def test_from_dict_missing_method_raises(self):
        with pytest.raises(CalibrationError, match="method"):
            CalibrationCurve.from_dict({"parameters": {}})

    def test_from_dict_unknown_method_raises(self):
        with pytest.raises(CalibrationError, match="Unsupported calibration method"):
            CalibrationCurve.from_dict({"method": "mystery", "parameters": {}})

    def test_from_dict_score_range_wrong_shape_raises(self):
        with pytest.raises(CalibrationError, match="score_range"):
            CalibrationCurve.from_dict(
                {"method": "identity", "parameters": {}, "score_range": [0.0]}
            )


# ---------------------------------------------------------------------------
# DatasetReference
# ---------------------------------------------------------------------------


class TestDatasetReference:
    def test_valid_reference(self):
        ref = DatasetReference(
            name="raid", fingerprint_sha256=hex64(5), split="test", sample_count=1000
        )
        assert ref.name == "raid"
        assert ref.manifest_sha256 is None

    def test_invalid_fingerprint_raises(self):
        with pytest.raises(CalibrationError, match="fingerprint"):
            DatasetReference(name="x", fingerprint_sha256="deadbeef", split="test", sample_count=1)

    def test_non_positive_sample_count_raises(self):
        with pytest.raises(CalibrationError, match="sample_count"):
            DatasetReference(name="x", fingerprint_sha256=hex64(5), split="test", sample_count=0)

    def test_bool_sample_count_raises(self):
        with pytest.raises(CalibrationError, match="sample_count"):
            DatasetReference(name="x", fingerprint_sha256=hex64(5), split="test", sample_count=True)

    def test_empty_name_raises(self):
        with pytest.raises(CalibrationError, match="name"):
            DatasetReference(name="  ", fingerprint_sha256=hex64(5), split="test", sample_count=1)

    def test_invalid_manifest_hash_raises(self):
        with pytest.raises(CalibrationError, match="manifest"):
            DatasetReference(
                name="x",
                fingerprint_sha256=hex64(5),
                split="test",
                sample_count=1,
                manifest_sha256="zzz",
            )

    def test_round_trip(self):
        ref = DatasetReference(
            name="raid",
            fingerprint_sha256=hex64(5),
            split="test",
            sample_count=1000,
            manifest_sha256=hex64(6),
            license="CC-BY-4.0",
        )
        restored = DatasetReference.from_dict(ref.to_dict())
        assert restored == ref


# ---------------------------------------------------------------------------
# CalibrationArtifact eligibility
# ---------------------------------------------------------------------------


class TestCalibrationArtifactEligibility:
    def test_eligible_artifact_has_no_issues(self):
        artifact = eligible_artifact()
        assert artifact.validation_issues() == []
        assert artifact.eligible_for_probability is True
        assert artifact.calibration_status == "validated"

    def test_missing_fit_dataset(self):
        kwargs = eligible_artifact_kwargs()
        del kwargs["fit_dataset"]
        artifact = CalibrationArtifact(
            artifact_id="d:c",
            detector_id="d",
            detector_version="1",
            curve=platt_curve(),
            calibration_id="c",
            **kwargs,
        )
        assert "fit_dataset is required for probability eligibility" in artifact.validation_issues()
        assert artifact.calibration_status == "incomplete"

    def test_missing_evaluation_dataset(self):
        kwargs = eligible_artifact_kwargs()
        del kwargs["evaluation_dataset"]
        artifact = CalibrationArtifact(
            artifact_id="d:c",
            detector_id="d",
            detector_version="1",
            curve=platt_curve(),
            calibration_id="c",
            **kwargs,
        )
        assert (
            "evaluation_dataset is required for probability eligibility"
            in artifact.validation_issues()
        )
        kwargs = eligible_artifact_kwargs()
        del kwargs["evaluation_dataset"]
        artifact = CalibrationArtifact(
            artifact_id="d:c",
            detector_id="d",
            detector_version="1",
            curve=platt_curve(),
            calibration_id="c",
            **kwargs,
        )
        assert (
            "evaluation_dataset is required for probability eligibility"
            in artifact.validation_issues()
        )

    def test_no_datasets_is_incomplete(self):
        artifact = CalibrationArtifact(
            artifact_id="d:c",
            detector_id="d",
            detector_version="1",
            curve=platt_curve(),
            calibration_id="c",
        )
        assert artifact.calibration_status == "incomplete"
        assert artifact.eligible_for_probability is False

    def test_same_fingerprints_rejected(self):
        kwargs = eligible_artifact_kwargs()
        kwargs["evaluation_dataset"] = DatasetReference(
            name="same", fingerprint_sha256=hex64(2), split="test", sample_count=200
        )
        artifact = CalibrationArtifact(
            artifact_id="d:c",
            detector_id="d",
            detector_version="1",
            curve=platt_curve(),
            calibration_id="c",
            **kwargs,
        )
        assert "fit and evaluation dataset fingerprints must differ" in artifact.validation_issues()

    def test_evaluation_split_must_be_held_out(self):
        kwargs = eligible_artifact_kwargs()
        kwargs["evaluation_dataset"] = DatasetReference(
            name="eval", fingerprint_sha256=hex64(3), split="train", sample_count=200
        )
        artifact = CalibrationArtifact(
            artifact_id="d:c",
            detector_id="d",
            detector_version="1",
            curve=platt_curve(),
            calibration_id="c",
            **kwargs,
        )
        issues = artifact.validation_issues()
        assert any("held-out split" in issue for issue in issues)
        # Same split as fit is also rejected.
        assert any("splits must differ" in issue for issue in issues)

    def test_sample_size_floor(self):
        assert MIN_CALIBRATION_SAMPLES == 100
        kwargs = eligible_artifact_kwargs()
        kwargs["evaluation_dataset"] = DatasetReference(
            name="eval", fingerprint_sha256=hex64(3), split="test", sample_count=99
        )
        artifact = CalibrationArtifact(
            artifact_id="d:c",
            detector_id="d",
            detector_version="1",
            curve=platt_curve(),
            calibration_id="c",
            **kwargs,
        )
        assert any("at least 100" in issue for issue in artifact.validation_issues())

    def test_missing_disjointness_declaration(self):
        kwargs = eligible_artifact_kwargs()
        kwargs["disjointness"] = {}
        artifact = CalibrationArtifact(
            artifact_id="d:c",
            detector_id="d",
            detector_version="1",
            curve=platt_curve(),
            calibration_id="c",
            **kwargs,
        )
        assert "disjointness declaration is required" in artifact.validation_issues()

    def test_disjointness_without_evidence(self):
        kwargs = eligible_artifact_kwargs()
        kwargs["disjointness"] = {"strategy": "x"}
        artifact = CalibrationArtifact(
            artifact_id="d:c",
            detector_id="d",
            detector_version="1",
            curve=platt_curve(),
            calibration_id="c",
            **kwargs,
        )
        assert any("must record evidence" in issue for issue in artifact.validation_issues())

    def test_disjointness_manifest_accepted(self):
        kwargs = eligible_artifact_kwargs()
        kwargs["disjointness"] = {"strategy": "x", "sample_id_manifest_sha256": hex64(7)}
        artifact = CalibrationArtifact(
            artifact_id="d:c",
            detector_id="d",
            detector_version="1",
            curve=platt_curve(),
            calibration_id="c",
            **kwargs,
        )
        assert artifact.eligible_for_probability is True

    def test_missing_metrics(self):
        kwargs = eligible_artifact_kwargs()
        kwargs["metrics"] = {}
        artifact = CalibrationArtifact(
            artifact_id="d:c",
            detector_id="d",
            detector_version="1",
            curve=platt_curve(),
            calibration_id="c",
            **kwargs,
        )
        issues = artifact.validation_issues()
        assert "metrics.brier is required for probability eligibility" in issues
        assert "metrics.ece is required for probability eligibility" in issues
        assert "metrics.log_loss is required for probability eligibility" in issues

    def test_metric_out_of_range(self):
        kwargs = eligible_artifact_kwargs()
        kwargs["metrics"] = {"brier": 1.5, "ece": 0.05, "log_loss": 0.3}
        artifact = CalibrationArtifact(
            artifact_id="d:c",
            detector_id="d",
            detector_version="1",
            curve=platt_curve(),
            calibration_id="c",
            **kwargs,
        )
        assert any("outside its valid range" in issue for issue in artifact.validation_issues())

    def test_negative_log_loss_rejected(self):
        kwargs = eligible_artifact_kwargs()
        kwargs["metrics"] = {"brier": 0.1, "ece": 0.05, "log_loss": -0.1}
        artifact = CalibrationArtifact(
            artifact_id="d:c",
            detector_id="d",
            detector_version="1",
            curve=platt_curve(),
            calibration_id="c",
            **kwargs,
        )
        assert any("outside its valid range" in issue for issue in artifact.validation_issues())

    def test_missing_code_version_and_run_artifact(self):
        kwargs = eligible_artifact_kwargs()
        kwargs["code_version"] = None
        kwargs["run_artifact_sha256"] = None
        artifact = CalibrationArtifact(
            artifact_id="d:c",
            detector_id="d",
            detector_version="1",
            curve=platt_curve(),
            calibration_id="c",
            **kwargs,
        )
        issues = artifact.validation_issues()
        assert "code_version is required for probability eligibility" in issues
        assert "run_artifact_sha256 is required for probability eligibility" in issues
        assert artifact.calibration_status == "evaluated_incomplete"

    def test_identity_is_diagnostic_only(self):
        artifact = CalibrationArtifact(
            artifact_id="d:c",
            detector_id="d",
            detector_version="1",
            curve=CalibrationCurve(method="identity", parameters={}),
            calibration_id="c",
            **eligible_artifact_kwargs(),
        )
        assert any("diagnostic only" in issue for issue in artifact.validation_issues())
        assert artifact.calibration_status == "diagnostic"
        assert artifact.eligible_for_probability is False

    def test_empty_required_strings_raise_at_construction(self):
        # Empty detector_id / detector_version / calibration_id are structural
        # errors that surface during construction, not as validation issues.
        with pytest.raises(CalibrationError, match="detector_id"):
            CalibrationArtifact(
                artifact_id="d:c",
                detector_id="",
                detector_version="1",
                curve=platt_curve(),
                calibration_id="c",
            )
        with pytest.raises(CalibrationError, match="detector_version"):
            CalibrationArtifact(
                artifact_id="d:c",
                detector_id="d",
                detector_version="",
                curve=platt_curve(),
                calibration_id="c",
            )
        with pytest.raises(CalibrationError, match="calibration_id"):
            CalibrationArtifact(
                artifact_id="d:c",
                detector_id="d",
                detector_version="1",
                curve=platt_curve(),
                calibration_id="",
            )

    def test_invalid_created_at_raises(self):
        with pytest.raises(CalibrationError, match="created_at"):
            CalibrationArtifact(
                artifact_id="d:c",
                detector_id="d",
                detector_version="1",
                curve=platt_curve(),
                calibration_id="c",
                created_at="not-a-date",
            )

    def test_invalid_run_artifact_hash_raises(self):
        with pytest.raises(CalibrationError, match="run_artifact_sha256"):
            CalibrationArtifact(
                artifact_id="d:c",
                detector_id="d",
                detector_version="1",
                curve=platt_curve(),
                calibration_id="c",
                run_artifact_sha256="nope",
            )

    def test_non_mapping_disjointness_raises(self):
        with pytest.raises(CalibrationError, match="disjointness"):
            CalibrationArtifact(
                artifact_id="d:c",
                detector_id="d",
                detector_version="1",
                curve=platt_curve(),
                calibration_id="c",
                disjointness=["x"],  # type: ignore[arg-type]
            )

    def test_non_mapping_metrics_raises(self):
        with pytest.raises(CalibrationError, match="metrics"):
            CalibrationArtifact(
                artifact_id="d:c",
                detector_id="d",
                detector_version="1",
                curve=platt_curve(),
                calibration_id="c",
                metrics=["x"],  # type: ignore[arg-type]
            )

    def test_curve_must_be_curve_instance(self):
        with pytest.raises(CalibrationError, match="curve must be a CalibrationCurve"):
            CalibrationArtifact(
                artifact_id="d:c",
                detector_id="d",
                detector_version="1",
                curve={"method": "platt"},  # type: ignore[arg-type]
                calibration_id="c",
            )


class TestCalibrationArtifactApplication:
    def test_apply_on_eligible_returns_validated(self):
        artifact = eligible_artifact()
        result = artifact.apply(0.5)
        assert isinstance(result, CalibrationResult)
        assert result.status == "validated"
        assert result.probability_eligible is True
        assert result.calibration_id == "cal1"
        assert result.value == pytest.approx(0.6224593312018546)

    def test_apply_on_ineligible_raises_by_default(self):
        artifact = CalibrationArtifact(
            artifact_id="d:c",
            detector_id="d",
            detector_version="1",
            curve=platt_curve(),
            calibration_id="c",
        )
        with pytest.raises(CalibrationError, match="not eligible for probability emission"):
            artifact.apply(0.5)

    def test_apply_allow_unvalidated_marks_status(self):
        artifact = CalibrationArtifact(
            artifact_id="d:c",
            detector_id="d",
            detector_version="1",
            curve=platt_curve(),
            calibration_id="c",
        )
        result = artifact.apply(0.5, allow_unvalidated=True)
        assert result.status == "unvalidated"
        assert result.probability_eligible is False

    def test_calibrate_mirrors_apply_value(self):
        artifact = eligible_artifact()
        assert artifact.calibrate(0.5) == artifact.apply(0.5).value

    def test_calibrate_raises_for_ineligible(self):
        artifact = CalibrationArtifact(
            artifact_id="d:c",
            detector_id="d",
            detector_version="1",
            curve=platt_curve(),
            calibration_id="c",
        )
        with pytest.raises(CalibrationError):
            artifact.calibrate(0.5)

    def test_calibrate_allow_unvalidated(self):
        artifact = CalibrationArtifact(
            artifact_id="d:c",
            detector_id="d",
            detector_version="1",
            curve=platt_curve(),
            calibration_id="c",
        )
        assert artifact.calibrate(0.5, allow_unvalidated=True) == pytest.approx(0.6224593312018546)


class TestCalibrationArtifactContentHash:
    def test_deterministic_across_instances(self):
        first = eligible_artifact()
        second = CalibrationArtifact(
            artifact_id="other:id",
            detector_id="det1",
            detector_version="1.0",
            curve=platt_curve(),
            calibration_id="cal1",
            created_at="2024-01-01T00:00:00+00:00",
            **eligible_artifact_kwargs(),
        )
        assert first.content_hash == second.content_hash

    def test_changes_on_curve_change(self):
        first = eligible_artifact()
        kwargs = eligible_artifact_kwargs()
        other = CalibrationArtifact(
            artifact_id="det1:cal1",
            detector_id="det1",
            detector_version="1.0",
            curve=CalibrationCurve(method="platt", parameters={"A": 2.0, "B": 0.0}),
            calibration_id="cal1",
            created_at="2024-01-01T00:00:00+00:00",
            **kwargs,
        )
        assert first.content_hash != other.content_hash

    def test_changes_on_metrics_change(self):
        first = eligible_artifact()
        kwargs = eligible_artifact_kwargs()
        kwargs["metrics"] = {"brier": 0.2, "ece": 0.05, "log_loss": 0.3}
        other = CalibrationArtifact(
            artifact_id="det1:cal1",
            detector_id="det1",
            detector_version="1.0",
            curve=platt_curve(),
            calibration_id="cal1",
            created_at="2024-01-01T00:00:00+00:00",
            **kwargs,
        )
        assert first.content_hash != other.content_hash

    def test_tampered_content_hash_rejected(self):
        payload = eligible_artifact().to_dict()
        payload["metrics"]["brier"] = 0.99  # tamper without recomputing the hash
        with pytest.raises(CalibrationError, match="content_hash does not match"):
            CalibrationArtifact.from_dict(payload)

    def test_malformed_content_hash_rejected(self):
        payload = eligible_artifact().to_dict()
        payload["content_hash"] = "deadbeef"
        with pytest.raises(CalibrationError, match="content_hash"):
            CalibrationArtifact.from_dict(payload)

    def test_from_dict_round_trip_preserves_eligibility(self):
        artifact = eligible_artifact()
        restored = CalibrationArtifact.from_dict(artifact.to_dict())
        assert restored == artifact
        assert restored.eligible_for_probability is True

    def test_from_dict_missing_required_keys_raise(self):
        payload = eligible_artifact().to_dict()
        del payload["artifact_id"]
        with pytest.raises(KeyError):
            CalibrationArtifact.from_dict(payload)


# ---------------------------------------------------------------------------
# CalibrationManager
# ---------------------------------------------------------------------------


class TestCalibrationManager:
    @pytest.fixture
    def storage(self):
        with tempfile.TemporaryDirectory() as td:
            yield Path(td)

    def test_store_and_get(self, storage):
        mgr = CalibrationManager(storage)
        artifact = store_eligible(mgr, "det1", "cal1")
        retrieved = mgr.get("det1:cal1")
        assert retrieved is not None
        assert retrieved == artifact
        assert retrieved.eligible_for_probability is True

    def test_generated_calibration_id_is_deterministic(self, storage):
        mgr = CalibrationManager(storage)
        first = mgr.store(
            "det2",
            "1.0",
            platt_curve(),
            created_at="2024-01-01T00:00:00+00:00",
        )
        second = CalibrationManager(storage).store(
            "det2",
            "1.0",
            platt_curve(),
            created_at="2024-01-01T00:00:00+00:00",
        )
        assert first.calibration_id == second.calibration_id
        assert first.artifact_id == f"det2:{first.calibration_id}"

    def test_store_rejects_artifact_id_reuse_with_different_content(self, storage):
        mgr = CalibrationManager(storage)
        store_eligible(mgr, "det1", "cal1")
        with pytest.raises(CalibrationError, match="different content"):
            mgr.store(
                "det1",
                "1.0",
                CalibrationCurve(method="platt", parameters={"A": 2.0, "B": 0.0}),
                calibration_id="cal1",
                created_at="2024-01-01T00:00:00+00:00",
            )

    def test_store_is_idempotent_for_identical_content(self, storage):
        mgr = CalibrationManager(storage)
        first = store_eligible(mgr, "det1", "cal1")
        second = store_eligible(mgr, "det1", "cal1")
        assert first == second
        assert len(list(storage.glob("*.json"))) == 1

    def test_get_nonexistent_returns_none(self, storage):
        assert CalibrationManager(storage).get("missing") is None

    def test_get_latest_for_detector_prefers_newest(self, storage):
        mgr = CalibrationManager(storage)
        store_eligible(mgr, "det1", "cal1")
        artifact = mgr.store(
            "det1",
            "1.0",
            platt_curve(),
            calibration_id="cal2",
            created_at="2025-06-01T00:00:00+00:00",
        )
        latest = mgr.get_latest_for_detector("det1")
        assert latest is not None
        assert latest.calibration_id == "cal2"
        assert latest == artifact

    def test_get_latest_for_unknown_detector(self, storage):
        assert CalibrationManager(storage).get_latest_for_detector("ghost") is None

    def test_get_lineage_sorted_oldest_first(self, storage):
        mgr = CalibrationManager(storage)
        store_eligible(mgr, "det1", "cal2")
        mgr.store(
            "det1",
            "1.0",
            platt_curve(),
            calibration_id="cal1",
            created_at="2023-01-01T00:00:00+00:00",
        )
        lineage = mgr.get_lineage("det1")
        assert [item.calibration_id for item in lineage] == ["cal1", "cal2"]

    def test_filename_is_content_hash(self, storage):
        mgr = CalibrationManager(storage)
        artifact = store_eligible(mgr, "det1", "cal1")
        assert list(storage.glob("*.json")) == [storage / f"{artifact.content_hash}.json"]

    def test_atomic_save_leaves_no_temp_files(self, storage):
        mgr = CalibrationManager(storage)
        store_eligible(mgr, "det1", "cal1")
        assert [path.name for path in storage.iterdir()] == [
            f"{store_eligible(mgr, 'det1', 'cal1').content_hash}.json"
        ]

    def test_reload_preserves_artifacts(self, storage):
        mgr = CalibrationManager(storage)
        original = store_eligible(mgr, "det1", "cal1")
        reloaded = CalibrationManager(storage)
        assert reloaded.get("det1:cal1") == original

    def test_corrupt_file_fails_closed(self, storage):
        (storage / "bad.json").write_text("not json", encoding="utf-8")
        with pytest.raises(CalibrationError, match="bad.json"):
            CalibrationManager(storage)

    def test_duplicate_content_hash_fails_closed(self, storage):
        artifact = eligible_artifact()
        rendered = json.dumps(artifact.to_dict(), indent=2) + "\n"
        (storage / f"{artifact.content_hash}.json").write_text(rendered, encoding="utf-8")
        (storage / "copy.json").write_text(rendered, encoding="utf-8")
        with pytest.raises(CalibrationError, match="Duplicate calibration content hash"):
            CalibrationManager(storage)

    def test_duplicate_artifact_id_with_different_content_fails_closed(self, storage):
        first = eligible_artifact()
        second = CalibrationArtifact(
            artifact_id="det1:cal1",
            detector_id="det1",
            detector_version="2.0",
            curve=platt_curve(),
            calibration_id="cal1",
            created_at="2024-01-01T00:00:00+00:00",
            **eligible_artifact_kwargs(),
        )
        assert first.content_hash != second.content_hash
        for artifact in (first, second):
            (storage / f"{artifact.content_hash}.json").write_text(
                json.dumps(artifact.to_dict(), indent=2) + "\n", encoding="utf-8"
            )
        with pytest.raises(CalibrationError, match="two different contents"):
            CalibrationManager(storage)


class TestCalibrationManagerValidation:
    @pytest.fixture
    def storage(self):
        with tempfile.TemporaryDirectory() as td:
            yield Path(td)

    @pytest.fixture
    def jsonl(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as handle:
            for index in range(50):
                score = 0.2 if index % 2 == 0 else 0.8
                label = "human" if index % 2 == 0 else "ai"
                handle.write(json.dumps({"score": score, "label": label}) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
            path = Path(handle.name)
        yield path
        path.unlink(missing_ok=True)

    def test_validate_artifact_reports_metrics(self, storage, jsonl):
        mgr = CalibrationManager(storage)
        store_eligible(mgr, "det1", "cal1")
        results = mgr.validate_artifact("det1:cal1", jsonl, strict=True)
        assert set(results) == {"brier", "ece", "log_loss", "sample_count", "positive_rate"}
        assert results["sample_count"] == 50
        assert results["positive_rate"] == 0.5
        assert 0.0 <= results["brier"] <= 1.0
        assert 0.0 <= results["ece"] <= 1.0
        assert results["log_loss"] >= 0.0

    def test_validate_artifact_missing_artifact(self, storage, jsonl):
        mgr = CalibrationManager(storage)
        with pytest.raises(CalibrationError, match="Artifact not found"):
            mgr.validate_artifact("ghost", jsonl)

    def test_validate_artifact_invalid_json_strict(self, storage, jsonl):
        mgr = CalibrationManager(storage)
        store_eligible(mgr, "det1", "cal1")
        bad = storage / "bad.jsonl"
        bad.write_text("not json\n", encoding="utf-8")
        with pytest.raises(CalibrationError, match="invalid JSON"):
            mgr.validate_artifact("det1:cal1", bad, strict=True)

    def test_validate_artifact_invalid_json_non_strict_skips(self, storage, jsonl):
        mgr = CalibrationManager(storage)
        store_eligible(mgr, "det1", "cal1")
        bad = storage / "bad.jsonl"
        bad.write_text(
            "not json\n" + json.dumps({"score": 0.5, "label": "ai"}) + "\n", encoding="utf-8"
        )
        results = mgr.validate_artifact("det1:cal1", bad, strict=False)
        assert results["sample_count"] == 1

    def test_validate_artifact_missing_fields_strict(self, storage, jsonl):
        mgr = CalibrationManager(storage)
        store_eligible(mgr, "det1", "cal1")
        bad = storage / "missing.jsonl"
        bad.write_text(json.dumps({"score": 0.5}) + "\n", encoding="utf-8")
        with pytest.raises(CalibrationError, match="missing score or label"):
            mgr.validate_artifact("det1:cal1", bad, strict=True)

    def test_validate_artifact_missing_fields_non_strict_skips(self, storage, jsonl):
        mgr = CalibrationManager(storage)
        store_eligible(mgr, "det1", "cal1")
        bad = storage / "missing.jsonl"
        bad.write_text(
            json.dumps({"score": 0.5}) + "\n" + json.dumps({"score": 0.5, "label": "ai"}) + "\n",
            encoding="utf-8",
        )
        results = mgr.validate_artifact("det1:cal1", bad, strict=False)
        assert results["sample_count"] == 1

    def test_validate_artifact_invalid_label_strict(self, storage, jsonl):
        mgr = CalibrationManager(storage)
        store_eligible(mgr, "det1", "cal1")
        bad = storage / "label.jsonl"
        bad.write_text(json.dumps({"score": 0.5, "label": "maybe"}) + "\n", encoding="utf-8")
        with pytest.raises(CalibrationError, match="invalid label"):
            mgr.validate_artifact("det1:cal1", bad, strict=True)

    def test_validate_artifact_invalid_label_non_strict_skips(self, storage, jsonl):
        mgr = CalibrationManager(storage)
        store_eligible(mgr, "det1", "cal1")
        bad = storage / "label.jsonl"
        bad.write_text(
            json.dumps({"score": 0.5, "label": "maybe"})
            + "\n"
            + json.dumps({"score": 0.5, "label": "ai"})
            + "\n",
            encoding="utf-8",
        )
        results = mgr.validate_artifact("det1:cal1", bad, strict=False)
        assert results["sample_count"] == 1

    def test_validate_artifact_out_of_range_score_strict(self, storage, jsonl):
        mgr = CalibrationManager(storage)
        store_eligible(mgr, "det1", "cal1")
        bad = storage / "score.jsonl"
        bad.write_text(json.dumps({"score": 1.5, "label": "ai"}) + "\n", encoding="utf-8")
        with pytest.raises(CalibrationError, match="invalid score"):
            mgr.validate_artifact("det1:cal1", bad, strict=True)

    def test_validate_artifact_empty_dataset_raises(self, storage):
        mgr = CalibrationManager(storage)
        store_eligible(mgr, "det1", "cal1")
        empty = storage / "empty.jsonl"
        empty.write_text("", encoding="utf-8")
        with pytest.raises(CalibrationError, match="No valid samples"):
            mgr.validate_artifact("det1:cal1", empty)

    def test_validate_artifact_works_on_ineligible_artifact(self, storage, jsonl):
        # Measurement is independent of probability eligibility.
        mgr = CalibrationManager(storage)
        mgr.store(
            "det2",
            "1.0",
            platt_curve(),
            calibration_id="cal1",
            created_at="2024-01-01T00:00:00+00:00",
        )
        results = mgr.validate_artifact("det2:cal1", jsonl)
        assert results["sample_count"] == 50


class TestCalibrationManagerScores:
    @pytest.fixture
    def storage(self):
        with tempfile.TemporaryDirectory() as td:
            yield Path(td)

    def test_get_calibrated_score_on_eligible(self, storage):
        mgr = CalibrationManager(storage)
        store_eligible(mgr, "det1", "cal1")
        value = mgr.get_calibrated_score("det1", 0.5)
        assert value is not None
        assert 0.0 <= value <= 1.0

    def test_get_calibrated_score_on_ineligible_raises(self, storage):
        mgr = CalibrationManager(storage)
        mgr.store(
            "det1",
            "1.0",
            platt_curve(),
            calibration_id="cal1",
            created_at="2024-01-01T00:00:00+00:00",
        )
        with pytest.raises(CalibrationError, match="not eligible"):
            mgr.get_calibrated_score("det1", 0.5)

    def test_get_calibrated_score_allow_unvalidated(self, storage):
        mgr = CalibrationManager(storage)
        mgr.store(
            "det1",
            "1.0",
            platt_curve(),
            calibration_id="cal1",
            created_at="2024-01-01T00:00:00+00:00",
        )
        value = mgr.get_calibrated_score("det1", 0.5, allow_unvalidated=True)
        assert value == pytest.approx(0.6224593312018546)

    def test_get_calibrated_score_unknown_detector_returns_none(self, storage):
        assert CalibrationManager(storage).get_calibrated_score("ghost", 0.5) is None

    def test_get_calibrated_result_on_eligible(self, storage):
        mgr = CalibrationManager(storage)
        store_eligible(mgr, "det1", "cal1")
        result = mgr.get_calibrated_result("det1", 0.5)
        assert result is not None
        assert result.status == "validated"
        assert result.probability_eligible is True

    def test_get_calibrated_result_on_ineligible_raises(self, storage):
        mgr = CalibrationManager(storage)
        mgr.store(
            "det1",
            "1.0",
            platt_curve(),
            calibration_id="cal1",
            created_at="2024-01-01T00:00:00+00:00",
        )
        with pytest.raises(CalibrationError):
            mgr.get_calibrated_result("det1", 0.5)

    def test_get_calibrated_result_unknown_detector_returns_none(self, storage):
        assert CalibrationManager(storage).get_calibrated_result("ghost", 0.5) is None


# ---------------------------------------------------------------------------
# Helpers and convenience functions
# ---------------------------------------------------------------------------


class TestValidateCalibrationArtifactFunction:
    def test_returns_issues_for_ineligible(self):
        artifact = CalibrationArtifact(
            artifact_id="d:c",
            detector_id="d",
            detector_version="1",
            curve=platt_curve(),
            calibration_id="c",
        )
        issues = validate_calibration_artifact(artifact)
        assert isinstance(issues, list)
        assert "fit_dataset is required for probability eligibility" in issues

    def test_returns_empty_for_eligible(self):
        assert validate_calibration_artifact(eligible_artifact()) == []

    def test_rejects_non_artifact(self):
        with pytest.raises(CalibrationError, match="must be a CalibrationArtifact"):
            validate_calibration_artifact({"not": "an artifact"})  # type: ignore[arg-type]


class TestProbabilityMetrics:
    def test_perfect_predictions(self):
        metrics = _probability_metrics([1.0, 0.0], [1, 0])
        assert metrics["brier"] == pytest.approx(0.0)
        assert metrics["log_loss"] == pytest.approx(0.0)
        assert metrics["ece"] == pytest.approx(0.0)

    def test_known_values(self):
        metrics = _probability_metrics([0.2, 0.8], [0, 1])
        assert metrics["brier"] == pytest.approx(0.04)
        assert metrics["log_loss"] == pytest.approx(0.2231435513142097)
        assert metrics["ece"] == pytest.approx(0.2)
        assert metrics["sample_count"] == 2
        assert metrics["positive_rate"] == pytest.approx(0.5)

    def test_worst_predictions(self):
        metrics = _probability_metrics([0.0, 1.0], [1, 0])
        assert metrics["brier"] == pytest.approx(1.0)

    def test_empty_raises(self):
        with pytest.raises(CalibrationError, match="non-empty"):
            _probability_metrics([], [])

    def test_length_mismatch_raises(self):
        with pytest.raises(CalibrationError, match="equally sized"):
            _probability_metrics([0.5], [1, 0])


class TestCoerceLabel:
    @pytest.mark.parametrize("value", [1, True, "ai", "AI", "machine", "1", "true", " True "])
    def test_positive(self, value):
        assert _coerce_label(value) == 1

    @pytest.mark.parametrize("value", [0, False, "human", "HUMAN", "0", "false", " False "])
    def test_negative(self, value):
        assert _coerce_label(value) == 0

    @pytest.mark.parametrize("value", ["maybe", "2", None, 0.5, [], {}])
    def test_invalid(self, value):
        assert _coerce_label(value) is None


class TestConvenienceFunctions:
    def test_create_calibration_manager(self):
        with tempfile.TemporaryDirectory() as td:
            mgr = create_calibration_manager(td)
            assert isinstance(mgr, CalibrationManager)
            assert mgr.storage_path == Path(td)

    def test_save_and_load_round_trip(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "nested" / "artifact.json"
            artifact = eligible_artifact()
            save_calibration_artifact(artifact, path)
            assert path.exists()
            loaded = load_calibration_artifact(path)
            assert loaded == artifact

    def test_load_invalid_json_raises_calibration_error(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "artifact.json"
            path.write_text("not json", encoding="utf-8")
            with pytest.raises(CalibrationError, match="not valid JSON"):
                load_calibration_artifact(path)

    def test_load_missing_file_raises_calibration_error(self):
        with pytest.raises(CalibrationError, match="Failed to read"):
            load_calibration_artifact("does-not-exist.json")

    def test_load_non_object_raises_calibration_error(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "artifact.json"
            path.write_text("[]", encoding="utf-8")
            with pytest.raises(CalibrationError, match="JSON object"):
                load_calibration_artifact(path)


# ---------------------------------------------------------------------------
# Mutation kill tests (Phase 5, calibration prefix-200 batch)
# ---------------------------------------------------------------------------

#: Texts whose builtin-heuristic scores are separable: the "human" text
#: scores ~0.216 and the "AI" text ~0.663, so a threshold between them has
#: FPR 0 and TPR 1. Distinct suffixes keep calibration/evaluation rows
#: disjoint for the contamination checks.
_HUMAN_TEXT = (
    "I ran this test yesterday. The first result looked odd, "
    "so I changed one cable and wrote down the second result."
)
_AI_TEXT = (
    "Furthermore, it is important to note that this robust solution "
    "seamlessly unlocks the potential of an ever-evolving landscape."
)


def _write_scored_rows(path: Path, human_suffix: str, ai_suffix: str) -> None:
    """Write 4 human + 4 AI rows (label + text) to a JSONL file."""
    rows = [
        {"label": "human", "text": f"{_HUMAN_TEXT} {human_suffix} {index}"} for index in range(4)
    ] + [{"label": "ai", "text": f"{_AI_TEXT} {ai_suffix} {index}"} for index in range(4)]
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


class TestCalibrationMutationKillTests:
    """Behaviour tests that distinguish the original calibration.py from
    each surviving cosmic-ray mutant in the Phase 5 prefix-200 batch
    (indices [8], [114]-[128], [131], [132], [143], [144], [153],
    [161]-[163], [166], [167], [179], [181], [182], [186] of the
    classification table). Each test asserts real, observable behaviour
    — a value, a raised error, or a validation issue — never merely
    that a call succeeds.

    NOT covered here (genuinely equivalent, reported to the
    coordinator — no existing baseline kind fits them):
    [130] ExceptionReplacer on the ``except CalibrationError`` in
    ``CalibrationArtifact.validation_issues`` (dead handler:
    ``__post_init__`` validates ``created_at`` first, so no live
    instance can reach it); [147]/[148] NumberReplacer on the
    ``_sigmoid`` branch threshold (the two branches are algebraically
    identical; hand-applied mutants differ by at most 2 ulps over a
    40,000-point sweep of [-20, 20]).
    """

    # -- _parse_iso8601 ([8], [161], [162]) ------------------------------

    def test_parse_iso8601_keeps_explicit_offset(self):
        # Mutant [8] negates `if parsed.tzinfo is None:`: an explicit
        # +05:00 offset would be overwritten with UTC.
        parsed = _parse_iso8601("2024-01-01T00:00:00+05:00", "created_at")
        assert parsed.utcoffset() == timedelta(hours=5)

    def test_parse_iso8601_zulu_suffix(self):
        # Mutants [161] (1 -> 2) and [162] (1 -> 0) in `text[:-1]`
        # corrupt the "Z" strip, so parsing a Zulu timestamp raises.
        parsed = _parse_iso8601("2024-01-01T00:00:00Z", "created_at")
        assert parsed == datetime(2024, 1, 1, 0, 0, tzinfo=UTC)

    # -- _sigmoid ([153]) -------------------------------------------------

    def test_sigmoid_negative_branch_value(self):
        # Mutant [153] (1.0 -> 2.0) in `z / (1.0 + z)`: Platt with
        # A=1, B=-1 at score 0 evaluates _sigmoid(-1) = 1 / (1 + e).
        curve = CalibrationCurve(method="platt", parameters={"A": 1.0, "B": -1.0})
        assert curve.calibrate(0.0) == pytest.approx(0.2689414213699951)

    # -- CalibrationCurve defaults ([163], [166], [167]) ------------------

    def test_curve_default_sample_count_is_zero(self):
        # Mutant [163] (0 -> 1): the default sample_count would be 1.
        curve = CalibrationCurve(method="platt", parameters={"A": 1.0, "B": 0.0})
        assert curve.sample_count == 0

    def test_curve_default_score_range(self):
        # Mutants [166] (0.0 -> -1.0) and [167] (1.0 -> 2.0): the
        # default score_range would be (-1.0, 1.0) or (0.0, 2.0).
        curve = CalibrationCurve(method="platt", parameters={"A": 1.0, "B": 0.0})
        assert curve.score_range == (0.0, 1.0)

    # -- Curve parameter validation ([179], [181], [182], [186]) ----------

    def test_temperature_fractional_value_accepted(self):
        # Mutant [179] (0.0 -> 1.0) in `temperature <= 0.0`: T=0.5
        # would be rejected as non-positive.
        curve = CalibrationCurve(method="temperature", parameters={"T": 0.5})
        # calibrate(0.5) = sigmoid(0.5 / 0.5) = sigmoid(1.0).
        assert curve.calibrate(0.5) == pytest.approx(0.7310585786300049)

    def test_temperature_zero_rejected(self):
        with pytest.raises(CalibrationError, match="positive"):
            CalibrationCurve(method="temperature", parameters={"T": 0.0})

    def test_beta_default_c_is_zero(self):
        # Mutants [181] (0.0 -> 1.0) and [182] (0.0 -> -1.0) in the
        # default for `parameters.get("c", 0.0)`: with a=b=1 and no
        # "c", calibrate(0.5) is sigmoid(0) = 0.5 exactly.
        curve = CalibrationCurve(method="beta", parameters={"a": 1.0, "b": 1.0})
        assert curve.calibrate(0.5) == pytest.approx(0.5)

    def test_beta_negative_b_rejected(self):
        # Mutant [186] (0.0 -> -1.0) in `b < 0.0`: b=-0.5 would be
        # accepted as non-negative.
        with pytest.raises(CalibrationError, match="non-negative"):
            CalibrationCurve(method="beta", parameters={"a": 1.0, "b": -0.5, "c": 0.0})

    # -- ThresholdSelectionResult.to_dict ([114]) -------------------------

    def test_threshold_result_to_dict_default_warning(self):
        # Mutant [114] negates `if self.warning:`: with warning=None
        # the record would carry None instead of the default text.
        result = ThresholdSelectionResult(
            threshold=0.5,
            observed_fpr=0.0,
            observed_tpr=1.0,
            target_fpr=0.01,
            human_samples=4,
            ai_samples=4,
            detector_id="det1",
            detector_version="1.0",
            calibration_dataset_hash=hex64(9),
        )
        record = result.to_dict()
        assert record["warning"].startswith("This artifact is fitted")

    def test_threshold_result_to_dict_custom_warning(self):
        # Same mutant, other direction: a custom warning would be
        # dropped in favour of the default text.
        result = ThresholdSelectionResult(
            threshold=0.5,
            observed_fpr=0.0,
            observed_tpr=1.0,
            target_fpr=0.01,
            human_samples=4,
            ai_samples=4,
            detector_id="det1",
            detector_version="1.0",
            calibration_dataset_hash=hex64(9),
            warning="custom warning",
        )
        assert result.to_dict()["warning"] == "custom warning"

    # -- select_threshold ([115]-[119]) -----------------------------------

    def test_select_threshold_valid_call_succeeds(self):
        # Mutants [115] (valid target_fpr raises), [116] (both classes
        # present raises), [118] (best never updated -> RuntimeError)
        # and [119] (RuntimeError when a threshold was found) all turn
        # this successful selection into an exception.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "calibration.jsonl"
            _write_scored_rows(path, "observation", "sample")
            result = select_threshold(path, target_fpr=0.01)
            assert result.threshold is not None

    def test_select_threshold_result_respects_target_fpr(self):
        # Mutant [117] negates `if fpr <= target_fpr:`: it only
        # accepts thresholds with FPR *above* the target, so its
        # result has observed_fpr 1.0 on this separable data.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "calibration.jsonl"
            _write_scored_rows(path, "observation", "sample")
            result = select_threshold(path, target_fpr=0.01)
            assert result.observed_fpr <= result.target_fpr
            assert result.observed_tpr == pytest.approx(1.0)

    def test_select_threshold_invalid_target_fpr_rejected(self):
        # Mutant [115], other direction: target_fpr=1.5 would be
        # accepted instead of raising.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "calibration.jsonl"
            _write_scored_rows(path, "observation", "sample")
            with pytest.raises(ValueError, match="between 0 and 1"):
                select_threshold(path, target_fpr=1.5)

    def test_select_threshold_single_class_rejected(self):
        # Mutant [116], other direction: a human-only file would
        # proceed (and die with ZeroDivisionError) instead of raising
        # ValueError.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "calibration.jsonl"
            rows = [{"label": "human", "text": f"{_HUMAN_TEXT} only {i}"} for i in range(4)]
            path.write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="utf-8",
            )
            with pytest.raises(ValueError, match="at least one human"):
                select_threshold(path, target_fpr=0.01)

    # -- evaluate_threshold ([120]) ---------------------------------------

    def test_evaluate_threshold_same_dataset_rejected(self):
        # Mutant [120] negates the same-dataset guard: evaluating on
        # the calibration dataset itself would proceed.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            _write_scored_rows(path, "observation", "sample")
            with pytest.raises(ValueError, match="matches the calibration"):
                evaluate_threshold(
                    path,
                    0.5,
                    calibration_dataset_hash=dataset_sha256(path),
                )

    def test_evaluate_threshold_different_dataset_accepted(self):
        # Same mutant, other direction: a genuinely different dataset
        # would be rejected as if it were the calibration set.
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "calibration.jsonl"
            eval_path = Path(tmp) / "evaluation.jsonl"
            _write_scored_rows(cal_path, "observation", "sample")
            _write_scored_rows(eval_path, "eval", "check")
            result = evaluate_threshold(
                eval_path,
                0.5,
                calibration_dataset_hash=dataset_sha256(cal_path),
            )
            assert result.evaluated == 8

    # -- validate_no_contamination ([121], [122]) -------------------------

    def test_no_contamination_identical_files_flagged(self):
        # Mutant [121] negates `if cal_hash == test_hash:`: identical
        # files would take the sample-overlap path and report
        # shared_samples = 8 instead of -1 with the identical-file
        # warning.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            _write_scored_rows(path, "observation", "sample")
            result = validate_no_contamination(path, path)
            assert result["contamination_detected"] is True
            assert result["shared_samples"] == -1
            assert "identical" in result["warning"]

    def test_no_contamination_shared_sample_detected(self):
        # Mutant [122] negates `if shared:`: a real one-sample overlap
        # would be reported as valid.
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "calibration.jsonl"
            eval_path = Path(tmp) / "evaluation.jsonl"
            shared = {"label": "human", "text": f"{_HUMAN_TEXT} shared"}
            cal_rows = [shared] + [{"label": "ai", "text": f"{_AI_TEXT} cal {i}"} for i in range(3)]
            eval_rows = [shared] + [
                {"label": "ai", "text": f"{_AI_TEXT} eval {i}"} for i in range(3)
            ]
            cal_path.write_text(
                "".join(json.dumps(row) + "\n" for row in cal_rows),
                encoding="utf-8",
            )
            eval_path.write_text(
                "".join(json.dumps(row) + "\n" for row in eval_rows),
                encoding="utf-8",
            )
            result = validate_no_contamination(cal_path, eval_path)
            assert result["contamination_detected"] is True
            assert result["shared_samples"] == 1
            assert result["valid"] is False

    def test_no_contamination_disjoint_files_valid(self):
        # Mutants [121]/[122], other direction: disjoint files would
        # be flagged as contaminated.
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "calibration.jsonl"
            eval_path = Path(tmp) / "evaluation.jsonl"
            _write_scored_rows(cal_path, "observation", "sample")
            _write_scored_rows(eval_path, "eval", "check")
            result = validate_no_contamination(cal_path, eval_path)
            assert result["contamination_detected"] is False
            assert result["shared_samples"] == 0
            assert result["valid"] is True

    # -- load_threshold_artifact ([123]-[127]) ----------------------------

    def _valid_threshold_record(self) -> dict:
        return {
            "schema": THRESHOLD_SELECTION_SCHEMA,
            "threshold": 0.5,
            "calibration_dataset_hash": hex64(9),
        }

    def test_load_threshold_artifact_valid_round_trip(self):
        # Mutants [123] (a dict raises), [124] (valid schema flagged),
        # [125] (present threshold flagged missing), [126] (present
        # hash flagged missing) and [127] (raise when there are no
        # errors) all reject this valid artifact.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "artifact.json"
            path.write_text(json.dumps(self._valid_threshold_record()), encoding="utf-8")
            assert load_threshold_artifact(path) == self._valid_threshold_record()

    def test_load_threshold_artifact_non_object_rejected(self):
        # Mutant [123], other direction: a JSON list would proceed
        # (and die with AttributeError) instead of raising ValueError.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "artifact.json"
            path.write_text("[]", encoding="utf-8")
            with pytest.raises(ValueError, match="JSON object"):
                load_threshold_artifact(path)

    def test_load_threshold_artifact_bad_schema_rejected(self):
        # Mutant [124], other direction: an unsupported schema would
        # be accepted.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "artifact.json"
            record = self._valid_threshold_record()
            record["schema"] = "textforensics.nope/v9"
            path.write_text(json.dumps(record), encoding="utf-8")
            with pytest.raises(ValueError, match="Unsupported schema"):
                load_threshold_artifact(path)

    def test_load_threshold_artifact_missing_threshold_rejected(self):
        # Mutant [125], other direction: a record without "threshold"
        # would be accepted.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "artifact.json"
            record = self._valid_threshold_record()
            del record["threshold"]
            path.write_text(json.dumps(record), encoding="utf-8")
            with pytest.raises(ValueError, match="Missing required field: threshold"):
                load_threshold_artifact(path)

    def test_load_threshold_artifact_missing_hash_rejected(self):
        # Mutant [126], other direction: a record without
        # "calibration_dataset_hash" would be accepted.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "artifact.json"
            record = self._valid_threshold_record()
            del record["calibration_dataset_hash"]
            path.write_text(json.dumps(record), encoding="utf-8")
            with pytest.raises(
                ValueError, match="Missing required field: calibration_dataset_hash"
            ):
                load_threshold_artifact(path)

    # -- run_calibration_evaluation ([128]) -------------------------------

    def test_run_calibration_evaluation_disjoint_pipeline(self):
        # Mutant [128] negates `if validation["contamination_detected"]:`:
        # a clean pipeline would raise instead of returning results.
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "calibration.jsonl"
            eval_path = Path(tmp) / "evaluation.jsonl"
            _write_scored_rows(cal_path, "observation", "sample")
            _write_scored_rows(eval_path, "eval", "check")
            result = run_calibration_evaluation(cal_path, eval_path, target_fpr=0.01)
            assert result["validation"]["contamination_detected"] is False
            assert result["evaluation_result"]["evaluated"] == 8
            assert result["calibration_result"]["observed_false_positive_rate"] <= 0.01

    # -- validation_issues except handlers ([131], [132]) -----------------

    def test_validation_issues_bad_manifest_hash_reported(self):
        # Mutant [131] replaces the `except CalibrationError` in
        # _disjointness_declaration_issues: an invalid manifest hash
        # would propagate out of validation_issues instead of being
        # reported as an issue.
        kwargs = eligible_artifact_kwargs()
        kwargs["disjointness"] = {
            "strategy": "disjoint_sample_ids",
            "evidence": "ids differ",
            "sample_id_manifest_sha256": "not-a-sha256-hash",
        }
        artifact = CalibrationArtifact(
            artifact_id="det1:cal1",
            detector_id="det1",
            detector_version="1.0",
            curve=platt_curve(),
            calibration_id="cal1",
            created_at="2024-01-01T00:00:00+00:00",
            **kwargs,
        )
        issues = artifact.validation_issues()
        assert any("sample_id_manifest_sha256" in issue for issue in issues)

    def test_validation_issues_non_numeric_metric_reported(self):
        # Mutant [132] replaces the `except CalibrationError` in
        # _metric_issues: a non-numeric metric would propagate out of
        # validation_issues instead of being reported as an issue.
        kwargs = eligible_artifact_kwargs()
        kwargs["metrics"] = {"brier": "not-a-number", "ece": 0.05, "log_loss": 0.30}
        artifact = CalibrationArtifact(
            artifact_id="det1:cal1",
            detector_id="det1",
            detector_version="1.0",
            curve=platt_curve(),
            calibration_id="cal1",
            created_at="2024-01-01T00:00:00+00:00",
            **kwargs,
        )
        issues = artifact.validation_issues()
        assert any("metrics.brier" in issue for issue in issues)

    # -- validate_no_contamination except handlers ([143], [144]) ---------

    def test_no_contamination_unreadable_calibration_samples(self):
        # Mutant [143] replaces the `except Exception` around the
        # calibration-side _compute_sample_hashes: a file whose bytes
        # are not valid UTF-8 (dataset_sha256 still hashes it fine)
        # would propagate UnicodeDecodeError instead of returning
        # valid=False with a warning.
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "calibration.jsonl"
            eval_path = Path(tmp) / "evaluation.jsonl"
            cal_path.write_bytes(b"\xff\xfe\x00not valid utf-8\n")
            _write_scored_rows(eval_path, "eval", "check")
            result = validate_no_contamination(cal_path, eval_path)
            assert result["valid"] is False
            assert "warning" in result

    def test_no_contamination_unreadable_test_samples(self):
        # Mutant [144]: same, test side.
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "calibration.jsonl"
            eval_path = Path(tmp) / "evaluation.jsonl"
            _write_scored_rows(cal_path, "observation", "sample")
            eval_path.write_bytes(b"\xff\xfe\x00not valid utf-8\n")
            result = validate_no_contamination(cal_path, eval_path)
            assert result["valid"] is False
            assert "warning" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
