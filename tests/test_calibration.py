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

import hashlib
import json
import math
import os
import tempfile
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from textforensics.benchmark import DatasetFormatError, dataset_sha256
from textforensics.calibration import (
    MIN_CALIBRATION_SAMPLES,
    THRESHOLD_SELECTION_SCHEMA,
    CalibrationArtifact,
    CalibrationCurve,
    CalibrationError,
    CalibrationManager,
    CalibrationResult,
    DatasetReference,
    EvaluationResult,
    ThresholdSelectionResult,
    _canonical_json,
    _coerce_label,
    _parse_iso8601,
    _probability_metrics,
    create_calibration_manager,
    create_threshold_selection_artifact,
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
        # Exact inference identity (CORE-05): an eligible artifact must
        # record provider/model/config/native semantics/regime.
        "provider": "local",
        "model": "builtin-heuristic-0.1.0",
        "config_hash": hex64(5),
        "native_score_semantics": "probability_higher_means_ai",
        "regime": "unedited",
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
        # Temperature on probability inputs: sigmoid(logit(p)/T).
        # Independent oracle values (Guo et al.): at T=2, p=0 -> 0,
        # p=0.5 -> 0.5, p=1 -> 1.
        curve = CalibrationCurve(method="temperature", parameters={"T": 2.0})
        assert curve.calibrate(0.0) == pytest.approx(0.0)
        assert curve.calibrate(1.0) == pytest.approx(1.0)
        assert curve.calibrate(0.5) == pytest.approx(0.5)
        assert curve.calibrate(0.2) == pytest.approx(1.0 / 3.0)
        assert curve.calibrate(0.8) == pytest.approx(2.0 / 3.0)

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
        value = mgr.get_calibrated_score("det1", 0.5, identity=_audit_identity())
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
            identity=_audit_identity(),
        )
        with pytest.raises(CalibrationError, match="not eligible"):
            mgr.get_calibrated_score("det1", 0.5, identity=_audit_identity())

    def test_get_calibrated_score_allow_unvalidated(self, storage):
        mgr = CalibrationManager(storage)
        mgr.store(
            "det1",
            "1.0",
            platt_curve(),
            calibration_id="cal1",
            created_at="2024-01-01T00:00:00+00:00",
            identity=_audit_identity(),
        )
        value = mgr.get_calibrated_score(
            "det1", 0.5, identity=_audit_identity(), allow_unvalidated=True
        )
        assert value == pytest.approx(0.6224593312018546)

    def test_get_calibrated_score_unknown_detector_returns_none(self, storage):
        assert (
            CalibrationManager(storage).get_calibrated_score(
                "ghost", 0.5, identity=_audit_identity(detector_id="ghost")
            )
            is None
        )

    def test_get_calibrated_result_on_eligible(self, storage):
        mgr = CalibrationManager(storage)
        store_eligible(mgr, "det1", "cal1")
        result = mgr.get_calibrated_result("det1", 0.5, identity=_audit_identity())
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
            identity=_audit_identity(),
        )
        with pytest.raises(CalibrationError):
            mgr.get_calibrated_result("det1", 0.5, identity=_audit_identity())

    def test_get_calibrated_result_unknown_detector_returns_none(self, storage):
        assert (
            CalibrationManager(storage).get_calibrated_result(
                "ghost", 0.5, identity=_audit_identity(detector_id="ghost")
            )
            is None
        )


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


def _write_scored_rows_to(handle, human_suffix: str, ai_suffix: str) -> None:
    """Write 4 human + 4 AI rows (label + text) to an open handle."""
    rows = [
        {"label": "human", "text": f"{_HUMAN_TEXT} {human_suffix} {index}"} for index in range(4)
    ] + [{"label": "ai", "text": f"{_AI_TEXT} {ai_suffix} {index}"} for index in range(4)]
    handle.write("".join(json.dumps(row) + "\n" for row in rows))


def _write_scored_rows(path: Path, human_suffix: str, ai_suffix: str) -> None:
    """Write 4 human + 4 AI rows (label + text) to a JSONL file."""
    with path.open("w", encoding="utf-8") as handle:
        _write_scored_rows_to(handle, human_suffix, ai_suffix)


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
        # calibrate(0.5) = sigmoid(logit(0.5) / 0.5) = sigmoid(0) = 0.5.
        assert curve.calibrate(0.5) == pytest.approx(0.5)

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

    def test_run_calibration_evaluation_disjoint_pipeline_is_held_out(self):
        # Mutant ReplaceFalseWithTrue:34 (W2-era :24, renumbered by the
        # W2 defect fix) flips `allow_same_dataset=False` in
        # run_calibration_evaluation to True: evaluate_threshold then
        # labels the result "diagnostic" instead of "held_out" even
        # though the disjointness proof is verified. W2 broke the
        # recorded equivalence: evaluate_threshold consults
        # allow_same_dataset for evaluation_mode, not just for the
        # same-dataset raise (audit-w2-f-diffprobe.py).
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "calibration.jsonl"
            eval_path = Path(tmp) / "evaluation.jsonl"
            _write_scored_rows(cal_path, "observation", "sample")
            _write_scored_rows(eval_path, "eval", "check")
            result = run_calibration_evaluation(cal_path, eval_path, target_fpr=0.01)
            assert result["evaluation_result"]["evaluation_mode"] == "held_out"

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


# ---------------------------------------------------------------------------
# Mutation kill tests (Phase 5, calibration remainder batch, items 200-1936)
# ---------------------------------------------------------------------------

#: Spread texts: builtin-heuristic scores (measured with the suffixes
#: used below) are h1=0.2031, h2=0.3903, a1=0.4254, a2=0.6614 — four
#: distinct scores, so a 2-human + 2-AI file has candidates with
#: FPR/TPR in {0, 0.5, 1.0} at every boundary the selection logic
#: branches on. The overlap file reuses the AI text as a human row
#: (humans [0.2031, 0.6614], AIs [0.4254, 0.6614]); the high-human
#: file uses a formal text as a human row (humans [0.2031, 0.5147],
#: AIs [0.4254, 0.6614]) so the best accepted threshold has TPR 0.5.
_H2_TEXT = (
    "The report shows sales rose slightly in March. "
    "Our main supplier raised prices, which may affect the next quarter."
)
_A1_TEXT = (
    "Overall, the evidence supports this conclusion. "
    "The study shows that the new process is both reliable and efficient."
)
_HH_TEXT = (
    "In summary, the data indicates a positive trend. "
    "It is therefore recommended that the team adopt the proposed framework."
)


def _write_spread_rows(path: Path) -> None:
    """Write 2 human + 2 AI rows with distinct scores (see _H2_TEXT)."""
    rows = [
        {"label": "human", "text": f"{_HUMAN_TEXT} spread human 0"},
        {"label": "human", "text": f"{_H2_TEXT} spread human 1"},
        {"label": "ai", "text": f"{_A1_TEXT} spread ai 0"},
        {"label": "ai", "text": f"{_AI_TEXT} spread ai 1"},
    ]
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def _write_overlap_rows(path: Path) -> None:
    """Write 2 human + 2 AI rows where one human scores like the top AI."""
    rows = [
        {"label": "human", "text": f"{_HUMAN_TEXT} overlap human 0"},
        {"label": "human", "text": f"{_AI_TEXT} overlap human 1"},
        {"label": "ai", "text": f"{_A1_TEXT} overlap ai 0"},
        {"label": "ai", "text": f"{_AI_TEXT} overlap ai 1"},
    ]
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def _write_high_human_rows(path: Path) -> None:
    """Write 2 human + 2 AI rows where a human outscores the lower AI."""
    rows = [
        {"label": "human", "text": f"{_HUMAN_TEXT} high human 0"},
        {"label": "human", "text": f"{_HH_TEXT} high human 1"},
        {"label": "ai", "text": f"{_A1_TEXT} high ai 0"},
        {"label": "ai", "text": f"{_AI_TEXT} high ai 1"},
    ]
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def _artifact_kwargs(**overrides: object) -> dict:
    """Constructor kwargs for an eligible artifact, with overrides."""
    kwargs: dict = {
        "artifact_id": "det1:cal1",
        "detector_id": "det1",
        "detector_version": "1.0",
        "curve": platt_curve(),
        "calibration_id": "cal1",
        "created_at": "2024-01-01T00:00:00+00:00",
        **eligible_artifact_kwargs(),
    }
    kwargs.update(overrides)
    return kwargs


def _threshold_result(**overrides: object) -> ThresholdSelectionResult:
    """A ThresholdSelectionResult with fixed, deterministic fields."""
    kwargs: dict = {
        "threshold": 0.5,
        "observed_fpr": 0.0,
        "observed_tpr": 1.0,
        "target_fpr": 0.01,
        "human_samples": 4,
        "ai_samples": 4,
        "detector_id": "det1",
        "detector_version": "1.0",
        "calibration_dataset_hash": hex64(9),
    }
    kwargs.update(overrides)
    return ThresholdSelectionResult(**kwargs)


class TestCalibrationMutationKillTestsRemainder:
    """Behaviour tests that distinguish the original calibration.py from
    each surviving cosmic-ray mutant in the Phase 5 remainder batch
    (items 200-1936 of the 1937-item session). Each test asserts real,
    observable behaviour — a value, a raised error, or a validation
    issue — never merely that a call succeeds.

    NOT covered here (genuinely equivalent, reported to the
    coordinator — no existing baseline kind fits them): the
    closed-domain comparison-operator mutants, the dead-tiebreak and
    dead-RuntimeError-branch mutants, the redundant-guard mutants,
    and the <=2-ulp ``_sigmoid`` mutants [1275]/[1311] (same family
    as prefix [147]/[148]). Three literal-value mutants ARE
    baselined as ``unobservable-value`` instead: [63] (``_coerce_label``
    ``0`` in ``(0, False)``), [1574] (``False`` in the same tuple),
    and [40] (``sample_count`` default in
    ``DatasetReference.from_dict`` — 0 and -1 are both rejected with
    the identical "must be positive" message) — see
    mutation-baseline.toml. Two more candidates, [75] and [83] (ECE
    bin-count initial value / increment), are equivalent only up to
    1 ulp in the ECE float — the count cancels algebraically but the
    evaluation order rounds differently — so they join the ulp group
    above instead of being baselined.
    """

    # -- Curve math and parameter validation ------------------------------

    def test_beta_a_fraction_at_zero(self):
        # Mutant [13] (0.0 -> 1.0) in `a > 0.0` in _calibrate_beta:
        # with a=0.5 and value=0.0, left is -inf (a > 0), so
        # calibrate(0.0) is sigmoid(-inf) = 0.0; the mutant takes
        # the a <= 1 branch (left 0.0) and returns 0.5.
        curve = CalibrationCurve(method="beta", parameters={"a": 0.5, "b": 1.0})
        assert curve.calibrate(0.0) == pytest.approx(0.0)

    def test_beta_c_nonzero(self):
        # Mutant [275] (`+` -> `-`) in `left + right + c`: with
        # a=b=1, c=0.5, calibrate(0.5) is sigmoid(0.5); the mutant
        # returns sigmoid(-0.5).
        curve = CalibrationCurve(method="beta", parameters={"a": 1.0, "b": 1.0, "c": 0.5})
        assert curve.calibrate(0.5) == pytest.approx(0.6224593312018546)

    def test_isotonic_two_points_construct(self):
        # Mutants [1038]/[1039] (`-` -> `^`) in `range(len(...) - 1)`:
        # with 2 points, len ^ 1 = 3, so the check indexes past the
        # end and raises IndexError instead of constructing.
        curve = CalibrationCurve(method="isotonic", parameters={"x": [0.0, 1.0], "y": [0.0, 1.0]})
        assert curve.calibrate(0.5) == pytest.approx(0.5)

    def test_isotonic_four_points_construct_and_interpolate(self):
        # Mutant [211] (`+` -> `<<`) in `index + 1`: with 4 points the
        # monotonicity check indexes parsed_y[4] and raises IndexError.
        # Mutant [1117] (`-` -> `>>`) in `lower = upper - 1`: upper=3
        # gives lower=1 instead of 2, so calibrate(0.75) extrapolates
        # from the wrong segment (1.7 instead of 0.95).
        curve = CalibrationCurve(
            method="isotonic",
            parameters={"x": [0.0, 0.25, 0.5, 1.0], "y": [0.0, 0.1, 0.9, 1.0]},
        )
        assert curve.calibrate(0.75) == pytest.approx(0.95)

    def test_isotonic_interior_interpolation(self):
        # Mutant [735] (`/` -> `**`) in `(value - x0) / (x1 - x0)`:
        # calibrate(0.1) on the identity map is 0.1; the mutant
        # raises the fraction to a power (0.1 ** 0.5 = 0.316) and
        # returns 0.158. (0.25 is not used: 0.25 / 0.5 and
        # 0.25 ** 0.5 are both 0.5, so that point cannot tell them
        # apart.)
        curve = CalibrationCurve(
            method="isotonic", parameters={"x": [0.0, 0.5, 1.0], "y": [0.0, 0.5, 1.0]}
        )
        assert curve.calibrate(0.1) == pytest.approx(0.1)

    def test_isotonic_below_first_knot(self):
        # Mutants [1384] (`<=` -> `==`) and [1409] (`<=` -> `is`) in
        # `value <= x_values[0]`: below the first knot the curve must
        # return y[0]; both mutants fall through to the bisect path
        # and return 0.0 instead of 0.1.
        curve = CalibrationCurve(
            method="isotonic",
            parameters={"x": [0.2, 0.5, 1.0], "y": [0.1, 0.5, 0.9]},
        )
        assert curve.calibrate(0.1) == pytest.approx(0.1)

    def test_isotonic_above_last_knot(self):
        # Mutants [1270] (`>=` -> `==`) and [1285] (`>=` -> `is`) in
        # `value >= x_values[-1]`: above the last knot the curve must
        # return y[-1] = 0.9; both mutants extrapolate to 1.167.
        curve = CalibrationCurve(
            method="isotonic",
            parameters={"x": [0.0, 0.5, 0.8], "y": [0.0, 0.5, 0.9]},
        )
        assert curve.calibrate(1.0) == pytest.approx(0.9)

    def test_isotonic_decreasing_x_rejected(self):
        # Mutant [1269] (`>=` -> `==`) in the strictly-increasing
        # check: x=[0.5, 0.0, 1.0] must raise; the mutant only
        # rejects equal neighbours and accepts the decrease.
        with pytest.raises(CalibrationError, match="strictly increasing"):
            CalibrationCurve(
                method="isotonic",
                parameters={"x": [0.5, 0.0, 1.0], "y": [0.0, 0.5, 1.0]},
            )

    def test_isotonic_equal_x_rejected_distinct_objects(self):
        # Mutant [1284] (`>=` -> `is`) in the strictly-increasing
        # check: equal neighbours must raise. The two 0.5s are built
        # with float("0.5") so they are distinct objects — `is`
        # compares identity, not value, and the mutant accepts.
        with pytest.raises(CalibrationError, match="strictly increasing"):
            CalibrationCurve(
                method="isotonic",
                parameters={
                    "x": [float("0.5"), float("0.5"), 1.0],
                    "y": [0.0, 0.5, 1.0],
                },
            )

    def test_isotonic_equal_y_accepted(self):
        # Mutant [1324] (`>` -> `>=`) in the non-decreasing check:
        # equal adjacent y values are legal; the mutant rejects them.
        curve = CalibrationCurve(
            method="isotonic",
            parameters={"x": [0.0, 0.5, 1.0], "y": [0.1, 0.1, 0.2]},
        )
        assert curve.calibrate(0.25) == pytest.approx(0.1)

    def test_score_range_equal_bounds_rejected(self):
        # Mutant [1276] (`>=` -> `>`) in `minimum >= maximum`: equal
        # bounds must raise; the mutant accepts (1.0, 1.0).
        with pytest.raises(CalibrationError, match="below maximum"):
            CalibrationCurve(
                method="platt",
                parameters={"A": 1.0, "B": 0.0},
                score_range=(1.0, 1.0),
            )

    def test_platt_negative_coefficient_accepted(self):
        # Mutant [1226] (`==` -> `<=`) in `coefficient == 0.0`: only
        # A == 0 is rejected; A = -1 must construct and calibrate
        # (sigmoid(-0.5)).
        curve = CalibrationCurve(method="platt", parameters={"A": -1.0, "B": 0.0})
        assert curve.calibrate(0.5) == pytest.approx(0.3775406687981454)

    def test_curve_schema_low_prefix_rejected(self):
        # Mutant [1495] (`!=` -> `>`) in the schema check: "aaa" is
        # below the curve schema lexicographically, so the mutant
        # accepts a schema the original rejects.
        with pytest.raises(CalibrationError, match="schema"):
            CalibrationCurve(method="platt", parameters={"A": 1.0, "B": 0.0}, schema="aaa")

    def test_score_range_single_element_rejected(self):
        # Mutant [1496] (`!=` -> `>`) in `len(score_range) != 2`: a
        # one-element range must raise CalibrationError; the mutant
        # proceeds and dies with IndexError on score_range[1].
        with pytest.raises(CalibrationError, match="two-element|pair"):
            CalibrationCurve(
                method="platt",
                parameters={"A": 1.0, "B": 0.0},
                score_range=(0.0,),
            )

    def test_isotonic_y_longer_than_x_rejected(self):
        # Mutant [1497] (`!=` -> `>`) in `len(x) != len(y)`: a longer
        # y must raise; the mutant only rejects a longer x.
        with pytest.raises(CalibrationError, match="same length"):
            CalibrationCurve(
                method="isotonic",
                parameters={"x": [0.0, 0.5], "y": [0.0, 0.5, 1.0]},
            )

    def test_isotonic_300_points_construct(self):
        # Mutant [1527] (`!=` -> `is not`) in `len(x) != len(y)`:
        # equal lengths up to 256 share the small-int singleton, but
        # 300 != 300 as objects, so the mutant rejects 300-point maps.
        points = [index / 299 for index in range(300)]
        curve = CalibrationCurve(method="isotonic", parameters={"x": points, "y": list(points)})
        assert curve.calibrate(0.5) == pytest.approx(0.5)

    def test_dataset_reference_fingerprint_too_long(self):
        # Mutant [1534] (`!=` -> `<`) in `len(value) != 64`: a
        # 65-character fingerprint must raise; the mutant only
        # rejects shorter ones.
        with pytest.raises(CalibrationError, match="64-character"):
            DatasetReference(
                name="x",
                fingerprint_sha256="a" * 65,
                split="train",
                sample_count=1,
            )

    def test_from_dict_score_range_three_elements(self):
        # Mutant [1538] (`!=` -> `<`) in `len(score_range) != 2` in
        # from_dict: a three-element range must raise; the mutant
        # only rejects shorter ones and constructs.
        with pytest.raises(CalibrationError, match="two-element"):
            CalibrationCurve.from_dict(
                {
                    "method": "platt",
                    "parameters": {"A": 1.0, "B": 0.0},
                    "score_range": [0.0, 0.5, 1.0],
                }
            )

    def test_isotonic_non_sequence_y_message(self):
        # Mutant [1596] (`or` -> `and`) in the sequence check: a
        # non-sequence y must fail with the sequences message; the
        # mutant proceeds and fails later with a different message.
        with pytest.raises(CalibrationError, match="require x and y sequences"):
            CalibrationCurve(method="isotonic", parameters={"x": [0.0, 1.0], "y": "ab"})

    def test_disjointness_asserts(self):
        # Mutants [135]/[136] (`and` -> `or`) in the asserts guarding
        # _disjointness_issues / _sample_size_issues: with only one
        # dataset present the precondition must fail; the mutant
        # passes the assert and dies with AttributeError instead.
        artifact = CalibrationArtifact(**_artifact_kwargs(fit_dataset=None))
        with pytest.raises(AssertionError):
            artifact._disjointness_issues()
        with pytest.raises(AssertionError):
            artifact._sample_size_issues()

    # -- _coerce_label and _probability_metrics ---------------------------

    def test_coerce_label_two_and_minus_one_are_none(self):
        # Mutant [59] (1 -> 2) in `(1, True)`: 2 would coerce to 1.
        # Mutant [64] (0 -> -1) in `(0, False)`: -1 would coerce to 0.
        assert _coerce_label(2) is None
        assert _coerce_label(-1) is None

    def test_probability_metrics_ece_binning(self):
        # Mutants [73]/[74] (n_bins 10 -> 11 / 9): [0.81, 0.89]
        # share bin 8 at n=10 (ECE 0.35) but split at n=9/11 (0.46).
        # Mutant [683] (`/` -> `//`) in average_positive: floor
        # division makes both bin averages 0 and ECE 0.0.
        # (Mutant [75], [0] -> [1], is equivalent only up to 1 ulp
        # in the ECE float — the bin count cancels algebraically
        # but rounds differently — so it is reported for a new kind,
        # not baselined and not killed.)
        metrics = _probability_metrics([0.81, 0.89], [0, 1])
        assert metrics["ece"] == pytest.approx(0.35)

    def test_probability_metrics_ece_high_bin(self):
        # Mutant [81] (n_bins - 1 -> n_bins - 2): the 0.95 value is
        # clamped from bin 9 to bin 8, merging it with 0.81 (ECE
        # 0.38 instead of 0.43). Mutant [1122] (`-` -> `>>`): the
        # cap becomes n_bins >> 1 = 5, merging both values in bin 5.
        metrics = _probability_metrics([0.81, 0.95], [0, 1])
        assert metrics["ece"] == pytest.approx(0.43)

    def test_probability_metrics_length_mismatch(self):
        # Mutant [1544] (`!=` -> `<`) in the length check: longer
        # values than targets must raise; the mutant silently zips.
        with pytest.raises(CalibrationError, match="equally sized"):
            _probability_metrics([0.1, 0.2, 0.3], [0, 1])

    def test_probability_metrics_300_samples(self):
        # Mutant [1532] (`!=` -> `is not`) in the length check:
        # equal lengths above 256 are distinct int objects, so the
        # mutant rejects a valid 300-sample call.
        metrics = _probability_metrics([0.5] * 300, [0] * 150 + [1] * 150)
        assert metrics["sample_count"] == 300

    # -- Artifact issue lists and bounds ----------------------------------

    def test_metric_bounds_below_and_above(self):
        # Mutant [44] (0.0 -> -1.0) in the brier minimum: brier=-0.5
        # must be flagged; the mutant accepts it. Mutant [48]
        # (0.0 -> -1.0) in the ece minimum: same for ece=-0.5.
        # Mutant [49] (1.0 -> 2.0) in the ece maximum: ece=1.5 must
        # be flagged; the mutant accepts it.
        artifact = CalibrationArtifact(
            **_artifact_kwargs(metrics={"brier": -0.5, "ece": -0.5, "log_loss": 0.3})
        )
        issues = artifact.validation_issues()
        assert any("metrics.brier is outside its valid range" in i for i in issues)
        assert any("metrics.ece is outside its valid range" in i for i in issues)
        artifact = CalibrationArtifact(
            **_artifact_kwargs(metrics={"brier": 0.1, "ece": 1.5, "log_loss": 0.3})
        )
        issues = artifact.validation_issues()
        assert any("metrics.ece is outside its valid range" in i for i in issues)

    def test_metric_bounds_at_extremes_no_issue(self):
        # Mutant [1327] (`>` -> `>=`) in `value > maximum`:
        # brier=1.0 is in range; the mutant flags it. Mutant [1472]
        # (`<` -> `<=`) in `value < minimum`: ece=0.0 is in range;
        # the mutant flags it.
        artifact = CalibrationArtifact(
            **_artifact_kwargs(metrics={"brier": 1.0, "ece": 0.0, "log_loss": 0.3})
        )
        issues = artifact.validation_issues()
        assert not any("outside its valid range" in i for i in issues)

    def test_metric_issues_non_finite_then_out_of_range(self):
        # Mutant [1559] (`continue` -> `break`) in the except branch
        # of _metric_issues (L655, after a non-finite metric): with
        # a non-finite brier AND an out-of-range ece, both issues
        # must appear; the mutant stops after brier.
        artifact = CalibrationArtifact(
            **_artifact_kwargs(metrics={"brier": "bad", "ece": 1.5, "log_loss": 0.3})
        )
        issues = artifact.validation_issues()
        assert any("metrics.brier" in i for i in issues)
        assert any("metrics.ece is outside its valid range" in i for i in issues)

    def test_metric_issues_all_missing(self):
        # Mutant [1559] (`continue` -> `break`) in _metric_issues:
        # with no metrics at all, all three required-metric issues
        # must appear; the mutant stops after brier.
        artifact = CalibrationArtifact(**_artifact_kwargs(metrics={}))
        issues = artifact.validation_issues()
        assert "metrics.brier is required for probability eligibility" in issues
        assert "metrics.ece is required for probability eligibility" in issues
        assert "metrics.log_loss is required for probability eligibility" in issues

    def test_disjointness_fingerprint_order(self):
        # Mutant [1159] (`==` -> `>=`) in the fingerprint check:
        # fit hex64(3) vs eval hex64(2) differ, so no issue; the
        # mutant flags them because "3..." >= "2...".
        artifact = CalibrationArtifact(
            **_artifact_kwargs(
                fit_dataset=DatasetReference(
                    name="fit", fingerprint_sha256=hex64(3), split="train", sample_count=200
                ),
                evaluation_dataset=DatasetReference(
                    name="eval", fingerprint_sha256=hex64(2), split="test", sample_count=200
                ),
            )
        )
        issues = artifact.validation_issues()
        assert "fit and evaluation dataset fingerprints must differ" not in issues

    def test_disjointness_split_order(self):
        # Mutant [1238] (`==` -> `<=`) in the split check: fit
        # "dev" vs eval "test" differ, so no issue; the mutant flags
        # them because "dev" <= "test".
        artifact = CalibrationArtifact(
            **_artifact_kwargs(
                fit_dataset=DatasetReference(
                    name="fit", fingerprint_sha256=hex64(2), split="dev", sample_count=200
                ),
            )
        )
        issues = artifact.validation_issues()
        assert "fit and evaluation splits must differ" not in issues

    def test_sample_size_floor_boundaries(self):
        # Mutants [1438] (`<` -> `==`) and [1458] (`<` -> `is`) in
        # the fit floor: 50 < 100 must be flagged; both mutants miss
        # it. Mutants [1470]/[1471] (`<` -> `<=`): exactly 100 must
        # NOT be flagged; both mutants flag it.
        artifact = CalibrationArtifact(
            **_artifact_kwargs(
                fit_dataset=DatasetReference(
                    name="fit", fingerprint_sha256=hex64(2), split="train", sample_count=50
                ),
            )
        )
        issues = artifact.validation_issues()
        assert any("at least 100" in i for i in issues)
        artifact = CalibrationArtifact(
            **_artifact_kwargs(
                fit_dataset=DatasetReference(
                    name="fit", fingerprint_sha256=hex64(2), split="train", sample_count=100
                ),
                evaluation_dataset=DatasetReference(
                    name="eval", fingerprint_sha256=hex64(3), split="test", sample_count=100
                ),
            )
        )
        issues = artifact.validation_issues()
        assert not any("at least 100" in i for i in issues)

    def test_disjointness_strategy_non_string_issue(self):
        # Mutant [1600] (`or` -> `and`) in the strategy check: a
        # non-string strategy must be an issue; the mutant calls
        # .strip() on it and raises AttributeError instead.
        artifact = CalibrationArtifact(
            **_artifact_kwargs(disjointness={"strategy": 123, "evidence": "x"})
        )
        issues = artifact.validation_issues()
        assert "disjointness.strategy must be a non-empty string" in issues

    def test_artifact_content_hash_non_string(self):
        # Mutant [1599] (`or` -> `and`) in the content_hash check:
        # a non-string hash must raise CalibrationError; the mutant
        # calls len() on it and raises TypeError instead.
        with pytest.raises(CalibrationError, match="content_hash"):
            CalibrationArtifact(**_artifact_kwargs(content_hash=123))

    def test_artifact_schema_rejected(self):
        # Mutant [1499] (`!=` -> `>`) in the schema check: "aaa"
        # sorts below the artifact schema, so the mutant accepts it.
        # Mutant [1539] (`!=` -> `<`): "zzz" sorts above it, so the
        # mutant accepts that one.
        with pytest.raises(CalibrationError, match="schema"):
            CalibrationArtifact(**_artifact_kwargs(schema="aaa"))
        with pytest.raises(CalibrationError, match="schema"):
            CalibrationArtifact(**_artifact_kwargs(schema="zzz"))

    def test_artifact_content_hash_mismatch_and_length(self):
        # Mutant [1501] (`!=` -> `>`) in the hash comparison: "0"*64
        # is below every real hash, so the mutant accepts the wrong
        # digest. Mutants [1500] (`!=` -> `>`) and [1540]
        # (`!=` -> `<`) in the length check: a 63- or 65-character
        # hash must fail with the 64-character message; the mutants
        # fall through to the mismatch message instead.
        with pytest.raises(CalibrationError, match="does not match"):
            CalibrationArtifact(**_artifact_kwargs(content_hash="0" * 64))
        with pytest.raises(CalibrationError, match="64-character"):
            CalibrationArtifact(**_artifact_kwargs(content_hash="a" * 63))
        with pytest.raises(CalibrationError, match="64-character"):
            CalibrationArtifact(**_artifact_kwargs(content_hash="a" * 65))

    # -- Dataclasses, canonical JSON, and stored files --------------------

    def test_dataclasses_frozen(self):
        # Mutants [1616]/[1618]/[1620]/[1622] (frozen=True -> False)
        # on the four dataclasses: assignment must raise
        # FrozenInstanceError; the mutants allow it.
        curve = platt_curve()
        with pytest.raises(FrozenInstanceError):
            curve.sample_count = 5
        ref = DatasetReference(name="x", fingerprint_sha256=hex64(1), split="train", sample_count=1)
        with pytest.raises(FrozenInstanceError):
            ref.sample_count = 5
        artifact = eligible_artifact()
        with pytest.raises(FrozenInstanceError):
            artifact.detector_id = "other"
        result = CalibrationResult(
            value=0.5, calibration_id="cal1", status="ok", probability_eligible=True
        )
        with pytest.raises(FrozenInstanceError):
            result.value = 0.6

    def test_dataclasses_slots(self):
        # Mutants [1617]/[1619]/[1621]/[1623] (slots=True -> False):
        # slotted instances have no __dict__; the mutants give them one.
        assert not hasattr(platt_curve(), "__dict__")
        ref = DatasetReference(name="x", fingerprint_sha256=hex64(1), split="train", sample_count=1)
        assert not hasattr(ref, "__dict__")
        assert not hasattr(eligible_artifact(), "__dict__")
        assert not hasattr(
            CalibrationResult(
                value=0.5, calibration_id="cal1", status="ok", probability_eligible=True
            ),
            "__dict__",
        )

    def test_manager_nested_storage_path(self):
        # Mutant [1624] (parents=True -> False) in __init__: a
        # nested, nonexistent storage path must be created; the
        # mutant raises FileNotFoundError.
        with tempfile.TemporaryDirectory() as tmp:
            mgr = CalibrationManager(Path(tmp) / "a" / "b" / "c")
            assert mgr.storage_path == Path(tmp) / "a" / "b" / "c"

    def test_save_artifact_nested_parent(self):
        # Mutants [1633] (parents=True -> False) and [1634]
        # (exist_ok=True -> False) in save_calibration_artifact: a
        # nested, nonexistent parent must be created on the first
        # save; a second save must succeed with the parent already
        # present (the exist_ok mutant raises FileExistsError).
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "x" / "y" / "artifact.json"
            save_calibration_artifact(eligible_artifact(), target)
            assert target.is_file()
            save_calibration_artifact(eligible_artifact(), target)
            assert target.is_file()

    def test_threshold_artifact_nested_parent(self):
        # Mutants [1641] (parents=True -> False) and [1642]
        # (exist_ok=True -> False) in create_threshold_selection_
        # artifact: same, nested parent then re-save.
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "x" / "y" / "threshold.json"
            create_threshold_selection_artifact(_threshold_result(), target)
            assert target.is_file()
            create_threshold_selection_artifact(_threshold_result(), target)
            assert target.is_file()

    def test_save_artifact_indent_two_spaces(self):
        # Mutants [53]/[54] (indent=2 -> 3 / 1) in _save_artifact:
        # the stored file must use two-space indentation.
        with tempfile.TemporaryDirectory() as tmp:
            mgr = CalibrationManager(Path(tmp))
            artifact = store_eligible(mgr, "det1", "cal1")
            text = (Path(tmp) / f"{artifact.content_hash}.json").read_text(encoding="utf-8")
            # Anchor on the file start: a nested "schema" (the curve)
            # sits deeper and would match a bare substring search even
            # at indent=1.
            assert text.startswith('{\n  "schema"')

    def test_save_calibration_artifact_indent_two_spaces(self):
        # Mutants [93]/[94] (indent=2 -> 3 / 1) in
        # save_calibration_artifact: same, two-space indentation.
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "artifact.json"
            save_calibration_artifact(eligible_artifact(), target)
            # Anchor on the file start (see test_save_artifact_indent).
            assert target.read_text(encoding="utf-8").startswith('{\n  "schema"')

    def test_threshold_artifact_indent_two_spaces(self):
        # Mutants [117]/[118] (indent=2 -> 3 / 1) in
        # create_threshold_selection_artifact: the written artifact
        # must use two-space indentation.
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "threshold.json"
            create_threshold_selection_artifact(_threshold_result(), target)
            # Sorted keys: the first key is "ai_samples".
            assert target.read_text(encoding="utf-8").startswith('{\n  "ai_samples"')

    def test_canonical_json_sort_keys(self):
        # Mutant [1615] (sort_keys=True -> False): canonical JSON
        # must order keys alphabetically.
        assert _canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'

    def test_canonical_json_non_ascii(self):
        # Mutant [1565] (ensure_ascii=False -> True): canonical JSON
        # must keep non-ASCII characters raw, not \u-escaped.
        assert _canonical_json({"a": "é"}) == '{"a":"é"}'

    def test_canonical_json_nan_rejected(self):
        # Mutant [1566] (allow_nan=False -> True): canonical JSON
        # must reject NaN; the mutant serialises it.
        with pytest.raises(ValueError):
            _canonical_json({"a": float("nan")})

    def test_save_artifact_non_ascii_detector(self):
        # Mutant [1569] (ensure_ascii=False -> True) in
        # _save_artifact: a non-ASCII detector id must be written raw.
        with tempfile.TemporaryDirectory() as tmp:
            mgr = CalibrationManager(Path(tmp))
            artifact = store_eligible(mgr, "dét1", "cal1")
            text = (Path(tmp) / f"{artifact.content_hash}.json").read_text(encoding="utf-8")
            assert "dét1" in text

    def test_save_artifact_nan_metadata_rejected(self):
        # Mutant [1570] (allow_nan=False -> True) in _save_artifact:
        # NaN smuggled into metadata after construction (so it never
        # passes through _canonical_json) must still be rejected at
        # the file write; the mutant writes it as NaN.
        # W2 (CORE-04): metadata is deeply frozen, so the smuggle
        # itself now fails with TypeError, and NaN metadata cannot
        # even be constructed (the content hash rejects non-finite
        # JSON). Both are fail-closed; neither writes NaN to disk.
        with tempfile.TemporaryDirectory() as tmp:
            mgr = CalibrationManager(Path(tmp))
            artifact = eligible_artifact()
            with pytest.raises(TypeError):
                artifact.metadata["nan_value"] = float("nan")  # type: ignore[index]
            with pytest.raises(ValueError):
                CalibrationArtifact(
                    artifact_id="d:c",
                    detector_id="d",
                    detector_version="1",
                    curve=platt_curve(),
                    calibration_id="c",
                    metadata={"nan_value": float("nan")},
                )
            mgr._save_artifact(artifact)
            assert (Path(tmp) / f"{artifact.content_hash}.json").exists()

    def test_save_calibration_artifact_non_ascii_detector(self):
        # Mutant [1575] (ensure_ascii=False -> True) in
        # save_calibration_artifact: non-ASCII must be written raw.
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "artifact.json"
            artifact = CalibrationArtifact(**_artifact_kwargs(detector_id="dét1"))
            save_calibration_artifact(artifact, target)
            assert "dét1" in target.read_text(encoding="utf-8")

    def test_save_calibration_artifact_nan_metadata_rejected(self):
        # Mutant [1576] (allow_nan=False -> True) in
        # save_calibration_artifact: same NaN-via-metadata case.
        # W2 (CORE-04): metadata is deeply frozen, so the post-
        # construction smuggle fails with TypeError and NaN metadata
        # cannot be constructed at all (see the _save_artifact test
        # above). Neither path writes NaN to disk.
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "artifact.json"
            artifact = eligible_artifact()
            with pytest.raises(TypeError):
                artifact.metadata["nan_value"] = float("nan")  # type: ignore[index]
            save_calibration_artifact(artifact, target)
            assert target.exists()

    def test_threshold_artifact_non_ascii_detector(self):
        # Mutant [1588] (ensure_ascii=False -> True) in
        # create_threshold_selection_artifact: non-ASCII raw.
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "threshold.json"
            create_threshold_selection_artifact(_threshold_result(detector_id="dét1"), target)
            assert "dét1" in target.read_text(encoding="utf-8")

    def test_threshold_artifact_sorted_keys(self):
        # Mutant [1643] (sort_keys=True -> False) in
        # create_threshold_selection_artifact: the written keys must
        # be sorted, so "calibration_dataset_hash" precedes "schema".
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "threshold.json"
            create_threshold_selection_artifact(_threshold_result(), target)
            text = target.read_text(encoding="utf-8")
            assert text.index('"calibration_dataset_hash"') < text.index('"schema"')

    # -- ThresholdSelectionResult record hash and rounding ----------------

    def test_threshold_result_record_hash_exact(self):
        # Mutants [1493]/[1505]/[1517]/[1545]/[1557] (`!=` -> `==` /
        # `>` / `>=` / `<` / `<=`) in the record-hash filter and [1635]
        # (sort_keys=True -> False): the record hash must equal the
        # SHA-256 of the canonical record computed independently
        # here; every mutant changes the hashed content.
        result = _threshold_result()
        record = result.to_dict()
        canonical = json.dumps(
            {k: v for k, v in record.items() if k != "calibration_record_hash"},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        assert record["calibration_record_hash"] == expected

    def test_threshold_result_record_hash_non_ascii(self):
        # Mutant [1577] (ensure_ascii=False -> True) in to_dict: the
        # record hash must be computed over raw non-ASCII; the mutant
        # hashes the escaped form.
        result = _threshold_result(detector_id="dét1")
        record = result.to_dict()
        canonical = json.dumps(
            {k: v for k, v in record.items() if k != "calibration_record_hash"},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        assert record["calibration_record_hash"] == expected

    def test_threshold_result_nan_threshold_rejected(self):
        # Mutant [1578] (allow_nan=False -> True) in to_dict: a NaN
        # threshold must be rejected while hashing; the mutant
        # serialises it.
        with pytest.raises(ValueError):
            _threshold_result(threshold=float("nan")).to_dict()

    def test_evaluation_result_rounding(self):
        # Mutants [95]-[106] (round(..., 4) -> 5 / 3) in
        # EvaluationResult.to_dict: all six rounded fields must be
        # rounded to four decimals (0.12346 -> 0.1235, not 0.12346
        # or 0.123).
        result = EvaluationResult(
            threshold=0.5,
            tp=4,
            fp=0,
            tn=4,
            fn=0,
            accuracy=0.12346,
            fpr=0.12346,
            fnr=0.12346,
            tpr=0.12346,
            specificity=0.12346,
            precision=0.12346,
            evaluated=8,
            test_dataset_hash=hex64(8),
            calibration_dataset_hash=hex64(9),
        )
        record = result.to_dict()
        assert record["accuracy"] == 0.1235
        assert record["precision"] == 0.1235
        assert record["true_positive_rate"] == 0.1235
        assert record["specificity"] == 0.1235
        assert record["false_positive_rate"] == 0.1235
        assert record["false_negative_rate"] == 0.1235

    def test_evaluation_result_contamination_default_false(self):
        # Mutant [1579] (contamination_detected=False -> True):
        # the default must be False, in the object and the record.
        result = EvaluationResult(
            threshold=0.5,
            tp=4,
            fp=0,
            tn=4,
            fn=0,
            accuracy=1.0,
            fpr=0.0,
            fnr=0.0,
            tpr=1.0,
            specificity=1.0,
            precision=1.0,
            evaluated=8,
            test_dataset_hash=hex64(8),
            calibration_dataset_hash=hex64(9),
        )
        assert result.contamination_detected is False
        assert result.to_dict()["contamination_detected"] is False

    # -- Contamination, defaults, and hash ordering ----------------------

    def test_contamination_identical_files_valid_false(self):
        # Mutant [1582] (result["valid"] = False -> True) in the
        # identical-files branch: identical files must be invalid.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            _write_scored_rows(path, "observation", "sample")
            result = validate_no_contamination(path, path)
            assert result["valid"] is False
            assert result["contamination_detected"] is True

    def test_contamination_invalid_line_skipped_cal(self):
        # Mutant [1583] (strict=False -> True) on the calibration
        # side: one invalid-JSON line must be skipped, leaving the
        # disjoint files valid; the mutant treats it as fatal.
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "calibration.jsonl"
            eval_path = Path(tmp) / "evaluation.jsonl"
            cal_path.write_text("not json\n", encoding="utf-8")
            with cal_path.open("a", encoding="utf-8") as handle:
                _write_scored_rows_to(handle, "observation", "sample")
            _write_scored_rows(eval_path, "eval", "check")
            result = validate_no_contamination(cal_path, eval_path)
            assert result["valid"] is True

    def test_contamination_invalid_line_skipped_eval(self):
        # Mutant [1585] (strict=False -> True) on the test side:
        # same, invalid line in the evaluation file.
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "calibration.jsonl"
            eval_path = Path(tmp) / "evaluation.jsonl"
            _write_scored_rows(cal_path, "observation", "sample")
            eval_path.write_text("not json\n", encoding="utf-8")
            with eval_path.open("a", encoding="utf-8") as handle:
                _write_scored_rows_to(handle, "eval", "check")
            result = validate_no_contamination(cal_path, eval_path)
            assert result["valid"] is True

    def test_evaluate_threshold_hash_order(self):
        # Mutant [1244] (`==` -> `<=`) in the same-dataset guard:
        # two different datasets must evaluate even when the test
        # hash sorts below the calibration hash; the mutant rejects
        # them as the same dataset. The roles are assigned from the
        # measured hashes so the order is the killing one.
        with tempfile.TemporaryDirectory() as tmp:
            path_a = Path(tmp) / "a.jsonl"
            path_b = Path(tmp) / "b.jsonl"
            _write_scored_rows(path_a, "observation", "sample")
            _write_scored_rows(path_b, "eval", "check")
            hash_a = dataset_sha256(path_a)
            hash_b = dataset_sha256(path_b)
            cal_path, eval_path = (path_a, path_b) if hash_a >= hash_b else (path_b, path_a)
            result = evaluate_threshold(
                eval_path,
                0.5,
                calibration_dataset_hash=dataset_sha256(cal_path),
            )
            assert result.evaluated == 8

    def test_contamination_hash_order_disjoint_valid(self):
        # Mutant [1167] (`==` -> `>=`) in the identical-files check:
        # disjoint files must be valid even when the calibration
        # hash sorts above the test hash; the mutant flags them.
        with tempfile.TemporaryDirectory() as tmp:
            path_a = Path(tmp) / "a.jsonl"
            path_b = Path(tmp) / "b.jsonl"
            _write_scored_rows(path_a, "observation", "sample")
            _write_scored_rows(path_b, "eval", "check")
            hash_a = dataset_sha256(path_a)
            hash_b = dataset_sha256(path_b)
            cal_path, eval_path = (path_a, path_b) if hash_a >= hash_b else (path_b, path_a)
            result = validate_no_contamination(cal_path, eval_path)
            assert result["valid"] is True
            assert result["contamination_detected"] is False

    def test_select_threshold_target_zero_and_one(self):
        # Mutants [1422] (`0 <=` -> `0 <`) and [1431] (`0 <=` ->
        # `0 !=`): target_fpr=0.0 must be accepted; both mutants
        # reject it. Mutant [1423] (`<= 1` -> `< 1`): target_fpr=1.0
        # must be accepted; the mutant rejects it. Mutant [110]
        # (0 -> -1) in the lower bound: target_fpr=-0.5 must raise;
        # the mutant accepts it.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "calibration.jsonl"
            _write_spread_rows(path)
            assert select_threshold(path, target_fpr=0.0).observed_fpr == 0.0
            assert select_threshold(path, target_fpr=1.0).observed_fpr == 1.0
            with pytest.raises(ValueError, match="between 0 and 1"):
                select_threshold(path, target_fpr=-0.5)

    def test_select_threshold_default_target(self):
        # Mutants [107]/[108] (target_fpr 0.01 -> 1.01 / -0.99):
        # the default target must be valid; both mutants make the
        # default raise.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "calibration.jsonl"
            _write_spread_rows(path)
            result = select_threshold(path)
            assert result.target_fpr == 0.01
            assert result.observed_fpr <= 0.01

    def test_run_evaluation_default_target(self):
        # Mutants [119]/[120] (target_fpr 0.01 -> 1.01 / -0.99) in
        # run_calibration_evaluation: the default target must work.
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "calibration.jsonl"
            eval_path = Path(tmp) / "evaluation.jsonl"
            _write_spread_rows(cal_path)
            _write_scored_rows(eval_path, "eval", "check")
            result = run_calibration_evaluation(cal_path, eval_path)
            assert result["calibration_result"]["target_false_positive_rate"] == 0.01

    def test_select_threshold_spread_target_half(self):
        # Spread file, target 0.5: candidates are h1 (fpr 1.0),
        # h2 (fpr 0.5, tpr 1.0, first accepted), a1 (fpr 0, tpr 1.0),
        # a2 (fpr 0, tpr 0.5), nextafter (fpr 0, tpr 0). Best is h2.
        # The fp-division mutants [645]/[673]/[687]/[701]/[715]/
        # [729]/[743]/[757]/[771] (`/` -> `&`/`^`/`//`/`<<`/`%`/`*`/
        # `**`/`>>`/`-`) all change the fpr at h2 (fp=1) from 0.5 to
        # 0, 1, 2, 3, 4 or -1. The update-condition mutants [1323]
        # (`>` -> `==`), [1328] (`>` -> `>=`), [144] (`and` ->
        # `or`), [1449] (`<` -> `>`), [1457] (`<` -> `>=`), [1465]
        # (`<` -> `is not`), [1481] (`<` -> `!=`) all promote the
        # later equal-TPR candidate a1 (fpr 0) to best.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "calibration.jsonl"
            _write_spread_rows(path)
            result = select_threshold(path, target_fpr=0.5)
            assert 0.35 < result.threshold < 0.41
            assert result.observed_fpr == 0.5
            assert result.observed_tpr == 1.0

    def test_select_threshold_spread_target_one(self):
        # Spread file, target 1.0: best is h1 (fpr 1.0, tpr 1.0).
        # The fp mutants [1272] (`>=` -> `==`), [1286] (`>=` ->
        # `is`), [1300] (`>=` -> `<`), [1316] (`>=` -> `!=`) all
        # report fpr 0.5 or 0.0 at h1 instead of 1.0. The tp mutant
        # [1273] (`>=` -> `==`) reports tpr 0.0 at h1, so best
        # becomes a1 (fpr 0). Mutant [1424] (`<=` -> `<`) in
        # `fpr <= target_fpr` rejects h1 (fpr == target) and best
        # becomes h2.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "calibration.jsonl"
            _write_spread_rows(path)
            result = select_threshold(path, target_fpr=1.0)
            assert result.threshold < 0.30
            assert result.observed_fpr == 1.0
            assert result.observed_tpr == 1.0

    def test_select_threshold_overlap_target_half(self):
        # Overlap file, target 0.5: best is a1 (fpr 0.5, tpr 1.0).
        # The tp mutants [1293] (`>=` -> `is not`) and [1317]
        # (`>=` -> `!=`) report tpr 0.5 at a1 (one AI score is the
        # threshold object / equals it), so the nextafter candidate
        # (tpr 1.0 under the mutant) wins and best becomes nextafter
        # with fpr 0.0.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "calibration.jsonl"
            _write_overlap_rows(path)
            result = select_threshold(path, target_fpr=0.5)
            assert 0.40 < result.threshold < 0.45
            assert result.observed_fpr == 0.5
            assert result.observed_tpr == 1.0

    def test_select_threshold_high_human_target_zero(self):
        # High-human file, target 0.0: the only accepted candidates
        # are a2 (fpr 0, tpr 0.5) and nextafter (fpr 0, tpr 0), so
        # best is a2 with tpr 0.5. Mutant [688] (`/` -> `//`) in
        # tpr reports 1 // 2 = 0. Mutants [1301] (`>=` -> `<`) and
        # [1309] (`>=` -> `<=`) in tp report tpr 0.5 at a2 but 1.0
        # at nextafter, so nextafter wins with tpr 1.0.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "calibration.jsonl"
            _write_high_human_rows(path)
            result = select_threshold(path, target_fpr=0.0)
            assert result.threshold > 0.60
            assert result.observed_fpr == 0.0
            assert result.observed_tpr == 0.5

    def test_evaluate_threshold_hash_passthrough(self):
        # Mutant [1614] (`or` -> `and`) in
        # `calibration_dataset_hash or ""`: the hash must pass
        # through; the mutant returns "" for a non-empty hash.
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "calibration.jsonl"
            eval_path = Path(tmp) / "evaluation.jsonl"
            _write_scored_rows(cal_path, "observation", "sample")
            _write_scored_rows(eval_path, "eval", "check")
            cal_hash = dataset_sha256(cal_path)
            result = evaluate_threshold(eval_path, 0.5, calibration_dataset_hash=cal_hash)
            assert result.calibration_dataset_hash == cal_hash

    def test_get_latest_other_detector_excluded(self):
        # Mutants [1161]/[1162] (`==` -> `>=`) and [1239]/[1240]
        # (`==` -> `<=`) in the detector filters: "det2" >= "det1"
        # and "det0" <= "det1", so the mutants include the other
        # detectors' (later) artifacts in det1's latest/lineage.
        with tempfile.TemporaryDirectory() as tmp:
            mgr = CalibrationManager(Path(tmp))
            kwargs = eligible_artifact_kwargs()
            mgr.store(
                detector_id="det0",
                detector_version="1.0",
                curve=platt_curve(),
                calibration_id="cal0",
                created_at="2024-01-03T00:00:00+00:00",
                **kwargs,
            )
            mgr.store(
                detector_id="det1",
                detector_version="1.0",
                curve=platt_curve(),
                calibration_id="cal1",
                created_at="2024-01-01T00:00:00+00:00",
                **kwargs,
            )
            mgr.store(
                detector_id="det2",
                detector_version="1.0",
                curve=platt_curve(),
                calibration_id="cal2",
                created_at="2024-01-02T00:00:00+00:00",
                **kwargs,
            )
            latest = mgr.get_latest_for_detector("det1")
            assert latest is not None
            assert latest.artifact_id == "det1:cal1"
            assert [a.artifact_id for a in mgr.get_lineage("det1")] == ["det1:cal1"]

    def test_get_latest_dynamic_detector_id(self):
        # Mutants [1179]/[1180] (`==` -> `is`) in the detector
        # filters: a detector id built at runtime is equal but not
        # identical to the stored one, so the mutants find nothing.
        with tempfile.TemporaryDirectory() as tmp:
            mgr = CalibrationManager(Path(tmp))
            store_eligible(mgr, "det1", "cal1")
            dynamic_id = "".join(["det", "1"])
            twin = "".join(["det", "1"])
            assert dynamic_id == twin
            # The two runtime-built strings are equal but distinct
            # objects (ruff must not rewrite this to `!=`: identity
            # is the point — the `==` -> `is` mutants find nothing
            # for a non-identical id).
            assert dynamic_id is not twin
            latest = mgr.get_latest_for_detector(dynamic_id)
            assert latest is not None
            assert latest.artifact_id == "det1:cal1"
            assert [a.artifact_id for a in mgr.get_lineage(dynamic_id)] == ["det1:cal1"]

    def test_store_different_content_same_id_rejected(self):
        # Mutant [1543] (`!=` -> `<`) in the duplicate-id check in
        # store(): a second artifact with the same id but different
        # content must raise. The larger hash is stored first, so
        # existing < new is False and the mutant accepts the clash.
        with tempfile.TemporaryDirectory() as tmp:
            mgr = CalibrationManager(Path(tmp))
            kwargs = eligible_artifact_kwargs()
            first_version = "1.0"
            second_version = "2.0"
            hash_first = CalibrationArtifact(
                **_artifact_kwargs(detector_version=first_version)
            ).content_hash
            hash_second = CalibrationArtifact(
                **_artifact_kwargs(detector_version=second_version)
            ).content_hash
            if hash_first < hash_second:
                first_version, second_version = second_version, first_version
            mgr.store(
                detector_id="det1",
                detector_version=first_version,
                curve=platt_curve(),
                calibration_id="cal1",
                created_at="2024-01-01T00:00:00+00:00",
                **kwargs,
            )
            with pytest.raises(CalibrationError, match="different content"):
                mgr.store(
                    detector_id="det1",
                    detector_version=second_version,
                    curve=platt_curve(),
                    calibration_id="cal1",
                    created_at="2024-01-01T00:00:00+00:00",
                    **kwargs,
                )

    def test_load_all_same_id_different_content_rejected(self):
        # Mutants [1542] (`!=` -> `<`) and [1554] (`!=` -> `<=`)
        # in the duplicate-id check in _load_all: two files with the
        # same artifact id but different content must refuse to load.
        # The files are named a.json / b.json (not by hash), with the
        # larger hash first, so existing < new and existing <= new
        # are both False and the mutants load the ambiguous registry.
        with tempfile.TemporaryDirectory() as tmp:
            storage = Path(tmp)
            artifact_a = CalibrationArtifact(**_artifact_kwargs(detector_version="1.0"))
            artifact_b = CalibrationArtifact(**_artifact_kwargs(detector_version="2.0"))
            first, second = (
                (artifact_a, artifact_b)
                if artifact_a.content_hash > artifact_b.content_hash
                else (artifact_b, artifact_a)
            )
            (storage / "a.json").write_text(json.dumps(first.to_dict()), encoding="utf-8")
            (storage / "b.json").write_text(json.dumps(second.to_dict()), encoding="utf-8")
            with pytest.raises(CalibrationError, match="two different contents"):
                CalibrationManager(storage)

    def test_validate_artifact_line_numbers(self):
        # Mutants [57]/[58] (enumerate start 1 -> 0 / 2): a bad
        # JSON line on line 2 must be reported as line 2.
        with tempfile.TemporaryDirectory() as tmp:
            mgr = CalibrationManager(Path(tmp))
            store_eligible(mgr, "det1", "cal1")
            bad = Path(tmp) / "bad.jsonl"
            bad.write_text(
                json.dumps({"score": 0.5, "label": "ai"})
                + "\nnot json\n"
                + json.dumps({"score": 0.5, "label": "human"})
                + "\n",
                encoding="utf-8",
            )
            with pytest.raises(CalibrationError, match="Line 2: invalid JSON"):
                mgr.validate_artifact("det1:cal1", bad, strict=True)

    def test_validate_artifact_non_strict_skips_blank_line(self):
        # Mutant [1560] (`continue` -> `break`) after a blank line
        # (L880): with a blank line between two valid rows, both
        # rows must be counted; the mutant stops at the blank line
        # and counts only the first.
        with tempfile.TemporaryDirectory() as tmp:
            mgr = CalibrationManager(Path(tmp))
            store_eligible(mgr, "det1", "cal1")
            path = Path(tmp) / "data.jsonl"
            path.write_text(
                json.dumps({"score": 0.5, "label": "ai"})
                + "\n\n"
                + json.dumps({"score": 0.5, "label": "human"})
                + "\n",
                encoding="utf-8",
            )
            results = mgr.validate_artifact("det1:cal1", path, strict=False)
            assert results["sample_count"] == 2

    def test_validate_artifact_non_strict_skips_bad_score(self):
        # Mutant [1563] (`continue` -> `break`) after an invalid
        # score (L896): with an unparseable score first and a valid
        # row after, non-strict validation must still find the valid
        # sample; the mutant stops at the bad row and reports none.
        with tempfile.TemporaryDirectory() as tmp:
            mgr = CalibrationManager(Path(tmp))
            store_eligible(mgr, "det1", "cal1")
            bad = Path(tmp) / "bad.jsonl"
            bad.write_text(
                json.dumps({"score": "bad", "label": "ai"})
                + "\n"
                + json.dumps({"score": 0.5, "label": "ai"})
                + "\n",
                encoding="utf-8",
            )
            results = mgr.validate_artifact("det1:cal1", bad, strict=False)
            assert results["sample_count"] == 1

    def test_validate_artifact_missing_label_strict(self):
        # Mutant [1608] (`or` -> `and`) in the row check: `and`
        # binds tighter than `or`, so the mutant becomes
        # `(not dict and no score) or no label`. A row WITH a label
        # but WITHOUT a score must raise "missing score or label";
        # the mutant proceeds and dies with KeyError on "score".
        with tempfile.TemporaryDirectory() as tmp:
            mgr = CalibrationManager(Path(tmp))
            store_eligible(mgr, "det1", "cal1")
            bad = Path(tmp) / "bad.jsonl"
            bad.write_text(json.dumps({"label": "ai"}) + "\n", encoding="utf-8")
            with pytest.raises(CalibrationError, match="missing score or label"):
                mgr.validate_artifact("det1:cal1", bad, strict=True)

    def test_calibrate_positional_kwarg_rejected(self):
        # Mutants [858]/[859]/[861]/[862]/[863]/[871]/[872]/[873]
        # (`*` -> `/`) in the keyword-only markers: the keyword-only
        # arguments must reject positional passing with TypeError;
        # the mutants accept it.
        artifact = eligible_artifact()
        with pytest.raises(TypeError):
            artifact.calibrate(0.5, True)
        with pytest.raises(TypeError):
            artifact.apply(0.5, True)
        with tempfile.TemporaryDirectory() as tmp:
            mgr = CalibrationManager(Path(tmp))
            store_eligible(mgr, "det1", "cal1")
            bad = Path(tmp) / "bad.jsonl"
            bad.write_text(json.dumps({"score": 0.5, "label": "ai"}) + "\n", encoding="utf-8")
            with pytest.raises(TypeError):
                mgr.validate_artifact("det1:cal1", bad, True)
            with pytest.raises(TypeError):
                mgr.get_calibrated_score("det1", 0.5, True)
            with pytest.raises(TypeError):
                mgr.get_calibrated_result("det1", 0.5, True)
            cal_path = Path(tmp) / "calibration.jsonl"
            eval_path = Path(tmp) / "evaluation.jsonl"
            _write_spread_rows(cal_path)
            _write_spread_rows(eval_path)
            with pytest.raises(TypeError):
                select_threshold(cal_path, 0.01)
            with pytest.raises(TypeError):
                evaluate_threshold(eval_path, 0.5, True)
            with pytest.raises(TypeError):
                run_calibration_evaluation(cal_path, eval_path, 0.01)

    def test_from_dict_defaults(self):
        # Mutants [25]/[26]/[27]/[28] (score_range [0.0, 1.0]
        # defaults) and [31]/[32] (sample_count 0 default): the
        # defaults must be (0.0, 1.0) and 0.
        curve = CalibrationCurve.from_dict({"method": "platt", "parameters": {"A": 1.0, "B": 0.0}})
        assert curve.score_range == (0.0, 1.0)
        assert curve.sample_count == 0

    def test_dataset_reference_negative_sample_count_rejected(self):
        # Mutant [1386] (`<=` -> `==`) in the sample_count check:
        # -1 must raise; the mutant only rejects exactly 0.
        with pytest.raises(CalibrationError, match="must be positive"):
            DatasetReference(
                name="x",
                fingerprint_sha256=hex64(1),
                split="train",
                sample_count=-1,
            )

    def test_dataset_reference_from_dict_missing_sample_count_rejected(self):
        # Mutant [39] (sample_count 0 -> 1): from_dict without a
        # sample_count must raise ("must be positive"); the mutant
        # defaults to 1 and constructs. (Mutant [40], 0 -> -1, is
        # equivalent — -1 is rejected with the identical message —
        # and is baselined as unobservable-value, not killed.)
        with pytest.raises(CalibrationError, match="must be positive"):
            DatasetReference.from_dict(
                {"name": "x", "fingerprint_sha256": hex64(1), "split": "train"}
            )

    def test_manager_store_id_length(self):
        # Mutants [55]/[56] ([:24] -> [:25] / [:23]): a generated
        # calibration id must be exactly 24 characters.
        with tempfile.TemporaryDirectory() as tmp:
            mgr = CalibrationManager(Path(tmp))
            artifact = mgr.store(
                detector_id="det1",
                detector_version="1.0",
                curve=platt_curve(),
                created_at="2024-01-01T00:00:00+00:00",
                **eligible_artifact_kwargs(),
            )
            assert len(artifact.calibration_id) == 24

    def test_validate_artifact_strict_default(self):
        # Mutant [1628] (strict=True -> False) in validate_artifact:
        # the default must be strict.
        with tempfile.TemporaryDirectory() as tmp:
            mgr = CalibrationManager(Path(tmp))
            store_eligible(mgr, "det1", "cal1")
            bad = Path(tmp) / "bad.jsonl"
            bad.write_text("not json\n", encoding="utf-8")
            with pytest.raises(CalibrationError, match="invalid JSON"):
                mgr.validate_artifact("det1:cal1", bad)

    def test_select_threshold_strict_default(self):
        # Mutant [1636] (strict=True -> False) in select_threshold:
        # the default must be strict.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "calibration.jsonl"
            path.write_text("not json\n", encoding="utf-8")
            with path.open("a", encoding="utf-8") as handle:
                _write_scored_rows_to(handle, "observation", "sample")
            with pytest.raises(DatasetFormatError, match="not valid JSON"):
                select_threshold(path)

    def test_evaluate_threshold_strict_default(self):
        # Mutant [1637] (strict=True -> False) in evaluate_threshold:
        # the default must be strict.
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "calibration.jsonl"
            eval_path = Path(tmp) / "evaluation.jsonl"
            _write_scored_rows(cal_path, "observation", "sample")
            eval_path.write_text("not json\n", encoding="utf-8")
            with eval_path.open("a", encoding="utf-8") as handle:
                _write_scored_rows_to(handle, "eval", "check")
            with pytest.raises(DatasetFormatError, match="not valid JSON"):
                evaluate_threshold(eval_path, 0.5)

    def test_run_evaluation_strict_default(self):
        # Mutant [1644] (strict=True -> False) in
        # run_calibration_evaluation: the default must be strict.
        with tempfile.TemporaryDirectory() as tmp:
            cal_path = Path(tmp) / "calibration.jsonl"
            eval_path = Path(tmp) / "evaluation.jsonl"
            cal_path.write_text("not json\n", encoding="utf-8")
            with cal_path.open("a", encoding="utf-8") as handle:
                _write_scored_rows_to(handle, "observation", "sample")
            _write_scored_rows(eval_path, "eval", "check")
            with pytest.raises(DatasetFormatError, match="not valid JSON"):
                run_calibration_evaluation(cal_path, eval_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


# ---------------------------------------------------------------------------
# Audit W2 — Worker B regression tests (CORE-03/04/05/06)
# Added RED first, from the audit's stated expected results and independent
# oracles (never from current product output).
# ---------------------------------------------------------------------------


def _oracle_temperature_probability(p: float, temperature: float) -> float:
    """Independent oracle: sigmoid(logit(p) / T), Guo et al. temperature scaling.

    Computed here with plain math only — never by calling the product.
    Endpoints are the documented limits sigmoid(+/-inf) = 1/0.
    """
    if p == 0.0:
        return 0.0
    if p == 1.0:
        return 1.0
    logit = math.log(p) - math.log1p(-p)
    return 1.0 / (1.0 + math.exp(-logit / temperature))


def _oracle_sigmoid(value: float) -> float:
    return 1.0 / (1.0 + math.exp(-value))


class TestTemperatureProbabilityDomainAuditW2:
    """CORE-03: temperature scaling must use sigmoid(logit(p)/T) for
    probability inputs, or sigmoid(z/T) for explicit logit inputs."""

    def test_probability_identity_at_T1(self):
        curve = CalibrationCurve(method="temperature", parameters={"T": 1.0})
        for p in (0.2, 0.5, 0.8):
            assert curve.calibrate(p) == pytest.approx(_oracle_temperature_probability(p, 1.0))
            assert curve.calibrate(p) == pytest.approx(p)

    def test_probability_at_other_temperatures(self):
        for temperature in (0.5, 2.0, 3.0):
            curve = CalibrationCurve(method="temperature", parameters={"T": temperature})
            for p in (0.2, 0.5, 0.8):
                assert curve.calibrate(p) == pytest.approx(
                    _oracle_temperature_probability(p, temperature)
                )

    def test_probability_endpoints(self):
        curve = CalibrationCurve(method="temperature", parameters={"T": 2.0})
        assert curve.calibrate(0.0) == 0.0
        assert curve.calibrate(1.0) == 1.0

    def test_nonfinite_probability_rejected(self):
        curve = CalibrationCurve(method="temperature", parameters={"T": 1.0})
        for bad in (float("nan"), float("inf"), float("-inf")):
            with pytest.raises(CalibrationError):
                curve.calibrate(bad)

    def test_logit_curve_matches_sigmoid_over_T(self):
        from textforensics.calibration import CalibrationCurve as _Curve

        curve = _Curve(method="temperature", parameters={"T": 2.0}, input_semantics="logit")
        for z in (-2.0, -0.5, 0.0, 0.5, 2.0, 5.0):
            assert curve.calibrate(z) == pytest.approx(_oracle_sigmoid(z / 2.0))

    def test_logit_probability_equivalence(self):
        prob = CalibrationCurve(
            method="temperature", parameters={"T": 2.0}, input_semantics="probability"
        )
        logit_curve = CalibrationCurve(
            method="temperature", parameters={"T": 2.0}, input_semantics="logit"
        )
        for p in (0.2, 0.5, 0.8):
            z = math.log(p) - math.log1p(-p)
            assert prob.calibrate(p) == pytest.approx(logit_curve.calibrate(z))

    def test_logit_nonfinite_rejected(self):
        curve = CalibrationCurve(
            method="temperature", parameters={"T": 1.0}, input_semantics="logit"
        )
        for bad in (float("nan"), float("inf"), float("-inf")):
            with pytest.raises(CalibrationError):
                curve.calibrate(bad)

    def test_unsupported_semantics_rejected(self):
        with pytest.raises(CalibrationError):
            CalibrationCurve(
                method="temperature", parameters={"T": 1.0}, input_semantics="raw_score"
            )
        with pytest.raises(CalibrationError):
            CalibrationCurve(
                method="platt",
                parameters={"A": 1.0, "B": 0.0},
                input_semantics="logit",
            )

    def test_lower_means_ai_temperature_inverts_probability(self):
        curve = CalibrationCurve(
            method="temperature",
            parameters={"T": 1.0},
            native_score_direction="lower_means_ai",
        )
        # A raw probability 0.2 under lower_means_ai is P(AI) = 0.8.
        assert curve.calibrate(0.2) == pytest.approx(_oracle_temperature_probability(0.8, 1.0))

    def test_legacy_v2_temperature_preserves_old_math_but_is_not_eligible(self):
        from textforensics.calibration import CalibrationCurve as _Curve

        legacy = _Curve.from_dict(
            {
                "schema": "textforensics.calibration-curve/v2",
                "method": "temperature",
                "parameters": {"T": 1.0},
            }
        )
        assert legacy.schema == "textforensics.calibration-curve/v2"
        assert legacy.is_legacy is True
        # Old math preserved for verification of old artifacts only:
        assert legacy.calibrate(0.2) == pytest.approx(0.549833997312478)
        kwargs = eligible_artifact_kwargs()
        artifact = CalibrationArtifact(
            artifact_id="d:c",
            detector_id="d",
            detector_version="1",
            curve=legacy,
            calibration_id="c",
            **kwargs,
        )
        assert artifact.eligible_for_probability is False
        assert any("legacy" in issue.lower() for issue in artifact.validation_issues())

    def test_migrated_legacy_curve_drops_old_metrics(self):
        from textforensics.calibration import (
            CalibrationCurve as _Curve,
        )
        from textforensics.calibration import (
            migrate_legacy_temperature_curve,
        )

        legacy = _Curve.from_dict(
            {
                "schema": "textforensics.calibration-curve/v2",
                "method": "temperature",
                "parameters": {"T": 2.0},
                "sample_count": 200,
                "calibration_error": 0.05,
                "reference_dataset_hash": hex64(7),
            }
        )
        migrated = migrate_legacy_temperature_curve(legacy)
        assert migrated.schema == "textforensics.calibration-curve/v3"
        assert migrated.input_semantics == "probability"
        assert migrated.parameters["T"] == 2.0
        # Old metrics must NOT be carried over: the migrated curve needs
        # a refit/re-evaluation before it can support a probability.
        assert migrated.sample_count == 0
        assert migrated.calibration_error is None
        assert migrated.reference_dataset_hash == ""
        assert migrated.calibrate(0.2) == pytest.approx(_oracle_temperature_probability(0.2, 2.0))


class TestCalibrationImmutabilityAuditW2:
    """CORE-04: frozen artifacts must be deeply immutable; the manager
    must publish memory only after durable storage succeeds."""

    def test_mutating_original_parameters_cannot_change_output(self):
        params = {"T": 1.0}
        curve = CalibrationCurve(method="temperature", parameters=params)
        before = curve.calibrate(0.2)
        params["T"] = 0.001
        assert curve.calibrate(0.2) == pytest.approx(before)
        assert curve.calibrate(0.2) == pytest.approx(0.2)

        platt_params = {"A": 1.0, "B": 0.0}
        platt = CalibrationCurve(method="platt", parameters=platt_params)
        platt_params["A"] = 99.0
        assert platt.calibrate(0.5) == pytest.approx(0.6224593312018546)

    def test_mutating_returned_parameters_cannot_change_output(self):
        curve = CalibrationCurve(method="temperature", parameters={"T": 1.0})
        payload = curve.to_dict()
        payload["parameters"]["T"] = 0.001
        assert curve.calibrate(0.2) == pytest.approx(0.2)
        with pytest.raises(TypeError):
            curve.parameters["T"] = 0.001  # type: ignore[index]

    def test_isotonic_nested_lists_are_frozen(self):
        curve = CalibrationCurve(
            method="isotonic",
            parameters={"x": [0.0, 0.5, 1.0], "y": [0.0, 0.5, 1.0]},
        )
        with pytest.raises(TypeError):
            curve.parameters["x"][0] = 0.9  # type: ignore[index]

    def test_artifact_nested_mappings_are_frozen(self):
        artifact = eligible_artifact()
        with pytest.raises(TypeError):
            artifact.metrics["brier"] = 0.99  # type: ignore[index]
        with pytest.raises(TypeError):
            artifact.disjointness["strategy"] = "tampered"  # type: ignore[index]
        with pytest.raises(TypeError):
            artifact.metadata["note"] = "tampered"  # type: ignore[index]
        assert artifact.eligible_for_probability is True
        assert artifact.content_hash == artifact.compute_content_hash()

    def test_mutating_serialized_artifact_cannot_change_it(self):
        artifact = eligible_artifact()
        payload = artifact.to_dict()
        payload["metrics"]["brier"] = 0.99
        payload["curve"]["parameters"]["A"] = 99.0
        assert artifact.metrics["brier"] == pytest.approx(0.10)
        assert artifact.calibrate(0.5) == pytest.approx(0.6224593312018546)
        assert artifact.content_hash == artifact.compute_content_hash()

    def test_tampered_content_hash_rejected_at_load(self):
        artifact = eligible_artifact()
        payload = artifact.to_dict()
        payload["metrics"]["brier"] = 0.99  # hash no longer matches content
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "artifact.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with pytest.raises(CalibrationError, match="content_hash"):
                load_calibration_artifact(path)

    def test_store_publishes_only_after_persist(self, tmp_path):
        mgr = CalibrationManager(tmp_path)
        original_save = CalibrationManager._save_artifact

        def _failing_save(self, artifact):  # noqa: ANN001, ANN202
            raise OSError("simulated disk failure")

        CalibrationManager._save_artifact = _failing_save  # type: ignore[method-assign]
        try:
            with pytest.raises(OSError, match="simulated disk failure"):
                store_eligible(mgr, "det1", "cal1")
        finally:
            CalibrationManager._save_artifact = original_save  # type: ignore[method-assign]
        assert mgr.get("det1:cal1") is None
        assert list(tmp_path.glob("*.json")) == []
        # A later successful store works and is visible.
        stored = store_eligible(mgr, "det1", "cal1")
        assert mgr.get("det1:cal1") == stored
        assert list(tmp_path.glob("*.json")) == [tmp_path / f"{stored.content_hash}.json"]

    def test_failed_store_leaves_prior_artifact_intact(self, tmp_path):
        mgr = CalibrationManager(tmp_path)
        original = store_eligible(mgr, "det1", "cal1")
        original_save = CalibrationManager._save_artifact

        def _failing_save(self, artifact):  # noqa: ANN001, ANN202
            raise OSError("simulated disk failure")

        CalibrationManager._save_artifact = _failing_save  # type: ignore[method-assign]
        try:
            # A new artifact id (so no content-conflict check fires):
            # the disk failure must leave the prior artifact intact.
            with pytest.raises(OSError, match="simulated disk failure"):
                mgr.store(
                    "det1",
                    "1.0",
                    CalibrationCurve(method="platt", parameters={"A": 2.0, "B": 0.0}),
                    calibration_id="cal2",
                    created_at="2024-01-01T00:00:00+00:00",
                    **eligible_artifact_kwargs(),
                )
        finally:
            CalibrationManager._save_artifact = original_save  # type: ignore[method-assign]
        assert mgr.get("det1:cal1") == original
        assert mgr.get("det1:cal2") is None
        assert (tmp_path / f"{original.content_hash}.json").exists()
        assert len(list(tmp_path.glob("*.json"))) == 1


def _audit_identity(**overrides):
    from textforensics.calibration import InferenceIdentity

    fields = {
        "detector_id": "det1",
        "detector_version": "1.0",
        "provider": "local",
        "model": "builtin-heuristic-0.1.0",
        "config_hash": hex64(5),
        "native_score_semantics": "probability_higher_means_ai",
        "calibration_id": "cal1",
        "regime": "unedited",
    }
    fields.update(overrides)
    return InferenceIdentity(**fields)


def _store_with_identity(
    mgr,
    *,
    detector_version="1.0",
    calibration_id="cal1",
    created_at="2024-01-01T00:00:00+00:00",
    **overrides,
):
    identity = _audit_identity(
        detector_version=detector_version, calibration_id=calibration_id, **overrides
    )
    # Pass the identity as one object; the individual identity fields
    # are not also passed as explicit kwargs.
    kwargs = eligible_artifact_kwargs()
    for field in ("provider", "model", "config_hash", "native_score_semantics", "regime"):
        kwargs.pop(field, None)
    return mgr.store(
        detector_id="det1",
        detector_version=detector_version,
        curve=platt_curve(),
        calibration_id=calibration_id,
        created_at=created_at,
        identity=identity,
        **kwargs,
    )


class TestInferenceIdentityAuditW2:
    """CORE-05: only an artifact matching the exact current inference
    identity may emit a validated probability."""

    def test_exact_identity_emits_validated_probability(self, tmp_path):
        mgr = CalibrationManager(tmp_path)
        _store_with_identity(mgr)
        result = mgr.get_calibrated_result_for_identity(_audit_identity(), 0.5)
        assert result is not None
        assert result.status == "validated"
        assert result.probability_eligible is True
        assert result.value == pytest.approx(0.6224593312018546)

    def test_old_version_cannot_emit_validated_probability(self, tmp_path):
        mgr = CalibrationManager(tmp_path)
        mgr.store(
            detector_id="det1",
            detector_version="old-version",
            curve=platt_curve(),
            calibration_id="cal1",
            created_at="2024-01-01T00:00:00+00:00",
            identity=_audit_identity(detector_version="old-version"),
            **eligible_artifact_kwargs(),
        )
        # Queried with the CURRENT version's identity: no exact match.
        assert mgr.get_for_identity(_audit_identity()) is None
        assert mgr.get_calibrated_result_for_identity(_audit_identity(), 0.5) is None
        assert mgr.get_calibrated_score_for_identity(_audit_identity(), 0.5) is None

    def test_changed_provider_model_config_regime_refused(self, tmp_path):
        mgr = CalibrationManager(tmp_path)
        _store_with_identity(mgr)
        for overrides in (
            {"provider": "other-provider"},
            {"model": "other-model-9.9"},
            {"config_hash": hex64(6)},
            {"regime": "paraphrased"},
            {"calibration_id": "cal2"},
            {"detector_version": "2.0"},
            {"native_score_semantics": "logit_higher_means_ai"},
        ):
            assert mgr.get_for_identity(_audit_identity(**overrides)) is None
            assert mgr.get_calibrated_result_for_identity(_audit_identity(**overrides), 0.5) is None

    def test_latest_by_time_does_not_cross_identity_epochs(self, tmp_path):
        mgr = CalibrationManager(tmp_path)
        _store_with_identity(
            mgr,
            detector_version="1.0",
            calibration_id="cal1",
            created_at="2024-01-01T00:00:00+00:00",
        )
        # A later artifact for an OLD version must not be selected for
        # the current version's identity.
        _store_with_identity(
            mgr,
            detector_version="old-version",
            calibration_id="cal-old",
            created_at="2025-06-01T00:00:00+00:00",
        )
        found = mgr.get_for_identity(_audit_identity())
        assert found is not None
        assert found.detector_version == "1.0"
        assert found.calibration_id == "cal1"

    def test_competing_artifacts_each_selected_by_own_identity(self, tmp_path):
        mgr = CalibrationManager(tmp_path)
        _store_with_identity(mgr, calibration_id="cal1", config_hash=hex64(5))
        _store_with_identity(mgr, calibration_id="cal2", config_hash=hex64(6))
        first = mgr.get_for_identity(_audit_identity(calibration_id="cal1"))
        second = mgr.get_for_identity(_audit_identity(calibration_id="cal2", config_hash=hex64(6)))
        assert first is not None and first.calibration_id == "cal1"
        assert second is not None and second.calibration_id == "cal2"
        assert first.content_hash != second.content_hash

    def test_missing_identity_fields_make_artifact_ineligible(self):
        kwargs = eligible_artifact_kwargs()
        for field in (
            "provider",
            "model",
            "config_hash",
            "native_score_semantics",
            "regime",
        ):
            kwargs.pop(field, None)
        artifact = CalibrationArtifact(
            artifact_id="d:c",
            detector_id="d",
            detector_version="1",
            curve=platt_curve(),
            calibration_id="c",
            **kwargs,
        )
        assert artifact.eligible_for_probability is False
        assert any("identity" in issue.lower() for issue in artifact.validation_issues())

    def test_artifact_with_complete_identity_is_eligible(self):
        artifact = CalibrationArtifact(
            artifact_id="det1:cal1",
            detector_id="det1",
            detector_version="1.0",
            curve=platt_curve(),
            calibration_id="cal1",
            created_at="2024-01-01T00:00:00+00:00",
            **eligible_artifact_kwargs(),
        )
        assert artifact.validation_issues() == []
        assert artifact.eligible_for_probability is True
        assert artifact.inference_identity() == _audit_identity()

    def test_legacy_id_only_methods_require_identity(self, tmp_path):
        mgr = CalibrationManager(tmp_path)
        _store_with_identity(mgr)
        with pytest.raises(CalibrationError, match="InferenceIdentity"):
            mgr.get_calibrated_score("det1", 0.5)
        with pytest.raises(CalibrationError, match="InferenceIdentity"):
            mgr.get_calibrated_result("det1", 0.5)

    def test_diagnostic_use_never_emits_validated_probability(self, tmp_path):
        mgr = CalibrationManager(tmp_path)
        # Ineligible artifact (no fit/evaluation provenance) stored under
        # a matching identity: explicit diagnostic use stays unvalidated.
        identity = _audit_identity()
        mgr.store(
            "det1",
            "1.0",
            platt_curve(),
            calibration_id="cal1",
            created_at="2024-01-01T00:00:00+00:00",
            identity=identity,
        )
        result = mgr.get_calibrated_result_for_identity(identity, 0.5, allow_unvalidated=True)
        assert result is not None
        assert result.status == "unvalidated"
        assert result.probability_eligible is False
        with pytest.raises(CalibrationError, match="not eligible"):
            mgr.get_calibrated_result_for_identity(identity, 0.5)

    def test_artifact_apply_rejects_mismatched_identity(self):
        artifact = CalibrationArtifact(
            artifact_id="det1:cal1",
            detector_id="det1",
            detector_version="1.0",
            curve=platt_curve(),
            calibration_id="cal1",
            created_at="2024-01-01T00:00:00+00:00",
            **eligible_artifact_kwargs(),
        )
        with pytest.raises(CalibrationError, match="InferenceIdentity"):
            artifact.apply(0.5, identity=_audit_identity(detector_version="2.0"))
        assert artifact.apply(0.5, identity=_audit_identity()).status == "validated"


def _write_jsonl_rows(path: Path, rows) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


_AUDIT_HUMAN = {
    "label": "human",
    "text": "I ran this test yesterday and wrote the numbers in my notebook.",
}
_AUDIT_AI = {
    "label": "ai",
    "text": "Furthermore, it is important to note that this robust solution seamlessly unlocks potential.",
}


class TestHeldOutDisjointnessAuditW2:
    """CORE-06: a held-out label requires a verified sample/group-level
    disjointness proof; unknown or contaminated cases are rejected or
    honestly labelled diagnostic."""

    def test_no_provenance_is_never_held_out(self, tmp_path):
        eval_path = tmp_path / "eval.jsonl"
        _write_jsonl_rows(eval_path, [_AUDIT_HUMAN, _AUDIT_AI])
        result = evaluate_threshold(eval_path, 0.5)
        assert result.evaluation_mode == "diagnostic"
        assert result.disjointness_status == "unknown"

    def test_allow_same_dataset_is_diagnostic_not_held_out(self, tmp_path):
        path = tmp_path / "data.jsonl"
        _write_jsonl_rows(path, [_AUDIT_HUMAN, _AUDIT_AI])
        result = evaluate_threshold(
            path, 0.5, calibration_dataset_hash="dummy", allow_same_dataset=True
        )
        assert result.evaluation_mode == "diagnostic"
        assert result.disjointness_status == "unknown"

    def test_verified_proof_stays_held_out(self, tmp_path):
        from textforensics.benchmark import prove_disjointness

        cal_path = tmp_path / "cal.jsonl"
        eval_path = tmp_path / "eval.jsonl"
        _write_jsonl_rows(cal_path, [_AUDIT_HUMAN, _AUDIT_AI])
        _write_jsonl_rows(
            eval_path,
            [
                {"label": "human", "text": "A completely different human sentence here."},
                {"label": "ai", "text": "A completely different machine sentence here."},
            ],
        )
        proof = prove_disjointness(cal_path, eval_path)
        assert proof.status == "verified"
        result = evaluate_threshold(eval_path, 0.5, disjointness_proof=proof)
        assert result.evaluation_mode == "held_out"
        assert result.disjointness_status == "verified"
        assert result.overlap_count == 0

    def test_contaminated_proof_raises_and_diagnostic_reports_overlap(self, tmp_path):
        from textforensics.benchmark import prove_disjointness

        cal_path = tmp_path / "cal.jsonl"
        eval_path = tmp_path / "eval.jsonl"
        _write_jsonl_rows(cal_path, [_AUDIT_HUMAN, _AUDIT_AI])
        # Reordered rows: file hash changes, sample overlap is complete.
        _write_jsonl_rows(eval_path, [_AUDIT_AI, _AUDIT_HUMAN])
        proof = prove_disjointness(cal_path, eval_path)
        assert proof.status == "contaminated"
        assert proof.overlap_count == 2
        with pytest.raises(ValueError, match="Contamination"):
            evaluate_threshold(eval_path, 0.5, disjointness_proof=proof)
        diagnostic = evaluate_threshold(eval_path, 0.5, disjointness_proof=proof, diagnostic=True)
        assert diagnostic.evaluation_mode == "diagnostic"
        assert diagnostic.disjointness_status == "contaminated"
        assert diagnostic.overlap_count == 2

    def test_unknown_proof_raises_and_diagnostic_reports_unknown(self, tmp_path):
        from textforensics.benchmark import DisjointnessProof

        eval_path = tmp_path / "eval.jsonl"
        _write_jsonl_rows(eval_path, [_AUDIT_HUMAN, _AUDIT_AI])
        proof = DisjointnessProof(
            status="unknown",
            overlap_count=-1,
            training_count=0,
            evaluation_count=2,
            training_hash="",
            evaluation_hash="",
            errors=("training file could not be read",),
        )
        with pytest.raises(ValueError, match="could not be verified"):
            evaluate_threshold(eval_path, 0.5, disjointness_proof=proof)
        diagnostic = evaluate_threshold(eval_path, 0.5, disjointness_proof=proof, diagnostic=True)
        assert diagnostic.evaluation_mode == "diagnostic"
        assert diagnostic.disjointness_status == "unknown"

    def test_run_calibration_evaluation_rejects_reordered_rows(self, tmp_path):
        cal_path = tmp_path / "cal.jsonl"
        eval_path = tmp_path / "eval.jsonl"
        _write_jsonl_rows(cal_path, [_AUDIT_HUMAN, _AUDIT_AI])
        _write_jsonl_rows(eval_path, [_AUDIT_AI, _AUDIT_HUMAN])
        with pytest.raises(ValueError, match="Contamination"):
            run_calibration_evaluation(cal_path, eval_path, target_fpr=0.5)

    def test_run_calibration_evaluation_diagnostic_override_is_diagnostic(self, tmp_path):
        cal_path = tmp_path / "cal.jsonl"
        eval_path = tmp_path / "eval.jsonl"
        _write_jsonl_rows(cal_path, [_AUDIT_HUMAN, _AUDIT_AI])
        _write_jsonl_rows(eval_path, [_AUDIT_AI, _AUDIT_HUMAN])
        result = run_calibration_evaluation(cal_path, eval_path, target_fpr=0.5, diagnostic=True)
        assert result["evaluation_result"]["evaluation_mode"] == "diagnostic"
        assert result["evaluation_result"]["disjointness_status"] == "contaminated"
        assert result["evaluation_result"]["overlap_count"] == 2

    def test_validate_no_contamination_carries_proof(self, tmp_path):
        cal_path = tmp_path / "cal.jsonl"
        eval_path = tmp_path / "eval.jsonl"
        _write_jsonl_rows(cal_path, [_AUDIT_HUMAN, _AUDIT_AI])
        _write_jsonl_rows(eval_path, [_AUDIT_AI, _AUDIT_HUMAN])
        result = validate_no_contamination(cal_path, eval_path)
        assert result["valid"] is False
        assert result["contamination_detected"] is True
        assert result["proof"]["status"] == "contaminated"
        assert result["proof"]["overlap_count"] == 2
