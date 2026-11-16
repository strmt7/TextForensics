"""Worker F (W6) — kill tests for the detectors.py phase-1 survivors.

Fixtures are copied from tests/test_audit_w6_worker_e.py (the CC-17
worker): the current builtin prediction, its identity, and an eligible
artifact. Each test names the mutant(s) it kills.

- test_matching_binding_succeeds_and_stamps_fingerprint kills
  Delete_Not occ 41 / AddNot occ 92 ([1035, 11], the
  ``isinstance(identity, ...)`` guard), AddNot occ 93 ([1044, 15],
  the identity-field mismatch check), AddNot occ 94 ([1051, 11],
  the calibration_id mismatch check), IsNot_Is occ 25 ([1052, 36],
  ``identity.calibration_id is not None``), ReplaceAndWithOr occ 18
  ([1053, 12], the calibration_id mismatch conjunction), AddNot
  occ 98 ([1119, 7]) and IsNot_Is occ 28 ([1119, 35], the
  evaluation-fingerprint branch). It asserts the fingerprint is
  stamped, so the [1119] mutants (which skip the branch) fail it.
- test_explicit_matching_identity_binds kills IsNot_Is occ 26
  ([1066, 61]) and occ 27 ([1070, 54]) and AddNot occ 95 ([1066, 40])
  and occ 96 ([1070, 38]): the explicit identity supplies
  config_hash/regime, so the mutants (which take the caller's None
  instead) leave the binding unbound and raise.
- test_unbound_identity_refused kills all 22 Add_* mutants at
  [1099, 12] / [1100, 12] (occ 0 / occ 1): the missing-identity error
  message is built with ``+``; every replacement operator raises
  TypeError on str operands instead of DetectorContractError.
- test_identity_with_greater_version_refused kills NotEq_Lt occ 10
  and NotEq_LtE occ 10 ([1044, 45]).
- test_identity_with_smaller_version_refused kills NotEq_Gt occ 10
  and NotEq_GtE occ 10 ([1044, 45]).
- test_identity_with_greater_calibration_id_refused kills NotEq_Lt
  occ 11 and NotEq_LtE occ 11 ([1053, 40]).
- test_identity_with_smaller_calibration_id_refused kills NotEq_Gt
  occ 11 and NotEq_GtE occ 11 ([1053, 40]).
- test_identity_with_equal_value_calibration_id_binds kills
  NotEq_IsNot occ 8 ([1053, 40]): the identity's calibration_id
  is passed as a ``str`` subclass with the same value as the
  artifact's. The mutant (``is not``) rejects it because the
  subclass instance can never be identical to the artifact's plain
  ``str``; the original (``!=``) accepts it because the values are
  equal. (A plain-``str`` equal value does NOT kill it: the test
  fixtures pass the same BUILTIN_CALIBRATION_ID constant object, so
  ``is not`` is False there too.)
- test_inference_identity_rejects_positional_detector kills
  Mul_Div occ 8 ([939, 4]): the ``*`` keyword-only marker -> ``/``
  would accept a positional detector argument.
- test_apply_calibration_rejects_positional_identity kills Mul_Div
  occ 9 ([978, 4]): the ``*`` keyword-only marker -> ``/`` would
  accept a positional identity argument.
- test_unvalidated_artifact_refused_by_default kills
  ReplaceFalseWithTrue occ 2 ([983, 30]): the
  ``allow_unvalidated=False`` default -> True would return an
  unvalidated result instead of raising CalibrationError.
- test_binding_with_greater_declared_version_refused kills
  NotEq_Lt occ 8 ([919, 39]) in _validate_calibration_binding.
- test_binding_with_long_config_hash_refused kills NotEq_Lt occ 9
  ([929, 28]) and ReplaceOrWithAnd occ 21 ([929, 8]).
- test_binding_with_short_config_hash_refused kills NotEq_Gt occ 9
  ([929, 28]).
- test_binding_with_non_hex_config_hash_refused kills
  ReplaceOrWithAnd occ 22 ([930, 8]).
- test_binding_with_non_string_declared_field_refused kills
  ReplaceOrWithAnd occ 19 ([915, 41]).

NOTE: the AddNot occ 99 at [1138, 3] (``if TYPE_CHECKING:``) is NOT
killable: the mutant executes the import at runtime, which succeeds
(no import cycle — evidence does not import detectors) and binds a
name no runtime code reads (the functions import it lazily). It is
classified runtime-equivalent (unobservable-value) in
audit-w6-f-equiv-reasons-detectors.json.
"""

from __future__ import annotations

import dataclasses
import unittest

from textforensics.calibration import (
    CalibrationArtifact,
    CalibrationCurve,
    CalibrationError,
    DatasetReference,
)
from textforensics.detectors import (
    BuiltinHeuristicDetector,
    DetectorContractError,
    DetectorPrediction,
    apply_calibration,
    inference_identity_for_prediction,
)
from textforensics.engine import builtin_inference_identity


def _hex64(seed: int) -> str:
    return f"{seed:064x}"


def _platt_curve() -> CalibrationCurve:
    return CalibrationCurve(
        method="platt",
        parameters={"A": 1.0, "B": 0.0},
        reference_dataset_hash=_hex64(1),
        reference_dataset_name="test",
        calibrated_at="2024-01-01T00:00:00Z",
        sample_count=200,
    )


def _eligible_artifact_kwargs() -> dict:
    return {
        "fit_dataset": DatasetReference(
            name="fit", fingerprint_sha256=_hex64(2), split="train", sample_count=200
        ),
        "evaluation_dataset": DatasetReference(
            name="eval", fingerprint_sha256=_hex64(3), split="test", sample_count=200
        ),
        "disjointness": {"strategy": "disjoint_sample_ids", "evidence": "ids differ"},
        "metrics": {"brier": 0.10, "ece": 0.05, "log_loss": 0.30},
        "code_version": "abc123",
        "run_artifact_sha256": _hex64(4),
    }


BUILTIN_CONFIG_HASH = _hex64(5)
BUILTIN_REGIME = "unedited"
BUILTIN_CALIBRATION_ID = "cal-builtin-1"

_TEXT = (
    "The committee published its annual report on Tuesday, describing a year of "
    "steady progress across every department. Revenue grew modestly, membership "
    "remained stable, and the new training programme reached twice as many "
    "participants as the previous cycle. Several long-standing projects were "
    "completed, including the renovation of the central library and the "
    "replacement of the ageing heating system. The chair thanked volunteers, "
    "staff, and partner organisations for their continued support, and noted "
    "that the coming year would focus on consolidating these gains rather "
    "than expanding into new areas of work."
)


class TestDetectorsW6Killers(unittest.TestCase):
    def _current_prediction(self) -> DetectorPrediction:
        prediction = BuiltinHeuristicDetector().detect(_TEXT)
        self.assertIsNone(prediction.calibrated_ai_probability)
        return prediction

    def _current_identity(self):
        return builtin_inference_identity(
            config_hash=BUILTIN_CONFIG_HASH,
            calibration_id=BUILTIN_CALIBRATION_ID,
            regime=BUILTIN_REGIME,
        )

    def _artifact(self, **overrides) -> CalibrationArtifact:
        identity = self._current_identity()
        kwargs: dict = {
            "artifact_id": f"{identity.detector_id}:{BUILTIN_CALIBRATION_ID}",
            "detector_id": identity.detector_id,
            "detector_version": identity.detector_version,
            "curve": _platt_curve(),
            "calibration_id": BUILTIN_CALIBRATION_ID,
            "created_at": "2024-01-01T00:00:00+00:00",
            "provider": identity.provider,
            "model": identity.model,
            "config_hash": identity.config_hash,
            "native_score_semantics": identity.native_score_semantics,
            "regime": identity.regime,
            **_eligible_artifact_kwargs(),
        }
        kwargs.update(overrides)
        artifact = CalibrationArtifact(**kwargs)
        self.assertTrue(
            artifact.eligible_for_probability,
            f"fixture artifact must be eligible: {artifact.validation_issues()}",
        )
        return artifact

    def _calibrated_prediction(self, **calibration_overrides):
        prediction = self._current_prediction()
        prediction.calibrated_ai_probability = 0.42
        prediction.calibration_id = BUILTIN_CALIBRATION_ID
        calibration = {
            "calibration_id": BUILTIN_CALIBRATION_ID,
            "method": "platt",
            "detector_id": "textforensics/builtin-heuristic",
            "detector_version": BuiltinHeuristicDetector.detector_version,
            "provider": "textforensics",
            "model": "builtin-stylometric-heuristic",
            "native_score_semantics": "probability_higher_means_ai",
        }
        calibration.update(calibration_overrides)
        prediction.calibration = calibration
        return prediction

    def test_matching_binding_succeeds_and_stamps_fingerprint(self):
        prediction = self._current_prediction()
        bound = apply_calibration(
            prediction,
            self._artifact(),
            config_hash=BUILTIN_CONFIG_HASH,
            regime=BUILTIN_REGIME,
        )
        self.assertIsNotNone(bound.calibrated_ai_probability)
        self.assertEqual(bound.calibration_id, BUILTIN_CALIBRATION_ID)
        self.assertEqual(bound.calibration.get("evaluation_fingerprint"), _hex64(3))

    def test_explicit_matching_identity_binds(self):
        prediction = self._current_prediction()
        bound = apply_calibration(
            prediction,
            self._artifact(),
            identity=self._current_identity(),
        )
        self.assertIsNotNone(bound.calibrated_ai_probability)
        self.assertEqual(bound.calibration_id, BUILTIN_CALIBRATION_ID)

    def test_unbound_identity_refused(self):
        prediction = self._current_prediction()
        with self.assertRaises(DetectorContractError):
            apply_calibration(prediction, self._artifact())

    def test_identity_with_greater_version_refused(self):
        prediction = self._current_prediction()
        identity = dataclasses.replace(self._current_identity(), detector_version="9.9.9")
        with self.assertRaises(DetectorContractError):
            apply_calibration(
                prediction,
                self._artifact(),
                identity=identity,
                config_hash=BUILTIN_CONFIG_HASH,
                regime=BUILTIN_REGIME,
            )

    def test_identity_with_smaller_version_refused(self):
        prediction = self._current_prediction()
        identity = dataclasses.replace(self._current_identity(), detector_version="0.0.9")
        with self.assertRaises(DetectorContractError):
            apply_calibration(
                prediction,
                self._artifact(),
                identity=identity,
                config_hash=BUILTIN_CONFIG_HASH,
                regime=BUILTIN_REGIME,
            )

    def test_identity_with_greater_calibration_id_refused(self):
        prediction = self._current_prediction()
        identity = dataclasses.replace(self._current_identity(), calibration_id="zzz-cal")
        with self.assertRaises(DetectorContractError):
            apply_calibration(
                prediction,
                self._artifact(),
                identity=identity,
                config_hash=BUILTIN_CONFIG_HASH,
                regime=BUILTIN_REGIME,
            )

    def test_identity_with_smaller_calibration_id_refused(self):
        prediction = self._current_prediction()
        identity = dataclasses.replace(self._current_identity(), calibration_id="aaa-cal")
        with self.assertRaises(DetectorContractError):
            apply_calibration(
                prediction,
                self._artifact(),
                identity=identity,
                config_hash=BUILTIN_CONFIG_HASH,
                regime=BUILTIN_REGIME,
            )

    def test_identity_with_equal_value_calibration_id_binds(self):
        prediction = self._current_prediction()

        class CalibrationId(str):
            pass

        identity = dataclasses.replace(
            self._current_identity(),
            calibration_id=CalibrationId(BUILTIN_CALIBRATION_ID),
        )
        bound = apply_calibration(
            prediction,
            self._artifact(),
            identity=identity,
            config_hash=BUILTIN_CONFIG_HASH,
            regime=BUILTIN_REGIME,
        )
        self.assertIsNotNone(bound.calibrated_ai_probability)
        self.assertEqual(bound.calibration_id, BUILTIN_CALIBRATION_ID)

    def test_inference_identity_rejects_positional_detector(self):
        prediction = self._current_prediction()
        with self.assertRaises(TypeError):
            inference_identity_for_prediction(prediction, None)

    def test_apply_calibration_rejects_positional_identity(self):
        prediction = self._current_prediction()
        with self.assertRaises(TypeError):
            apply_calibration(prediction, self._artifact(), None)

    def test_unvalidated_artifact_refused_by_default(self):
        prediction = self._current_prediction()
        identity = self._current_identity()
        artifact = CalibrationArtifact(
            artifact_id=f"{identity.detector_id}:{BUILTIN_CALIBRATION_ID}",
            detector_id=identity.detector_id,
            detector_version=identity.detector_version,
            curve=_platt_curve(),
            calibration_id=BUILTIN_CALIBRATION_ID,
            created_at="2024-01-01T00:00:00+00:00",
            provider=identity.provider,
            model=identity.model,
            config_hash=identity.config_hash,
            native_score_semantics=identity.native_score_semantics,
            regime=identity.regime,
        )
        self.assertFalse(artifact.eligible_for_probability)
        with self.assertRaises(CalibrationError):
            apply_calibration(
                prediction,
                artifact,
                config_hash=BUILTIN_CONFIG_HASH,
                regime=BUILTIN_REGIME,
            )

    def test_binding_with_greater_declared_version_refused(self):
        prediction = self._calibrated_prediction(detector_version="9.9.9")
        with self.assertRaises(DetectorContractError):
            prediction.validate(detector=BuiltinHeuristicDetector())

    def test_binding_with_long_config_hash_refused(self):
        prediction = self._calibrated_prediction(config_hash="a" * 65)
        with self.assertRaises(DetectorContractError):
            prediction.validate(detector=BuiltinHeuristicDetector())

    def test_binding_with_short_config_hash_refused(self):
        prediction = self._calibrated_prediction(config_hash="a" * 63)
        with self.assertRaises(DetectorContractError):
            prediction.validate(detector=BuiltinHeuristicDetector())

    def test_binding_with_non_hex_config_hash_refused(self):
        prediction = self._calibrated_prediction(config_hash="g" * 64)
        with self.assertRaises(DetectorContractError):
            prediction.validate(detector=BuiltinHeuristicDetector())

    def test_binding_with_non_string_declared_field_refused(self):
        prediction = self._calibrated_prediction(detector_id=5)
        with self.assertRaises(DetectorContractError):
            prediction.validate(detector=BuiltinHeuristicDetector())


if __name__ == "__main__":
    unittest.main()
