#!/usr/bin/env python3
"""W6 Worker E: CC-14 + CC-17 regression tests (audit W6 fold-ins).

CC-14 — the mutation-baseline validator rejects every multi-line span
with "outside the current source" (``scripts/run_mutation.py``:
``_validate_runtime_entry`` and the parallel check in
``_validate_annotation_entry`` both require ``start_line == end_line``).
The sealing AddNot mutant's TRUE span is multi-line
(``[422, 7]-[424, 5]`` on this head: ``not advapi32.OpenProcessToken(``
across three lines), so only the ``not``-token span could ever validate.

CC-17 — CORE-05 adapter-level stale-curve binding: the
CalibrationManager API is identity-bound (W2), but no production call
site threads ``InferenceIdentity`` through the adapter layer
(``detectors.py``/``engine.py``), so a calibration fitted for a stale
detector version/config could be bound to a current prediction without
any check. These tests prove a stale curve is refused at the adapter
level, never silently bound.
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

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
)
from textforensics.engine import builtin_inference_identity


def _load_runner(runner_path: Path):
    """Load scripts/run_mutation.py as a module (scripts/ is not a package)."""
    spec = importlib.util.spec_from_file_location("run_mutation", runner_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


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


# The built-in heuristic's current inference identity (CC-17): the exact
# fields a calibration artifact must record to bind to a prediction
# from BuiltinHeuristicDetector on this head.
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


class TestCC14MultiLineSpan(unittest.TestCase):
    """CC-14: the baseline validator must accept multi-line spans."""

    @classmethod
    def setUpClass(cls):
        cls.project_root = Path(__file__).parent.parent
        cls.runner = _load_runner(cls.project_root / "scripts" / "run_mutation.py")
        cls.baseline = cls.runner.load_baseline(cls.project_root / "mutation-baseline.toml")

    def _sealing_addnot_multiline_entry(self) -> dict:
        """The sealing AddNot entry with its TRUE multi-line span.

        The live AddNot mutant covers the whole ``not <call>`` expression
        ``[422, 7]-[424, 5]`` in ``_restrict_to_owner_windows``
        (``sealing.py``); the baseline records only the ``not``-token span
        ``[422, 7]-[422, 10]`` because the validator rejected multi-line
        spans. The fingerprint is the baseline entry's own (unchanged).
        """
        import ast

        entry = next(
            e for e in self.baseline["entries"] if e["id"] == "textforensics.sealing:core/AddNot:13"
        )
        source = (self.project_root / "src" / "textforensics" / "sealing.py").read_text()
        tree = ast.parse(source)
        name, node = self.runner._enclosing_function(tree, 422, 7)
        self.assertEqual(name, "_restrict_to_owner_windows")
        self.assertEqual(
            self.runner._function_fingerprint(source, node),
            entry["source_fingerprint"],
        )
        lines = source.splitlines()
        source_text = "\n".join([lines[421][7:], lines[422], lines[423][:5]])
        self.assertEqual(
            source_text,
            "not advapi32.OpenProcessToken(\n"
            "        kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)\n"
            "    )",
        )
        return {
            **entry,
            "start_pos": [422, 7],
            "end_pos": [424, 5],
            "source_text": source_text,
        }

    def test_sealing_addnot_validates_with_true_multiline_span(self):
        """CC-14: the sealing AddNot entry validates with its true span."""
        entry = self._sealing_addnot_multiline_entry()
        ok, reason = self.runner.validate_baseline_entry(entry, self.project_root)
        self.assertTrue(ok, f"multi-line span must validate: {reason}")

    def test_multiline_span_with_wrong_source_text_fails_closed(self):
        """A multi-line span holding different text fails on content, not
        on the span shape: the refusal must name the content mismatch."""
        entry = self._sealing_addnot_multiline_entry()
        entry["source_text"] = "not advapi32.OpenProcessToken()"
        ok, reason = self.runner.validate_baseline_entry(entry, self.project_root)
        self.assertFalse(ok, "tampered multi-line source text must not validate")
        self.assertIn("no longer holds", reason)

    def test_multiline_span_outside_source_fails(self):
        """A multi-line span running past the end of the file fails."""
        entry = self._sealing_addnot_multiline_entry()
        entry["end_pos"] = [10_000, 5]
        ok, reason = self.runner.validate_baseline_entry(entry, self.project_root)
        self.assertFalse(ok, "span past end of file must not validate")
        self.assertIn("outside the current source", reason)

    def test_annotation_multiline_span_is_examined_not_dismissed(self):
        """CC-14 (parallel check): a multi-line annotation span is
        examined on its merits and fails closed on content — it must
        NOT be dismissed as 'outside the current source'."""
        entry = next(
            e for e in self.baseline["entries"] if e["kind"] in ("arg", "return", "annassign")
        )
        start_line, start_col = entry["start_pos"]
        tampered = dict(entry)
        tampered["end_pos"] = [start_line + 1, start_col + 1]
        ok, reason = self.runner.validate_baseline_entry(tampered, self.project_root)
        self.assertFalse(ok, "multi-line annotation span must not validate")
        self.assertNotIn(
            "outside the current source",
            reason,
            "a multi-line span is inside the source; refuse on content, not shape",
        )

    def test_single_line_runtime_entry_still_validates(self):
        """Guard: the existing single-line token-span entry still validates."""
        entry = next(
            e for e in self.baseline["entries"] if e["id"] == "textforensics.sealing:core/AddNot:13"
        )
        ok, reason = self.runner.validate_baseline_entry(entry, self.project_root)
        self.assertTrue(ok, f"single-line entry must still validate: {reason}")


class TestCC17AdapterStaleCurve(unittest.TestCase):
    """CC-17: adapter-level calibration must refuse a stale curve."""

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

    def test_adapter_identity_constants_match_engine(self):
        """Drift guard: the adapter stamps exactly the engine's canonical
        identity values. The constants live in engine.py and the adapter
        keeps literals (so the mutation-baseline line pins do not move);
        this test pins the two copies together."""
        from textforensics.engine import (
            BUILTIN_DETECTOR_ID,
            BUILTIN_DETECTOR_MODEL_ID,
            BUILTIN_DETECTOR_PROVIDER,
            BUILTIN_DETECTOR_VERSION,
            BUILTIN_SCORE_SEMANTICS,
        )

        self.assertEqual(BuiltinHeuristicDetector.detector_id, BUILTIN_DETECTOR_ID)
        self.assertEqual(BuiltinHeuristicDetector.detector_version, BUILTIN_DETECTOR_VERSION)
        prediction = self._current_prediction()
        self.assertEqual(prediction.score_semantics, BUILTIN_SCORE_SEMANTICS)
        assert prediction.runtime is not None
        self.assertEqual(prediction.runtime["provider"], BUILTIN_DETECTOR_PROVIDER)
        self.assertEqual(prediction.runtime["model_id"], BUILTIN_DETECTOR_MODEL_ID)

    def test_engine_builtin_identity_matches_detector_prediction(self):
        """The engine's builtin identity is the prediction's identity:
        detector id/version, provider, model and score semantics agree.
        (The derived identity carries ``calibration_id=None``: the fresh
        prediction is uncalibrated, and the calibration id comes from
        the artifact at binding time — see ``apply_calibration``.)"""
        from textforensics.detectors import inference_identity_for_prediction

        identity = builtin_inference_identity(
            config_hash=BUILTIN_CONFIG_HASH,
            regime=BUILTIN_REGIME,
        )
        prediction = self._current_prediction()
        derived = inference_identity_for_prediction(
            prediction,
            config_hash=BUILTIN_CONFIG_HASH,
            regime=BUILTIN_REGIME,
        )
        self.assertEqual(derived, identity)

    def test_matching_curve_binds_at_adapter_level(self):
        """A curve fitted for the current identity binds and stamps a
        calibrated probability with its calibration id."""
        from textforensics.detectors import apply_calibration

        prediction = self._current_prediction()
        bound = apply_calibration(
            prediction,
            self._artifact(),
            config_hash=BUILTIN_CONFIG_HASH,
            regime=BUILTIN_REGIME,
        )
        self.assertIsNotNone(bound.calibrated_ai_probability)
        self.assertEqual(bound.calibration_id, BUILTIN_CALIBRATION_ID)
        self.assertEqual(
            bound.calibration["detector_version"],
            BuiltinHeuristicDetector.detector_version,
        )
        # The input prediction is untouched: binding builds a new one.
        self.assertIsNone(prediction.calibrated_ai_probability)

    def test_stale_version_curve_refused_at_adapter_level(self):
        """A curve fitted for detector version 0.0.9 is refused for a
        0.1.0 prediction — and the prediction stays uncalibrated."""
        from textforensics.detectors import apply_calibration

        prediction = self._current_prediction()
        stale = self._artifact(detector_version="0.0.9")
        with self.assertRaises(CalibrationError):
            apply_calibration(
                prediction,
                stale,
                config_hash=BUILTIN_CONFIG_HASH,
                regime=BUILTIN_REGIME,
            )
        self.assertIsNone(prediction.calibrated_ai_probability)

    def test_stale_config_curve_refused_at_adapter_level(self):
        """A curve fitted for a different config hash is refused."""
        from textforensics.detectors import apply_calibration

        prediction = self._current_prediction()
        stale = self._artifact(config_hash=_hex64(99))
        with self.assertRaises(CalibrationError):
            apply_calibration(
                prediction,
                stale,
                config_hash=BUILTIN_CONFIG_HASH,
                regime=BUILTIN_REGIME,
            )
        self.assertIsNone(prediction.calibrated_ai_probability)

    def test_stale_provider_curve_refused_at_adapter_level(self):
        """A curve fitted for a different provider/model is refused."""
        from textforensics.detectors import apply_calibration

        prediction = self._current_prediction()
        stale = self._artifact(provider="other-provider", model="other-model")
        with self.assertRaises(CalibrationError):
            apply_calibration(
                prediction,
                stale,
                config_hash=BUILTIN_CONFIG_HASH,
                regime=BUILTIN_REGIME,
            )
        self.assertIsNone(prediction.calibrated_ai_probability)

    def test_explicit_stale_identity_refused_at_adapter_level(self):
        """An explicitly supplied identity for the old version is
        refused even when the artifact itself matches the current one:
        the caller cannot smuggle a stale binding past the adapter."""
        from textforensics.detectors import apply_calibration
        from textforensics.evidence import InferenceIdentity

        prediction = self._current_prediction()
        stale_identity = InferenceIdentity(
            detector_id="textforensics/builtin-heuristic",
            detector_version="0.0.9",
            provider="textforensics",
            model="builtin-stylometric-heuristic",
            config_hash=BUILTIN_CONFIG_HASH,
            native_score_semantics="probability_higher_means_ai",
            calibration_id=BUILTIN_CALIBRATION_ID,
            regime=BUILTIN_REGIME,
        )
        with self.assertRaises(DetectorContractError):
            apply_calibration(
                prediction,
                self._artifact(),
                identity=stale_identity,
            )
        self.assertIsNone(prediction.calibrated_ai_probability)

    def test_prediction_with_stale_calibration_metadata_refused(self):
        """Validation refuses a prediction whose calibration metadata
        declares a stale detector version: the stale curve cannot be
        silently bound by hand-stamping the metadata either."""
        prediction = self._current_prediction()
        prediction.calibrated_ai_probability = 0.42
        prediction.calibration_id = BUILTIN_CALIBRATION_ID
        prediction.calibration = {
            "calibration_id": BUILTIN_CALIBRATION_ID,
            "method": "platt",
            "detector_id": "textforensics/builtin-heuristic",
            "detector_version": "0.0.9",
        }
        with self.assertRaises(DetectorContractError):
            prediction.validate(detector=BuiltinHeuristicDetector())

    def test_prediction_with_matching_calibration_metadata_validates(self):
        """Guard: calibration metadata declaring the CURRENT identity
        still validates."""
        prediction = self._current_prediction()
        prediction.calibrated_ai_probability = 0.42
        prediction.calibration_id = BUILTIN_CALIBRATION_ID
        prediction.calibration = {
            "calibration_id": BUILTIN_CALIBRATION_ID,
            "method": "platt",
            "detector_id": "textforensics/builtin-heuristic",
            "detector_version": BuiltinHeuristicDetector.detector_version,
            "provider": "textforensics",
            "model": "builtin-stylometric-heuristic",
            "native_score_semantics": "probability_higher_means_ai",
        }
        prediction.validate(detector=BuiltinHeuristicDetector())

    def test_prediction_with_free_text_semantics_refused(self):
        """The identity descriptor is the normalised
        ``"probability_higher_means_ai"``, not the prediction's
        free-text ``score_semantics``: metadata declaring the free-text
        string as the curve semantics is refused."""
        prediction = self._current_prediction()
        prediction.calibrated_ai_probability = 0.42
        prediction.calibration_id = BUILTIN_CALIBRATION_ID
        prediction.calibration = {
            "calibration_id": BUILTIN_CALIBRATION_ID,
            "method": "platt",
            "detector_id": "textforensics/builtin-heuristic",
            "detector_version": BuiltinHeuristicDetector.detector_version,
            "native_score_semantics": (
                "higher_means_more_machine_like; uncalibrated pattern score"
            ),
        }
        with self.assertRaises(DetectorContractError):
            prediction.validate(detector=BuiltinHeuristicDetector())


if __name__ == "__main__":
    unittest.main()
