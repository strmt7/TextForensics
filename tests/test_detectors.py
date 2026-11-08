import unittest
from types import SimpleNamespace
from unittest.mock import patch

from textforensics.consensus import family_balanced_consensus
from textforensics.detectors import (
    DETECTOR_EVIDENCE_SCHEMA,
    DETECTOR_SCHEMA_V1,
    DETECTOR_SCHEMA_V2,
    BuiltinHeuristicDetector,
    DetectorContractError,
    DetectorFailure,
    DetectorPrediction,
    DetectorRegistry,
    PluginHealth,
    _entry_points,
    detector_determinism,
    discover_detector_registry,
    discover_detectors,
    execute_detector,
    list_detector_health,
    list_detector_metadata,
    normalize_prediction,
    run_all_detectors,
    validate_prediction,
)
from textforensics.report import build_forensic_bundle


def prediction(
    detector_id="detector",
    family="family",
    verdict="ai_like",
    score=0.8,
    probability=None,
    calibration_id=None,
):
    return DetectorPrediction(
        schema="textforensics.detector-result/v1",
        detector_id=detector_id,
        detector_version="1",
        detector_family=family,
        execution="local",
        score=score,
        score_semantics="test native score",
        verdict=verdict,
        threshold=0.5,
        calibrated_ai_probability=probability,
        calibration_id=calibration_id,
    )


class FakeDetector:
    detector_id = "fake/detector"
    detector_version = "1"
    detector_family = "fake-family"

    def detect(self, text):
        return prediction(
            detector_id=self.detector_id,
            family=self.detector_family,
        )


class LargeScaleDetector:
    detector_id = "fake/large-scale"
    detector_version = "1"
    detector_family = "large-native-scale"

    def detect(self, text):
        return prediction(
            detector_id=self.detector_id,
            family=self.detector_family,
            verdict="human_like",
            score=float(len(text) * 10),
        )


class EchoWarningDetector:
    detector_id = "fake/echo-warning"
    detector_version = "1"
    detector_family = "echo-family"

    def detect(self, text):
        result = prediction(
            detector_id=self.detector_id,
            family=self.detector_family,
        )
        result.warnings = [f"Provider response: {text}"]
        return result


class FailingDetector:
    detector_id = "fake/failing"
    detector_version = "1"
    detector_family = "failure-family"

    def detect(self, text):
        raise RuntimeError("secret submitted text must never appear")


class BadEntryPoint:
    name = "bad-plugin"

    def load(self):
        raise RuntimeError("provider echoed secret source text")


class DetectorContractTests(unittest.TestCase):
    def test_native_score_is_not_forced_into_probability_range(self):
        result = prediction(score=12.5)
        validate_prediction(result)

    def test_probability_requires_calibration_id(self):
        result = prediction(probability=0.7)
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_probability_with_calibration_id_is_valid(self):
        result = prediction(
            probability=0.7,
            calibration_id="calibration-1",
        )
        validate_prediction(result)

    def test_raw_text_evidence_fields_are_rejected(self):
        result = prediction()
        result.evidence = [{"snippet": "private source text"}]
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_nested_raw_text_evidence_fields_are_rejected(self):
        result = prediction()
        result.evidence = [{"details": {"snippet": "private source text"}}]
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_source_echo_in_warning_fails_closed(self):
        submitted = (
            "This is private submitted source text with enough length "
            "to trigger source-echo protection."
        )
        _, failure = execute_detector(EchoWarningDetector(), submitted)
        self.assertIsNotNone(failure)
        self.assertEqual(failure.error_type, "DetectorContractError")
        self.assertNotIn(submitted, failure.message)

    def test_detector_identity_must_match_adapter(self):
        result = prediction(detector_id="wrong")
        with self.assertRaises(DetectorContractError):
            validate_prediction(result, detector=FakeDetector())

    def test_execution_failure_redacts_exception_message(self):
        _, failure = execute_detector(
            FailingDetector(),
            "private source text",
        )
        self.assertIsNotNone(failure)
        self.assertNotIn("secret submitted", failure.message)

    def test_native_score_stability_is_not_normalized_implicitly(self):
        data = build_forensic_bundle(
            "A stable test sentence with enough variation for representation probes.",
            detectors=[LargeScaleDetector()],
        ).to_dict()
        robustness = data["robustness"]["detectors"][0]
        self.assertIn("native_score_range", robustness)
        self.assertNotIn("score_stability", robustness)
        self.assertGreaterEqual(robustness["native_score_range"], 0)
        stability = next(
            row for row in data["trust_map"]["dimensions"] if row["dimension"] == "benign_stability"
        )
        self.assertEqual(stability["state"], "supported")

    def test_report_survives_detector_failure(self):
        data = build_forensic_bundle(
            "A sufficiently ordinary test sentence for failure handling.",
            detectors=[FailingDetector()],
        ).to_dict()
        self.assertEqual(data["detector_results"], [])
        self.assertEqual(len(data["detector_failures"]), 1)
        self.assertEqual(data["consensus"]["verdict"], "abstain")
        self.assertEqual(data["trust_map"]["overall"], "insufficient")

    def test_plugin_health_surfaces_load_failure_without_secret(self):
        with patch(
            "textforensics.detectors._entry_points",
            return_value=[BadEntryPoint()],
        ):
            registry = discover_detector_registry()
        bad = [item for item in registry.plugin_health if item.entry_point == "bad-plugin"][0]
        self.assertEqual(bad.status, "error")
        self.assertNotIn("secret", bad.message)

    def test_family_balancing_prevents_duplicate_family_vote_inflation(self):
        result = family_balanced_consensus(
            [
                prediction("a1", "transformer", "ai_like"),
                prediction("a2", "transformer", "ai_like"),
                prediction("b1", "likelihood", "human_like"),
            ]
        )
        self.assertEqual(result.independent_families, 2)
        self.assertEqual(result.verdict, "abstain")
        self.assertEqual(len(result.family_votes), 2)

    def test_component_probabilities_are_not_averaged_into_ensemble(self):
        result = family_balanced_consensus(
            [
                prediction(
                    "a",
                    "transformer",
                    "ai_like",
                    probability=0.9,
                    calibration_id="a-cal",
                ),
                prediction(
                    "b",
                    "likelihood",
                    "ai_like",
                    probability=0.8,
                    calibration_id="b-cal",
                ),
            ]
        )
        self.assertIsNone(result.calibrated_ai_probability)
        self.assertTrue(any("separately" in warning.lower() for warning in result.warnings))

    def test_top_level_probability_requires_ensemble_calibration(self):
        rows = [prediction("a", "transformer", "ai_like")]
        with self.assertRaises(ValueError):
            family_balanced_consensus(
                rows,
                ensemble_probability=0.75,
            )
        result = family_balanced_consensus(
            rows,
            ensemble_probability=0.75,
            ensemble_calibration_id="ensemble-v1",
        )
        self.assertEqual(result.calibrated_ai_probability, 0.75)


if __name__ == "__main__":
    unittest.main()


def _fresh_string(*parts):
    """Build a string equal to ``"".join(parts)`` but a distinct object."""
    return "".join(parts)


class _WarningDetector:
    detector_id = "fake/warning"
    detector_version = "1"
    detector_family = "warning-family"

    def __init__(self, warnings):
        self._warnings = warnings

    def detect(self, text):
        result = prediction(detector_id=self.detector_id, family=self.detector_family)
        result.warnings = list(self._warnings)
        return result


class _EvidenceDetector:
    detector_id = "fake/evidence"
    detector_version = "1"
    detector_family = "evidence-family"

    def __init__(self, evidence):
        self._evidence = evidence

    def detect(self, text):
        result = prediction(detector_id=self.detector_id, family=self.detector_family)
        result.evidence = self._evidence
        return result


class _FakeEntryPoint:
    def __init__(self, name, target):
        self.name = name
        self._target = target

    def load(self):
        return self._target


class _DuplicateIdDetector(FakeDetector):
    detector_id = "textforensics/builtin-heuristic"


class _EmptyIdDetector(FakeDetector):
    detector_id = ""


class _NotADetector:
    detector_id = "fake/not-a-detector"
    detector_version = "1"
    detector_family = "fake-family"


class _DeterministicDetector:
    deterministic = True
    determinism_reason = None


class _NonDeterministicDetector:
    deterministic = False
    determinism_reason = None


class _UnknownDeterminismDetector:
    pass


class _TruthyDeterminismDetector:
    deterministic = 1


class _ZeroDeterminismDetector:
    deterministic = 0


class _StringDeterminismDetector:
    deterministic = "yes"


class _ReasonDetector:
    deterministic = True
    determinism_reason = "because"


class _EmptyReasonDetector:
    deterministic = True
    determinism_reason = ""


class _BlankReasonDetector:
    deterministic = True
    determinism_reason = "   "


class _IntReasonDetector:
    deterministic = True
    determinism_reason = 123


class _SpacedReasonDetector:
    deterministic = True
    determinism_reason = "  x  "


def _fake_analysis(verdict, score=0.7):
    return SimpleNamespace(
        verdict=verdict,
        score=score,
        analyzers=[
            SimpleNamespace(name="a1", score=0.123456, reliability=0.987654),
        ],
        warnings=["w1"],
        diagnostic_reliability=0.9,
    )


class DetectorsMutationKillTests(unittest.TestCase):
    """Kill tests for the full-session mutation survivors in detectors.py.

    Every test targets one or more surviving mutants from the full
    ``textforensics.detectors`` session (606 items, 178 killed, 428
    surviving at baseline). Annotation ``|`` mutants (66) and the one
    no-op-body mutant at ``normalize_prediction`` L260 are equivalent
    and are documented in the coordinator report, not killed here.
    """

    # -- detector_determinism -------------------------------------------

    def test_determinism_declared_true(self):
        self.assertEqual(
            detector_determinism(_DeterministicDetector()),
            ("deterministic", None),
        )

    def test_determinism_declared_false(self):
        self.assertEqual(
            detector_determinism(_NonDeterministicDetector()),
            ("non_deterministic", None),
        )

    def test_determinism_undeclared_is_unknown(self):
        self.assertEqual(
            detector_determinism(_UnknownDeterminismDetector()),
            ("unknown", None),
        )

    def test_determinism_truthy_non_bool_is_unknown(self):
        # ``1 == True`` but ``1 is True`` is False: kills the Is_Eq mutant
        # on ``declared is True``.
        self.assertEqual(
            detector_determinism(_TruthyDeterminismDetector()),
            ("unknown", None),
        )

    def test_determinism_zero_is_unknown(self):
        # ``0 == False`` but ``0 is False`` is False: kills the Is_Eq
        # mutant on ``declared is False``.
        self.assertEqual(
            detector_determinism(_ZeroDeterminismDetector()),
            ("unknown", None),
        )

    def test_determinism_string_is_unknown(self):
        self.assertEqual(
            detector_determinism(_StringDeterminismDetector()),
            ("unknown", None),
        )

    def test_determinism_reason_returned(self):
        self.assertEqual(
            detector_determinism(_ReasonDetector()),
            ("deterministic", "because"),
        )

    def test_determinism_empty_reason_is_none(self):
        self.assertEqual(
            detector_determinism(_EmptyReasonDetector()),
            ("deterministic", None),
        )

    def test_determinism_blank_reason_is_none(self):
        self.assertEqual(
            detector_determinism(_BlankReasonDetector()),
            ("deterministic", None),
        )

    def test_determinism_non_string_reason_is_none(self):
        self.assertEqual(
            detector_determinism(_IntReasonDetector()),
            ("deterministic", None),
        )

    def test_determinism_spaced_reason_kept_verbatim(self):
        self.assertEqual(
            detector_determinism(_SpacedReasonDetector()),
            ("deterministic", "  x  "),
        )

    # -- _require_finite_number ------------------------------------------

    def test_bool_score_is_rejected(self):
        result = prediction(score=True)
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_string_score_is_rejected(self):
        result = prediction(score="high")
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    # -- _validate_no_source_echo -----------------------------------------

    def test_exact_echo_short_source_passes(self):
        text = "exact12"
        result, failure = execute_detector(_WarningDetector([text]), text)
        self.assertIsNotNone(result)
        self.assertIsNone(failure)

    def test_exact_echo_eight_char_multiword_raises(self):
        text = "exact echo"
        _, failure = execute_detector(_WarningDetector([text]), text)
        self.assertIsNotNone(failure)
        self.assertEqual(failure.error_type, "DetectorContractError")

    def test_exact_echo_eight_char_single_word_raises(self):
        text = "exact123"
        _, failure = execute_detector(_WarningDetector([text]), text)
        self.assertIsNotNone(failure)
        self.assertEqual(failure.error_type, "DetectorContractError")

    def test_exact_echo_nine_char_raises(self):
        text = "exact1234"
        _, failure = execute_detector(_WarningDetector([text]), text)
        self.assertIsNotNone(failure)
        self.assertEqual(failure.error_type, "DetectorContractError")

    def test_echo_check_skips_blank_warning(self):
        text = "This is a long submitted source text for echo testing."
        _, failure = execute_detector(_WarningDetector(["   ", text]), text)
        self.assertIsNotNone(failure)
        self.assertEqual(failure.error_type, "DetectorContractError")

    def test_unrelated_long_warning_passes(self):
        submitted = "A completely different long submitted source text here."
        _, failure = execute_detector(
            _WarningDetector(["Something else entirely different here."]),
            submitted,
        )
        self.assertIsNone(failure)

    def test_long_excerpt_31_chars_passes(self):
        source = "x" * 100
        result, failure = execute_detector(_WarningDetector(["x" * 31]), source)
        self.assertIsNotNone(result)
        self.assertIsNone(failure)

    def test_long_excerpt_32_chars_raises(self):
        source = "x" * 100
        _, failure = execute_detector(_WarningDetector(["x" * 32]), source)
        self.assertIsNotNone(failure)
        self.assertEqual(failure.error_type, "DetectorContractError")

    def test_long_excerpt_33_chars_raises(self):
        source = "x" * 100
        _, failure = execute_detector(_WarningDetector(["x" * 33]), source)
        self.assertIsNotNone(failure)
        self.assertEqual(failure.error_type, "DetectorContractError")

    def test_short_substring_warning_passes(self):
        source = "x" * 100
        result, failure = execute_detector(_WarningDetector(["xxxxx"]), source)
        self.assertIsNotNone(result)
        self.assertIsNone(failure)

    def test_source_embedded_31_chars_passes(self):
        source = "y" * 31
        result, failure = execute_detector(
            _WarningDetector(["prefix " + source + " suffix"]), source
        )
        self.assertIsNotNone(result)
        self.assertIsNone(failure)

    def test_source_embedded_32_chars_raises(self):
        source = "y" * 32
        _, failure = execute_detector(
            _WarningDetector(["prefix " + source + " suffix"]), source
        )
        self.assertIsNotNone(failure)
        self.assertEqual(failure.error_type, "DetectorContractError")

    def test_source_embedded_33_chars_raises(self):
        source = "y" * 33
        _, failure = execute_detector(
            _WarningDetector(["prefix " + source + " suffix"]), source
        )
        self.assertIsNotNone(failure)
        self.assertEqual(failure.error_type, "DetectorContractError")

    def test_short_source_inside_warning_passes(self):
        source = "short"
        result, failure = execute_detector(
            _WarningDetector(["xx short yy"]), source
        )
        self.assertIsNotNone(result)
        self.assertIsNone(failure)

    def test_evidence_string_echo_raises(self):
        source = "This is a forty character long source text!"
        _, failure = execute_detector(
            _EvidenceDetector([{"note": source}]), source
        )
        self.assertIsNotNone(failure)
        self.assertEqual(failure.error_type, "DetectorContractError")

    def test_evidence_list_string_echo_raises(self):
        source = "This is a forty character long source text!"
        _, failure = execute_detector(
            _EvidenceDetector([{"notes": [source]}]), source
        )
        self.assertIsNotNone(failure)
        self.assertEqual(failure.error_type, "DetectorContractError")

    # -- normalize_prediction -------------------------------------------

    def test_v2_prediction_validates(self):
        result = prediction()
        result.schema = DETECTOR_SCHEMA_V2
        validate_prediction(result)
        self.assertEqual(result.schema, DETECTOR_SCHEMA_V2)

    def test_v2_prediction_distinct_object_validates(self):
        result = prediction()
        result.schema = _fresh_string(
            "textforensics.detector-result/", "v2"
        )
        validate_prediction(result)
        self.assertEqual(result.schema, DETECTOR_SCHEMA_V2)

    def test_v1_prediction_is_normalized(self):
        result = prediction()
        validate_prediction(result)
        self.assertEqual(result.schema, DETECTOR_SCHEMA_V2)
        self.assertEqual(result.protocol_version, "TFDP/1")
        self.assertEqual(result.normalized_from, DETECTOR_SCHEMA_V1)

    def test_unsupported_schema_is_rejected(self):
        result = prediction()
        result.schema = "bogus"
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_greater_schema_is_rejected(self):
        result = prediction()
        result.schema = "zzz"
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_normalize_keeps_declared_direction(self):
        result = prediction()
        result.schema = DETECTOR_SCHEMA_V1
        result.native_score_direction = "higher_means_ai"
        normalize_prediction(result)
        self.assertEqual(result.native_score_direction, "higher_means_ai")

    def test_normalize_keeps_unknown_direction_string(self):
        result = prediction()
        result.schema = DETECTOR_SCHEMA_V1
        result.native_score_direction = "zzz"
        normalize_prediction(result)
        self.assertEqual(result.native_score_direction, "zzz")

    def test_normalize_unknown_direction_with_score_stays_unknown(self):
        result = prediction()
        result.schema = DETECTOR_SCHEMA_V1
        result.native_score_direction = "unknown"
        result.score = 0.8
        normalize_prediction(result)
        self.assertEqual(result.native_score_direction, "unknown")

    def test_normalize_keeps_supported_length(self):
        result = prediction()
        result.schema = DETECTOR_SCHEMA_V1
        result.supported_length = {"min_words": 80, "max_words": 500}
        result.min_words = 80
        normalize_prediction(result)
        self.assertEqual(
            result.supported_length, {"min_words": 80, "max_words": 500}
        )

    def test_normalize_derives_supported_length(self):
        result = prediction()
        result.schema = DETECTOR_SCHEMA_V1
        result.supported_length = None
        result.min_words = 80
        normalize_prediction(result)
        self.assertEqual(
            result.supported_length, {"min_words": 80, "max_words": None}
        )

    def test_normalize_supported_length_without_min_words(self):
        result = prediction()
        result.schema = DETECTOR_SCHEMA_V1
        result.supported_length = {"min_words": 80, "max_words": 500}
        result.min_words = None
        normalize_prediction(result)
        self.assertEqual(
            result.supported_length, {"min_words": 80, "max_words": 500}
        )

    def test_normalize_keeps_runtime(self):
        result = prediction()
        result.schema = DETECTOR_SCHEMA_V1
        result.runtime = {"mode": "local", "provider": "x"}
        normalize_prediction(result)
        self.assertEqual(result.runtime, {"mode": "local", "provider": "x"})

    def test_normalize_derives_runtime(self):
        result = prediction()
        result.schema = DETECTOR_SCHEMA_V1
        result.runtime = None
        normalize_prediction(result)
        self.assertEqual(result.runtime, {"mode": "local"})

    # -- _validate_string_list / supported_* ------------------------------

    def test_supported_domains_valid(self):
        result = prediction()
        result.supported_domains = ["news"]
        validate_prediction(result)

    def test_supported_domains_empty_string_rejected(self):
        result = prediction()
        result.supported_domains = [""]
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_supported_domains_non_string_rejected(self):
        result = prediction()
        result.supported_domains = [123]
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_supported_domains_string_rejected(self):
        result = prediction()
        result.supported_domains = "notalist"
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_supported_languages_valid(self):
        result = prediction()
        result.supported_languages = ["en"]
        validate_prediction(result)

    def test_supported_languages_empty_string_rejected(self):
        result = prediction()
        result.supported_languages = [""]
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_supported_languages_non_string_rejected(self):
        result = prediction()
        result.supported_languages = [123]
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_supported_languages_string_rejected(self):
        result = prediction()
        result.supported_languages = "notalist"
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_supported_editing_regimes_valid(self):
        result = prediction()
        result.supported_editing_regimes = ["human_only"]
        validate_prediction(result)

    def test_supported_editing_regimes_bogus_rejected(self):
        result = prediction()
        result.supported_editing_regimes = ["bogus"]
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    # -- _validate_supported_length ---------------------------------------

    def test_supported_length_valid(self):
        result = prediction()
        result.supported_length = {"min_words": 80, "max_words": 500}
        result.min_words = 80
        validate_prediction(result)

    def test_supported_length_min_only_valid(self):
        result = prediction()
        result.supported_length = {"min_words": 5}
        result.min_words = 5
        validate_prediction(result)

    def test_supported_length_max_only_valid(self):
        result = prediction()
        result.supported_length = {"max_words": 10}
        result.min_words = None
        validate_prediction(result)

    def test_supported_length_equal_bounds_valid(self):
        result = prediction()
        result.supported_length = {"min_words": 5, "max_words": 5}
        result.min_words = 5
        validate_prediction(result)

    def test_supported_length_zero_min_valid(self):
        result = prediction()
        result.supported_length = {"min_words": 0}
        result.min_words = 0
        validate_prediction(result)

    def test_supported_length_one_min_valid(self):
        result = prediction()
        result.supported_length = {"min_words": 1}
        result.min_words = 1
        validate_prediction(result)

    def test_supported_length_none_min_with_max_valid(self):
        result = prediction()
        result.supported_length = {"min_words": None, "max_words": 10}
        result.min_words = None
        validate_prediction(result)

    def test_supported_length_string_rejected(self):
        result = prediction()
        result.supported_length = "bad"
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_supported_length_unknown_key_rejected(self):
        result = prediction()
        result.supported_length = {"bogus": 1}
        result.min_words = None
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_supported_length_empty_rejected(self):
        result = prediction()
        result.supported_length = {}
        result.min_words = None
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_supported_length_bad_bound_rejected(self):
        result = prediction()
        result.supported_length = {"min_words": "bad"}
        result.min_words = None
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_supported_length_bool_bound_rejected(self):
        result = prediction()
        result.supported_length = {"min_words": True}
        result.min_words = None
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_supported_length_negative_bound_rejected(self):
        result = prediction()
        result.supported_length = {"min_words": -1}
        result.min_words = None
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_supported_length_none_then_bad_bound_rejected(self):
        result = prediction()
        result.supported_length = {"min_words": None, "max_words": "bad"}
        result.min_words = None
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_supported_length_min_exceeds_max_rejected(self):
        result = prediction()
        result.supported_length = {"min_words": 10, "max_words": 5}
        result.min_words = 10
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_supported_length_min_mismatch_rejected(self):
        result = prediction()
        result.supported_length = {"min_words": 6}
        result.min_words = 5
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_supported_length_min_below_rejected(self):
        result = prediction()
        result.supported_length = {"min_words": 4}
        result.min_words = 5
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_supported_length_min_match_valid(self):
        shared = int("1000")
        result = prediction()
        result.supported_length = {"min_words": shared}
        result.min_words = shared
        validate_prediction(result)

    def test_supported_length_min_match_distinct_objects_valid(self):
        result = prediction()
        result.supported_length = {"min_words": int("1000")}
        result.min_words = int("1000")
        validate_prediction(result)

    # -- _validate_score_range --------------------------------------------

    def test_score_range_valid(self):
        result = prediction()
        result.score_range = [0.0, 1.0]
        result.score = 0.5
        validate_prediction(result)

    def test_score_range_length_one_rejected(self):
        result = prediction()
        result.score_range = [0.5]
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_score_range_length_three_rejected(self):
        result = prediction()
        result.score_range = [0.0, 0.5, 1.0]
        # Score inside [0.0, 0.5] so a mutant that skips the length
        # check would pass validation instead of raising later.
        result.score = 0.25
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_score_range_min_above_max_rejected(self):
        result = prediction()
        result.score_range = [2.0, 1.0]
        # Score None so a mutant that skips the min>=max check would
        # pass validation instead of raising on the empty interval.
        result.score = None
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_score_range_equal_bounds_rejected(self):
        result = prediction()
        result.score_range = [1.0, 1.0]
        result.score = 1.0
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_score_range_min_less_than_max_valid(self):
        result = prediction()
        result.score_range = [0.0, 1.0]
        result.score = 0.5
        validate_prediction(result)

    def test_score_out_of_range_rejected(self):
        result = prediction()
        result.score_range = [0.0, 1.0]
        result.score = 2.0
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_score_none_with_range_valid(self):
        result = prediction()
        result.score_range = [0.0, 1.0]
        result.score = None
        validate_prediction(result)

    def test_score_equal_to_range_min_valid(self):
        result = prediction()
        result.score_range = [0.5, 1.0]
        result.score = 0.5
        validate_prediction(result)

    def test_score_equal_to_range_max_valid(self):
        result = prediction()
        result.score_range = [0.0, 1.0]
        result.score = 1.0
        validate_prediction(result)

    def test_score_is_range_min_object_valid(self):
        result = prediction()
        result.score_range = [0.5, 1.0]
        result.score = result.score_range[0]
        validate_prediction(result)

    def test_score_is_range_max_object_valid(self):
        result = prediction()
        result.score_range = [0.0, 1.0]
        result.score = result.score_range[1]
        validate_prediction(result)

    # -- _validate_calibration_metadata -----------------------------------

    def _calibrated(self, calibration, probability=0.5, calibration_id="c1"):
        result = prediction(probability=probability, calibration_id=calibration_id)
        result.calibration = calibration
        return result

    def test_calibration_valid(self):
        validate_prediction(
            self._calibrated({"calibration_id": "c1", "method": "platt"})
        )

    def test_calibration_string_rejected(self):
        result = prediction()
        result.calibration = "bad"
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_calibration_bad_method_rejected(self):
        with self.assertRaises(DetectorContractError):
            validate_prediction(
                self._calibrated({"calibration_id": "c1", "method": "bogus"})
            )

    def test_calibration_no_fingerprint_valid(self):
        validate_prediction(
            self._calibrated({"calibration_id": "c1", "method": "platt"})
        )

    def test_calibration_fingerprint_63_rejected(self):
        with self.assertRaises(DetectorContractError):
            validate_prediction(
                self._calibrated(
                    {
                        "calibration_id": "c1",
                        "method": "platt",
                        "evaluation_fingerprint": "a" * 63,
                    }
                )
            )

    def test_calibration_fingerprint_65_rejected(self):
        with self.assertRaises(DetectorContractError):
            validate_prediction(
                self._calibrated(
                    {
                        "calibration_id": "c1",
                        "method": "platt",
                        "evaluation_fingerprint": "a" * 65,
                    }
                )
            )

    def test_calibration_fingerprint_64_valid(self):
        validate_prediction(
            self._calibrated(
                {
                    "calibration_id": "c1",
                    "method": "platt",
                    "evaluation_fingerprint": "a" * 64,
                }
            )
        )

    def test_calibration_fingerprint_non_hex_rejected(self):
        with self.assertRaises(DetectorContractError):
            validate_prediction(
                self._calibrated(
                    {
                        "calibration_id": "c1",
                        "method": "platt",
                        "evaluation_fingerprint": "a" * 63 + "g",
                    }
                )
            )

    def test_calibration_fingerprint_non_string_rejected(self):
        with self.assertRaises(DetectorContractError):
            validate_prediction(
                self._calibrated(
                    {
                        "calibration_id": "c1",
                        "method": "platt",
                        "evaluation_fingerprint": 123,
                    }
                )
            )

    def test_calibration_id_mismatch_rejected(self):
        with self.assertRaises(DetectorContractError):
            validate_prediction(
                self._calibrated(
                    {"calibration_id": "c1", "method": "platt"},
                    calibration_id="c2",
                )
            )

    def test_calibration_id_lower_mismatch_rejected(self):
        with self.assertRaises(DetectorContractError):
            validate_prediction(
                self._calibrated(
                    {"calibration_id": "c1", "method": "platt"},
                    calibration_id="c0",
                )
            )

    def test_calibration_id_match_same_object_valid(self):
        cid = _fresh_string("c", "1")
        result = prediction(probability=0.5, calibration_id=cid)
        result.calibration = {"calibration_id": cid, "method": "platt"}
        validate_prediction(result)

    def test_calibration_id_match_distinct_objects_valid(self):
        result = prediction(
            probability=0.5, calibration_id=_fresh_string("c", "1")
        )
        result.calibration = {
            "calibration_id": _fresh_string("c", "1"),
            "method": "platt",
        }
        validate_prediction(result)

    def test_calibration_id_none_valid(self):
        result = prediction()
        result.calibration = {"calibration_id": "c1", "method": "platt"}
        result.calibration_id = None
        validate_prediction(result)

    # -- _validate_runtime_metadata ---------------------------------------

    def test_runtime_valid(self):
        result = prediction()
        result.runtime = {"mode": "local"}
        validate_prediction(result)

    def test_runtime_none_valid(self):
        # V2 skips normalization (which would fill runtime); a null
        # runtime is accepted by _validate_runtime_metadata.
        result = prediction()
        result.runtime = None
        result.schema = DETECTOR_SCHEMA_V2
        validate_prediction(result)
        self.assertIsNone(result.runtime)

    def test_runtime_string_rejected(self):
        result = prediction()
        result.runtime = "bad"
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_runtime_mode_remote_mismatch_rejected(self):
        result = prediction()
        result.runtime = {"mode": "remote"}
        result.execution = "local"
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_runtime_mode_local_mismatch_rejected(self):
        result = prediction()
        result.runtime = {"mode": "local"}
        result.execution = "remote"
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_runtime_mode_match_distinct_objects_valid(self):
        result = prediction()
        result.runtime = {"mode": _fresh_string("loc", "al")}
        result.execution = "local"
        validate_prediction(result)

    def test_runtime_provider_empty_rejected(self):
        result = prediction()
        result.runtime = {"mode": "local", "provider": ""}
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_runtime_provider_non_string_rejected(self):
        result = prediction()
        result.runtime = {"mode": "local", "provider": 123}
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_runtime_provider_valid(self):
        result = prediction()
        result.runtime = {"mode": "local", "provider": "x"}
        validate_prediction(result)

    # -- validate_prediction main flow ------------------------------------

    def test_evidence_schema_bad_rejected(self):
        result = prediction()
        result.evidence_schema = "bogus"
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_evidence_schema_greater_rejected(self):
        result = prediction()
        result.evidence_schema = "zzz"
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_evidence_schema_match_distinct_objects_valid(self):
        result = prediction()
        result.evidence_schema = _fresh_string(
            "textforensics.detector-evidence/", "v1"
        )
        validate_prediction(result)
        self.assertEqual(result.evidence_schema, DETECTOR_EVIDENCE_SCHEMA)

    def test_empty_detector_id_rejected(self):
        result = prediction(detector_id="")
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_score_none_valid(self):
        result = prediction(score=None)
        validate_prediction(result)

    def test_score_infinite_rejected(self):
        result = prediction(score=float("inf"))
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_threshold_none_valid(self):
        result = prediction()
        result.threshold = None
        validate_prediction(result)

    def test_threshold_infinite_rejected(self):
        result = prediction()
        result.threshold = float("inf")
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_probability_negative_rejected(self):
        with self.assertRaises(DetectorContractError):
            validate_prediction(
                prediction(probability=-0.5, calibration_id="c1")
            )

    def test_probability_zero_valid(self):
        validate_prediction(prediction(probability=0.0, calibration_id="c1"))

    def test_probability_half_valid(self):
        validate_prediction(prediction(probability=0.5, calibration_id="c1"))

    def test_probability_one_valid(self):
        validate_prediction(prediction(probability=1.0, calibration_id="c1"))

    def test_probability_above_one_rejected(self):
        with self.assertRaises(DetectorContractError):
            validate_prediction(
                prediction(probability=1.5, calibration_id="c1")
            )

    def test_reliability_negative_rejected(self):
        result = prediction()
        result.reliability = -0.5
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_reliability_zero_valid(self):
        result = prediction()
        result.reliability = 0.0
        validate_prediction(result)

    def test_reliability_half_valid(self):
        result = prediction()
        result.reliability = 0.5
        validate_prediction(result)

    def test_reliability_one_valid(self):
        result = prediction()
        result.reliability = 1.0
        validate_prediction(result)

    def test_reliability_above_one_rejected(self):
        result = prediction()
        result.reliability = 1.5
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_min_words_negative_rejected(self):
        # V2 skips normalization: with a V1 schema, normalization
        # derives supported_length {"min_words": -1}, and the
        # supported-length check would raise first, masking the
        # min_words < 0 mutant below.
        result = prediction()
        result.schema = DETECTOR_SCHEMA_V2
        result.min_words = -1
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_min_words_zero_valid(self):
        result = prediction()
        result.min_words = 0
        validate_prediction(result)

    def test_min_words_one_valid(self):
        result = prediction()
        result.min_words = 1
        validate_prediction(result)

    def test_min_words_bool_rejected(self):
        result = prediction()
        result.min_words = True
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_min_words_string_rejected(self):
        result = prediction()
        result.min_words = "eighty"
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_runtime_ms_negative_rejected(self):
        result = prediction()
        result.runtime_ms = -1.0
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_runtime_ms_zero_valid(self):
        result = prediction()
        result.runtime_ms = 0.0
        validate_prediction(result)

    def test_runtime_ms_one_valid(self):
        result = prediction()
        result.runtime_ms = 1.0
        validate_prediction(result)

    def test_warnings_valid(self):
        result = prediction()
        result.warnings = ["ok"]
        validate_prediction(result)

    def test_warnings_non_string_rejected(self):
        result = prediction()
        result.warnings = [123]
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_evidence_valid(self):
        result = prediction()
        result.evidence = [{"a": 1}]
        validate_prediction(result)

    def test_evidence_non_object_rejected(self):
        result = prediction()
        result.evidence = ["x"]
        with self.assertRaises(DetectorContractError):
            validate_prediction(result)

    def test_detector_identity_mismatch_low_rejected(self):
        # Family and version match, so only detector_id differs: a
        # ``>`` mutant on the ``!=`` check would pass otherwise.
        result = prediction(detector_id="aaa", family="fake-family")
        with self.assertRaises(DetectorContractError):
            validate_prediction(result, detector=FakeDetector())

    def test_detector_identity_match_distinct_objects_valid(self):
        result = prediction(
            detector_id=_fresh_string("fake/", "detector"),
            family="fake-family",
        )
        validate_prediction(result, detector=FakeDetector())

    # -- slots=True ---------------------------------------------------------

    def test_prediction_slots_reject_new_attributes(self):
        result = prediction()
        with self.assertRaises(AttributeError):
            result.bogus_attr = 1

    def test_failure_slots_reject_new_attributes(self):
        failure = DetectorFailure(
            detector_id="d",
            detector_version="1",
            detector_family="f",
            error_type="E",
            message="m",
            runtime_ms=1.0,
        )
        with self.assertRaises(AttributeError):
            failure.bogus_attr = 1

    def test_plugin_health_slots_reject_new_attributes(self):
        row = PluginHealth(entry_point="e", status="ok")
        with self.assertRaises(AttributeError):
            row.bogus_attr = 1

    def test_registry_slots_reject_new_attributes(self):
        registry = DetectorRegistry()
        with self.assertRaises(AttributeError):
            registry.bogus_attr = 1

    # -- keyword-only detector argument --------------------------------------

    def test_validate_positional_detector_rejected(self):
        result = prediction()
        with self.assertRaises(TypeError):
            result.validate(FakeDetector())

    def test_validate_prediction_positional_detector_rejected(self):
        result = prediction()
        with self.assertRaises(TypeError):
            validate_prediction(result, FakeDetector())

    # -- BuiltinHeuristicDetector --------------------------------------------

    def test_builtin_machine_like_verdict(self):
        with patch(
            "textforensics.detectors.analyze_text",
            return_value=_fake_analysis("machine_like_patterns"),
        ):
            result = BuiltinHeuristicDetector().detect("some text")
        self.assertEqual(result.verdict, "ai_like")

    def test_builtin_human_like_verdict(self):
        with patch(
            "textforensics.detectors.analyze_text",
            return_value=_fake_analysis("human_like_patterns"),
        ):
            result = BuiltinHeuristicDetector().detect("some text")
        self.assertEqual(result.verdict, "human_like")

    def test_builtin_other_verdict_abstains(self):
        with patch(
            "textforensics.detectors.analyze_text",
            return_value=_fake_analysis("unclear"),
        ):
            result = BuiltinHeuristicDetector().detect("some text")
        self.assertEqual(result.verdict, "abstain")

    def test_builtin_prefix_verdict_abstains(self):
        # "human_like_patter" <= "human_like_patterns" but != it: kills
        # the Eq_LtE mutant on the human-like branch.
        with patch(
            "textforensics.detectors.analyze_text",
            return_value=_fake_analysis("human_like_patter"),
        ):
            result = BuiltinHeuristicDetector().detect("some text")
        self.assertEqual(result.verdict, "abstain")

    def test_builtin_evidence_rounding(self):
        with patch(
            "textforensics.detectors.analyze_text",
            return_value=_fake_analysis("machine_like_patterns"),
        ):
            result = BuiltinHeuristicDetector().detect("some text")
        self.assertEqual(result.evidence[0]["score"], 0.1235)
        self.assertEqual(result.evidence[0]["reliability"], 0.9877)

    def test_builtin_fixed_fields(self):
        with patch(
            "textforensics.detectors.analyze_text",
            return_value=_fake_analysis("machine_like_patterns"),
        ):
            result = BuiltinHeuristicDetector().detect("some text")
        self.assertEqual(result.min_words, 80)
        self.assertEqual(result.score_range, [0.0, 1.0])
        self.assertEqual(
            result.supported_length, {"min_words": 80, "max_words": None}
        )

    def test_builtin_runtime_ms_measured(self):
        with (
            patch(
                "textforensics.detectors.analyze_text",
                return_value=_fake_analysis("machine_like_patterns"),
            ),
            patch(
                "textforensics.detectors.time.perf_counter",
                side_effect=[10.0, 30.1234567],
            ),
        ):
            result = BuiltinHeuristicDetector().detect("some text")
        self.assertEqual(result.runtime_ms, 20123.457)

    def test_builtin_is_deterministic(self):
        self.assertEqual(
            detector_determinism(BuiltinHeuristicDetector()),
            ("deterministic", None),
        )

    # -- execute_detector runtime_ms ------------------------------------------

    def test_execute_sets_runtime_ms(self):
        with patch(
            "textforensics.detectors.time.perf_counter",
            side_effect=[10.0, 30.1234567],
        ):
            result, failure = execute_detector(FakeDetector(), "some text")
        self.assertIsNone(failure)
        self.assertEqual(result.runtime_ms, 20123.457)

    def test_execute_keeps_preset_runtime_ms(self):
        class _PresetDetector(FakeDetector):
            def detect(self, text):
                result = prediction(
                    detector_id=self.detector_id,
                    family=self.detector_family,
                )
                result.runtime_ms = 5.0
                return result

        with patch(
            "textforensics.detectors.time.perf_counter",
            side_effect=[10.0, 30.1234567],
        ):
            result, failure = execute_detector(_PresetDetector(), "some text")
        self.assertIsNone(failure)
        self.assertEqual(result.runtime_ms, 5.0)

    def test_execute_failure_runtime_ms_measured(self):
        with patch(
            "textforensics.detectors.time.perf_counter",
            side_effect=[10.0, 30.1234567],
        ):
            _, failure = execute_detector(FailingDetector(), "some text")
        self.assertIsNotNone(failure)
        self.assertEqual(failure.runtime_ms, 20123.457)

    # -- _entry_points ---------------------------------------------------------

    def test_entry_points_dict_style(self):
        entry_point = _FakeEntryPoint("fake-ep", FakeDetector)
        with patch(
            "importlib.metadata.entry_points",
            return_value={"textforensics.detectors": [entry_point]},
        ):
            self.assertEqual(_entry_points(), [entry_point])

    def test_entry_points_error_returns_empty(self):
        with patch(
            "importlib.metadata.entry_points",
            side_effect=RuntimeError("boom"),
        ):
            self.assertEqual(_entry_points(), [])

    # -- discover_detector_registry ----------------------------------------------

    def test_registry_contains_builtin(self):
        registry = discover_detector_registry()
        self.assertIn(
            "textforensics/builtin-heuristic", registry.detectors
        )

    def test_registry_registers_valid_plugin(self):
        with patch(
            "textforensics.detectors._entry_points",
            return_value=[_FakeEntryPoint("fake-ep", FakeDetector)],
        ):
            registry = discover_detector_registry()
        self.assertIn("fake/detector", registry.detectors)
        health = [
            item
            for item in registry.plugin_health
            if item.entry_point == "fake-ep"
        ][0]
        self.assertEqual(health.status, "ok")

    def test_registry_rejects_duplicate_plugin(self):
        with patch(
            "textforensics.detectors._entry_points",
            return_value=[_FakeEntryPoint("dup-ep", _DuplicateIdDetector)],
        ):
            registry = discover_detector_registry()
        health = [
            item
            for item in registry.plugin_health
            if item.entry_point == "dup-ep"
        ][0]
        self.assertEqual(health.status, "error")

    def test_registry_rejects_empty_id_plugin(self):
        with patch(
            "textforensics.detectors._entry_points",
            return_value=[_FakeEntryPoint("empty-ep", _EmptyIdDetector)],
        ):
            registry = discover_detector_registry()
        health = [
            item
            for item in registry.plugin_health
            if item.entry_point == "empty-ep"
        ][0]
        self.assertEqual(health.status, "error")

    def test_registry_rejects_non_detector_plugin(self):
        with patch(
            "textforensics.detectors._entry_points",
            return_value=[_FakeEntryPoint("bad-ep", _NotADetector)],
        ):
            registry = discover_detector_registry()
        health = [
            item
            for item in registry.plugin_health
            if item.entry_point == "bad-ep"
        ][0]
        self.assertEqual(health.status, "error")

    def test_discover_detectors_lists_builtin(self):
        self.assertIn(
            "textforensics/builtin-heuristic", discover_detectors()
        )

    def test_list_detector_metadata_lists_builtin(self):
        rows = list_detector_metadata()
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0]["detector_id"], "textforensics/builtin-heuristic"
        )

    def test_list_detector_health_lists_builtin_ok(self):
        rows = list_detector_health()
        builtin = [
            row
            for row in rows
            if row["detector_id"] == "textforensics/builtin-heuristic"
        ][0]
        self.assertEqual(builtin["status"], "ok")

    # -- run_all_detectors -------------------------------------------------------

    def test_run_all_detectors_returns_builtin_row(self):
        rows = run_all_detectors("Some ordinary English prose. " * 10)
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0]["detector_id"], "textforensics/builtin-heuristic"
        )
        self.assertEqual(rows[0]["determinism"], "deterministic")
        self.assertNotIn("failed", rows[0])

    def test_run_all_detectors_reports_failure_row(self):
        with patch(
            "textforensics.detectors._entry_points",
            return_value=[_FakeEntryPoint("fail-ep", FailingDetector)],
        ):
            rows = run_all_detectors("Some ordinary English prose. " * 10)
        failed = [row for row in rows if row.get("failed") is True]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["detector_id"], "fake/failing")
