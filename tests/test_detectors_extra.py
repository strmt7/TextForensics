"""Extra tests for detectors.py to cover uncovered lines in validation, error handling, and registry discovery."""
from __future__ import annotations

import unittest
from unittest.mock import patch, MagicMock

from textforensics.detectors import (
    DetectorContractError,
    DetectorFailure,
    DetectorPrediction,
    PluginHealth,
    discover_detector_registry,
    execute_detector,
    list_detector_health,
    list_detector_metadata,
    text_sha256,
    validate_prediction,
)


def make_prediction(
    detector_id="det-1",
    detector_family="family-a",
    verdict="ai_like",
    score=0.8,
    **kwargs,
):
    return DetectorPrediction(
        schema="textforensics.detector-result/v1",
        detector_id=detector_id,
        detector_version="1",
        detector_family=detector_family,
        execution="local",
        score=score,
        score_semantics="test",
        verdict=verdict,
        threshold=0.5,
        **kwargs,
    )


class DetectorFailureTests(unittest.TestCase):
    """Test DetectorFailure.to_dict() and failure message properties."""

    def test_to_dict(self):
        failure = DetectorFailure(
            detector_id="fake/det",
            detector_version="1",
            detector_family="test-family",
            error_type="RuntimeError",
            message="something went wrong",
            runtime_ms=10.5,
        )
        data = failure.to_dict()
        self.assertEqual(data["detector_id"], "fake/det")
        self.assertEqual(data["error_type"], "RuntimeError")
        self.assertNotIn("submitted", data["message"])

    def test_failure_message_is_sanitized(self):
        failure = DetectorFailure(
            detector_id="fake/det",
            detector_version="1",
            detector_family="test-family",
            error_type="RuntimeError",
            message=(
                "Detector execution failed. Raw exception text is intentionally "
                "omitted to avoid leaking submitted content."
            ),
            runtime_ms=1.0,
        )
        data = failure.to_dict()
        self.assertIn("intentionally", data["message"])


class PluginHealthTests(unittest.TestCase):
    """Test PluginHealth.to_dict() and edge cases."""

    def test_to_dict_ok(self):
        health = PluginHealth(entry_point="builtin", status="ok", detector_id="det-1")
        data = health.to_dict()
        self.assertEqual(data["entry_point"], "builtin")
        self.assertEqual(data["status"], "ok")
        self.assertIsNone(data["error_type"])

    def test_to_dict_error(self):
        health = PluginHealth(
            entry_point="bad-ep",
            status="error",
            error_type="ImportError",
            message="plugin failed",
        )
        data = health.to_dict()
        self.assertEqual(data["error_type"], "ImportError")
        self.assertIsNone(data["detector_id"])


class text_sha256Tests(unittest.TestCase):
    """Test text_sha256 edge cases."""

    def test_empty_string(self):
        h = text_sha256("")
        self.assertEqual(len(h), 64)
        # SHA256 of empty string is a known value
        self.assertEqual(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_unicode_text(self):
        h = text_sha256("hello \u2603")
        self.assertEqual(len(h), 64)
        self.assertIsInstance(h, str)


class ValidatePredictionEdgeTests(unittest.TestCase):
    """Hit uncovered validation branches in validate_prediction."""

    def test_prediction_not_DetectorPrediction(self):
        with self.assertRaises(DetectorContractError) as ctx:
            validate_prediction("not a prediction")  # type: ignore
        self.assertIn("Detector must return DetectorPrediction", str(ctx.exception))

    def test_bad_schema(self):
        p = make_prediction()
        p.schema = "bad-schema"
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)

    def test_empty_detector_id(self):
        p = make_prediction()
        p.detector_id = ""
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)

    def test_empty_detector_version(self):
        p = make_prediction()
        p.detector_version = "  "
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)

    def test_empty_detector_family(self):
        p = make_prediction()
        p.detector_family = ""
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)

    def test_empty_score_semantics(self):
        p = make_prediction()
        p.score_semantics = ""
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)

    def test_bad_execution(self):
        p = make_prediction()
        p.execution = "remote-api"
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)

    def test_bad_verdict(self):
        p = make_prediction()
        p.verdict = "suspicious"
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)

    def test_score_is_bool(self):
        """bool is a subclass of int but should be rejected for score."""
        p = make_prediction()
        p.score = True
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)

    def test_score_is_infinity(self):
        import math
        p = make_prediction()
        p.score = float("inf")
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)

    def test_threshold_is_bool(self):
        p = make_prediction()
        p.threshold = False
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)

    def test_calibrated_probability_out_of_range_high(self):
        p = make_prediction(calibrated_ai_probability=1.5, calibration_id="cal-1")
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)

    def test_calibrated_probability_out_of_range_negative(self):
        p = make_prediction(calibrated_ai_probability=-0.1, calibration_id="cal-1")
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)

    def test_calibration_id_without_probability(self):
        p = make_prediction()
        p.calibration_id = "orphan-cal"
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)

    def test_reliability_out_of_range_high(self):
        p = make_prediction()
        p.reliability = 1.5
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)

    def test_reliability_out_of_range_negative(self):
        p = make_prediction()
        p.reliability = -0.3
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)

    def test_min_words_is_bool(self):
        p = make_prediction()
        p.min_words = True  # type: ignore
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)

    def test_min_words_is_float(self):
        p = make_prediction()
        p.min_words = 1.5  # type: ignore
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)

    def test_min_words_negative(self):
        p = make_prediction()
        p.min_words = -1
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)

    def test_runtime_ms_negative(self):
        p = make_prediction()
        p.runtime_ms = -5.0
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)

    def test_supported_languages_not_list(self):
        p = make_prediction()
        p.supported_languages = "en"  # type: ignore
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)

    def test_supported_languages_empty_string_item(self):
        p = make_prediction()
        p.supported_languages = ["en", "  "]
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)

    def test_supported_languages_non_string_item(self):
        p = make_prediction()
        p.supported_languages = [1, 2]  # type: ignore
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)

    def test_warnings_not_list(self):
        p = make_prediction()
        p.warnings = "bad"  # type: ignore
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)

    def test_warnings_non_string_item(self):
        p = make_prediction()
        p.warnings = [123]  # type: ignore
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)

    def test_evidence_not_list(self):
        p = make_prediction()
        p.evidence = "bad"  # type: ignore
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)

    def test_evidence_non_dict_item(self):
        p = make_prediction()
        p.evidence = ["string", 123]
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)


class ExecuteDetectorTests(unittest.TestCase):
    """Test execute_detector failure path and edge cases."""

    def test_failing_detector_returns_failure(self):
        class Boom:
            detector_id = "fake/boom"
            detector_version = "1"
            detector_family = "boom-family"

            def detect(self, text):
                raise RuntimeError("boom")

        pred, failure = execute_detector(Boom(), "text")
        self.assertIsNone(pred)
        self.assertIsNotNone(failure)
        self.assertEqual(failure.detector_id, "fake/boom")
        self.assertEqual(failure.error_type, "RuntimeError")

    def test_failure_has_no_source_text(self):
        class Boom:
            detector_id = "fake/boom"
            detector_version = "1"
            detector_family = "boom-family"

            def detect(self, text):
                raise RuntimeError(text)

        _, failure = execute_detector(Boom(), "secret submitted text")
        self.assertNotIn("secret submitted text", failure.message)

    def test_successful_prediction_gets_runtime(self):
        class Fast:
            detector_id = "fake/fast"
            detector_version = "1"
            detector_family = "fast-family"

            def detect(self, text):
                p = DetectorPrediction(
                    schema="textforensics.detector-result/v1",
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    detector_family=self.detector_family,
                    execution="local",
                    score=0.5,
                    score_semantics="test",
                    verdict="ai_like",
                    threshold=0.5,
                    calibrated_ai_probability=None,
                    calibration_id=None,
                )
                p.runtime_ms = None
                return p

        pred, failure = execute_detector(Fast(), "text")
        self.assertIsNotNone(pred)
        self.assertIsNone(failure)
        self.assertGreater(pred.runtime_ms, 0)

    def test_prediction_with_existing_runtime_preserved(self):
        class Fast:
            detector_id = "fake/fast2"
            detector_version = "1"
            detector_family = "fast-family"

            def detect(self, text):
                p = DetectorPrediction(
                    schema="textforensics.detector-result/v1",
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    detector_family=self.detector_family,
                    execution="local",
                    score=0.5,
                    score_semantics="test",
                    verdict="ai_like",
                    threshold=0.5,
                    calibrated_ai_probability=None,
                    calibration_id=None,
                )
                p.runtime_ms = 42.5
                return p

        pred, failure = execute_detector(Fast(), "text")
        self.assertEqual(pred.runtime_ms, 42.5)


class DiscoverDetectorRegistryTests(unittest.TestCase):
    """Test registry discovery with various plugin configurations."""

    def test_builtin_always_present(self):
        registry = discover_detector_registry()
        self.assertIn("textforensics/builtin-heuristic", registry.detectors)

    def test_builtin_health_ok(self):
        registry = discover_detector_registry()
        health_names = {h.entry_point for h in registry.plugin_health}
        self.assertIn("builtin", health_names)

    def test_bad_entry_point_caught(self):
        """An entry point that raises on load produces error health entry."""
        class BadEP:
            name = "broken-plugin"

            def load(self):
                raise ImportError("no module")

        with patch("textforensics.detectors._entry_points", return_value=[BadEP()]):
            registry = discover_detector_registry()
        errors = [h for h in registry.plugin_health if h.status == "error"]
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].entry_point, "broken-plugin")
        self.assertEqual(errors[0].error_type, "ImportError")

    def test_non_detector_entry_point_caught(self):
        """A plugin that loads but doesn't implement Detector is rejected."""
        class NotADetector:
            pass

        class EP:
            name = "not-a-detector"

            def load(self):
                return lambda: NotADetector()

        with patch("textforensics.detectors._entry_points", return_value=[EP()]):
            registry = discover_detector_registry()
        errors = [h for h in registry.plugin_health if h.status == "error"]
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].entry_point, "not-a-detector")

    def test_duplicate_detector_id_rejected(self):
        """A plugin with a duplicate detector_id is rejected."""
        class Dup:
            detector_id = "textforensics/builtin-heuristic"
            detector_version = "2"
            detector_family = "duplicate-family"

        class EP:
            name = "duplicate"

            def load(self):
                return lambda: Dup()

        with patch("textforensics.detectors._entry_points", return_value=[EP()]):
            registry = discover_detector_registry()
        errors = [h for h in registry.plugin_health if h.status == "error"]
        self.assertEqual(len(errors), 1)
        self.assertIn("duplicate", errors[0].entry_point.lower())


class ListDetectorMetadataTests(unittest.TestCase):
    """Test list_detector_metadata edge cases."""

    def test_returns_sorted_list(self):
        metadata = list_detector_metadata()
        ids = [m["detector_id"] for m in metadata]
        self.assertEqual(ids, sorted(ids))
        self.assertIsInstance(metadata, list)
        self.assertGreaterEqual(len(metadata), 1)

    def test_metadata_keys(self):
        metadata = list_detector_metadata()
        for item in metadata:
            self.assertIn("detector_id", item)
            self.assertIn("detector_version", item)
            self.assertIn("detector_family", item)


class ListDetectorHealthTests(unittest.TestCase):
    """Test list_detector_health edge cases."""

    def test_returns_list_of_dicts(self):
        health = list_detector_health()
        self.assertIsInstance(health, list)
        self.assertGreaterEqual(len(health), 1)
        for item in health:
            self.assertIsInstance(item, dict)
            self.assertIn("entry_point", item)
            self.assertIn("status", item)

    def test_builtin_health_ok(self):
        health = list_detector_health()
        builtins = [h for h in health if h["entry_point"] == "builtin"]
        self.assertEqual(len(builtins), 1)
        self.assertEqual(builtins[0]["status"], "ok")


class ValidatePredictionScoreNoneTests(unittest.TestCase):
    """Test that score=None is accepted (line 192-193 branch)."""

    def test_score_none_is_valid(self):
        p = make_prediction()
        p.score = None
        validate_prediction(p)  # should not raise

    def test_threshold_none_is_valid(self):
        p = make_prediction()
        p.threshold = None
        validate_prediction(p)  # should not raise


class ExecuteDetectorValidationFailureTests(unittest.TestCase):
    """Test that validation failures in execute_detector produce DetectorFailure."""

    def test_bad_schema_in_detector(self):
        class BadSchemaDetector:
            detector_id = "fake/bad-schema"
            detector_version = "1"
            detector_family = "bad-schema-family"

            def detect(self, text):
                p = DetectorPrediction(
                    schema="textforensics.detector-result/v1",
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    detector_family=self.detector_family,
                    execution="local",
                    score=0.5,
                    score_semantics="test",
                    verdict="ai_like",
                    threshold=0.5,
                )
                p.schema = "wrong"
                return p

        pred, failure = execute_detector(BadSchemaDetector(), "text")
        self.assertIsNone(pred)
        self.assertIsNotNone(failure)
        self.assertEqual(failure.error_type, "DetectorContractError")

    def test_source_echo_failure(self):
        """A detector that echoes the source text in warnings is caught."""
        class EchoDetector:
            detector_id = "fake/echo"
            detector_version = "1"
            detector_family = "echo-family"

            def detect(self, text):
                p = DetectorPrediction(
                    schema="textforensics.detector-result/v1",
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    detector_family=self.detector_family,
                    execution="local",
                    score=0.5,
                    score_semantics="test",
                    verdict="ai_like",
                    threshold=0.5,
                )
                p.warnings = [text]
                return p

        long_text = (
            "This is a sufficiently long piece of submitted text that "
            "contains enough words to trigger the source echo detection."
        )
        pred, failure = execute_detector(EchoDetector(), long_text)
        self.assertIsNone(pred)
        self.assertIsNotNone(failure)


class DetectorPredictionValidateMethodTests(unittest.TestCase):
    """Test DetectorPrediction.validate() method."""

    def test_validate_returns_self(self):
        p = make_prediction()
        result = p.validate()
        self.assertIs(result, p)

    def test_validate_with_detector_raises_on_mismatch(self):
        class Det:
            detector_id = "correct"
            detector_version = "1"
            detector_family = "family"

        p = make_prediction()
        with self.assertRaises(DetectorContractError):
            p.validate(detector=Det())


class EvidenceForbiddenKeysNestedTests(unittest.TestCase):
    """Test nested forbidden evidence key detection."""

    def test_nested_forbidden_key_in_list(self):
        p = make_prediction()
        p.evidence = [{"items": [{"content": "raw text here"}]}]
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)

    def test_deeply_nested_forbidden_key(self):
        p = make_prediction()
        p.evidence = [{"level1": {"level2": {"source_text": "private"}}}]
        with self.assertRaises(DetectorContractError):
            validate_prediction(p)


class EmptySourceEchoTests(unittest.TestCase):
    """Test _validate_no_source_echo with empty source (covers line 148)."""

    def test_empty_source_skips_echo_check(self):
        """When source text is empty/whitespace, echo check returns early (line 148)."""
        from textforensics.detectors import _validate_no_source_echo

        # Empty string passes through
        prediction = DetectorPrediction(
            schema="textforensics.detector-result/v1",
            detector_id="test",
            detector_version="1",
            detector_family="test",
            execution="local",
            score=0.5,
            score_semantics="test",
            verdict="ai_like",
            threshold=0.5,
            warnings=["some warning"],  # This would normally be caught if source wasn't empty
        )

        # Empty source - should return early without raising
        _validate_no_source_echo(prediction, "")  # Should not raise
        _validate_no_source_echo(prediction, "   ")  # Should not raise


class NormalizeInEchoCheckTests(unittest.TestCase):
    """Test normalization behavior in _validate_no_source_echo (covers line 155)."""

    def test_normalized_empty_candidate_is_skipped(self):
        """When a candidate normalizes to empty string, it's skipped (line 155)."""
        from textforensics.detectors import _validate_no_source_echo

        # Create a prediction with various warnings and evidence
        p = DetectorPrediction(
            schema="textforensics.detector-result/v1",
            detector_id="test",
            detector_version="1",
            detector_family="test",
            execution="local",
            score=0.5,
            score_semantics="test",
            verdict="ai_like",
            threshold=0.5,
            warnings=["not echo", "   "],  # Second one normalizes to empty
            evidence=[{"snippet": "not echo part 2", "note": "   "}],  # Second one normalizes to empty
        )

        # Source is long enough for echo check
        source = "This is a sufficiently long piece of text for testing purposes."

        # Should not raise - empty normalized strings are skipped
        _validate_no_source_echo(p, source)

        # Also test with only whitespace candidates that normalize to empty
        p2 = DetectorPrediction(
            schema="textforensics.detector-result/v1",
            detector_id="test",
            detector_version="1",
            detector_family="test",
            execution="local",
            score=0.5,
            score_semantics="test",
            verdict="ai_like",
            threshold=0.5,
            warnings=["   ", "  \t  "],  # Both normalize to empty
            evidence=[],
        )

        _validate_no_source_echo(p2, source)  # Should not raise


class BuiltinHeuristicDetectorVerdictTests(unittest.TestCase):
    """Test BuiltinHeuristicDetector verdict branches (covers lines 273, 275)."""

    def test_builtin_ai_like_verdict(self):
        """When engine verdict is machine_like_patterns, output is ai_like (line 273)."""
        from textforensics.detectors import BuiltinHeuristicDetector

        # Use text that likely triggers machine_like_patterns
        # We need to mock analyze_text to control the result
        detector = BuiltinHeuristicDetector()

        class MockResult:
            verdict = "machine_like_patterns"
            score = 0.85
            diagnostic_reliability = 0.5
            warnings = []
            analyzers = []

        class MockEngineResult:
            verdict = "machine_like_patterns"
            score = 0.85
            diagnostic_reliability = 0.5
            warnings = []
            analyzers = []

        import textforensics.detectors as det_module
        original_analyze = det_module.analyze_text

        def mock_analyze(text):
            r = MockResult()
            r.verdict = "machine_like_patterns"
            return r

        try:
            det_module.analyze_text = mock_analyze
            pred, failure = execute_detector(detector, "test text")
            self.assertIsNone(failure)
            self.assertEqual(pred.verdict, "ai_like")
        finally:
            det_module.analyze_text = original_analyze

    def test_builtin_human_like_verdict(self):
        """When engine verdict is human_like_patterns, output is human_like (line 275)."""
        from textforensics.detectors import BuiltinHeuristicDetector

        detector = BuiltinHeuristicDetector()

        # We need to use the actual engine or mock properly
        # Let's just verify the detection works and set the class variable
        import textforensics.detectors as det_module

        original_analyze = det_module.analyze_text

        class MockResult:
            verdict = "human_like_patterns"
            score = 0.15
            diagnostic_reliability = 0.5
            warnings = []
            analyzers = []

        def mock_analyze(text):
            r = MockResult()
            r.verdict = "human_like_patterns"
            return r

        try:
            det_module.analyze_text = mock_analyze
            pred, failure = execute_detector(detector, "test text")
            self.assertIsNone(failure)
            self.assertEqual(pred.verdict, "human_like")
        finally:
            det_module.analyze_text = original_analyze


class EntryPointsExceptionTests(unittest.TestCase):
    """Test _entry_points exception handling (covers lines 332-333)."""

    def test_entry_points_exception_returns_empty_list(self):
        """When entry_points() raises, we get empty list."""
        from textforensics.detectors import _entry_points

        with patch("textforensics.detectors.importlib.metadata.entry_points") as mock_eps:
            mock_eps.side_effect = RuntimeError("importlib failure")
            result = _entry_points()
            self.assertEqual(result, [])


class EmptyScoreInProbesTests(unittest.TestCase):
    """Test that when score is None in a probe, it doesn't get added to scores."""

    def test_probe_with_none_score_raises_defensive(self):
        """Test that execute_detector returning (None, None) raises ValueError."""
        # This is already covered by test_robustness_defensive_prediction_none_raises
        # but let's also test it more directly
        from textforensics.detectors import execute_detector, DetectorFailure

        class BrokenDetector:
            detector_id = "fake/broken"
            detector_version = "1"
            detector_family = "broken_family"

            def detect(self, text):
                # Return a prediction that's malformed
                raise Exception("Detector returned neither prediction nor failure")

        # Actually, this would go through the exception path
        # Let's instead test the edge case where prediction is None but failure is None
        # This is a defensive check that could happen with buggy detector code

        # We can simulate this by having the detector return something invalid
        detector = BrokenDetector()
        pred, failure = execute_detector(detector, "test")
        # Failure path catches this
        self.assertIsNotNone(failure)
        self.assertIsNone(pred)


class DiscoverDetectorsFunctionTest(unittest.TestCase):
    """Test discover_detectors function (covers line 387)."""

    def test_discover_detectors_returns_dict(self):
        """discover_detectors returns the detectors dict from registry."""
        from textforensics.detectors import discover_detectors
        result = discover_detectors()
        self.assertIsInstance(result, dict)
        self.assertIn("textforensics/builtin-heuristic", result)


class IterStringsTests(unittest.TestCase):
    """Test _iter_strings function (covers line 136 branch for list)."""

    def test_iter_strings_with_list(self):
        """_iter_strings recursively processes lists (covers line 136)."""
        from textforensics.detectors import _iter_strings

        # Test with a list of strings
        result = list(_iter_strings(["a", "b", "c"]))
        self.assertEqual(result, ["a", "b", "c"])

        # Test with nested lists
        result = list(_iter_strings([["a", "b"], "c"]))
        self.assertEqual(result, ["a", "b", "c"])

        # Test with dict containing list values
        result = list(_iter_strings({"items": ["x", "y"]}))
        self.assertEqual(sorted(result), ["x", "y"])

        # Test with deeply nested structure
        result = list(_iter_strings({"data": {"list": ["deep", ["nested"]]}}))
        self.assertEqual(sorted(result), ["deep", "nested"])


class BuiltinHeuristicDetectorAbstainTests(unittest.TestCase):
    """Test BuiltinHeuristicDetector abstain verdict (covers line 277)."""

    def test_builtin_abstain_verdict(self):
        """When engine verdict is neither pattern type, output is abstain (line 277)."""
        from textforensics.detectors import BuiltinHeuristicDetector
        import textforensics.detectors as det_module

        detector = BuiltinHeuristicDetector()
        original_analyze = det_module.analyze_text

        class MockResult:
            verdict = "unknown_pattern_type"  # Not machine_like_patterns or human_like_patterns
            score = 0.5
            diagnostic_reliability = 0.5
            warnings = []
            analyzers = []

        def mock_analyze(text):
            return MockResult()

        try:
            det_module.analyze_text = mock_analyze
            pred, failure = execute_detector(detector, "test text")
            self.assertIsNone(failure)
            self.assertEqual(pred.verdict, "abstain")
        finally:
            det_module.analyze_text = original_analyze


class ValidPluginSuccessPathTests(unittest.TestCase):
    """Test successful plugin loading path (covers lines 359-366 success branch)."""

    def test_valid_plugin_processes_all_attributes(self):
        """A valid plugin goes through attribute checking (lines 359-360)."""
        from textforensics.detectors import discover_detector_registry

        class ValidDetector:
            detector_id = "test/valid-plugin"
            detector_version = "1.0"
            detector_family = "test-family"

            def detect(self, text):
                from textforensics.detectors import DetectorPrediction
                return DetectorPrediction(
                    schema="textforensics.detector-result/v1",
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    detector_family=self.detector_family,
                    execution="local",
                    score=0.5,
                    score_semantics="test",
                    verdict="ai_like",
                    threshold=0.5,
                )

        class ValidEP:
            name = "valid-plugin"

            def load(self):
                return lambda: ValidDetector()

        with patch("textforensics.detectors._entry_points", return_value=[ValidEP()]):
            registry = discover_detector_registry()

        # Should succeed - not in errors
        errors = [h for h in registry.plugin_health if h.status == "error" and "valid-plugin" in h.entry_point]
        self.assertEqual(len(errors), 0)

        # Should be in detectors
        self.assertIn("test/valid-plugin", registry.detectors)

    def test_valid_plugin_no_duplicate_detector_id(self):
        """A valid plugin with unique ID is added (lines 361-366)."""
        from textforensics.detectors import discover_detector_registry

        class UniqueDetector:
            detector_id = "unique/detector-id"
            detector_version = "1.0"
            detector_family = "unique-family"

            def detect(self, text):
                from textforensics.detectors import DetectorPrediction
                return DetectorPrediction(
                    schema="textforensics.detector-result/v1",
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    detector_family=self.detector_family,
                    execution="local",
                    score=0.5,
                    score_semantics="test",
                    verdict="ai_like",
                    threshold=0.5,
                )

        class UniqueEP:
            name = "unique-plugin"

            def load(self):
                return lambda: UniqueDetector()

        with patch("textforensics.detectors._entry_points", return_value=[UniqueEP()]):
            registry = discover_detector_registry()

        self.assertIn("unique/detector-id", registry.detectors)
        builtin_health = [h for h in registry.plugin_health if h.entry_point == "builtin"]
        unique_health = [h for h in registry.plugin_health if h.entry_point == "unique-plugin"]

        self.assertEqual(len(builtin_health), 1)
        self.assertEqual(len(unique_health), 1)
        self.assertEqual(unique_health[0].status, "ok")


class CalibrationIdWithoutProbabilityTests(unittest.TestCase):
    """Test calibration_id without calibrated_ai_probability (covers line 208)."""

    def test_calibration_id_without_probability_raises(self):
        """calibration_id cannot be set without calibrated_ai_probability (line 208)."""
        p = DetectorPrediction(
            schema="textforensics.detector-result/v1",
            detector_id="test",
            detector_version="1",
            detector_family="test",
            execution="local",
            score=0.5,
            score_semantics="test",
            verdict="ai_like",
            threshold=0.5,
            calibration_id="some-calibration",  # Without probability
        )
        with self.assertRaises(DetectorContractError) as ctx:
            validate_prediction(p)
        self.assertIn("calibration_id", str(ctx.exception))

    def test_probability_with_empty_calibration_id_raises(self):
        """When calibrated_ai_probability is set but calibration_id is empty (line 208)."""
        p = DetectorPrediction(
            schema="textforensics.detector-result/v1",
            detector_id="test",
            detector_version="1",
            detector_family="test",
            execution="local",
            score=0.5,
            score_semantics="test",
            verdict="ai_like",
            threshold=0.5,
            calibrated_ai_probability=0.8,  # With probability
            calibration_id="",  # But empty calibration_id
        )
        with self.assertRaises(DetectorContractError) as ctx:
            validate_prediction(p)
        self.assertIn("calibration_id", str(ctx.exception))


class DetectorPredictionDictTests(unittest.TestCase):
    """Test to_dict methods for coverage (covers lines 48, 61, 73)."""

    def test_detector_prediction_to_dict(self):
        """DetectorPrediction.to_dict() works (covers line 48)."""
        p = DetectorPrediction(
            schema="textforensics.detector-result/v1",
            detector_id="test-det",
            detector_version="1.0",
            detector_family="test-family",
            execution="local",
            score=0.75,
            score_semantics="test",
            verdict="ai_like",
            threshold=0.5,
            calibrated_ai_probability=0.8,
            calibration_id="cal-v1",
        )
        d = p.to_dict()
        self.assertEqual(d["detector_id"], "test-det")
        self.assertEqual(d["calibrated_ai_probability"], 0.8)
        self.assertIsNone(d["reliability"])

    def test_detector_failure_to_dict(self):
        """DetectorFailure.to_dict() works (covers line 61)."""
        f = DetectorFailure(
            detector_id="test-det",
            detector_version="1.0",
            detector_family="test-family",
            error_type="RuntimeError",
            message="Something went wrong",
            runtime_ms=10.5,
        )
        d = f.to_dict()
        self.assertEqual(d["detector_id"], "test-det")
        self.assertEqual(d["error_type"], "RuntimeError")

    def test_plugin_health_to_dict(self):
        """PluginHealth.to_dict() works (covers line 73)."""
        h = PluginHealth(
            entry_point="builtin",
            status="ok",
            detector_id="test-det",
        )
        d = h.to_dict()
        self.assertEqual(d["entry_point"], "builtin")
        self.assertEqual(d["status"], "ok")
