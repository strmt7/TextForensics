"""Tests for the case-file v4 model (U2 follow-up: seal-time
``not_reproducible`` declaration).

v4 is v3 plus a per-observation determinism declaration
(``determinism`` / ``determinism_reason`` on
``detector_observations`` items, required on ``kind: "observed"``
items).  A detector declared ``non_deterministic`` at seal time whose
replayed score, verdict, version or calibration differs is reported
``not_reproducible`` instead of failing replay; the replay outcome is
then ``"inconclusive"`` (valid but inconclusive), never silently
passed.  A ``"deterministic"`` or ``"unknown"`` declaration fails
closed on a mismatch.
"""

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from textforensics.casefile import (
    CASE_SCHEMA_V3,
    CASE_SCHEMA_V4,
    _hash_without_seal,
    build_detector_observations,
    replay_case_file,
    seal_case_file,
    verify_case_file,
)
from textforensics.constants import EXIT_OK
from textforensics.detectors import (
    DETECTOR_SCHEMA_V2,
    BuiltinHeuristicDetector,
    DetectorPrediction,
    detector_determinism,
)
from textforensics.ollama import OllamaDetectorMixin
from textforensics.report import build_forensic_bundle
from textforensics.sealed_bundle import pack_sealed_bundle, verify_sealed_bundle

TEXT = (
    "The committee met on Tuesday to review the quarterly figures and "
    "discuss the outlook for the coming year. The chair opened the meeting "
    "with a summary of the previous session, and the members agreed to "
    "focus on three items: revenue, staffing, and the maintenance budget. "
    "Revenue grew modestly in the first quarter, driven by new contracts "
    "in the northern region. Staffing remains tight, and the hiring plan "
    "was approved with minor changes. The maintenance budget was reduced "
    "after a review of the supplier quotes. The meeting ended with a plan "
    "to reconvene in four weeks to review progress on each item."
)
BUILTIN_ID = "textforensics/builtin-heuristic"


def _prediction(detector_id, score, verdict):
    return DetectorPrediction(
        schema=DETECTOR_SCHEMA_V2,
        detector_id=detector_id,
        detector_version="1.0.0",
        detector_family="test",
        execution="local",
        score=score,
        score_semantics="higher_means_ai; test prediction",
        verdict=verdict,
        threshold=None,
    )


class TogglingDetector:
    """A fake detector whose second run differs from its first."""

    detector_id = "test/toggling-detector"
    detector_version = "1.0.0"
    detector_family = "test"

    def __init__(self):
        self.calls = 0

    def detect(self, text):
        self.calls += 1
        if self.calls == 1:
            return _prediction(self.detector_id, 0.2, "human_like")
        return _prediction(self.detector_id, 0.9, "ai_like")


class TogglingNonDeterministicDetector(TogglingDetector):
    deterministic = False
    determinism_reason = "Test detector: sampled output changes between runs."


class TogglingDeterministicDetector(TogglingDetector):
    deterministic = True


class TogglingUnknownDetector(TogglingDetector):
    """Toggling detector that declares nothing: determinism unknown."""


class FakeOllamaDetector(OllamaDetectorMixin):
    """A concrete detector carrying the Ollama non-determinism declaration."""

    detector_id = "test/ollama-detector"
    detector_version = "1.0.0"
    detector_family = "test"

    def detect(self, text):
        return _prediction(self.detector_id, 0.5, "human_like")


class DeterminismDeclarationTests(unittest.TestCase):
    def test_builtin_declares_deterministic(self):
        self.assertEqual(
            detector_determinism(BuiltinHeuristicDetector()),
            ("deterministic", None),
        )
        self.assertTrue(BuiltinHeuristicDetector.deterministic)

    def test_ollama_mixin_declares_non_deterministic_with_reason(self):
        value, reason = detector_determinism(FakeOllamaDetector())
        self.assertEqual(value, "non_deterministic")
        self.assertIsInstance(reason, str)
        self.assertIn("sampling", reason)

    def test_undeclared_detector_is_unknown(self):
        self.assertEqual(
            detector_determinism(TogglingUnknownDetector()),
            ("unknown", None),
        )

    def test_analysis_records_determinism_for_builtin(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        result = bundle["detector_results"][0]
        self.assertEqual(result["detector_id"], BUILTIN_ID)
        self.assertEqual(result["determinism"], "deterministic")
        self.assertIsNone(result["determinism_reason"])

    def test_analysis_records_determinism_for_ollama_detector(self):
        bundle = build_forensic_bundle(TEXT, detectors=[FakeOllamaDetector()]).to_dict()
        result = bundle["detector_results"][0]
        self.assertEqual(result["determinism"], "non_deterministic")
        self.assertIn("sampling", result["determinism_reason"] or "")

    def test_analysis_records_unknown_for_undeclared_detector(self):
        bundle = build_forensic_bundle(TEXT, detectors=[TogglingUnknownDetector()]).to_dict()
        self.assertEqual(bundle["detector_results"][0]["determinism"], "unknown")

    def test_observations_carry_determinism(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        observations = build_detector_observations(bundle)
        observed = [item for item in observations if item["kind"] == "observed"]
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]["determinism"], "deterministic")
        self.assertIsNone(observed[0]["determinism_reason"])

    def test_invalid_bundle_determinism_fails_seal(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        bundle["detector_results"][0]["determinism"] = "sometimes"
        with self.assertRaises(ValueError):
            seal_case_file(bundle)


class SealV4Tests(unittest.TestCase):
    def test_v4_is_default(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle)
        self.assertEqual(case["schema"], CASE_SCHEMA_V4)
        self.assertTrue(verify_case_file(case)["valid"])
        observed = [item for item in case["detector_observations"] if item["kind"] == "observed"]
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]["determinism"], "deterministic")

    def test_v3_seal_still_verifies(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle, version="v3")
        self.assertEqual(case["schema"], CASE_SCHEMA_V3)
        self.assertTrue(verify_case_file(case)["valid"])

    def test_v3_observed_item_without_determinism_verifies(self):
        # v3 keeps determinism optional: an older v3 file whose observed
        # items carry no declaration still verifies.
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle, version="v3")
        for item in case["detector_observations"]:
            item.pop("determinism", None)
            item.pop("determinism_reason", None)
        case["case_sha256"] = _hash_without_seal(case)
        self.assertTrue(verify_case_file(case)["valid"])

    def test_v4_observed_item_missing_determinism_fails(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle)
        tampered = copy.deepcopy(case)
        observed = next(
            item for item in tampered["detector_observations"] if item["kind"] == "observed"
        )
        del observed["determinism"]
        # Re-seal the hash so the failure is the missing declaration,
        # not a hash mismatch.
        tampered["case_sha256"] = _hash_without_seal(tampered)
        result = verify_case_file(tampered)
        self.assertFalse(result["valid"])
        self.assertTrue(
            any(
                error.startswith("v4_detector_observations_determinism_missing")
                for error in result["errors"]
            ),
            result["errors"],
        )

    def test_explicit_override_wins_over_bundle_value(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(
            bundle,
            determinism={BUILTIN_ID: "non_deterministic"},
            determinism_reasons={BUILTIN_ID: "sealer knows this run sampled"},
        )
        observed = next(
            item for item in case["detector_observations"] if item["kind"] == "observed"
        )
        self.assertEqual(observed["determinism"], "non_deterministic")
        self.assertEqual(observed["determinism_reason"], "sealer knows this run sampled")
        # The override is recorded in the sealed bundle copy too, so
        # verification rebuilds exactly what was sealed.
        self.assertEqual(
            case["forensic_bundle"]["detector_results"][0]["determinism"],
            "non_deterministic",
        )
        self.assertTrue(verify_case_file(case)["valid"])

    def test_override_for_unknown_detector_is_rejected(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        with self.assertRaises(ValueError):
            seal_case_file(bundle, determinism={"test/no-such-detector": "unknown"})

    def test_override_with_invalid_value_is_rejected(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        with self.assertRaises(ValueError):
            seal_case_file(bundle, determinism={BUILTIN_ID: "sometimes"})

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_v4_case_validates_against_packaged_schema(self):
        import jsonschema

        from textforensics.schema import load_schema

        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle)
        jsonschema.validate(case, load_schema("case-file"))
        bundle_result = bundle["detector_results"][0]
        jsonschema.validate(bundle_result, load_schema("detector-result"))


class ReplayNotReproducibleTests(unittest.TestCase):
    def test_non_deterministic_mismatch_is_not_reproducible(self):
        detector = TogglingNonDeterministicDetector()
        bundle = build_forensic_bundle(TEXT, detectors=[detector]).to_dict()
        case = seal_case_file(bundle)
        self.assertTrue(verify_case_file(case)["valid"])
        result = replay_case_file(case, text=TEXT, detectors=[detector])
        self.assertTrue(result["valid"])
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["replay_outcome"], "inconclusive")
        row = result["checks"]["detectors"]["detectors"][detector.detector_id]
        self.assertEqual(row["status"], "not_reproducible")
        self.assertTrue(
            any(
                warning.startswith(f"not_reproducible:{detector.detector_id}")
                and "sampled output changes between runs" in warning
                for warning in result["warnings"]
            ),
            result["warnings"],
        )

    def test_deterministic_mismatch_still_fails(self):
        detector = TogglingDeterministicDetector()
        bundle = build_forensic_bundle(TEXT, detectors=[detector]).to_dict()
        case = seal_case_file(bundle)
        result = replay_case_file(case, text=TEXT, detectors=[detector])
        self.assertFalse(result["valid"])
        self.assertEqual(result["replay_outcome"], "failed")
        self.assertTrue(
            any(error.startswith("score_mismatch:") for error in result["errors"]),
            result["errors"],
        )
        row = result["checks"]["detectors"]["detectors"][detector.detector_id]
        self.assertEqual(row["status"], "observed")

    def test_unknown_determinism_mismatch_fails_closed(self):
        detector = TogglingUnknownDetector()
        bundle = build_forensic_bundle(TEXT, detectors=[detector]).to_dict()
        case = seal_case_file(bundle)
        result = replay_case_file(case, text=TEXT, detectors=[detector])
        self.assertFalse(result["valid"])
        self.assertEqual(result["replay_outcome"], "failed")
        self.assertTrue(
            any(error.startswith("score_mismatch:") for error in result["errors"]),
            result["errors"],
        )

    def test_override_to_non_deterministic_makes_replay_inconclusive(self):
        detector = TogglingDeterministicDetector()
        bundle = build_forensic_bundle(TEXT, detectors=[detector]).to_dict()
        case = seal_case_file(
            bundle,
            determinism={detector.detector_id: "non_deterministic"},
            determinism_reasons={detector.detector_id: "sealer override: this run sampled"},
        )
        result = replay_case_file(case, text=TEXT, detectors=[detector])
        self.assertTrue(result["valid"])
        self.assertEqual(result["replay_outcome"], "inconclusive")
        self.assertTrue(
            any(
                warning.startswith(f"not_reproducible:{detector.detector_id}")
                for warning in result["warnings"]
            ),
            result["warnings"],
        )

    def test_matching_replay_reproduces(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle)
        result = replay_case_file(case, text=TEXT, detectors=[BuiltinHeuristicDetector()])
        self.assertTrue(result["valid"])
        self.assertEqual(result["replay_outcome"], "reproduced")
        row = result["checks"]["detectors"]["detectors"][BUILTIN_ID]
        self.assertEqual(row["status"], "observed")


class SealedBundleReplayTests(unittest.TestCase):
    def test_inconclusive_replay_maps_to_exit_code_2(self):
        detector = TogglingNonDeterministicDetector()
        bundle = build_forensic_bundle(TEXT, detectors=[detector]).to_dict()
        case = seal_case_file(bundle)
        archive, _record = pack_sealed_bundle(case)
        report = verify_sealed_bundle(archive, text=TEXT, detectors=[detector])
        self.assertEqual(report["replay"]["replay_outcome"], "inconclusive")
        self.assertTrue(report["replay"]["valid"])
        self.assertEqual(report["exit_code"], 2)

    def test_reproduced_replay_maps_to_exit_code_0(self):
        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle)
        archive, _record = pack_sealed_bundle(case)
        report = verify_sealed_bundle(archive, text=TEXT, detectors=[BuiltinHeuristicDetector()])
        self.assertEqual(report["replay"]["replay_outcome"], "reproduced")
        self.assertEqual(report["exit_code"], 0)


class StandaloneV4Tests(unittest.TestCase):
    def test_standalone_accepts_v4_bundle(self):
        from tests.test_standalone_verify import build_bundle, load_standalone

        bundle_bytes, _manifest, _case = build_bundle()
        self.assertIn(b"textforensics.case-file/v4", bundle_bytes)
        module = load_standalone()
        report = module.verify_bundle_bytes(bundle_bytes)
        self.assertEqual(report["exit_code"], 0, report)

    def test_standalone_rejects_tampered_determinism(self):
        from tests.test_standalone_verify import build_bundle, canonical_json, load_standalone

        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle)
        tampered = copy.deepcopy(case)
        observed = next(
            item for item in tampered["detector_observations"] if item["kind"] == "observed"
        )
        observed["determinism"] = "non_deterministic"
        observed["determinism_reason"] = "forged declaration"
        # Recompute the case hash so the failure is the observations
        # check, not the hash check.
        tampered["case_sha256"] = _hash_without_seal(tampered)
        bundle_bytes, _manifest, _case = build_bundle(
            case_bytes=canonical_json(tampered), case=tampered
        )
        module = load_standalone()
        report = module.verify_bundle_bytes(bundle_bytes)
        self.assertEqual(report["exit_code"], 1, report)
        failed = [check for check in report["checks"] if check["status"] == "fail"]
        self.assertTrue(
            any(check["id"] == "seal_case_observations" for check in failed),
            failed,
        )

    def test_standalone_rejects_unrehashed_tampered_determinism(self):
        from tests.test_standalone_verify import build_bundle, canonical_json, load_standalone

        bundle = build_forensic_bundle(TEXT).to_dict()
        case = seal_case_file(bundle)
        tampered = copy.deepcopy(case)
        observed = next(
            item for item in tampered["detector_observations"] if item["kind"] == "observed"
        )
        observed["determinism"] = "non_deterministic"
        bundle_bytes, _manifest, _case = build_bundle(
            case_bytes=canonical_json(tampered), case=tampered
        )
        module = load_standalone()
        report = module.verify_bundle_bytes(bundle_bytes)
        self.assertEqual(report["exit_code"], 1, report)
        failed = [check for check in report["checks"] if check["status"] == "fail"]
        self.assertTrue(
            any(check["id"] == "seal_case_hash" for check in failed),
            failed,
        )


class CliDeterminismTests(unittest.TestCase):
    def run_cli(self, *args, input_text=None):
        return subprocess.run(
            [sys.executable, "-m", "textforensics.cli", *args],
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_cli_determinism_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.txt"
            case_path = Path(tmp) / "case.json"
            source.write_text(TEXT, encoding="utf-8")
            exported = self.run_cli(
                "case",
                "export",
                "--file",
                str(source),
                "--output",
                str(case_path),
                "--determinism",
                f"{BUILTIN_ID}:non_deterministic",
            )
            self.assertEqual(exported.returncode, EXIT_OK, exported.stderr)
            case = json.loads(case_path.read_text(encoding="utf-8"))
            self.assertEqual(case["schema"], "textforensics.case-file/v4")
            observed = next(
                item for item in case["detector_observations"] if item["kind"] == "observed"
            )
            self.assertEqual(observed["determinism"], "non_deterministic")
            verified = self.run_cli("case", "verify", str(case_path), "--text", TEXT)
            self.assertEqual(verified.returncode, EXIT_OK, verified.stderr)
            payload = json.loads(verified.stdout)
            self.assertEqual(payload["replay"]["replay_outcome"], "reproduced")
            self.assertIn("replay_outcome: reproduced", payload["scope"])

    def test_cli_determinism_invalid_value_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.txt"
            case_path = Path(tmp) / "case.json"
            source.write_text(TEXT, encoding="utf-8")
            exported = self.run_cli(
                "case",
                "export",
                "--file",
                str(source),
                "--output",
                str(case_path),
                "--determinism",
                f"{BUILTIN_ID}:sometimes",
            )
            self.assertNotEqual(exported.returncode, EXIT_OK)
            self.assertFalse(case_path.exists())

    def test_cli_sealed_bundle_verify_surfaces_replay_outcome(self):
        # The CLI itself does not re-run detectors, so a CLI replay can
        # only reproduce or fail — never go inconclusive.  This checks
        # the sealed-bundle verify path surfaces replay_outcome; the
        # inconclusive exit-code-2 mapping is covered directly in
        # SealedBundleReplayTests.
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.txt"
            case_path = Path(tmp) / "case.json"
            source.write_text(TEXT, encoding="utf-8")
            exported = self.run_cli(
                "case",
                "export",
                "--file",
                str(source),
                "--output",
                str(case_path),
                "--seal",
                "--determinism",
                f"{BUILTIN_ID}:non_deterministic",
            )
            self.assertEqual(exported.returncode, EXIT_OK, exported.stderr)
            bundle_path = Path(str(case_path.with_suffix(".sealed.zip")))
            self.assertTrue(bundle_path.exists())
            verified = self.run_cli("case", "verify", str(bundle_path), "--text", TEXT)
            # No detectors are re-run by the CLI, so the replay
            # reproduces the seal/text checks; the outcome is surfaced.
            self.assertEqual(verified.returncode, EXIT_OK, verified.stderr)
            payload = json.loads(verified.stdout)
            self.assertEqual(payload["replay"]["replay_outcome"], "reproduced")


if __name__ == "__main__":
    unittest.main()
