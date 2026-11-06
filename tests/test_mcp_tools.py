"""Tests for MCP tool implementations (standalone, no MCP runtime needed)."""

from __future__ import annotations

import unittest

from textforensics import constants

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
from textforensics.casefile import _hash_without_seal
from textforensics.detectors import text_sha256 as _text_sha256
from textforensics.mcp_tools import (
    capability_check,
    capability_list,
    capability_register,
    check_contamination,
    drift_compare,
    drift_report,
    drift_snapshot,
    fingerprint_dataset,
    verify_case_file,
)

SAMPLE_CORPUS = {
    "schema": "textforensics.drift-corpus/v1",
    "samples": [
        {
            "id": "probe-1",
            "text": "This is probe sample one.",
            "text_sha256": _text_sha256("This is probe sample one."),
            "metadata": {"label": "human"},
        },
        {
            "id": "probe-2",
            "text": "This is probe sample two.",
            "text_sha256": _text_sha256("This is probe sample two."),
            "metadata": {"label": "ai"},
        },
    ],
}


# Generate a proper case file for testing
def _generate_valid_case_file():
    from textforensics.casefile import seal_case_file
    from textforensics.report import build_forensic_bundle

    bundle = build_forensic_bundle(
        "Test text for MCP tools.", deterministic=True, fixed_timestamp="1970-01-01T00:00:00+00:00"
    )
    bundle_dict = bundle.to_dict()
    case = seal_case_file(
        bundle_dict, deterministic=True, fixed_timestamp="1970-01-01T00:00:00+00:00"
    )
    # Override trust_map overall to "strong" for test
    case["forensic_bundle"]["trust_map"]["overall"] = "strong"
    for dim in case["forensic_bundle"]["trust_map"]["dimensions"]:
        if dim["dimension"] == "language":
            dim["state"] = "supported"
    return case


VALID_CASE_FILE = _generate_valid_case_file()

# Compute a valid seal for the test case file
VALID_CASE_FILE["case_sha256"] = _hash_without_seal(VALID_CASE_FILE)

SAMPLE_OBSERVATIONS = [
    {
        "sample_id": "probe-1",
        "detector_id": "baseline_detector",
        "detector_version": "1.0.0",
        "detector_family": "stylometric",
        "execution": "local",
        "verdict": "human_like",
        "score": 0.3,
        "score_semantics": "ai_probability",
        "threshold": 0.5,
        "supported_languages": ["en"],
        "min_words": 50,
    },
    {
        "sample_id": "probe-2",
        "detector_id": "baseline_detector",
        "detector_version": "1.0.0",
        "detector_family": "stylometric",
        "execution": "local",
        "verdict": "ai_like",
        "score": 0.85,
        "score_semantics": "ai_probability",
        "threshold": 0.5,
        "supported_languages": ["en"],
        "min_words": 50,
    },
]


class TestCapabilityRegister(unittest.TestCase):
    def test_validated_claim_with_executed_evidence(self):
        result = capability_register(
            {
                "detector_id": "det_a",
                "capability": "language_coverage.en",
                "tier": "validated",
                "evidence": [
                    {
                        "label": "executed",
                        "tier": "validated",
                        "artifact": "bench_run/2026-01-01",
                        "detail": "AUROC=0.95",
                    },
                ],
                "valid_until": "2027-01-01",
            }
        )
        self.assertTrue(result["success"])
        self.assertEqual(result["exit_code"], constants.EXIT_OK)
        self.assertEqual(len(result["issues"]), 0)
        self.assertEqual(result["claim"]["tier"], "validated")

    def test_readable_claim_no_evidence(self):
        result = capability_register(
            {
                "detector_id": "det_b",
                "capability": "language_coverage.fr",
                "tier": "readable",
            }
        )
        self.assertTrue(result["success"])
        self.assertEqual(result["exit_code"], constants.EXIT_INCOMPLETE)
        self.assertGreater(len(result["issues"]), 0)

    def test_validated_without_executed_evidence(self):
        result = capability_register(
            {
                "detector_id": "det_c",
                "capability": "length_robustness.medium",
                "tier": "validated",
                "evidence": [
                    {"label": "reported", "tier": "tool_backed", "artifact": "paper-123"},
                ],
            }
        )
        self.assertTrue(result["success"])
        self.assertEqual(result["exit_code"], constants.EXIT_INCOMPLETE)
        self.assertTrue(any("EXECUTED" in issue for issue in result["issues"]))

    def test_invalid_tier(self):
        result = capability_register(
            {
                "detector_id": "det_d",
                "capability": "x",
                "tier": "not_a_tier",
            }
        )
        self.assertFalse(result["success"])
        self.assertEqual(result["exit_code"], constants.EXIT_ERROR)


class TestCapabilityCheck(unittest.TestCase):
    def _make_ledger(self, tier: str, evidence: list[dict] | None = None) -> dict:
        capability_register(
            {
                "detector_id": "det_a",
                "capability": "language_coverage.en",
                "tier": tier,
                "evidence": evidence or [],
            }
        )
        # Build a ledger dict manually
        return {
            "schema": "textforensics.capability-ledger/v1",
            "claims": {
                "det_a": [
                    {
                        "capability": "language_coverage.en",
                        "tier": tier,
                        "evidence": evidence or [],
                        "valid_until": None,
                    }
                ]
            },
        }

    def test_validated_claim(self):
        ledger = self._make_ledger(
            "validated",
            [
                {"label": "executed", "tier": "validated", "artifact": "run-1"},
            ],
        )
        result = capability_check(
            {
                "ledger": ledger,
                "detector_id": "det_a",
                "capability": "language_coverage.en",
            }
        )
        self.assertTrue(result["success"])
        self.assertTrue(result["is_validated"])
        self.assertEqual(result["tier"], "validated")

    def test_readable_claim(self):
        ledger = self._make_ledger(
            "readable",
            [
                {"label": "reported", "tier": "readable", "artifact": "paper"},
            ],
        )
        result = capability_check(
            {
                "ledger": ledger,
                "detector_id": "det_a",
                "capability": "language_coverage.en",
            }
        )
        self.assertTrue(result["success"])
        self.assertFalse(result["is_validated"])
        self.assertEqual(result["exit_code"], constants.EXIT_DOWNGRADED)

    def test_missing_capability(self):
        ledger = self._make_ledger("validated", [])
        result = capability_check(
            {
                "ledger": ledger,
                "detector_id": "det_a",
                "capability": "language_coverage.fr",
            }
        )
        self.assertTrue(result["success"])
        self.assertFalse(result["is_validated"])
        self.assertEqual(result["reason"], "no claim registered")

    def test_invalid_ledger(self):
        result = capability_check(
            {
                "ledger": "not a dict",
                "detector_id": "det_a",
                "capability": "x",
            }
        )
        self.assertFalse(result["success"])


class TestCapabilityList(unittest.TestCase):
    def test_list_all(self):
        ledger = {
            "schema": "textforensics.capability-ledger/v1",
            "claims": {
                "det_a": [
                    {
                        "capability": "lang.en",
                        "tier": "validated",
                        "evidence": [],
                        "valid_until": None,
                    },
                ],
                "det_b": [
                    {
                        "capability": "lang.fr",
                        "tier": "readable",
                        "evidence": [],
                        "valid_until": None,
                    },
                ],
            },
        }
        result = capability_list({"ledger": ledger})
        self.assertTrue(result["success"])
        self.assertIn("det_a", result["claims"])
        self.assertIn("det_b", result["claims"])

    def test_filter_by_detector(self):
        ledger = {
            "schema": "textforensics.capability-ledger/v1",
            "claims": {
                "det_a": [
                    {
                        "capability": "lang.en",
                        "tier": "validated",
                        "evidence": [],
                        "valid_until": None,
                    },
                ],
                "det_b": [
                    {
                        "capability": "lang.fr",
                        "tier": "readable",
                        "evidence": [],
                        "valid_until": None,
                    },
                ],
            },
        }
        result = capability_list({"ledger": ledger, "detector_id": "det_a"})
        self.assertTrue(result["success"])
        self.assertIn("det_a", result["claims"])
        self.assertNotIn("det_b", result["claims"])


class TestVerifyCaseFile(unittest.TestCase):
    def test_valid_case_file(self):
        result = verify_case_file({"case_file": VALID_CASE_FILE})
        self.assertTrue(result["success"])
        # The nversion replay re-derives trust map as insufficient due to no registry,
        # but the casefile verification (seal, schema, manifest) should pass.
        self.assertTrue(result["casefile_verify"]["valid"])
        self.assertTrue(result["nversion_replay"]["seal_verified"])

    def test_missing_case_file_key(self):
        result = verify_case_file({})
        self.assertFalse(result["success"])
        self.assertEqual(result["exit_code"], constants.EXIT_ERROR)

    def test_non_dict_case_file(self):
        result = verify_case_file({"case_file": "not a dict"})
        self.assertFalse(result["success"])
        self.assertEqual(result["exit_code"], constants.EXIT_ERROR)


class TestDriftSnapshot(unittest.TestCase):
    def test_valid_snapshot(self):
        result = drift_snapshot(
            {
                "corpus": SAMPLE_CORPUS,
                "observations": SAMPLE_OBSERVATIONS,
                "label": "v1",
            }
        )
        self.assertTrue(result["success"])
        self.assertIn("snapshot", result)
        self.assertEqual(result["snapshot"]["label"], "v1")

    def test_missing_corpus(self):
        result = drift_snapshot({"observations": SAMPLE_OBSERVATIONS})
        self.assertFalse(result["success"])
        self.assertEqual(result["exit_code"], constants.EXIT_ERROR)

    def test_invalid_observation(self):
        result = drift_snapshot(
            {
                "corpus": SAMPLE_CORPUS,
                "observations": [{"sample_id": "nonexistent"}],
            }
        )
        self.assertFalse(result["success"])
        self.assertEqual(result["exit_code"], constants.EXIT_ERROR)


class TestDriftCompare(unittest.TestCase):
    def _make_snapshots(self) -> tuple[dict, dict]:
        obs1 = list(SAMPLE_OBSERVATIONS)
        obs2 = [{**o, "score": o["score"] + 0.05} for o in SAMPLE_OBSERVATIONS]
        snap1 = drift_snapshot(
            {
                "corpus": SAMPLE_CORPUS,
                "observations": obs1,
                "label": "baseline",
            }
        )["snapshot"]
        snap2 = drift_snapshot(
            {
                "corpus": SAMPLE_CORPUS,
                "observations": obs2,
                "label": "current",
            }
        )["snapshot"]
        return snap1, snap2

    def test_compare_two_snapshots(self):
        snap1, snap2 = self._make_snapshots()
        result = drift_compare(
            {
                "corpus": SAMPLE_CORPUS,
                "baseline": snap1,
                "current": snap2,
            }
        )
        self.assertTrue(result["success"])
        self.assertIn("report", result)
        self.assertIn("detectors", result["report"])

    def test_missing_params(self):
        result = drift_compare({})
        self.assertFalse(result["success"])
        self.assertEqual(result["exit_code"], constants.EXIT_ERROR)


class TestDriftReport(unittest.TestCase):
    def test_report_from_three_snapshots(self):
        obs1 = list(SAMPLE_OBSERVATIONS)
        obs2 = [{**o, "score": o["score"] + 0.01} for o in SAMPLE_OBSERVATIONS]
        obs3 = [{**o, "score": o["score"] + 0.03} for o in SAMPLE_OBSERVATIONS]
        snapshots = []
        for i, obs in enumerate([obs1, obs2, obs3]):
            snap_result = drift_snapshot(
                {
                    "corpus": SAMPLE_CORPUS,
                    "observations": obs,
                    "label": f"v{i + 1}",
                }
            )
            if snap_result["success"]:
                snapshots.append(snap_result["snapshot"])

        result = drift_report(
            {
                "corpus": SAMPLE_CORPUS,
                "snapshots": snapshots,
            }
        )
        self.assertTrue(result["success"])
        self.assertIn("report", result)
        self.assertEqual(result["snapshot_count"], 3)

    def test_too_few_snapshots(self):
        result = drift_report(
            {
                "corpus": SAMPLE_CORPUS,
                "snapshots": [],
            }
        )
        self.assertFalse(result["success"])
        self.assertEqual(result["exit_code"], constants.EXIT_ERROR)


class TestFingerprintDataset(unittest.TestCase):
    def test_missing_params(self):
        result = fingerprint_dataset({})
        self.assertFalse(result["success"])
        self.assertEqual(result["exit_code"], constants.EXIT_ERROR)

    def test_nonexistent_file(self):
        result = fingerprint_dataset(
            {
                "path": "/nonexistent/path.jsonl",
                "name": "fake",
            }
        )
        self.assertFalse(result["success"])
        self.assertEqual(result["exit_code"], constants.EXIT_ERROR)


class TestCheckContamination(unittest.TestCase):
    def test_missing_params(self):
        result = check_contamination({})
        self.assertFalse(result["success"])
        self.assertEqual(result["exit_code"], constants.EXIT_ERROR)

    def test_invalid_fingerprint(self):
        result = check_contamination(
            {
                "dataset1_path": "a.jsonl",
                "fingerprint1": "not a dict",
                "dataset2_path": "b.jsonl",
                "fingerprint2": {},
            }
        )
        self.assertFalse(result["success"])
        self.assertEqual(result["exit_code"], constants.EXIT_ERROR)


if __name__ == "__main__":
    unittest.main()
