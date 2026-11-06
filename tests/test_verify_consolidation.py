"""Wave (d) consolidation tests: one verifier entry point, one bundle format.

Covers the combined case-file verifier (N-version replay AND
primary-path seal check), the ``_recompute_overall`` agreement fixes,
and the codec speaking the one current (v2) bundle format.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import sys
import warnings
from io import StringIO

import pytest

from textforensics.casefile import seal_case_file
from textforensics.constants import EXIT_INCOMPLETE, EXIT_OK
from textforensics.report import build_forensic_bundle
from textforensics.trust import TRUST_DIMENSIONS
from textforensics.verify import (
    _recompute_overall,
    verify_all,
    verify_case_file_combined,
    verify_case_file_path_combined,
)

TEXT = (
    "I tested the device twice yesterday and wrote down what changed. "
    "The second run was warmer, so I plan to repeat it before drawing conclusions."
)


def _sealed_case():
    return seal_case_file(build_forensic_bundle(TEXT).to_dict())


def _reseal(case):
    """Recompute the case seal after tampering (mirrors _hash_without_seal)."""
    resealed = copy.deepcopy(case)
    stripped = copy.deepcopy(resealed)
    stripped.pop("case_sha256", None)
    stripped.pop("created_at_utc", None)
    canonical = json.dumps(
        stripped, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    resealed["case_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return resealed


def _other_overall(current):
    for state in ("strong", "mixed", "insufficient"):
        if state != current:
            return state
    raise AssertionError("unreachable")


class TestCombinedVerifier:
    def test_valid_case_passes_both(self):
        case = _sealed_case()
        result = verify_case_file_combined(case)
        assert result["valid"] is True
        assert result["errors"] == []
        assert result["nversion"]["valid"] is True
        assert result["primary"]["valid"] is True
        assert result["seal_verified"] is True
        assert result["trust_map_verified"] is True

    def test_tampered_trust_map_overall_fails_combined(self):
        # Tamper, then re-seal: the seal check passes but the replay
        # re-derives a different overall — the two verifiers disagree,
        # and the combined entry point reports invalid.
        case = _sealed_case()
        real = case["forensic_bundle"]["trust_map"]["overall"]
        case["forensic_bundle"]["trust_map"]["overall"] = _other_overall(real)
        case = _reseal(case)
        result = verify_case_file_combined(case)
        assert result["valid"] is False
        assert result["primary"]["valid"] is True
        assert result["nversion"]["valid"] is False
        assert any("overall mismatch" in e for e in result["errors"])

    def test_stale_manifest_fails_combined(self):
        # Tamper the manifest, then re-seal: the replay passes but the
        # seal check fails on the manifest — again the combined entry
        # point reports invalid.
        case = _sealed_case()
        assert isinstance(case.get("manifest"), dict)
        case["manifest"]["calibration_ids"] = ["tampered"]
        case = _reseal(case)
        result = verify_case_file_combined(case)
        assert result["valid"] is False
        assert result["nversion"]["valid"] is True
        assert result["primary"]["valid"] is False
        assert any("manifest_mismatch" in e for e in result["errors"])

    def test_nan_score_is_invalid_not_a_crash(self):
        # A non-finite float makes the primary-path check raise
        # (canonical JSON, allow_nan=False); the combined entry point
        # must report invalid, never raise.
        case = _sealed_case()
        case["forensic_bundle"]["detector_results"][0]["score"] = math.nan
        result = verify_case_file_combined(case)
        assert result["valid"] is False
        assert result["primary"]["valid"] is False
        assert any("primary verification failed" in e for e in result["errors"])

    def test_path_variant_never_raises(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        result = verify_case_file_path_combined(bad)
        assert result["valid"] is False
        assert any("invalid JSON" in e for e in result["errors"])

        non_dict = tmp_path / "list.json"
        non_dict.write_text("[1, 2]", encoding="utf-8")
        result = verify_case_file_path_combined(non_dict)
        assert result["valid"] is False
        assert "must be a JSON object" in result["errors"][0]

        good = tmp_path / "good.json"
        good.write_text(json.dumps(_sealed_case()), encoding="utf-8")
        assert verify_case_file_path_combined(good)["valid"] is True

    def test_verify_all_uses_combined(self):
        case = _sealed_case()
        assert verify_all(case_payload=case).overall_valid is True
        case["forensic_bundle"]["trust_map"]["overall"] = _other_overall(
            case["forensic_bundle"]["trust_map"]["overall"]
        )
        case = _reseal(case)
        assert verify_all(case_payload=case).overall_valid is False

    def test_mcp_tool_agrees_with_combined(self):
        from textforensics.mcp_tools import verify_case_file as mcp_verify

        case = _sealed_case()
        assert mcp_verify({"case_file": case})["overall_valid"] is True
        case["forensic_bundle"]["trust_map"]["overall"] = _other_overall(
            case["forensic_bundle"]["trust_map"]["overall"]
        )
        case = _reseal(case)
        assert mcp_verify({"case_file": case})["overall_valid"] is False
        assert (
            mcp_verify({"case_file": case})["overall_valid"]
            == (verify_case_file_combined(case)["valid"])
        )

    def test_top_level_exports(self):
        import textforensics
        from textforensics.verify import verify_case_file as nversion

        assert textforensics.verify_case_file_nversion is nversion
        # Backwards-compatible alias kept.
        assert textforensics.verify_case_file_legacy is nversion
        assert textforensics.verify_case_file_combined is verify_case_file_combined
        assert textforensics.verify_case_file_path_combined is verify_case_file_path_combined


class TestRecomputeOverall:
    def _dims(self, states):
        return [
            {"dimension": name, "state": state, "reason": "test"}
            for name, state in zip(TRUST_DIMENSIONS, states, strict=False)
        ]

    def test_empty_dimensions_is_insufficient_not_strong(self):
        assert _recompute_overall([]) == "insufficient"

    def test_all_supported_is_strong(self):
        assert _recompute_overall(self._dims(["supported"] * 10)) == "strong"

    def test_duplicated_dimension_cannot_stand_in_for_missing_one(self):
        # Nine entries, all supported, but only nine distinct dimensions
        # (one duplicated, one missing) — the primary path says "mixed".
        dims = self._dims(["supported"] * 9)
        dims.append(dict(dims[0]))
        assert _recompute_overall(dims) == "mixed"

    def test_non_dict_dimension_is_skipped_not_a_crash(self):
        dims = self._dims(["supported"] * 10)
        dims.append("junk")
        assert _recompute_overall(dims) == "strong"

    def test_out_of_scope_language_is_insufficient(self):
        dims = self._dims(["supported"] * 10)
        dims[0]["state"] = "out_of_scope"  # language
        assert _recompute_overall(dims) == "insufficient"


class TestCliAgreement:
    def _run_main(self, argv):
        from textforensics.cli import main

        old_argv, old_stdout, old_stderr = sys.argv, sys.stdout, sys.stderr
        try:
            sys.argv = ["textforensics", *argv]
            sys.stdout, sys.stderr = StringIO(), StringIO()
            return main(), sys.stdout.getvalue()
        except SystemExit as exc:
            return exc.code, sys.stdout.getvalue()
        finally:
            sys.argv, sys.stdout, sys.stderr = old_argv, old_stdout, old_stderr

    def test_case_verify_and_verify_agree(self, tmp_path):
        valid = tmp_path / "valid.json"
        valid.write_text(json.dumps(_sealed_case()), encoding="utf-8")
        code, _ = self._run_main(["case", "verify", str(valid)])
        assert code == EXIT_OK
        code, _ = self._run_main(["verify", str(valid)])
        assert code == EXIT_OK

        tampered = _sealed_case()
        tampered["forensic_bundle"]["trust_map"]["overall"] = _other_overall(
            tampered["forensic_bundle"]["trust_map"]["overall"]
        )
        tampered = _reseal(tampered)
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps(tampered), encoding="utf-8")
        # Before wave (d) these disagreed: `case verify` passed (seal
        # only) while `verify` failed (replay). Now both fail.
        code, _ = self._run_main(["case", "verify", str(bad)])
        assert code == EXIT_INCOMPLETE
        code, _ = self._run_main(["verify", str(bad)])
        assert code == EXIT_INCOMPLETE

    def test_case_verify_malformed_file_is_incomplete_not_crash(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        code, _ = self._run_main(["case", "verify", str(bad)])
        assert code == EXIT_INCOMPLETE


class TestCodecOneFormat:
    # Version handling is what's under test here (schema validation of
    # full bundles is covered by test_result_codec.py), so validation
    # is off and the payloads are minimal.
    def test_decode_current_format_is_clean(self):
        from textforensics.result_codec import ResultCodec

        data = {
            "schema": "textforensics.forensic-bundle/v2",
            "content_sha256": "0" * 64,
            "input": {"word_count": 1, "raw_text_included": False},
        }
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            decoded = ResultCodec().decode(json.dumps(data), "forensic-bundle", validate=False)
        assert decoded["schema"] == "textforensics.forensic-bundle/v2"

    def test_decode_legacy_format_keeps_its_label_and_warns(self):
        from textforensics.result_codec import ResultCodec

        data = {
            "schema": "textforensics.forensic-bundle/v1",
            "content_sha256": "0" * 64,
            "input": {"word_count": 1, "raw_text_included": False},
        }
        with pytest.warns(UserWarning, match="No migration path"):
            decoded = ResultCodec().decode(json.dumps(data), "forensic-bundle", validate=False)
        # No silent relabelling: the artifact keeps its true version.
        assert decoded["schema"] == "textforensics.forensic-bundle/v1"

    def test_encode_adds_current_schema(self):
        from textforensics.result_codec import ResultCodec

        encoded = ResultCodec().encode(
            {"content_sha256": "0" * 64}, "forensic-bundle", validate=False
        )
        assert json.loads(encoded)["schema"] == "textforensics.forensic-bundle/v2"

    def test_strict_version_rejects_legacy(self):
        from textforensics.result_codec import (
            CodecConfig,
            ResultCodec,
            VersionMigrationError,
        )

        data = {"schema": "textforensics.forensic-bundle/v1"}
        with pytest.raises(VersionMigrationError):
            ResultCodec(CodecConfig(strict_version=True)).decode(
                json.dumps(data), "forensic-bundle", validate=False
            )
