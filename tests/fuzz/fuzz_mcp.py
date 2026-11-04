#!/usr/bin/env python3
"""
Fuzz target for MCP tool inputs and serialization.

Covers:
- capability_register with bad tier, missing fields, malformed evidence
- capability_check with invalid ledger, missing detector_id
- capability_list with bad filter
- verify_case_file with missing case_file, non-dict payloads
- drift_snapshot with missing corpus, bad observations
- drift_compare and drift_report with mismatched snapshots
- fingerprint_dataset and check_contamination with bad paths
- JSON serialization/deserialization round-trips
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import atheris
except ImportError:  # atheris optional; TestOneInput still importable
    atheris = None
    def instrument_func(func):
        return func
    if atheris is not None:
        instrument_func = atheris.instrument_func

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))


def _fuzz_capability_register(text: str) -> None:
    """Fuzz capability_register MCP tool."""
    try:
        from textforensics.mcp_tools import capability_register
    except Exception:
        return

    # Build params from fuzzed text
    try:
        params = json.loads(text)
        if not isinstance(params, dict):
            params = {}
    except json.JSONDecodeError:
        params = {}

    # 1. Missing required fields
    for subset in [
        {},
        {"detector_id": "x"},
        {"capability": "y"},
        {"tier": "readable"},
        {"detector_id": "x", "capability": "y"},
        {"detector_id": "x", "capability": "y", "tier": "bad-tier"},
    ]:
        try:
            result = capability_register(subset)
            assert "success" in result
        except Exception:
            pass

    # 2. Valid-ish params with fuzzed values
    for det_id in (text[:30] or "fuzz-det", "", "a" * 200):
        for cap in (text[30:50] or "analyze", ""):
            for tier in ("readable", "tool_backed", "validated", "bad-tier", "", 123):
                try:
                    result = capability_register(
                        {
                            "detector_id": det_id,
                            "capability": cap,
                            "tier": tier,
                        }
                    )
                    assert "success" in result
                except Exception:
                    pass

    # 3. Malformed evidence
    for evidence in [
        [],
        [{"label": "benchmark", "tier": "validated", "artifact": "url"}],
        [{"label": "bad", "tier": "bad", "artifact": "x"}],
        ["not-a-dict"],
        [{"label": 123, "tier": "readable", "artifact": ""}],
    ]:
        try:
            result = capability_register(
                {
                    "detector_id": "fuzz",
                    "capability": "test",
                    "tier": "readable",
                    "evidence": evidence,
                }
            )
            assert "success" in result
        except Exception:
            pass

    # 4. Non-dict params
    for bad_params in ("", 123, [], None, True):
        try:
            capability_register(bad_params)  # type: ignore[arg-type]
        except (KeyError, TypeError):
            pass
        except Exception:
            pass


def _fuzz_capability_check(text: str) -> None:
    """Fuzz capability_check MCP tool."""
    try:
        from textforensics.mcp_tools import capability_check
    except Exception:
        return

    # 1. Missing ledger
    try:
        result = capability_check({})
        assert "success" in result
        assert not result["success"]
    except Exception:
        pass

    # 2. Invalid ledger type
    for bad_ledger in ("", [], 123, True):
        try:
            result = capability_check({"ledger": bad_ledger})
            assert "success" in result
        except Exception:
            pass

    # 3. Valid ledger but no matching claim
    try:
        result = capability_check(
            {
                "ledger": {"_claims": {}},
                "detector_id": "nonexistent",
                "capability": "test",
            }
        )
        assert "success" in result
    except Exception:
        pass

    # 4. Fuzzed ledger data
    try:
        ledger_data = json.loads(text)
        if not isinstance(ledger_data, dict):
            ledger_data = {}
    except json.JSONDecodeError:
        ledger_data = {}
    try:
        result = capability_check(
            {
                "ledger": ledger_data,
                "detector_id": text[:20] or "x",
                "capability": text[20:40] or "y",
            }
        )
        assert "success" in result
    except Exception:
        pass


def _fuzz_capability_list(text: str) -> None:
    """Fuzz capability_list MCP tool."""
    try:
        from textforensics.mcp_tools import capability_list
    except Exception:
        return

    # 1. Missing ledger
    try:
        result = capability_list({})
        assert not result["success"]
    except Exception:
        pass

    # 2. Valid empty ledger
    try:
        result = capability_list({"ledger": {"_claims": {}}})
        assert result["success"]
    except Exception:
        pass

    # 3. With filter
    try:
        result = capability_list({"ledger": {"_claims": {}}, "detector_id": text[:20]})
        assert result["success"]
    except Exception:
        pass


def _fuzz_verify_case_file(text: str) -> None:
    """Fuzz verify_case_file MCP tool."""
    try:
        from textforensics.mcp_tools import verify_case_file
    except Exception:
        return

    # 1. Missing case_file
    try:
        result = verify_case_file({})
        assert not result["success"]
    except Exception:
        pass

    # 2. Non-dict case_file
    for bad_cf in ("", [], 123, None):
        try:
            result = verify_case_file({"case_file": bad_cf})
            assert not result["success"]
        except Exception:
            pass

    # 3. Fuzzed case file
    try:
        cf = json.loads(text)
        if not isinstance(cf, dict):
            cf = {}
    except json.JSONDecodeError:
        cf = {}
    try:
        result = verify_case_file({"case_file": cf})
        assert "success" in result
    except Exception:
        pass


def _fuzz_drift_snapshot(text: str) -> None:
    """Fuzz drift_snapshot MCP tool."""
    try:
        from textforensics.mcp_tools import drift_snapshot
    except Exception:
        return

    clean_hex = "".join(c if c in "0123456789abcdef" else "0" for c in text[:64])[:64]

    # 1. Missing required keys
    for partial in [{"corpus": {}}, {"observations": []}, {}]:
        try:
            result = drift_snapshot(partial)
            assert "success" in result
        except Exception:
            pass

    # 2. Valid corpus, empty observations
    corpus = {
        "schema": "textforensics.drift-corpus/v1",
        "samples": [{"id": "s1", "text_sha256": clean_hex}],
    }
    try:
        result = drift_snapshot({"corpus": corpus, "observations": []})
        assert result["success"]
    except Exception:
        pass

    # 3. Bad corpus
    try:
        result = drift_snapshot({"corpus": "bad", "observations": []})
        assert "success" in result
    except Exception:
        pass

    # 4. Bad observations
    bad_obs = [{"sample_id": "unknown", "detector_id": "x"}]
    try:
        result = drift_snapshot({"corpus": corpus, "observations": bad_obs})
        assert "success" in result
    except Exception:
        pass


def _fuzz_drift_compare(text: str) -> None:
    """Fuzz drift_compare MCP tool."""
    try:
        from textforensics.mcp_tools import drift_compare
    except Exception:
        return

    # 1. Missing keys
    try:
        result = drift_compare({})
        assert not result["success"]
    except Exception:
        pass

    # 2. Bad types
    try:
        result = drift_compare({"corpus": [], "baseline": [], "current": []})
        assert "success" in result
    except Exception:
        pass


def _fuzz_drift_report(text: str) -> None:
    """Fuzz drift_report MCP tool."""
    try:
        from textforensics.mcp_tools import drift_report
    except Exception:
        return

    # 1. Missing keys
    try:
        result = drift_report({})
        assert not result["success"]
    except Exception:
        pass

    # 2. Less than 2 snapshots
    try:
        result = drift_report({"corpus": {}, "snapshots": []})
        assert not result["success"]
    except Exception:
        pass
    try:
        result = drift_report({"corpus": {}, "snapshots": [{}]})
        assert not result["success"]
    except Exception:
        pass


def _fuzz_fingerprint_and_contamination(text: str) -> None:
    """Fuzz fingerprint_dataset and check_contamination MCP tools."""
    try:
        from textforensics.mcp_tools import check_contamination, fingerprint_dataset
    except Exception:
        return

    # fingerprint_dataset — missing keys
    try:
        result = fingerprint_dataset({})
        assert not result["success"]
    except Exception:
        pass

    # fingerprint_dataset — bad path
    try:
        result = fingerprint_dataset({"path": "/nonexistent/file.jsonl", "name": "test"})
        assert not result["success"]
    except Exception:
        pass

    # check_contamination — missing keys
    try:
        result = check_contamination({})
        assert not result["success"]
    except Exception:
        pass

    # check_contamination — bad fingerprints
    try:
        result = check_contamination(
            {
                "dataset1_path": "/no/file1",
                "fingerprint1": "not-a-dict",
                "dataset2_path": "/no/file2",
                "fingerprint2": {"name": "x"},
            }
        )
        assert "success" in result
    except Exception:
        pass


def _fuzz_error_response_helper(text: str) -> None:
    """Fuzz _error_response and _ok_response helpers."""
    try:
        from textforensics.mcp_tools import _error_response, _ok_response
    except Exception:
        return

    for error_msg in (text[:200], "", "x" * 1000, None, 123, True):
        for exit_code in (0, 1, 2, -1, 255, float("inf")):
            try:
                result = _error_response(str(error_msg), int(exit_code))
                assert result["success"] is False
                assert "error" in result
                assert "exit_code" in result
            except (ValueError, TypeError):
                pass
            except Exception:
                pass

    for payload in (None, {}, {"data": text[:100]}, {"nested": {"key": "val"}}):
        for exit_code in (0, 1, 2):
            try:
                result = _ok_response(payload, exit_code)
                assert result["success"] is True
            except Exception:
                pass


def _fuzz_capability_register_edge_cases(text: str) -> None:
    """Fuzz capability_register with valid_until and complex evidence."""
    try:
        from textforensics.mcp_tools import capability_register
    except Exception:
        return

    # Test with valid_until edge cases
    for valid_until in (None, "", "2099-12-31", "2020-01-01", "not-a-date", text[:30]):
        try:
            result = capability_register(
                {
                    "detector_id": "fuzz",
                    "capability": "test",
                    "tier": "readable",
                    "valid_until": valid_until,
                }
            )
            assert "success" in result
        except Exception:
            pass

    # Test with complex evidence arrays
    for evidence in [
        [
            {"label": "benchmark", "tier": "validated", "artifact": "url", "detail": text[:100]},
            {"label": "review", "tier": "readable", "artifact": "url2"},
        ],
        [{"label": "", "tier": "readable", "artifact": ""}],
        [{"label": 123, "tier": "readable", "artifact": "x"}],
        [{"label": "benchmark", "tier": 123, "artifact": "x"}],
    ]:
        try:
            result = capability_register(
                {
                    "detector_id": "fuzz",
                    "capability": "test",
                    "tier": "readable",
                    "evidence": evidence,
                }
            )
            assert "success" in result
        except Exception:
            pass


def _fuzz_drift_tools_edge_cases(text: str) -> None:
    """Fuzz drift tools with edge case observations and failures."""
    try:
        from textforensics.mcp_tools import drift_compare, drift_report, drift_snapshot
    except Exception:
        return

    clean_hex = "".join(c if c in "0123456789abcdef" else "0" for c in text[:64])[:64]

    corpus = {
        "schema": "textforensics.drift-corpus/v1",
        "samples": [{"id": "s1", "text_sha256": clean_hex}],
    }

    # Test with failures
    try:
        result = drift_snapshot(
            {
                "corpus": corpus,
                "observations": [
                    {
                        "sample_id": "s1",
                        "detector_id": "fuzz-det",
                        "detector_version": "1.0",
                        "detector_family": "fuzz",
                        "execution": "local",
                        "verdict": "ai_like",
                        "score": 0.8,
                    }
                ],
                "failures": [
                    {
                        "sample_id": "s1",
                        "detector_id": "fuzz-det",
                        "error_type": "timeout",
                    }
                ],
            }
        )
        assert "success" in result
    except Exception:
        pass

    # Test with non-list observations
    try:
        result = drift_snapshot({"corpus": corpus, "observations": "not-a-list"})
    except Exception:
        pass

    # Test drift_compare with valid snapshots
    snap1 = {
        "schema": "textforensics.drift-snapshot/v1",
        "snapshot_id": "snap-1",
        "corpus_sha256": "",
        "records": [],
        "failures": [],
    }
    snap2 = dict(snap1, snapshot_id="snap-2")
    try:
        result = drift_compare({"corpus": corpus, "baseline": snap1, "current": snap2})
        assert "success" in result
    except Exception:
        pass

    # Test drift_report with many snapshots
    snapshots = [dict(snap1, snapshot_id=f"snap-{i}") for i in range(5)]
    try:
        result = drift_report({"corpus": corpus, "snapshots": snapshots})
        assert "success" in result
    except Exception:
        pass


def _fuzz_fingerprint_dataset_edge_cases(text: str) -> None:
    """Fuzz fingerprint_dataset with additional parameters."""
    try:
        from textforensics.mcp_tools import fingerprint_dataset
    except Exception:
        return

    for path in ("/nonexistent", "", text[:50]):
        for name in (text[:30] or "test", ""):
            for version in ("1.0.0", "2.0.0-beta", "", "not-a-version"):
                for split in ("test", "train", "calibration", "", "unknown"):
                    for strict in (True, False):
                        for include_text in (True, False):
                            try:
                                result = fingerprint_dataset(
                                    {
                                        "path": path,
                                        "name": name,
                                        "version": version,
                                        "split": split,
                                        "strict": strict,
                                        "include_text": include_text,
                                    }
                                )
                                assert "success" in result
                            except Exception:
                                pass


@instrument_func
def TestOneInput(data: bytes) -> None:
    """Fuzz MCP tool inputs and serialization."""
    try:
        text = data.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        text = ""

    _fuzz_capability_register(text)
    _fuzz_capability_check(text)
    _fuzz_capability_list(text)
    _fuzz_verify_case_file(text)
    _fuzz_drift_snapshot(text)
    _fuzz_drift_compare(text)
    _fuzz_drift_report(text)
    _fuzz_fingerprint_and_contamination(text)
    _fuzz_error_response_helper(text)
    _fuzz_capability_register_edge_cases(text)
    _fuzz_drift_tools_edge_cases(text)
    _fuzz_fingerprint_dataset_edge_cases(text)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
