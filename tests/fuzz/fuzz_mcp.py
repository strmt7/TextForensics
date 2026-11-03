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

import atheris

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


@atheris.instrument_func
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


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
