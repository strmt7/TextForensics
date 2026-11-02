"""Standalone MCP tool implementations for TextForensics.

Each function accepts a JSON-serialisable dict and returns a JSON-serialisable
dict.  They are deliberately independent of the MCP runtime so they can be
unit-tested in isolation.
"""

from __future__ import annotations

import json
from typing import Any

from . import constants
from .benchmark_fingerprint import (
    DatasetFingerprint,
    check_disjointness,
    fingerprint_dataset as _fingerprint_dataset,
    load_fingerprint,
    save_fingerprint,
    verify_fingerprint,
)
from .capability_ledger import (
    CapabilityClaim,
    CapabilityLedger,
    EvidenceLabel,
    EvidenceRef,
    EvidenceTier,
    validate_claim,
)
from .casefile import verify_case_file as casefile_verify
from .drift import DriftObservatory
from .verify import verify_case_file as nversion_verify


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _error_response(error: str, exit_code: int) -> dict[str, Any]:
    return {
        "success": False,
        "error": error,
        "exit_code": exit_code,
    }


def _ok_response(payload: dict[str, Any] | None = None, exit_code: int = constants.EXIT_OK) -> dict[str, Any]:
    result = {"success": True, "exit_code": exit_code}
    if payload:
        result.update(payload)
    return result


# ---------------------------------------------------------------------------
# Capability Ledger tools
# ---------------------------------------------------------------------------

def capability_register(params: dict[str, Any]) -> dict[str, Any]:
    """Register a capability claim.

    Expected input keys:
        detector_id (str)
        capability (str)
        tier (str): one of "readable", "tool_backed", "validated"
        evidence (list[dict], optional): each with label, tier, artifact, detail?
        valid_until (str, optional): ISO date
    """
    try:
        detector_id = params["detector_id"]
        capability = params["capability"]
        tier = EvidenceTier(params["tier"])
    except (KeyError, ValueError, TypeError) as exc:
        return _error_response(f"Invalid input: {exc}", constants.EXIT_ERROR)

    # Build evidence list
    evidence = []
    for e in params.get("evidence", []):
        try:
            evidence.append(EvidenceRef(
                label=EvidenceLabel(e["label"]),
                tier=EvidenceTier(e["tier"]),
                artifact=e["artifact"],
                detail=e.get("detail"),
            ))
        except (KeyError, ValueError, TypeError) as exc:
            return _error_response(f"Invalid evidence entry: {exc}", constants.EXIT_ERROR)

    claim = CapabilityClaim(
        detector_id=detector_id,
        capability=capability,
        tier=tier,
        evidence=evidence,
        valid_until=params.get("valid_until"),
    )

    issues = validate_claim(claim)
    response: dict[str, Any] = {
        "success": True,
        "claim": {
            "detector_id": claim.detector_id,
            "capability": claim.capability,
            "tier": claim.tier.value,
            "evidence": [
                {"label": e.label.value, "tier": e.tier.value, "artifact": e.artifact, "detail": e.detail}
                for e in claim.evidence
            ],
            "valid_until": claim.valid_until,
        },
        "issues": issues,
    }

    if issues:
        response["exit_code"] = constants.EXIT_INCOMPLETE
    else:
        response["exit_code"] = constants.EXIT_OK

    return response


def capability_check(params: dict[str, Any]) -> dict[str, Any]:
    """Check if a capability is validated in a ledger.

    Expected input keys:
        ledger (dict): serialized ledger from capability_register/to_dict
        detector_id (str)
        capability (str)
    """
    ledger_data = params.get("ledger")
    if not isinstance(ledger_data, dict):
        return _error_response("ledger must be a dict", constants.EXIT_ERROR)

    try:
        ledger = CapabilityLedger.from_dict(ledger_data)
    except (ValueError, TypeError) as exc:
        return _error_response(f"Invalid ledger: {exc}", constants.EXIT_ERROR)

    detector_id = params.get("detector_id", "")
    capability = params.get("capability", "")

    claim = ledger.get(detector_id, capability)
    if claim is None:
        return _ok_response({
            "detector_id": detector_id,
            "capability": capability,
            "is_validated": False,
            "tier": None,
            "reason": "no claim registered",
        }, constants.EXIT_DOWNGRADED)

    is_validated = claim.tier == EvidenceTier.VALIDATED
    return _ok_response({
        "detector_id": detector_id,
        "capability": capability,
        "is_validated": is_validated,
        "tier": claim.tier.value,
        "evidence_count": len(claim.evidence),
        "valid_until": claim.valid_until,
    }, constants.EXIT_OK if is_validated else constants.EXIT_DOWNGRADED)


def capability_list(params: dict[str, Any]) -> dict[str, Any]:
    """List all registered capability claims.

    Expected input keys:
        ledger (dict): serialized ledger
        detector_id (str, optional): filter to one detector
    """
    ledger_data = params.get("ledger")
    if not isinstance(ledger_data, dict):
        return _error_response("ledger must be a dict", constants.EXIT_ERROR)

    try:
        ledger = CapabilityLedger.from_dict(ledger_data)
    except (ValueError, TypeError) as exc:
        return _error_response(f"Invalid ledger: {exc}", constants.EXIT_ERROR)

    detector_filter = params.get("detector_id")

    result = {}
    for det_id, claims in ledger._claims.items():
        if detector_filter and det_id != detector_filter:
            continue
        result[det_id] = [
            {
                "capability": c.capability,
                "tier": c.tier.value,
                "evidence_count": len(c.evidence),
                "valid_until": c.valid_until,
            }
            for c in claims
        ]

    return _ok_response({"claims": result})


# ---------------------------------------------------------------------------
# Verify tool
# ---------------------------------------------------------------------------

def verify_case_file(params: dict[str, Any]) -> dict[str, Any]:
    """Run N-version integrity replay on a case file.

    Expected input keys:
        case_file (dict): parsed case file JSON object
    """
    try:
        case_payload = params["case_file"]
    except (KeyError, TypeError):
        return _error_response("Missing required key: case_file", constants.EXIT_ERROR)

    if not isinstance(case_payload, dict):
        return _error_response("case_file must be a JSON object", constants.EXIT_ERROR)

    # Run both verification paths
    nversion_result = nversion_verify(case_payload)
    casefile_result = casefile_verify(case_payload)

    # Aggregate
    all_errors = list(nversion_result.get("errors", []))
    all_errors.extend(casefile_result.get("errors", []))
    overall_valid = nversion_result.get("valid", False) and casefile_result.get("valid", False)

    return {
        "success": True,
        "exit_code": constants.EXIT_OK if overall_valid else constants.EXIT_DOWNGRADED,
        "overall_valid": overall_valid,
        "nversion_replay": nversion_result,
        "casefile_verify": casefile_result,
        "errors": all_errors,
    }


# ---------------------------------------------------------------------------
# Drift tools
# ---------------------------------------------------------------------------

def drift_snapshot(params: dict[str, Any]) -> dict[str, Any]:
    """Take a detector drift snapshot from observations.

    Expected input keys:
        corpus (list[dict] or dict): drift corpus with samples
        observations (list[dict]): normalised observations
        failures (list[dict], optional)
        taken_at (str, optional): ISO timestamp
        snapshot_id (str, optional)
        label (str, optional)
        detector_ids (list[str], optional)
    """
    try:
        corpus = params["corpus"]
        observations = params["observations"]
    except (KeyError, TypeError):
        return _error_response("Missing required keys: corpus and observations", constants.EXIT_ERROR)

    try:
        observatory = DriftObservatory(corpus=corpus)
    except (ValueError, TypeError) as exc:
        return _error_response(f"Invalid corpus: {exc}", constants.EXIT_ERROR)

    try:
        snapshot = observatory.snapshot_from_observations(
            observations,
            failures=params.get("failures") or [],
            taken_at=params.get("taken_at"),
            snapshot_id=params.get("snapshot_id"),
            label=params.get("label"),
            detector_ids=params.get("detector_ids"),
        )
    except (ValueError, TypeError) as exc:
        return _error_response(f"Snapshot error: {exc}", constants.EXIT_ERROR)

    return _ok_response({"snapshot": snapshot})


def drift_compare(params: dict[str, Any]) -> dict[str, Any]:
    """Compare two drift snapshots.

    Expected input keys:
        corpus (list[dict] or dict): drift corpus with samples
        baseline (dict): baseline snapshot
        current (dict): current snapshot
    """
    try:
        corpus = params["corpus"]
        baseline = params["baseline"]
        current = params["current"]
    except (KeyError, TypeError):
        return _error_response(
            "Missing required keys: corpus, baseline and current", constants.EXIT_ERROR
        )

    try:
        observatory = DriftObservatory(corpus=corpus)
    except (ValueError, TypeError) as exc:
        return _error_response(f"Invalid corpus: {exc}", constants.EXIT_ERROR)

    try:
        report = observatory.compare_snapshots(baseline, current)
    except (ValueError, TypeError) as exc:
        return _error_response(f"Comparison error: {exc}", constants.EXIT_ERROR)

    overall = report.get("overall", {})
    has_drift = overall.get("status") == "drift_detected"
    return _ok_response(
        {"report": report},
        constants.EXIT_DOWNGRADED if has_drift else constants.EXIT_OK,
    )


def drift_report(params: dict[str, Any]) -> dict[str, Any]:
    """Generate a drift report from stored snapshots.

    Expected input keys:
        corpus (list[dict] or dict): drift corpus with samples
        snapshots (list[dict]): stored snapshots in order
    """
    try:
        corpus = params["corpus"]
        snapshots = params["snapshots"]
    except (KeyError, TypeError):
        return _error_response("Missing required keys: corpus and snapshots", constants.EXIT_ERROR)

    if not isinstance(snapshots, list) or len(snapshots) < 2:
        return _error_response(
            "At least two snapshots are required for a drift report", constants.EXIT_ERROR
        )

    try:
        observatory = DriftObservatory(corpus=corpus)
    except (ValueError, TypeError) as exc:
        return _error_response(f"Invalid corpus: {exc}", constants.EXIT_ERROR)

    # Load all snapshots into the observatory
    for snap in snapshots:
        try:
            observatory.add_snapshot(snap)
        except (ValueError, TypeError) as exc:
            return _error_response(f"Failed to load snapshot: {exc}", constants.EXIT_ERROR)

    # Compare first (baseline) and last (current)
    try:
        report = observatory.compare_snapshots(snapshots[0], snapshots[-1])
    except (ValueError, TypeError) as exc:
        return _error_response(f"Comparison error: {exc}", constants.EXIT_ERROR)

    overall = report.get("overall", {})
    has_drift = overall.get("status") == "drift_detected"

    return _ok_response({
        "report": report,
        "snapshot_count": len(snapshots),
        "baseline_snapshot_id": snapshots[0].get("snapshot_id"),
        "current_snapshot_id": snapshots[-1].get("snapshot_id"),
    }, constants.EXIT_DOWNGRADED if has_drift else constants.EXIT_OK)


# ---------------------------------------------------------------------------
# Benchmark fingerprint tools
# ---------------------------------------------------------------------------

def fingerprint_dataset(params: dict[str, Any]) -> dict[str, Any]:
    """Create a dataset fingerprint.

    Expected input keys:
        path (str): path to the JSONL dataset file
        name (str): dataset identifier
        version (str, optional): dataset version
        split (str, optional): split type
        filters (dict, optional): applied filters
        strict (bool, optional): fail on invalid JSON
        include_text (bool, optional): include text in sample hashes
    """
    try:
        path = params["path"]
        name = params["name"]
    except (KeyError, TypeError):
        return _error_response("Missing required keys: path and name", constants.EXIT_ERROR)

    try:
        fp = _fingerprint_dataset(
            path=path,
            name=name,
            version=params.get("version", "1.0.0"),
            split=params.get("split", "test"),
            filters=params.get("filters"),
            strict=params.get("strict", True),
            include_text=params.get("include_text", False),
        )
    except (FileNotFoundError, ValueError, TypeError, OSError) as exc:
        return _error_response(f"Fingerprint error: {exc}", constants.EXIT_ERROR)

    return _ok_response({"fingerprint": fp.to_dict()})


def check_contamination(params: dict[str, Any]) -> dict[str, Any]:
    """Check for benchmark contamination between two datasets.

    Expected input keys:
        dataset1_path (str): path to first JSONL dataset
        fingerprint1 (dict): fingerprint dict for dataset 1
        dataset2_path (str): path to second JSONL dataset
        fingerprint2 (dict): fingerprint dict for dataset 2
        strict (bool, optional): strict JSON parsing
    """
    try:
        path1 = params["dataset1_path"]
        fp1_data = params["fingerprint1"]
        path2 = params["dataset2_path"]
        fp2_data = params["fingerprint2"]
    except (KeyError, TypeError):
        return _error_response(
            "Missing required keys: dataset1_path, fingerprint1, dataset2_path, fingerprint2",
            constants.EXIT_ERROR,
        )

    if not isinstance(fp1_data, dict) or not isinstance(fp2_data, dict):
        return _error_response("fingerprints must be dicts", constants.EXIT_ERROR)

    try:
        fp1 = DatasetFingerprint.from_dict(fp1_data)
        fp2 = DatasetFingerprint.from_dict(fp2_data)
    except (ValueError, TypeError) as exc:
        return _error_response(f"Invalid fingerprint: {exc}", constants.EXIT_ERROR)

    try:
        result = check_disjointness(
            path1, fp1, path2, fp2,
            strict=params.get("strict", True),
        )
    except (FileNotFoundError, ValueError, TypeError, OSError) as exc:
        return _error_response(f"Contamination check error: {exc}", constants.EXIT_ERROR)

    is_contaminated = not result["disjoint"]
    return _ok_response(
        {"contamination_check": result},
        constants.EXIT_DOWNGRADED if is_contaminated else constants.EXIT_OK,
    )
