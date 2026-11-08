"""N-version integrity replay for TextForensics artifacts.

This module re-derives Trust Map states, calibration artifacts, and
benchmark metrics through *independent* code paths from the original
computation. The purpose is to catch corrupted, truncated, or
hand-edited JSON files before they are trusted in any report.

Each verification function is a separate implementation from the
primary path so that a single code-path bug cannot mask a data
corruption.
"""

from __future__ import annotations

import hashlib
import json
import math
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Trust Map re-derivation (independent code path)
# ---------------------------------------------------------------------------

_TRUST_STATES = frozenset({"supported", "partial", "unknown", "out_of_scope"})
# v3 adds the "stale" state: a matching record exists but its effective
# status is stale (detector-version change, revalidation due, demotion).
_TRUST_STATES_V3 = frozenset({"supported", "partial", "unknown", "out_of_scope", "stale"})
_TRUST_MAP_V3_SCHEMA = "textforensics.trust-map/v3"
_TRUST_MAP_V2_SCHEMA = "textforensics.trust-map/v2"
_TRUST_MAP_V1_SCHEMA = "textforensics.trust-map/v1"

# Schemas accepted by the N-version replay.  v2 is primary; v1 is accepted
# for legacy artifacts so that older case files can still be replayed.
# v3 case files (U2) and v3 Trust Maps (U1) are accepted as well: a v3 map
# embedded in a case file must verify, with "stale" as a distinct state.
# v4 case files add the per-observation determinism declaration; they
# verify through the same sections as v3.
_CASE_FILE_SCHEMAS = frozenset(
    {
        "textforensics.case-file/v4",
        "textforensics.case-file/v3",
        "textforensics.case-file/v2",
        "textforensics.case-file/v1",
    }
)
_BUNDLE_SCHEMAS = frozenset(
    {"textforensics.forensic-bundle/v2", "textforensics.forensic-bundle/v1"}
)
_DETECTOR_RESULT_SCHEMAS = frozenset(
    {"textforensics.detector-result/v2", "textforensics.detector-result/v1"}
)
_CALIBRATION_SCHEMAS = frozenset(
    {"textforensics.calibration-artifact/v2", "textforensics.calibration/v1"}
)


def _verify_trust_dimension(dim: dict[str, Any], *, allow_stale: bool = False) -> str:
    """Validate a single Trust Map dimension entry.

    Returns the verification status for this dimension.  ``allow_stale``
    is true only for Trust Map v3, whose state vocabulary adds "stale";
    a v2/v1 map carrying "stale" is rejected here.
    """
    if not isinstance(dim, dict):
        return "error: dimension is not a dict"
    state = dim.get("state")
    allowed = _TRUST_STATES_V3 if allow_stale else _TRUST_STATES
    if state not in allowed:
        return f"error: invalid state {state!r}"
    if not isinstance(dim.get("dimension"), str) or not dim["dimension"]:
        return "error: missing or empty dimension name"
    if not isinstance(dim.get("reason"), str) or not dim["reason"]:
        return "error: missing or empty reason"
    return "ok"


def _recompute_overall(dimensions: list[dict[str, Any]]) -> str | None:
    """Re-derive the Trust Map ``overall`` state from stored dimensions.

    This is an *independent* implementation of the logic in
    ``trust._overall_state``.  It must agree with the primary path for a
    legitimately produced case file; disagreement signals tampering.

    The rules mirror the v2 contract:
    * ``out_of_scope`` on language or text_length, or no supported state at
      all, yields ``insufficient``;
    * four or more ``unknown`` dimensions also yields ``insufficient``;
    * any ``partial`` or ``unknown`` (but fewer than four) yields ``mixed``;
    * otherwise ``strong``.

    Agreement with the primary path is exact, not approximate: dimensions
    are deduplicated by name (a duplicated ``supported`` dimension must
    not stand in for a missing one), ``strong`` requires every declared
    dimension present and supported, and an empty dimension list yields
    ``insufficient`` — never ``strong``.  Only the declared dimension
    names are imported from ``trust`` (data, not logic); the derivation
    itself stays an independent implementation.  Non-dict entries are
    skipped here — they are already reported as errors by
    ``_verify_trust_dimension``.
    """
    from .trust import TRUST_DIMENSIONS

    by_name = {
        dim.get("dimension"): dim.get("state", "") for dim in dimensions if isinstance(dim, dict)
    }
    states = by_name.values()
    supported = sum(state == "supported" for state in states)
    partial = sum(state == "partial" for state in states)
    unknown = sum(state == "unknown" for state in states)

    if by_name.get("language") == "out_of_scope" or by_name.get("text_length") == "out_of_scope":
        return "insufficient"
    if supported == len(TRUST_DIMENSIONS):
        return "strong"
    if supported == 0 and partial == 0:
        return "insufficient"
    if supported == 0 and unknown >= 4:
        return "insufficient"
    return "mixed"


def _recompute_overall_v3(dimensions: list[dict[str, Any]]) -> str | None:
    """Re-derive the Trust Map ``overall`` state for a v3 map.

    This is an *independent* implementation of the logic in
    ``validation._overall_state_v3``: strong iff every dimension is
    supported; insufficient iff language or text_length is
    out_of_scope, or no dimension is supported or partial; else mixed.
    ``stale`` counts as neither supported nor partial.  Dimensions are
    deduplicated by name, as in :func:`_recompute_overall`.
    """
    by_name = {
        dim.get("dimension"): dim.get("state", "") for dim in dimensions if isinstance(dim, dict)
    }
    states = by_name.values()
    supported = sum(state == "supported" for state in states)
    partial = sum(state == "partial" for state in states)

    if by_name.get("language") == "out_of_scope" or by_name.get("text_length") == "out_of_scope":
        return "insufficient"
    if not by_name:
        # Mirrors the v2 independent implementation: an empty dimension
        # list yields insufficient, never strong.
        return "insufficient"
    if supported == len(by_name):
        return "strong"
    if supported == 0 and partial == 0:
        return "insufficient"
    return "mixed"


def verify_case_file(payload: dict[str, Any]) -> dict[str, Any]:
    """Verify a case file's integrity through N-version replay.

    Re-derives Trust Map states, checks structural constraints, and
    re-validates hash seals — all through an independent code path from
    the primary ``casefile.verify_case_file``.

    Parameters
    ----------
    payload:
        The parsed JSON payload of the case file.

    Returns
    -------
    A dict with keys:
        - valid: overall boolean
        - errors: list of error strings (empty when valid)
        - trust_map_verified: True if the Trust Map overall state
          matches the re-derived value
        - seal_verified: True if the case hash seal matches
        - dimensions: per-dimension verification results
    """
    errors: list[str] = []
    info: dict[str, Any] = {}
    dimensions_status: dict[str, str] = {}

    # --- Schema ---
    case_schema = payload.get("schema", "")
    if case_schema not in _CASE_FILE_SCHEMAS:
        errors.append(f"unexpected case schema: {case_schema!r}")

    # --- Raw text policy ---
    if payload.get("raw_text_included") is not False:
        errors.append("raw_text_included must be False")

    # --- Case hash seal (re-computed independently) ---
    bundle = payload.get("forensic_bundle")
    if not isinstance(bundle, dict):
        errors.append("forensic_bundle is not a dict")
        info["seal_verified"] = False
    else:
        # Re-derive the seal hash without the ``case_sha256`` field.  The
        # v2 seal also excludes ``created_at_utc`` so that sealing the same
        # content twice produces the same digest regardless of when it was
        # sealed; the independent replay path must match that exclusion.
        stripped = deepcopy(dict(payload))
        stripped.pop("case_sha256", None)
        stripped.pop("created_at_utc", None)

        def _sanitize_for_json(obj):
            """Replace non-finite floats with string representations for JSON serialization."""
            if isinstance(obj, float):
                if not math.isfinite(obj):
                    return "Infinity" if obj > 0 else "-Infinity" if obj < 0 else "NaN"
                return obj
            elif isinstance(obj, dict):
                return {k: _sanitize_for_json(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [_sanitize_for_json(v) for v in obj]
            return obj

        stripped = _sanitize_for_json(stripped)
        canonical = json.dumps(
            stripped,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        recomputed_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        supplied_hash = payload.get("case_sha256")
        seal_ok = isinstance(supplied_hash, str) and (
            len(supplied_hash) == 64
            and all(c in "0123456789abcdef" for c in supplied_hash)
            and supplied_hash == recomputed_hash
        )
        info["seal_verified"] = seal_ok
        if not seal_ok:
            errors.append("case hash seal mismatch")

    # --- Trust Map replay ---
    trust_map = bundle.get("trust_map") if isinstance(bundle, dict) else None
    dimensions_status = {}
    if isinstance(trust_map, dict):
        tm_schema = trust_map.get("schema")
        if tm_schema not in (_TRUST_MAP_V3_SCHEMA, _TRUST_MAP_V2_SCHEMA, _TRUST_MAP_V1_SCHEMA):
            errors.append(f"trust_map has unexpected schema: {tm_schema!r}")
        is_v3 = tm_schema == _TRUST_MAP_V3_SCHEMA
        dims = trust_map.get("dimensions")
        if not isinstance(dims, list):
            errors.append("trust_map.dimensions is not a list")
        else:
            for dim in dims:
                status = _verify_trust_dimension(dim, allow_stale=is_v3)
                dname = dim.get("dimension", "<unnamed>")
                dimensions_status[dname] = status
                if status != "ok":
                    errors.append(f"trust dimension {dname}: {status}")

            overall_stored = trust_map.get("overall", "")
            overall_derived = _recompute_overall_v3(dims) if is_v3 else _recompute_overall(dims)
            info["trust_map_verified"] = overall_stored == overall_derived
            if overall_stored != overall_derived:
                errors.append(
                    f"trust_map overall mismatch: stored={overall_stored!r} "
                    f"re-derived={overall_derived!r}"
                )
    else:
        info["trust_map_verified"] = False

    # --- Forensic bundle structural checks (independent path) ---
    if isinstance(bundle, dict):
        if bundle.get("schema") not in _BUNDLE_SCHEMAS:
            errors.append("forensic_bundle has unexpected schema")

        content_hash = bundle.get("content_sha256")
        if (
            not isinstance(content_hash, str)
            or len(content_hash) != 64
            or any(c not in "0123456789abcdef" for c in content_hash)
        ):
            errors.append("invalid content_sha256")

        inp = bundle.get("input")
        if not isinstance(inp, dict) or inp.get("raw_text_included") is not False:
            errors.append("input.raw_text_included must be False")

        # --- Detector results sanity ---
        for dr in bundle.get("detector_results", []):
            if isinstance(dr, dict):
                if dr.get("schema") not in _DETECTOR_RESULT_SCHEMAS:
                    errors.append(f"detector {dr.get('detector_id')} has wrong schema")
                score = dr.get("score")
                if score is not None:
                    if isinstance(score, bool) or not isinstance(score, (int, float)):
                        errors.append(f"detector {dr.get('detector_id')} score is not numeric")
                    elif not math.isfinite(float(score)):
                        errors.append(f"detector {dr.get('detector_id')} score is not finite")
                verdict = dr.get("verdict")
                if verdict not in {"ai_like", "human_like", "abstain"}:
                    errors.append(f"detector {dr.get('detector_id')} has invalid verdict")

    return {
        "valid": not errors,
        "errors": errors,
        "seal_verified": info.get("seal_verified"),
        "trust_map_verified": info.get("trust_map_verified"),
        "dimensions": dimensions_status,
    }


# ---------------------------------------------------------------------------
# Combined case-file verification — the single entry point
# ---------------------------------------------------------------------------


def verify_case_file_combined(
    payload: dict[str, Any], *, public_key: bytes | None = None
) -> dict[str, Any]:
    """Verify a case file through BOTH independent verifiers.

    This is the single entry point for case-file verification, used by
    ``case verify``, ``verify`` (via :func:`verify_all`) and the MCP
    ``verify_case_file`` tool.  It runs the N-version replay above
    (Trust Map re-derivation, detector-result checks, independent seal
    recomputation) AND the primary-path check in
    ``casefile.verify_case_file`` (seal, manifest, raw-text portability,
    tool identity) and requires both to pass.  The two verifiers stay
    separate code paths — that independence is the point of N-version
    replay — but no caller may pick only one of them any more: before
    this function, the same file could be "valid" under ``case verify``
    and "invalid" under ``verify`` (e.g. a tampered Trust Map overall
    passed the seal check but failed the replay, and a stale manifest
    passed the replay but failed the seal check).

    The combined result is valid only when both verifiers pass, so the
    change is strictness in one direction only: no file that was valid
    under both verifiers becomes invalid, and no file that was invalid
    under either becomes valid.

    The primary-path check raises ``ValueError`` on non-finite floats
    (its canonical JSON uses ``allow_nan=False``); the combined entry
    point never raises for bad data — it reports the file invalid
    instead.

    ``public_key`` supplies the Ed25519 public key for cryptographic
    verification of a v3 T2 signature in the primary path.  Without
    it, a present signature is reported in ``primary["warnings"]`` as
    unverified — never silently treated as verified.

    Returns a dict with the N-version keys (``valid``, ``errors``,
    ``seal_verified``, ``trust_map_verified``, ``dimensions``) plus the
    primary-path keys (``schema``, ``case_sha256``, ``note``) and the
    two sub-results under ``nversion`` and ``primary`` (kept so the MCP
    tool can still report each path separately).
    """
    nversion = verify_case_file(payload)
    try:
        from .casefile import verify_case_file as _casefile_verify

        primary = _casefile_verify(payload, public_key=public_key)
    except ValueError as exc:
        primary = {
            "valid": False,
            "errors": [f"primary verification failed: {exc}"],
            "schema": payload.get("schema"),
            "case_sha256": payload.get("case_sha256"),
            "note": None,
        }
    errors = list(nversion.get("errors", [])) + list(primary.get("errors", []))
    return {
        "valid": bool(nversion.get("valid", False) and primary.get("valid", False)),
        "errors": errors,
        "warnings": primary.get("warnings", []),
        "seal_verified": nversion.get("seal_verified"),
        "trust_map_verified": nversion.get("trust_map_verified"),
        "dimensions": nversion.get("dimensions", {}),
        "schema": primary.get("schema"),
        "case_sha256": primary.get("case_sha256"),
        "note": primary.get("note"),
        "nversion": nversion,
        "primary": primary,
    }


def verify_case_file_path_combined(
    path: str | Path, *, public_key: bytes | None = None
) -> dict[str, Any]:
    """Load a case file from disk and run the combined verification.

    Unlike ``casefile.verify_case_file_path`` this never raises for bad
    input: malformed JSON or a non-dict payload returns a failed dict
    (same contract as :func:`verify_case_file_path`).
    """
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {
            "valid": False,
            "errors": [f"invalid JSON: {exc}"],
            "seal_verified": False,
            "trust_map_verified": False,
            "dimensions": {},
            "schema": None,
            "case_sha256": None,
            "note": None,
            "nversion": None,
            "primary": None,
        }
    if not isinstance(payload, dict):
        return {
            "valid": False,
            "errors": ["case file must be a JSON object"],
            "seal_verified": False,
            "trust_map_verified": False,
            "dimensions": {},
            "schema": None,
            "case_sha256": None,
            "note": None,
            "nversion": None,
            "primary": None,
        }
    return verify_case_file_combined(payload, public_key=public_key)


# ---------------------------------------------------------------------------
# Calibration artifact verification (independent code path)
# ---------------------------------------------------------------------------

_CALIBRATION_SCHEMA = "textforensics.calibration/v1"


def verify_calibration(artifact: dict[str, Any]) -> dict[str, Any]:
    """Re-validate a calibration artifact through an independent code path.

    This is separate from ``benchmark.validate_calibration_artifact``.

    Parameters
    ----------
    artifact:
        The parsed JSON calibration artifact.

    Returns
    -------
    A dict with keys:
        - valid: overall boolean
        - errors: list of error strings
        - checks: dict of individual check results
    """
    errors: list[str] = []
    checks: dict[str, bool] = {}

    # Schema
    checks["schema"] = artifact.get("schema") == _CALIBRATION_SCHEMA
    if not checks["schema"]:
        errors.append("invalid calibration schema")

    # Detector identity
    detector_id = artifact.get("detector_id")
    checks["detector_id"] = isinstance(detector_id, str) and len(detector_id) > 1
    if not checks["detector_id"]:
        errors.append("missing or empty detector_id")

    detector_version = artifact.get("detector_version")
    checks["detector_version"] = isinstance(detector_version, str) and len(detector_version) > 0
    if not checks["detector_version"]:
        errors.append("missing or empty detector_version")

    # Threshold
    threshold = artifact.get("recommended_threshold")
    checks["threshold_finite"] = False
    if (
        threshold is not None
        and not isinstance(threshold, bool)
        and isinstance(threshold, (int, float))
        and math.isfinite(float(threshold))
    ):
        checks["threshold_finite"] = True
    else:
        errors.append("recommended_threshold is not a finite number")

    # Dataset fingerprint
    fp = artifact.get("calibration_dataset_sha256")
    checks["dataset_fingerprint"] = False
    if isinstance(fp, str) and len(fp) == 64 and all(c in "0123456789abcdef" for c in fp):
        checks["dataset_fingerprint"] = True
    else:
        errors.append("invalid calibration_dataset_sha256")

    # Operating-point metrics sanity
    for metric_name in (
        "observed_false_positive_rate",
        "observed_true_positive_rate",
    ):
        val = artifact.get(metric_name)
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            if not 0.0 <= float(val) <= 1.0:
                errors.append(f"{metric_name} is outside [0, 1]")
                checks[metric_name] = False
            else:
                checks[metric_name] = True
        elif val is not None:
            errors.append(f"{metric_name} is not numeric")
            checks[metric_name] = False

    # Samples
    for field_name in ("human_samples", "ai_samples"):
        val = artifact.get(field_name)
        if not isinstance(val, int) or val < 1:
            errors.append(f"{field_name} must be a positive integer")
            checks[field_name] = False
        else:
            checks[field_name] = True

    return {
        "valid": not errors,
        "errors": errors,
        "checks": checks,
    }


# ---------------------------------------------------------------------------
# Benchmark metrics verification (independent code path)
# ---------------------------------------------------------------------------


def verify_benchmark(result: dict[str, Any]) -> dict[str, Any]:
    """Re-derive benchmark metrics from stored raw counts for consistency.

    This is an independent implementation of the metrics check in
    ``benchmark._metrics``. It re-computes rates from tp/fp/tn/fn and
    compares them to the stored values.

    Parameters
    ----------
    result:
        A benchmark result dict (output of ``benchmark_jsonl`` or
        ``benchmark_with_calibration_jsonl``).

    Returns
    -------
    A dict with keys:
        - valid: overall boolean
        - errors: list of error strings
        - recomputed_metrics: dict of re-derived metric values
    """
    errors: list[str] = []
    recomputed: dict[str, Any] = {}

    tp = result.get("tp", 0)
    fp = result.get("fp", 0)
    tn = result.get("tn", 0)
    fn = result.get("fn", 0)
    evaluated = result.get("evaluated", 0)

    # Total check
    total = tp + fp + tn + fn
    if total != evaluated:
        errors.append(f"evaluated ({evaluated}) != tp+fp+tn+fn ({total})")

    # Re-compute rates independently
    if total:
        recomputed["accuracy"] = round((tp + tn) / total, 4)
        recomputed["true_positive_rate"] = round(tp / (tp + fn), 4) if (tp + fn) else 0.0
        recomputed["false_positive_rate"] = round(fp / (fp + tn), 4) if (fp + tn) else 0.0
        recomputed["specificity"] = round(tn / (tn + fp), 4) if (tn + fp) else 0.0
        recomputed["false_negative_rate"] = round(fn / (fn + tp), 4) if (fn + tp) else 0.0
        recomputed["precision"] = round(tp / (tp + fp), 4) if (tp + fp) else 0.0
    else:
        recomputed["accuracy"] = 0.0
        recomputed["true_positive_rate"] = 0.0
        recomputed["false_positive_rate"] = 0.0
        recomputed["specificity"] = 0.0
        recomputed["false_negative_rate"] = 0.0
        recomputed["precision"] = 0.0

    # Cross-check stored values against re-derived
    for metric in (
        "accuracy",
        "true_positive_rate",
        "false_positive_rate",
        "specificity",
        "false_negative_rate",
        "precision",
    ):
        stored = result.get(metric)
        derived = recomputed[metric]
        if stored is not None and derived is not None:
            if abs(stored - derived) > 0.001:
                errors.append(f"{metric}: stored={stored} recomputed={derived}")
        elif stored is None and derived is not None:
            errors.append(f"{metric}: stored value is None")

    # Dataset fingerprint
    fp_str = result.get("dataset_sha256")
    if not isinstance(fp_str, str) or len(fp_str) != 64:
        errors.append("missing or invalid dataset_sha256")

    # Threshold sanity
    threshold = result.get("threshold")
    if threshold is not None and (
        isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
        or not math.isfinite(float(threshold))
    ):
        errors.append("threshold is not a finite number")

    return {
        "valid": not errors,
        "errors": errors,
        "recomputed_metrics": recomputed,
    }


# ---------------------------------------------------------------------------
# Unified verification entry point
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class VerificationReport:
    """Aggregated verification report."""

    case_file: dict[str, Any] | None = None
    calibration: dict[str, Any] | None = None
    benchmark: dict[str, Any] | None = None
    overall_valid: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "textforensics.verification-report/v1",
            "overall_valid": self.overall_valid,
            "case_file": self.case_file,
            "calibration": self.calibration,
            "benchmark": self.benchmark,
        }


def verify_all(
    case_payload: dict[str, Any] | None = None,
    calibration_artifact: dict[str, Any] | None = None,
    benchmark_result: dict[str, Any] | None = None,
) -> VerificationReport:
    """Run all verifications and return a consolidated report.

    Parameters
    ----------
    case_payload:
        Parsed case file JSON.
    calibration_artifact:
        Parsed calibration artifact JSON.
    benchmark_result:
        Parsed benchmark result JSON.

    Returns
    -------
    VerificationReport with per-check results and an overall validity flag.
    """
    report = VerificationReport()
    results = []

    if case_payload is not None:
        # The case-file part is the combined verification (N-version
        # replay AND primary-path seal check) — see
        # verify_case_file_combined.  A file must pass both.
        report.case_file = verify_case_file_combined(case_payload)
        results.append(report.case_file)

    if calibration_artifact is not None:
        report.calibration = verify_calibration(calibration_artifact)
        results.append(report.calibration)

    if benchmark_result is not None:
        report.benchmark = verify_benchmark(benchmark_result)
        results.append(report.benchmark)

    report.overall_valid = all(r.get("valid", False) for r in results)
    return report


def verify_case_file_path(path: str | Path) -> VerificationReport:
    """Load a case file from disk and verify it end-to-end.

    Parameters
    ----------
    path:
        Path to the sealed case file JSON.

    Returns
    -------
    VerificationReport with results.
    """
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return VerificationReport(
            case_file={
                "valid": False,
                "errors": [f"invalid JSON: {e}"],
                "seal_verified": False,
                "trust_map_verified": False,
                "dimensions": {},
            },
            overall_valid=False,
        )
    if not isinstance(payload, dict):
        return VerificationReport(
            case_file={
                "valid": False,
                "errors": ["case file must be a JSON object"],
                "seal_verified": False,
                "trust_map_verified": False,
                "dimensions": {},
            },
            overall_valid=False,
        )
    return verify_all(case_payload=payload)


__all__ = [
    "verify_case_file",
    "verify_case_file_combined",
    "verify_case_file_path",
    "verify_case_file_path_combined",
    "verify_calibration",
    "verify_benchmark",
    "verify_all",
    "VerificationReport",
]
